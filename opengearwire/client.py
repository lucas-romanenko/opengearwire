# SPDX-License-Identifier: MIT
"""Read-only client for one openGear frame over OGP (TCP 5253).

    with Frame("192.0.2.10") as f:
        f.discover()              # which slots are occupied
        f.describe()              # every card's parameters, values, menus
        print(f.tree.device(0x14).find("Product").value)
        snap = f.snapshot()       # plain data, fit for JSON

How it talks, copied from DashBoard 10 on the capture:

- One TCP connection. The client introduces itself (a write of OID
  0xFF03 on the controller, the only write this library sends; it sets
  nothing on the frame), then the frame starts reporting.
- Cards are found by listening: every card reports its current draw
  about once a second, so within a second or two every occupied slot has
  spoken. Discovery stops as soon as the controller's "Active Cards"
  count is reached, or after a quiet spell with nobody new.
- One client at a time: an MFC-8322-S controller takes one control
  connection and hangs up on a second one (DashBoard open = this
  library locked out, and the other way round). Connect, read,
  disconnect; a hang-up at connect raises ``FrameBusy``.
- One request outstanding per device, every device in parallel. A
  request with no answer is sent again after ``retry_after`` seconds
  (DashBoard: 2.5 s; nine of its first requests went unanswered on the
  capture and each retry was answered at once). Requests still
  unanswered after ``retries`` get one more round once everything else
  is done; what stays unanswered is listed in ``Frame.unanswered``.
- Timeouts are no-progress: the frame reports its own status every
  second, so ``timeout`` seconds without a single byte from it means the
  link is dead. There is no fixed total.
- Nothing runs on a timer. Every method touches only what it says.
"""

import select
import socket
import time
from typing import Callable, Dict, Generator, Iterable, List, Optional, Tuple

from . import _protocol as P
from .model import Change, Device, Tree, address_of, slot_of

PORT = 5253

#: OID of the controller's "Active Cards" (number of cards in the frame).
ACTIVE_CARDS = 0x0717
#: "Product" on the controller and on every card of the capture.
PRODUCT = 0x0105

Exchange = Generator[P.Message, P.Message, None]


class FrameError(ConnectionError):
    """The frame stopped answering or refused the connection."""


class FrameBusy(FrameError):
    """The frame hung up at connect, before or right after the hello.

    The likely cause is another client: an MFC-8322-S controller takes
    one control connection at a time (Ross's MFC manual lists more than
    one only for the MFC-OG3-N) and hangs up on a second one.
    """

    def __init__(self):
        super().__init__(
            "the frame hung up as soon as we connected: another client such as"
            " DashBoard is probably connected, and this controller model"
            " (MFC-8322-S) takes one control connection at a time; close the"
            " other client and try again"
        )


def _key(m: P.Message) -> Tuple[int, int, bytes]:
    """What pairs a reply with its request: device, type, the echoed id."""
    t = m.type & 0x7F
    c = m.content
    dev = m.dst if not m.is_reply else m.src
    if t in (
        P.GET_DESCRIPTOR,
        P.GET_PARAM,
        P.SET_PARAM,
        P.GET_MENU_NAME,
        P.GET_MENU_OIDS,
        P.GET_MENU_STATE,
    ):
        k = c[1:3]
    elif t in (P.GET_MENUSET_NAME, P.GET_MENU_COUNT):
        k = c[1:2]
    elif t in (P.GET_ARRAY_ELEMENT, P.GET_EXTERNAL_OBJECT):
        k = c[1:5]
    else:
        k = b""
    return dev, t, bytes(k)


class Frame:
    """A connection to one frame. Use as a context manager."""

    def __init__(
        self,
        host: str,
        port: int = PORT,
        *,
        timeout: float = 5.0,
        retry_after: float = 2.5,
        retries: int = 3,
        client_name: Optional[str] = None,
        connect: Callable[..., socket.socket] = socket.create_connection,
    ):
        from . import __version__

        self.host = host
        self.port = port
        self.timeout = timeout
        self.retry_after = retry_after
        self.retries = retries
        self.client_name = client_name or f"opengearwire {__version__}"
        self._connect = connect
        self.sock: Optional[socket.socket] = None
        self.tree = Tree()
        self._deframer = P.Deframer()
        self._last_rx = 0.0
        self._replies: List[P.Message] = []
        self.changes: List[Change] = []
        #: Requests that got no answer after every retry and the final
        #: round, as plain dicts (see ``describe_request``).
        self.unanswered: List[dict] = []
        #: True from connect until the first reply after the hello: a
        #: hang-up in that window means "busy", later it is a plain error.
        self._connecting = False
        self.on_change: Optional[Callable[[Change], None]] = None
        self.hello: Tuple[int, ...] = ()

    # ------------------------------------------------------------ socket

    def __enter__(self) -> "Frame":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    def open(self) -> "Frame":
        self.sock = self._connect((self.host, self.port), self.timeout)
        self.sock.setblocking(False)
        self._last_rx = time.monotonic()
        self._connecting = True
        try:
            reply = self._exchange_one(P.hello(self.client_name))
            self.hello = P.parse_hello_reply(reply)
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _hung_up(self) -> FrameError:
        if self._connecting:
            return FrameBusy()
        return FrameError("the frame closed the connection")

    def _send(self, m: P.Message) -> None:
        data = m.encode()
        while data:
            try:
                n = self.sock.send(data)
                data = data[n:]
            except BlockingIOError:
                select.select([], [self.sock], [], self.timeout)
            except (BrokenPipeError, ConnectionResetError) as e:
                raise self._hung_up() from e

    def _pump(self, wait: float) -> None:
        """Read whatever arrives within ``wait`` s; file it in the tree."""
        r, _, _ = select.select([self.sock], [], [], max(0.0, wait))
        now = time.monotonic()
        if r:
            try:
                data = self.sock.recv(65536)
            except BlockingIOError:
                data = None
            except ConnectionResetError as e:
                raise self._hung_up() from e
            if data == b"":
                raise self._hung_up()
            if data:
                self._last_rx = now
                for m in self._deframer.feed(data):
                    self._receive(m)
        if now - self._last_rx > self.timeout:
            raise FrameError(f"nothing from the frame for {self.timeout:g} s")

    def _receive(self, m: P.Message) -> None:
        ch = self.tree.apply(m)
        if m.is_reply:
            if self.hello:
                self._connecting = False  # the frame took us: past the hello
            self._replies.append(m)
        if ch is not None and ch.pushed:
            self.changes.append(ch)
            if self.on_change:
                self.on_change(ch)

    # ---------------------------------------------------------- requests

    def _exchange_one(self, req: P.Message) -> P.Message:
        out: List[P.Message] = []

        def one() -> Exchange:
            r = yield req
            if r is not None:
                out.append(r)

        self._run({req.dst: one()})
        if not out:
            raise FrameError(f"no answer to {P.NAMES.get(req.type, hex(req.type))}")
        return out[0]

    def _run(self, exchanges: Dict[int, Exchange], final: bool = False) -> None:
        """Drive one exchange per device, one request in flight each.

        A request unanswered after every retry is skipped (its exchange
        gets None and goes on) and asked once more in a final round when
        all exchanges are done; only then is it listed as unanswered.
        """
        live: Dict[int, list] = {}  # dev -> [gen, req, sent_at, tries]
        gave_up: Dict[int, List[P.Message]] = {}

        def advance(dev: int, gen: Exchange, reply: Optional[P.Message]) -> None:
            try:
                req = gen.send(reply)  # None starts it, or reports a give-up
            except StopIteration:
                live.pop(dev, None)
                return
            live[dev] = [gen, req, time.monotonic(), 1]
            self._send(req)

        for dev, gen in exchanges.items():
            advance(dev, gen, None)
        while live:
            self._pump(0.05)
            replies, self._replies = self._replies, []
            for m in replies:
                k = _key(m)
                entry = live.get(k[0])
                if entry and _key(entry[1]) == k:
                    advance(k[0], entry[0], m)
            now = time.monotonic()
            for dev, entry in list(live.items()):
                gen, req, sent, tries = entry
                if now - sent < self.retry_after:
                    continue
                if tries > self.retries:
                    # Give up on this one request, not the device: the
                    # exchange gets None and carries on with the next.
                    if final:
                        self.unanswered.append(self.describe_request(req))
                    else:
                        gave_up.setdefault(dev, []).append(req)
                    advance(dev, gen, None)
                    continue
                entry[2], entry[3] = now, tries + 1
                self._send(req)
        if gave_up:
            self._run({dev: self._again(dev, reqs) for dev, reqs in gave_up.items()}, final=True)

    def _again(self, a: int, reqs: List[P.Message]) -> Exchange:
        """The final round: each skipped request once more, and if a late
        answer opens more work (an OID list, a chunked object, a menu
        set), that work too."""
        dev = self.tree.device(a)
        for req in reqs:
            r = yield req
            if r is None or r.rc != P.RC_OK:
                continue
            t = req.type
            if t == P.GET_PARAM_OIDS:
                new = [o for o in dev.oids if not (o in dev.params and dev.params[o].descriptor)]
                yield from self._params(a, new)
                for obj in dev.external_ids():
                    if obj not in dev.external:
                        yield from self._external(a, obj)
            elif t == P.GET_DESCRIPTOR:
                c = P.parse_descriptor(r).constraint
                if c.kind == "external" and c.object_id not in dev.external:
                    yield from self._external(a, c.object_id)
            elif t == P.GET_EXTERNAL_OBJECT:
                ch = P.parse_external_object(r)
                if ch.next:
                    yield from self._external(a, ch.object_id, ch.next)
            elif t == P.GET_MENUSET_NAME:
                yield from self._menuset(a, req.content[1])
            elif t == P.GET_MENU_COUNT:
                yield from self._menus(a, *P.parse_menu_count(r))

    def describe_request(self, req: P.Message) -> dict:
        """A request as plain data: slot, request, and what it asked for
        (OID and the parameter's name if known, menu, object)."""
        out = {"slot": slot_of(req.dst), "request": P.NAMES.get(req.type, hex(req.type))}
        c = req.content
        t = req.type
        if t in (P.GET_DESCRIPTOR, P.GET_PARAM, P.SET_PARAM, P.GET_ARRAY_ELEMENT):
            oid = int.from_bytes(c[1:3], "big")
            out["oid"] = f"0x{oid:04x}"
            p = self.tree.device(req.dst).params.get(oid)
            if p is not None and p.name:
                out["name"] = p.name
        elif t in (P.GET_MENU_NAME, P.GET_MENU_OIDS, P.GET_MENU_STATE):
            out.update(menuset=c[1], menu=c[2])
        elif t in (P.GET_MENUSET_NAME, P.GET_MENU_COUNT):
            out["menuset"] = c[1]
        elif t == P.GET_EXTERNAL_OBJECT:
            out.update(object=int.from_bytes(c[1:3], "big"), offset=int.from_bytes(c[3:5], "big"))
        out["content"] = c.hex()
        return out

    # ------------------------------------------------------------- reads

    def discover(self, quiet: float = 2.0) -> List[int]:
        """Occupied slots, by listening for the cards' own reports.

        Stops once the controller's Active Cards count is reached, or
        when ``quiet`` seconds pass with no new device speaking.
        """
        expected = None
        try:
            self._run({P.CONTROLLER: self._fetch(P.CONTROLLER, [ACTIVE_CARDS])})
            expected = self.tree.controller.value(ACTIVE_CARDS)
        except P.ProtocolError:
            pass
        last_new = time.monotonic()
        seen = len(self.tree.heard)
        while True:
            if expected is not None and len(self.tree.cards) >= expected:
                break
            if time.monotonic() - last_new > quiet:
                break
            self._pump(0.05)
            if len(self.tree.heard) != seen:
                seen = len(self.tree.heard)
                last_new = time.monotonic()
        return self.slots()

    def slots(self) -> List[int]:
        """Slots heard from so far, controller (0) first."""
        return sorted(slot_of(a) for a in self.tree.devices)

    def describe(self, slots: Optional[Iterable[int]] = None, menus: bool = True) -> None:
        """Every parameter's descriptor and value (and the menus) of the
        given slots (default: every slot heard), all slots in parallel."""
        if slots is None:
            slots = self.slots()
        self._run({address_of(s): self._describe(address_of(s), menus) for s in slots})

    def identify(self, slots: Optional[Iterable[int]] = None) -> Dict[int, str]:
        """Product name of each slot (two small reads per slot)."""
        if slots is None:
            slots = self.slots()
        slots = list(slots)
        self._run({address_of(s): self._fetch(address_of(s), [PRODUCT]) for s in slots})
        return {s: self.device(s).product for s in slots}

    def describe_oids(self, slot: int, oids: Iterable[int]) -> None:
        """Descriptor and value of just these OIDs of one slot."""
        a = address_of(slot)
        self._run({a: self._fetch(a, list(oids))})

    @staticmethod
    def _fetch(a: int, oids: List[int]) -> Exchange:
        for oid in oids:
            yield P.get_descriptor(a, oid)
            yield P.get_param(a, oid)

    _params = _fetch

    @staticmethod
    def _external(a: int, obj: int, offset: int = 0) -> Exchange:
        while True:
            r = yield P.get_external_object(a, obj, offset)
            if r is None or r.rc != P.RC_OK:
                return
            ch = P.parse_external_object(r)
            if ch.next == 0:
                return
            offset = ch.next

    def _menuset(self, a: int, s: int) -> Exchange:
        r = yield P.get_menu_count(a, s)
        if r is not None and r.rc == P.RC_OK:
            yield from self._menus(a, *P.parse_menu_count(r))

    @staticmethod
    def _menus(a: int, s: int, count: int) -> Exchange:
        for i in range(count):
            yield P.get_menu_name(a, s, i)
            yield P.get_menu_oids(a, s, i)
            yield P.get_menu_state(a, s, i)

    def _describe(self, a: int, menus: bool) -> Exchange:
        dev = self.tree.device(a)
        yield P.get_numparams(a)
        yield P.get_param_oids(a)
        yield from self._params(a, list(dev.oids))
        for obj in dev.external_ids():
            yield from self._external(a, obj)
        if not menus:
            return
        for s in range(3):
            r = yield P.get_menuset_name(a, s)
            if r is None:
                continue  # asked again in the final round
            if r.rc != P.RC_OK:
                break
            yield from self._menuset(a, s)

    def read(self, slot: int, *keys) -> Dict[int, object]:
        """Fresh values of the given OIDs (or names, once described)."""
        a = address_of(slot)
        dev = self.tree.device(a)
        oids = [k if isinstance(k, int) else dev.find(k).oid for k in keys]

        def ex() -> Exchange:
            for oid in oids:
                yield P.get_param(a, oid)

        self._run({a: ex()})
        return {o: dev.params[o].value for o in oids if o in dev.params}

    def watch(self, seconds: float) -> List[Change]:
        """Listen for ``seconds`` and return the changes the frame pushed.

        Reports keep arriving whether or not anyone listens; this only
        reads them. The tree is updated as they come.
        """
        start = len(self.changes)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self._pump(min(0.1, end - time.monotonic()))
        return self.changes[start:]

    def device(self, slot: int) -> Device:
        return self.tree.device(address_of(slot))

    def snapshot(self) -> dict:
        from .snapshot import snapshot

        return snapshot(self.tree, host=self.host, unanswered=self.unanswered)
