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
- One request outstanding per device, every device in parallel. A
  request with no answer is sent again after ``retry_after`` seconds
  (DashBoard: 2.5 s; nine of its first requests went unanswered on the
  capture and each retry was answered at once).
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
        #: Requests that got no answer after every retry: (slot, name, hex).
        self.unanswered: List[Tuple[int, str, str]] = []
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
        reply = self._exchange_one(P.hello(self.client_name))
        self.hello = P.parse_hello_reply(reply)
        return self

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _send(self, m: P.Message) -> None:
        data = m.encode()
        while data:
            try:
                n = self.sock.send(data)
                data = data[n:]
            except BlockingIOError:
                select.select([], [self.sock], [], self.timeout)

    def _pump(self, wait: float) -> None:
        """Read whatever arrives within ``wait`` s; file it in the tree."""
        r, _, _ = select.select([self.sock], [], [], max(0.0, wait))
        now = time.monotonic()
        if r:
            try:
                data = self.sock.recv(65536)
            except BlockingIOError:
                data = None
            if data == b"":
                raise FrameError("the frame closed the connection")
            if data:
                self._last_rx = now
                for m in self._deframer.feed(data):
                    self._receive(m)
        if now - self._last_rx > self.timeout:
            raise FrameError(f"nothing from the frame for {self.timeout:g} s")

    def _receive(self, m: P.Message) -> None:
        ch = self.tree.apply(m)
        if m.is_reply:
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

    def _run(self, exchanges: Dict[int, Exchange]) -> None:
        """Drive one exchange per device, one request in flight each."""
        live: Dict[int, list] = {}  # dev -> [gen, req, sent_at, tries]

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
                    self.unanswered.append(
                        (slot_of(dev), P.NAMES.get(req.type, hex(req.type)), req.content.hex())
                    )
                    advance(dev, gen, None)
                    continue
                entry[2], entry[3] = now, tries + 1
                self._send(req)

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

    def _describe(self, a: int, menus: bool) -> Exchange:
        dev = self.tree.device(a)
        yield P.get_numparams(a)
        yield P.get_param_oids(a)
        for oid in list(dev.oids):
            yield P.get_descriptor(a, oid)
            yield P.get_param(a, oid)
        for obj in dev.external_ids():
            offset = 0
            while True:
                r = yield P.get_external_object(a, obj, offset)
                if r is None:
                    break
                ch = P.parse_external_object(r)
                if ch.next == 0:
                    break
                offset = ch.next
        if not menus:
            return
        for s in range(3):
            r = yield P.get_menuset_name(a, s)
            if r is None or r.rc != P.RC_OK:
                break
            r = yield P.get_menu_count(a, s)
            if r is None:
                break
            _, count = P.parse_menu_count(r)
            for i in range(count):
                yield P.get_menu_name(a, s, i)
                yield P.get_menu_oids(a, s, i)
                yield P.get_menu_state(a, s, i)

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

        return snapshot(self.tree, host=self.host)
