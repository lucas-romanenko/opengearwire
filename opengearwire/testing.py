# SPDX-License-Identifier: MIT
"""A fake frame for tests and app development: no hardware, no network.

``FakeFrame`` listens on 127.0.0.1 and answers like the frame of the
bundled capture (``fixtures/dashboard-session.jsonl``: DashBoard 10.0.0
reading an OGX frame with an MFC-8322-S controller and ten DRA-8804
cards, sanitized by ``tools/fixture_from_capture.py``: serials, MAC,
names and addresses replaced).

    from opengearwire import Frame
    from opengearwire.testing import FakeFrame

    fake = FakeFrame()
    with Frame("127.0.0.1", fake.port) as f:
        f.discover()

Like the real MFC-8322-S it takes **one client at a time**: a second
connection while one is open is closed at once, which ``Frame`` reports
as ``FrameBusy``. ``fake.busy = True`` plays "DashBoard is connected"
(every connection is turned away) until set back to False.

For a frame to point an app at while developing:

    python -m opengearwire.testing --port 5253
"""

import argparse
import json
import os
import socket
import struct
import threading
import time
from collections import defaultdict
from typing import Iterable, List, Optional, Tuple

from . import _protocol as P
from .client import _key
from .model import address_of

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "dashboard-session.jsonl")

#: (seconds into the capture, "c2s" or "s2c", message)
Session = List[Tuple[float, str, P.Message]]


def load_session(path: str = FIXTURE) -> Session:
    """Every message of a capture fixture, in order."""
    out = []
    with open(path) as f:
        for line in f:
            x = json.loads(line)
            msgs, left = P.split_stream(bytes.fromhex(x["m"]))
            if left != 0 or len(msgs) != 1:
                raise ValueError(f"{path}: a line is not exactly one message")
            out.append((x["t"], x["d"], msgs[0]))
    return out


class FakeFrame:
    """A TCP server that answers like the captured frame.

    Each request is answered with the reply the frame gave DashBoard for
    the same request (in order, the last one repeating). A request the
    frame never saw gets no answer, like a lost one. After the hello it
    announces every device with the first report each sent on the
    capture, the way the real frame's periodic reports announced them,
    and reports the controller's status every ``beat`` seconds.

    One client at a time, as an MFC-8322-S: a connection while another
    is open is closed at once, and so is every connection while
    ``busy`` is True. ``hang_up`` plays a controller that already has a
    client: "connect" closes at once, "hello" closes right after
    answering the hello.

    ``report(slot, oid, raw)`` pushes a changed value to the connected
    client and answers later reads of it with the new value.

    ``delay`` (seconds) holds every answer that long, as a network round
    trip plus the card's own time would (the capture: 4 ms median, a slow
    site 20 ms or more). Devices answer in parallel, as on a real frame.
    """

    def __init__(
        self,
        session: Optional[Session] = None,
        hang_up: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 0,
        beat: float = 0.25,
        delay: float = 0.0,
    ):
        if session is None:
            session = load_session()
        self.hang_up = hang_up
        self.busy = False
        self.beat = beat
        self.delay = delay
        self.replies = defaultdict(list)
        self.announce = []
        self._reports = {}
        heard = set()
        for _, d, m in session:
            if d == "s2c" and m.is_reply:
                self.replies[_key(m)].append(m)
            elif d == "s2c" and m.type == P.REPORT_PARAM:
                self._reports.setdefault((m.src, m.content[1:3]), m)
                if m.src not in heard:
                    heard.add(m.src)
                    self.announce.append(m)
        # The real controller reports "Frame status" every second; that
        # steady trickle is what the client's silence timeout relies on.
        self.heartbeat = next(
            m
            for _, d, m in session
            if d == "s2c" and m.type == P.REPORT_PARAM and m.src == P.CONTROLLER
        )
        self.used = defaultdict(int)
        self.received: List[P.Message] = []
        self.drop = defaultdict(int)  # key -> how many times to ignore it
        self.silent = False
        #: Connections accepted and served (turned-away ones not counted).
        self.connections = 0
        #: Connections closed at once because another client was on.
        self.turned_away = 0
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, port))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.conn: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._closed = False
        threading.Thread(target=self._accept, daemon=True).start()

    # ------------------------------------------------------------ server

    def _accept(self):
        while not self._closed:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            if self.hang_up == "connect" or self.busy or self.conn is not None:
                self.turned_away += 1
                conn.close()
                continue
            self.conn = conn
            self.connections += 1
            self.used = defaultdict(int)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        threading.Thread(target=self._beat, args=(conn,), daemon=True).start()
        d = P.Deframer()
        try:
            while True:
                try:
                    data = conn.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                for m in d.feed(data):
                    self.received.append(m)
                    try:
                        self._answer(conn, m)
                    except OSError:
                        return
        finally:
            try:
                conn.close()
            except OSError:
                pass
            if self.conn is conn:
                self.conn = None

    def _answer(self, conn, m):
        k = _key(m)
        if self.silent:
            return
        if self.drop[k] > 0:
            self.drop[k] -= 1
            return
        options = self.replies.get(k)
        if not options:
            return
        i = min(self.used[k], len(options) - 1)
        self.used[k] += 1
        if self.delay and m.type != P.SET_PARAM:
            t = threading.Timer(self.delay, self._send_quietly, args=(conn, options[i]))
            t.daemon = True
            t.start()
            return
        self._send(conn, options[i])
        if m.type == P.SET_PARAM and self.hang_up == "hello":
            conn.shutdown(socket.SHUT_RDWR)
            return
        if m.type == P.SET_PARAM:
            self._send(conn, P.Message(P.CONTROLLER, P.BROADCAST, P.REPORT_0x11, b"\x01"))
            for a in self.announce:
                self._send(conn, a)

    def _beat(self, conn):
        while self.conn is conn:
            time.sleep(self.beat)
            if self.silent:
                continue
            try:
                self._send(conn, self.heartbeat)
            except OSError:
                return

    def _send(self, conn, m):
        with self._lock:
            conn.sendall(m.encode())

    def _send_quietly(self, conn, m):
        try:
            self._send(conn, m)
        except OSError:
            pass

    def send(self, m: P.Message) -> None:
        """Send a message to the connected client."""
        self._send(self.conn, m)

    # ------------------------------------------------------------ values

    def report(self, slot: int, oid: int, raw: bytes) -> None:
        """Push a changed value, as a card does unasked, and answer
        later reads of it with that value. No client: only the latter."""
        a = address_of(slot)
        key = struct.pack(">H", oid)
        seen = self._reports.get((a, key))
        flag = seen.content[:1] if seen is not None else b"\x00"
        value = key + bytes((len(raw),)) + raw
        self.replies[(a, P.GET_PARAM, key)] = [
            P.Message(a, P.CLIENT, P.GET_PARAM | P.RESPONSE_BIT, b"\x00" + value)
        ]
        if self.conn is not None:
            try:
                self.send(P.Message(a, P.BROADCAST, P.REPORT_PARAM, flag + value))
            except OSError:
                pass

    def close(self) -> None:
        self._closed = True
        for s in (self.conn, self.srv):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def main(argv: Optional[Iterable[str]] = None) -> None:
    ap = argparse.ArgumentParser(
        prog="python -m opengearwire.testing",
        description="Run a fake openGear frame (the bundled capture) until Ctrl-C.",
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5253)
    ap.add_argument("--busy", action="store_true", help="turn every client away (DashBoard open)")
    ap.add_argument("--delay", type=float, default=0.0, help="hold every answer this many ms")
    a = ap.parse_args(list(argv) if argv is not None else None)
    fake = FakeFrame(host=a.host, port=a.port, beat=1.0, delay=a.delay / 1000)
    fake.busy = a.busy
    print(f"fake openGear frame on {a.host}:{fake.port}{' (busy)' if a.busy else ''}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        fake.close()


if __name__ == "__main__":
    main()
