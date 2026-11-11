# SPDX-License-Identifier: MIT
"""The sanitized DashBoard session and a fake frame that replays it.

``fixtures/dashboard-session.jsonl`` is every OGP message of a capture
of DashBoard 10.0.0 reading an OGX frame (MFC-8322-S controller, ten
DRA-8804 cards), made by ``tools/fixture_from_capture.py`` with serials,
MAC, names and addresses replaced. Nothing here touches a real network:
the fake frame listens on 127.0.0.1.
"""

import json
import os
import socket
import threading
import time
from collections import defaultdict

import pytest

from opengearwire import _protocol as P
from opengearwire.client import _key
from opengearwire.model import Tree

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "dashboard-session.jsonl")


def load_session():
    out = []
    with open(FIXTURE) as f:
        for line in f:
            x = json.loads(line)
            msgs, left = P.split_stream(bytes.fromhex(x["m"]))
            assert left == 0 and len(msgs) == 1
            out.append((x["t"], x["d"], msgs[0]))
    return out


@pytest.fixture(scope="session")
def session():
    return load_session()


@pytest.fixture(scope="session")
def dashboard_tree(session):
    """The tree DashBoard got from its requests' replies (no pushes)."""
    t = Tree()
    for _, d, m in session:
        if d == "s2c" and m.is_reply:
            t.apply(m)
    return t


class FakeFrame:
    """A TCP server that answers like the captured frame.

    Each request is answered with the reply the frame gave DashBoard for
    the same request (in order, the last one repeating). A request the
    frame never saw gets no answer, like a lost one. After the hello it
    announces every device with the first report each sent on the
    capture, the way the real frame's periodic reports announced them.

    ``hang_up`` plays a controller that already has a client (an
    MFC-8322-S takes one): "connect" closes at once, "hello" closes
    right after answering the hello.
    """

    def __init__(self, session, hang_up=None):
        self.hang_up = hang_up
        self.replies = defaultdict(list)
        self.announce = []
        heard = set()
        for _, d, m in session:
            if d == "s2c" and m.is_reply:
                self.replies[_key(m)].append(m)
            elif d == "s2c" and m.type == P.REPORT_PARAM and m.src not in heard:
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
        self.received = []
        self.drop = defaultdict(int)  # key -> how many times to ignore it
        self.silent = False
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.conn = None
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            self.conn, _ = self.srv.accept()
        except OSError:
            return
        if self.hang_up == "connect":
            self.conn.close()
            return
        threading.Thread(target=self._beat, daemon=True).start()
        d = P.Deframer()
        while True:
            try:
                data = self.conn.recv(65536)
            except OSError:
                return
            if not data:
                return
            for m in d.feed(data):
                self.received.append(m)
                try:
                    self._answer(m)
                except OSError:
                    return

    def _answer(self, m):
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
        self.send(options[i])
        if m.type == P.SET_PARAM and self.hang_up == "hello":
            self.conn.shutdown(socket.SHUT_RDWR)
            return
        if m.type == P.SET_PARAM:
            self.send(P.Message(P.CONTROLLER, P.BROADCAST, P.REPORT_0x11, b"\x01"))
            for a in self.announce:
                self.send(a)

    def _beat(self):
        while True:
            time.sleep(0.25)
            if self.silent:
                continue
            try:
                self.send(self.heartbeat)
            except OSError:
                return

    def send(self, m):
        with self._lock:
            self.conn.sendall(m.encode())

    def close(self):
        for s in (self.conn, self.srv):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


@pytest.fixture
def fake(session):
    f = FakeFrame(session)
    yield f
    f.close()


def wait_for(cond, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False
