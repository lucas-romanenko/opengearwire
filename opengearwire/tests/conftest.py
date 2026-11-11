# SPDX-License-Identifier: MIT
"""The sanitized DashBoard session and the fake frame that replays it
(``opengearwire.testing``, public so apps can test against it too).

``opengearwire/fixtures/dashboard-session.jsonl`` is every OGP message of a capture
of DashBoard 10.0.0 reading an OGX frame (MFC-8322-S controller, ten
DRA-8804 cards), made by ``tools/fixture_from_capture.py`` with serials,
MAC, names and addresses replaced. Nothing here touches a real network:
the fake frame listens on 127.0.0.1.
"""

import time

import pytest

from opengearwire.model import Tree
from opengearwire.testing import FakeFrame, load_session

__all__ = ["FakeFrame", "load_session", "wait_for"]


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
