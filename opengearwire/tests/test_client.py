# SPDX-License-Identifier: MIT
"""The client against a fake frame replaying the captured session."""

import socket
import time

import pytest

from opengearwire import Frame, FrameBusy, FrameError, snapshot
from opengearwire import _protocol as P
from opengearwire.client import _key

from .conftest import wait_for


def frame(fake, **kw):
    kw.setdefault("timeout", 2.0)
    kw.setdefault("retry_after", 0.3)
    kw.setdefault("client_name", "Version 10.0.0 2026-08-27 T14:22")
    return Frame("127.0.0.1", fake.port, **kw)


def test_hello_is_dashboards(fake):
    with frame(fake) as f:
        assert f.hello == (1, 1, 0)
    assert fake.received[0].encode() == P.hello("Version 10.0.0 2026-08-27 T14:22").encode()


def test_discover_stops_at_active_cards(fake):
    with frame(fake) as f:
        t0 = time.monotonic()
        slots = f.discover(quiet=5.0)
        assert time.monotonic() - t0 < 2.0  # did not sit out the quiet spell
    assert slots == [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]


def test_describe_rebuilds_dashboards_tree(fake, dashboard_tree):
    with frame(fake) as f:
        f.discover()
        f.describe()
        assert f.unanswered == []
        got = f.tree
    assert sorted(got.devices) == sorted(dashboard_tree.devices)
    for a, want in dashboard_tree.devices.items():
        have = got.devices[a]
        assert have.oids == want.oids
        assert have.menusets == want.menusets
        assert {k: (m.name, m.oids, m.state) for k, m in have.menus.items()} == {
            k: (m.name, m.oids, m.state) for k, m in want.menus.items()
        }
        assert have.external == want.external
        for oid, p in want.params.items():
            q = have.params[oid]
            assert q.descriptor == p.descriptor, f"0x{a:02x} 0x{oid:04x}"
            assert q.raw == p.raw, f"0x{a:02x} 0x{oid:04x}"
            assert q.display == p.display


def test_reads_only(fake):
    """Apart from the hello, the client sends no write of any kind."""
    with frame(fake) as f:
        f.discover()
        f.describe()
    writes = [m for m in fake.received if m.type == P.SET_PARAM]
    assert len(writes) == 1 and writes[0].content[1:3] == b"\xff\x03"
    assert {m.type for m in fake.received} <= {
        P.SET_PARAM,
        P.GET_NUMPARAMS,
        P.GET_PARAM_OIDS,
        P.GET_DESCRIPTOR,
        P.GET_PARAM,
        P.GET_EXTERNAL_OBJECT,
        P.GET_MENUSET_NAME,
        P.GET_MENU_COUNT,
        P.GET_MENU_NAME,
        P.GET_MENU_OIDS,
        P.GET_MENU_STATE,
    }


def test_one_request_in_flight_per_device(fake):
    with frame(fake) as f:
        f.discover()
        f.describe()
    # Per device, requests strictly alternate with replies: the fake
    # answers at once, so a second request before the first reply would
    # show up as two requests in a row with nothing answered between.
    assert fake.used  # sanity: something was answered


def test_lost_request_is_retried(fake):
    k = _key(P.get_descriptor(0x14, 0x0B0B))
    fake.drop[k] = 1
    with frame(fake) as f:
        f.discover()
        f.describe([4])
        assert f.unanswered == []
        assert f.device(4).find(0x0B0B).name == "Channel Options"
    sent = [m for m in fake.received if _key(m) == k]
    assert len(sent) == 2


def test_never_answered_is_reported_not_fatal(fake):
    k = _key(P.get_param(0x14, 0x0B0B))
    fake.drop[k] = 99
    with frame(fake, retries=1) as f:
        f.discover()
        f.describe([4], menus=False)
        assert f.unanswered == [
            {
                "slot": 4,
                "request": "GET_PARAM",
                "oid": "0x0b0b",
                "name": "Channel Options",
                "content": "000b0b",
            }
        ]
        assert f.device(4).find(0x0B0A).name == "Enable Rear 12V"
        snap = f.snapshot()
    assert snap["unanswered"] == f.unanswered
    # retries=1: two sends in the main round, two more in the final round
    assert len([m for m in fake.received if _key(m) == k]) == 4


def test_final_round_catches_a_late_answer(fake):
    k = _key(P.get_descriptor(0x14, 0x0B0B))
    fake.drop[k] = 2  # lost twice: the main round gives up, the final round gets it
    with frame(fake, retries=1) as f:
        f.discover()
        f.describe([4], menus=False)
        assert f.unanswered == []
        assert f.device(4).find(0x0B0B).name == "Channel Options"


def test_final_round_finishes_what_a_late_answer_opens(fake, dashboard_tree):
    """A late OID list (or menu count) is followed through, not just filed."""
    for req in (P.get_param_oids(0x14), P.get_menu_count(0x14, 1)):
        fake.drop[_key(req)] = 2
    with frame(fake, retries=1) as f:
        f.discover()
        f.describe([4])
        assert f.unanswered == []
        have = f.device(4)
    want = dashboard_tree.devices[0x14]
    assert have.oids == want.oids
    assert have.external == want.external
    assert all(have.params[o].descriptor == want.params[o].descriptor for o in want.oids)
    assert {k: (m.name, m.oids) for k, m in have.menus.items()} == {
        k: (m.name, m.oids) for k, m in want.menus.items()
    }


def test_unanswered_in_snapshot_is_json(fake):
    import json

    fake.drop[_key(P.get_menu_state(0x14, 0, 1))] = 99
    with frame(fake, retries=0) as f:
        f.discover()
        f.describe([4])
        s = snapshot(f.tree, unanswered=f.unanswered)
    assert json.loads(json.dumps(s))["unanswered"] == [
        {"slot": 4, "request": "GET_MENU_STATE", "menuset": 0, "menu": 1, "content": "000001"}
    ]


def test_read_by_oid(fake):
    with frame(fake) as f:
        f.describe_oids(20, [0x0105, 0x0B04])
        vals = f.read(20, 0x0105, 0x0B04)
    assert vals[0x0105] == "DRA-8804"
    assert isinstance(vals[0x0B04], list) and len(vals[0x0B04]) == 2


def test_watch_returns_pushed_changes(fake, session):
    reports = [m for _, d, m in session if m.type == P.REPORT_PARAM and m.src == 0x24][:5]
    with frame(fake) as f:
        f.discover()
        f.describe([20], menus=False)
        for m in reports:
            fake.send(m)
        changes = f.watch(0.3)
    assert len(changes) >= 5
    assert {c.slot for c in changes} >= {20}


def test_silence_is_a_dead_link(fake):
    with frame(fake, timeout=0.5) as f:
        fake.silent = True
        with pytest.raises(FrameError, match="nothing from the frame"):
            f.describe([4])


def test_closed_connection(fake):
    """A hang-up once the frame has answered is the plain error."""
    with frame(fake) as f:
        f.discover()
        assert wait_for(lambda: fake.conn is not None)
        fake.conn.shutdown(socket.SHUT_RDWR)
        with pytest.raises(FrameError) as e:
            f.watch(1.0)
        assert not isinstance(e.value, FrameBusy)
        assert str(e.value) == "the frame closed the connection"


@pytest.mark.parametrize("when", ["connect", "hello"])
def test_hang_up_at_connect_is_busy(session, when):
    """An MFC-8322-S with a client already (DashBoard) hangs up on us."""
    from .conftest import FakeFrame

    fake = FakeFrame(session, hang_up=when)
    try:
        f = frame(fake)
        with pytest.raises(FrameBusy, match="DashBoard is probably connected") as e:
            f.open()
            f.discover()
        assert "one control connection at a time" in str(e.value)
        assert isinstance(e.value, FrameError)
    finally:
        fake.close()


def _readdress(session, old, new):
    """The session with one card moved to another address."""
    out = []
    for t, d, m in session:
        if d == "c2s" and m.dst == old:
            m = P.Message(m.src, new, m.type, m.content)
        elif d == "s2c" and m.src == old:
            m = P.Message(new, m.dst, m.type, m.content)
        out.append((t, d, m))
    return out


def test_any_slot_is_found_odd_slots_too(session):
    """A frame has 20 slots and single-width cards can sit on odd ones:
    discovery listens for whoever speaks, it never assumes a layout."""
    from .conftest import FakeFrame

    moved = _readdress(session, 0x14, 0x13)  # slot 4 -> slot 3
    fake = FakeFrame(moved)
    try:
        with frame(fake) as f:
            assert f.discover() == [0, 2, 3, 6, 8, 10, 12, 14, 16, 18, 20]
            f.describe([3], menus=False)
            assert f.device(3).product == "DRA-8804"
    finally:
        fake.close()
