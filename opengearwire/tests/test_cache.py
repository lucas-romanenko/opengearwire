# SPDX-License-Identifier: MIT
"""Descriptors kept between connections; values always read afresh."""

import json
import time
from collections import Counter

from opengearwire import Frame, cache, snapshot
from opengearwire import _protocol as P
from opengearwire.client import _key
from opengearwire.testing import FakeFrame


def frame(fake, store, **kw):
    kw.setdefault("timeout", 2.0)
    kw.setdefault("retry_after", 0.2)
    return Frame("127.0.0.1", fake.port, descriptors=store, **kw)


def read(fake, store, **kw):
    """One connection: discover and describe (no menus), like an app's
    first paint. Returns the frame and the requests the fake got."""
    fake.received.clear()
    with frame(fake, store, **kw) as f:
        f.discover()
        f.describe(menus=False)
    for _ in range(100):
        if fake.conn is None:
            break
        time.sleep(0.01)
    return f, Counter(m.type for m in fake.received)


def plain(snap):
    snap = dict(snap)
    snap.pop("taken_at")
    return snap


def test_miss_then_hit_reads_values_only(fake):
    store = {}
    f1, n1 = read(fake, store)
    assert f1.cache_hits == []
    # the controller, and one entry the ten DRA-8804s share (same model,
    # same software rev, same OID list: byte-identical descriptors)
    assert sorted(k[0] for k in store) == ["DRA-8804", "MFC-8322-S"]
    assert n1[P.GET_DESCRIPTOR] == 601  # 600 + Active Cards, asked in discovery

    f2, n2 = read(fake, store)
    assert sorted(f2.cache_hits) == [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    assert n2[P.GET_DESCRIPTOR] == 1  # discovery's Active Cards, asked before any key is known
    assert n2[P.GET_EXTERNAL_OBJECT] == 0
    assert n2[P.GET_PARAM] == n1[P.GET_PARAM]  # every value still read
    assert plain(f2.snapshot()) == plain(f1.snapshot())


def test_entries_hold_no_values(fake):
    store = {}
    f, _ = read(fake, store)
    for e in store.values():
        assert set(e) == {"version", "descriptors", "external", "unanswered"}
    json.dumps(list(store.values()))
    # a value the frame has (the controller's frame name) appears nowhere
    name = f.tree.controller.params[0x070B].raw
    assert name and name.hex() not in json.dumps(list(store.values()))


def test_values_are_this_connections_not_the_last(fake):
    store = {}
    read(fake, store)
    fake.report(20, 0x0805, b"12 (1694A) / 7 (1855A)\0")  # changed while nobody was connected
    f, _ = read(fake, store)
    assert 20 in f.cache_hits
    assert f.device(20).value(0x0805) == "12 (1694A) / 7 (1855A)"


def test_another_software_rev_is_a_miss(fake):
    store = {}
    read(fake, store)
    fake.report(4, cache.SOFTWARE_REV, b"9.99\0")
    f, n = read(fake, store)
    assert 4 not in f.cache_hits and 6 in f.cache_hits
    assert n[P.GET_DESCRIPTOR] == len(f.device(4).oids) + 1
    assert len(store) == 3  # the new rev has its own entry


def test_unusable_entry_is_a_miss(fake):
    store = {}
    read(fake, store)
    for k in store:
        store[k] = {"version": 0}
    f, n = read(fake, store)
    assert f.cache_hits == []
    assert n[P.GET_DESCRIPTOR] == 601
    assert all(e["version"] == cache.VERSION for e in store.values())  # rewritten


CARDS = range(0x12, 0x26, 2)


def test_unanswered_is_learned_and_skipped(fake):
    """A request no card of the model answers (firmware) is learned, and
    later reads don't wait it out."""
    store = {}
    lost = [P.get_param(a, 0x0B0B) for a in CARDS]
    for m in lost:
        fake.drop[_key(m)] = 999
    f1, _ = read(fake, store, retries=1)
    assert len(f1.unanswered) == 10
    k = cache.key(f1.device(4))
    assert store[k]["unanswered"] == ["0x0b0b"]

    t0 = time.monotonic()
    f2, _ = read(fake, store, retries=1)
    assert time.monotonic() - t0 < 1.0  # nothing waited out
    assert not any(_key(m) in {_key(x) for x in lost} for m in fake.received)
    assert f2.unanswered == []
    assert store[k]["unanswered"] == ["0x0b0b"]  # still known as unanswered

    # asked again when told to (an app's "Read again"); answered now: forgotten
    for m in lost:
        fake.drop[_key(m)] = 0
    fake.received.clear()
    with frame(fake, store) as f3:
        f3.discover()
        f3.describe(menus=False, skip_unanswered=False)
    assert any(_key(m) == _key(lost[0]) for m in fake.received)
    assert store[k]["unanswered"] == []


def test_one_cards_silence_is_not_learned_for_the_model(fake):
    """One card not answering says nothing about the others: not skipped."""
    store = {}
    fake.drop[_key(P.get_param(0x14, 0x0B0B))] = 999
    f1, _ = read(fake, store, retries=1)
    assert [(u["slot"], u["oid"]) for u in f1.unanswered] == [(4, "0x0b0b")]
    assert store[cache.key(f1.device(4))]["unanswered"] == []


def test_first_pass_does_not_wait_for_the_final_round(fake):
    fake.drop[_key(P.get_param(0x14, 0x0B0B))] = 999
    done = []
    with frame(fake, {}, retries=1) as f:
        f.discover()
        f.describe(menus=False, final_round=False, on_device=done.append)
        assert sorted(done) == [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
        assert f.pending == 1 and f.unanswered == []
        f.final_round()
        assert f.pending == 0
        assert [u["oid"] for u in f.unanswered] == ["0x0b0b"]


def test_request_counters(fake):
    fake.drop[_key(P.get_param(0x14, 0x0B0B))] = 1  # lost once, answered on the retry
    f, n = read(fake, None)
    assert f.requests == sum(n.values())
    assert f.resent == 1
    assert f.unanswered == []


def test_describe_again_reads_values_only(fake):
    with frame(fake, None) as f:
        f.discover()
        f.describe(menus=False)
        fake.received.clear()
        f.describe(menus=False)
    n = Counter(m.type for m in fake.received)
    assert n[P.GET_DESCRIPTOR] == 0 and n[P.GET_PARAM] > 500


def test_snapshot_is_the_same_with_and_without_a_cache(fake):
    f1, _ = read(fake, None)
    store = {}
    read(fake, store)
    f2, _ = read(fake, store)
    assert plain(snapshot(f2.tree)) == plain(snapshot(f1.tree))


def test_fake_frame_delay(session):
    fake = FakeFrame(session, delay=0.02)
    try:
        with Frame("127.0.0.1", fake.port, timeout=2.0) as f:
            t0 = time.monotonic()
            f.describe_oids(4, [0x0105])
            took = time.monotonic() - t0
        assert 0.04 <= took < 0.5  # two round trips of 20 ms
    finally:
        fake.close()
