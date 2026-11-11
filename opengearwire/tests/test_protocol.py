# SPDX-License-Identifier: MIT
"""Wire format, against every message of the captured session."""

import struct

import pytest

from opengearwire import _protocol as P
from opengearwire.client import _key

PARSERS = {
    0xC5: P.parse_numparams,
    0xC6: P.parse_param_oids,
    0xC7: P.parse_descriptor,
    0xC9: P.parse_param,
    0xCA: P.parse_hello_reply,
    0xCC: P.parse_array_element,
    0xD0: P.parse_menuset_name,
    0xD1: P.parse_menu_count,
    0xD2: P.parse_menu_name,
    0xD3: P.parse_menu_oids,
    0xD9: P.parse_external_object,
    0xDA: P.parse_menu_state,
    P.REPORT_PARAM: P.parse_param,
}


def test_header_layout():
    m = P.get_param(0x14, 0x0B04)
    assert m.encode() == bytes.fromhex("bad2ace5 00 14 49 0003 00 0b04".replace(" ", ""))


def test_deframer_handles_any_split(session):
    stream = b"".join(m.encode() for _, d, m in session if d == "s2c")
    for size in (1, 7, 9, 10, 1000):
        d = P.Deframer()
        got = []
        for i in range(0, len(stream), size):
            got.extend(d.feed(stream[i : i + size]))
        assert len(got) == sum(1 for _, x, _ in session if x == "s2c")
        assert d.pending == 0 and d.skipped == 0


def test_deframer_skips_noise_before_sync():
    d = P.Deframer()
    msgs = list(d.feed(b"\x00\x01junk" + P.get_param(0x10, 1).encode()))
    assert len(msgs) == 1 and d.skipped == 6


def test_every_reply_and_report_parses(session):
    """100 % of the frame's messages: nothing opaque but REPORT_0x11."""
    counts = {"parsed": 0, "remote-error": 0, "opaque": 0}
    for _, d, m in session:
        if d != "s2c":
            continue
        f = PARSERS.get(m.type)
        if f is None:
            assert m.type == P.REPORT_0x11 and m.content == b"\x01"
            counts["opaque"] += 1
            continue
        try:
            f(m)
            counts["parsed"] += 1
        except P.RemoteError as e:
            # The controller has no menu set 2: return code 0x11.
            assert (m.type, e.code) == (0xD0, P.RC_NO_SUCH_MENUSET)
            counts["remote-error"] += 1
    assert counts == {"parsed": 2438, "remote-error": 11, "opaque": 1}


def test_encoders_reproduce_every_dashboard_request(session):
    for _, d, m in session:
        if d != "c2s":
            continue
        c, a, t = m.content, m.dst, m.type
        if t == P.GET_NUMPARAMS:
            e = P.get_numparams(a)
        elif t == P.GET_PARAM_OIDS:
            e = P.get_param_oids(a, *struct.unpack(">HB", c[1:4]))
        elif t == P.GET_DESCRIPTOR:
            e = P.get_descriptor(a, struct.unpack(">H", c[1:3])[0])
        elif t == P.GET_PARAM:
            e = P.get_param(a, struct.unpack(">H", c[1:3])[0])
        elif t == P.SET_PARAM:
            e = P.hello("Version 10.0.0 2026-08-27 T14:22")
        elif t == P.GET_ARRAY_ELEMENT:
            e = P.get_array_element(a, *struct.unpack(">HH", c[1:5]))
        elif t == P.GET_MENUSET_NAME:
            e = P.get_menuset_name(a, c[1])
        elif t == P.GET_MENU_COUNT:
            e = P.get_menu_count(a, c[1])
        elif t == P.GET_MENU_NAME:
            e = P.get_menu_name(a, c[1], c[2])
        elif t == P.GET_MENU_OIDS:
            e = P.get_menu_oids(a, c[1], c[2])
        elif t == P.GET_MENU_STATE:
            e = P.get_menu_state(a, c[1], c[2])
        elif t == P.GET_EXTERNAL_OBJECT:
            e = P.get_external_object(a, *struct.unpack(">HH", c[1:5]))
        else:
            pytest.fail(f"unknown request 0x{t:02x}")
        assert e.encode() == m.encode()


def test_every_request_is_answered_or_retried(session):
    """Pairing: each reply answers exactly one outstanding request; the
    nine requests the frame never answered were each sent again."""
    pending = {}
    for _, d, m in session:
        k = _key(m)
        if d == "c2s":
            pending.setdefault(k, []).append(m)
        elif m.is_reply:
            assert pending.get(k), f"reply without a request: {m}"
            pending[k].pop(0)
    left = [k for k, v in pending.items() for _ in v]
    assert len(left) == 9


def test_descriptor_choice_array():
    # Enable Equalizer on a DRA-8804: int16[2] (channels A and B), rw.
    m = P.Message(
        0x14,
        0,
        0xC7,
        bytes.fromhex(
            "000b0432020c040100081145 6e61626c6520457175616c697a657200"
            "02180200000944697361626c656400000108456e61626c656400".replace(" ", "")
        ),
    )
    d = P.parse_descriptor(m)
    assert (d.oid, d.type_name, d.size, d.writable, d.widget) == (0x0B04, "int16[]", 4, True, 8)
    assert d.name == "Enable Equalizer"
    assert [(c.value, c.label) for c in d.constraint.choices] == [(0, "Disabled"), (1, "Enabled")]
    assert P.decode_value(d, b"\x00\x01\x00\x00") == [1, 0]


def test_string_array_elements_are_counted():
    d = P.Descriptor(0x0B02, 2, P.T_STRING_ARRAY, 64, 0, 30, 0, "Input BNC", P.Constraint("none"))
    raw = b"\x03ab\x00\x04cde\x00"
    assert P.decode_value(d, raw) == ["ab", "cde"]


def test_external_constraint_joins_chunks(session):
    chunks = [
        P.parse_external_object(m)
        for _, d, m in session
        if d == "s2c" and m.type == 0xD9 and m.src == 0x14
    ]
    assert [(c.offset, c.next) for c in chunks] == [(0, 13), (13, 0)]
    c = P.external_constraint(b"".join(x.data for x in chunks), P.T_INT16)
    labels = [ch.label for ch in c.choices]
    assert len(labels) == 14
    assert labels[0] == "No signal" and labels[4] == "HD signal"
    assert labels[13] == "6G signal (backup)"


def test_remote_error_carries_code():
    with pytest.raises(P.RemoteError) as e:
        P.parse_menuset_name(P.Message(0x10, 0, 0xD0, b"\x11\x02"))
    assert e.value.code == 0x11


def test_hello_reply_words(session):
    m = next(m for _, d, m in session if m.type == 0xCA)
    assert P.parse_hello_reply(m) == (1, 1, 0)


def test_ipv4():
    assert P.ipv4(struct.unpack(">i", bytes([192, 0, 2, 1]))[0]) == "192.0.2.1"
    assert P.ipv4(-2048) == "255.255.248.0"
