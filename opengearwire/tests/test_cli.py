# SPDX-License-Identifier: MIT
import json

from opengearwire.__main__ import main


def test_slots(fake, capsys):
    assert main(["127.0.0.1", "--port", str(fake.port), "slots"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["0", "MFC-8322-S"]
    assert len(lines) == 11 and all(line.split()[1] == "DRA-8804" for line in lines[1:])


def test_read_by_oid_json(fake, capsys):
    assert main(["127.0.0.1", "--port", str(fake.port), "--json", "read", "4", "0x0105"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out[0]["value"] == "DRA-8804"


def test_snapshot(fake, capsys):
    assert main(["127.0.0.1", "--port", str(fake.port), "snapshot"]) == 0
    s = json.loads(capsys.readouterr().out)
    assert len(s["cards"]) == 10


def test_unreachable_is_one_line(capsys):
    assert main(["127.0.0.1", "--port", "1", "--timeout", "0.5", "slots"]) == 1
    assert "opengearwire: 127.0.0.1:" in capsys.readouterr().err


def test_busy_frame_says_why(session, capsys):
    from .conftest import FakeFrame

    fake = FakeFrame(session, hang_up="connect")
    try:
        assert main(["127.0.0.1", "--port", str(fake.port), "snapshot"]) == 1
    finally:
        fake.close()
    err = capsys.readouterr().err
    assert "another client such as DashBoard is probably connected" in err
    assert err.count("\n") == 1


def test_unanswered_listed_on_stderr_and_in_snapshot(fake, capsys, monkeypatch):
    import functools

    from opengearwire import Frame
    from opengearwire import _protocol as P
    from opengearwire.client import _key

    monkeypatch.setattr(
        "opengearwire.__main__.Frame", functools.partial(Frame, retry_after=0.2, retries=1)
    )
    fake.drop[_key(P.get_param(0x14, 0x0B0B))] = 99
    assert main(["127.0.0.1", "--port", str(fake.port), "snapshot"]) == 0
    cap = capsys.readouterr()
    s = json.loads(cap.out)
    assert [(u["slot"], u["oid"]) for u in s["unanswered"]] == [(4, "0x0b0b")]
    assert "opengearwire: 1 request(s) never answered" in cap.err
    assert "slot 4 GET_PARAM 0x0b0b 'Channel Options'" in cap.err


def test_hello_test_prints_the_reply(fake, capsys):
    from opengearwire.__main__ import hello_test

    assert hello_test("127.0.0.1", fake.port, force=False, listen=0.5) == 0
    out = capsys.readouterr().out
    assert "hello reply words (1, 1, 0)" in out
    assert "force" in out.splitlines()[0] and "first word 1" not in out


def test_hello_test_while_busy_shows_the_hang_up(fake, capsys):
    from opengearwire.__main__ import hello_test

    fake.busy = True
    hello_test("127.0.0.1", fake.port, force=False, listen=0.5)
    out = capsys.readouterr().out
    assert "closed by the frame" in out or "reset by the frame" in out
    assert "hello reply" not in out


def test_forced_hello_layout():
    from opengearwire import _protocol as P

    plain = P.hello("x").content
    forced = P.hello("x", 1).content
    # SET_PARAM content: 00, oid 0xff03, length, value; the value's first word
    assert plain[4:6] == b"\x00\x00" and forced[4:6] == b"\x00\x01"
    assert plain[6:] == forced[6:]
