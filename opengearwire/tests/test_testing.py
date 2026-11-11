# SPDX-License-Identifier: MIT
"""The public fake frame (``opengearwire.testing``) that apps test against."""

import struct

import pytest

from opengearwire import Frame, FrameBusy
from opengearwire.testing import FIXTURE, load_session

from .conftest import wait_for


def frame(fake, **kw):
    kw.setdefault("timeout", 2.0)
    kw.setdefault("retry_after", 0.3)
    return Frame("127.0.0.1", fake.port, **kw)


def test_fixture_ships_with_the_package():
    assert FIXTURE.endswith("opengearwire/fixtures/dashboard-session.jsonl")
    assert len(load_session()) > 3000


def test_one_client_at_a_time(fake):
    with frame(fake) as first:
        first.discover()
        with pytest.raises(FrameBusy):
            frame(fake).open()
        assert fake.turned_away == 1
    # The first one left: the next client gets in, and is answered from
    # the start of the capture again.
    assert wait_for(lambda: fake.conn is None)
    with frame(fake) as again:
        assert again.discover()[:2] == [0, 2]
    assert fake.connections == 2


def test_busy_turns_everyone_away_until_cleared(fake):
    fake.busy = True
    with pytest.raises(FrameBusy):
        frame(fake).open()
    fake.busy = False
    with frame(fake) as f:
        assert f.hello


def test_report_pushes_and_is_read_back(fake):
    with frame(fake) as f:
        f.discover()
        f.describe([18], menus=False)
        assert f.device(18).find(0x0705).value == "67 (1694A) / 36 (1855A)"
        fake.report(18, 0x0705, b"12 (1694A) / 8 (1855A)\x00")
        changes = f.watch(0.5)
        assert [(c.slot, c.oid, c.new) for c in changes if c.oid == 0x0705] == [
            (18, 0x0705, "12 (1694A) / 8 (1855A)")
        ]
        assert f.read(18, 0x0705) == {0x0705: "12 (1694A) / 8 (1855A)"}


def test_report_of_a_number(fake):
    with frame(fake) as f:
        f.discover()
        f.describe([0], menus=False)
        fake.report(0, 0x0705, struct.pack(">h", 61))  # Frame Power (W)
        f.watch(0.5)
        assert f.device(0).find("Frame Power (W)").value == 61


def test_cli_parses(capsys):
    from opengearwire import testing

    with pytest.raises(SystemExit):
        testing.main(["--help"])
    assert "fake openGear frame" in capsys.readouterr().out
