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
