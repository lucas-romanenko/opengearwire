# SPDX-License-Identifier: MIT
import json

from opengearwire import snapshot


def test_snapshot_is_plain_json(dashboard_tree):
    s = snapshot(dashboard_tree, host="192.0.2.10")
    text = json.dumps(s)
    assert json.loads(text) == s
    assert s["frame"]["controller"] == "MFC-8322-S"
    assert s["frame"]["slots"] == [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    assert len(s["cards"]) == 10
    names = {p["name"] for p in s["cards"][0]["parameters"]}
    assert {"Product", "Enable Equalizer", "Channel A Status"} <= names
    assert "Header" not in {p["name"] for p in s["controller"]["parameters"]}
    assert s["unanswered"] == []


def test_choices_carry_their_label(dashboard_tree):
    """A consumer gets the number and DashBoard's label side by side."""
    s = snapshot(dashboard_tree)
    ch_a = next(p for p in s["cards"][0]["parameters"] if p["oid"] == "0x0702")
    assert ch_a["name"] == "Channel A Status"
    assert (ch_a["value"], ch_a["display"]) == (16, ["No input"])
    for d in [s["controller"]] + s["cards"]:
        for p in d["parameters"]:
            labels = {c["value"] for c in p.get("constraint", {}).get("choices", [])}
            if isinstance(p["value"], int) and p["value"] in labels:
                assert "display" in p, (d["slot"], p["oid"])


def test_health_follows_alarm_severity(dashboard_tree):
    s = snapshot(dashboard_tree)
    worst = max(
        (a["severity"] for d in [s["controller"]] + s["cards"] for a in d["alarms"]), default=0
    )
    assert s["frame"]["health"] == {0: "ok", 1: "warning", 2: "error"}[worst]
    for a in s["frame"]["alarms"]:
        assert a["severity"] > 0 and a["active"]
