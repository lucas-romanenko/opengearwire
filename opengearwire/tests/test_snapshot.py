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


def test_health_follows_alarm_severity(dashboard_tree):
    s = snapshot(dashboard_tree)
    worst = max(
        (a["severity"] for d in [s["controller"]] + s["cards"] for a in d["alarms"]), default=0
    )
    assert s["frame"]["health"] == {0: "ok", 1: "warning", 2: "error"}[worst]
    for a in s["frame"]["alarms"]:
        assert a["severity"] > 0 and a["active"]
