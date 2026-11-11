# SPDX-License-Identifier: MIT
"""The parameter tree DashBoard got, rebuilt passively from the replies."""

import pytest

from opengearwire import _protocol as P
from opengearwire.model import Tree, slot_of

CARDS = list(range(0x12, 0x26, 2))


def test_devices_and_counts(dashboard_tree):
    t = dashboard_tree
    assert sorted(t.devices) == [0x10] + CARDS
    assert [slot_of(a) for a in CARDS] == [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    assert len(t.controller.oids) == t.controller.count == 101
    for c in t.cards:
        assert len(c.oids) == c.count == 50
        assert c.described
        assert c.product == "DRA-8804"
    assert t.controller.described
    assert t.controller.product == "MFC-8322-S"


def test_menus(dashboard_tree):
    ctl = dashboard_tree.controller
    assert ctl.menusets == {0: "Status", 1: "Config"}
    assert [m.name for _, m in sorted(ctl.menus.items())] == [
        "Product",
        "Network",
        "Hardware",
        "Power",
        "Setup",
        "Network",
        "Frame Glow",
    ]
    card = dashboard_tree.device(0x14)
    assert [m.name for _, m in sorted(card.menus.items())] == [
        "Signal",
        "Hardware",
        "Product",
        "Setup",
        "Alarms",
    ]


def test_display_values(dashboard_tree):
    card = dashboard_tree.device(0x24)
    out_a = card.find(0x0704)
    assert out_a.name == "Output"
    assert isinstance(out_a.display, str) and out_a.display.startswith(
        ("Locked", "No signal", "Unlocked")
    )
    # External choice list resolved for "Input".
    inp = card.find(0x0703)
    assert inp.constraint.kind == "choice"
    assert inp.display in [c.label for c in inp.constraint.choices]
    # Per-channel settings are int16[2]: channel A, channel B.
    assert card.find("Enable Equalizer").display in (
        ["Enabled", "Enabled"],
        ["Enabled", "Disabled"],
        ["Disabled", "Enabled"],
        ["Disabled", "Disabled"],
    )
    assert card.find("Input BNC").value[0].startswith("HD-BNC 1")


def test_alarm_tables(dashboard_tree):
    ctl = dashboard_tree.controller
    fs = ctl.find("Frame status")
    assert fs.constraint.kind == "alarm" and fs.value == 0
    assert fs.display == [] and fs.severity == 0
    door = ctl.find("Fan Door")
    assert door.display == ["Closed"] and door.severity == 0


def test_controller_ip_fields_decode(dashboard_tree):
    ip = dashboard_tree.controller.find(0x0712)
    assert ip.name == "IP Address"
    assert ip.display.count(".") == 3


def test_ambiguous_names_need_an_oid(dashboard_tree):
    with pytest.raises(KeyError, match="ambiguous"):
        dashboard_tree.device(0x14).find("Output")
    assert dashboard_tree.device(0x14).find("0x0804").name == "Output"


def test_reports_are_changes(session):
    t = Tree(clock=lambda: 0.0)
    changes = [t.apply(m) for _, d, m in session if d == "s2c"]
    pushed = [c for c in changes if c is not None and c.pushed]
    assert len(pushed) == sum(1 for _, d, m in session if m.type == P.REPORT_PARAM)
    assert t.unhandled == 1  # REPORT_0x11
