# SPDX-License-Identifier: MIT
"""One frame as plain data: frame health plus every card's parameters.

The output is dicts, lists, strings and numbers only, so ``json.dumps``
takes it as is. Nothing here touches a network: it reads a Tree.
"""

import time
from typing import Iterable, List, Optional

from . import _protocol as P
from .model import Device, Tree

SEVERITY = {0: "ok", 1: "warning", 2: "error"}

#: Widgets that are layout, not data: headers, separators, notes.
LAYOUT_WIDGETS = {
    P.T_STRING: {5, 6, 7, 8, 10, 13},
}


def is_layout(p) -> bool:
    d = p.descriptor
    return bool(d) and d.widget in LAYOUT_WIDGETS.get(d.type, set())


def alarms(dev: Device) -> List[dict]:
    """Every alarm-table parameter of a device, with its active bits."""
    out = []
    for o in dev.oids or list(dev.params):
        p = dev.params.get(o)
        if p is None or p.severity is None:
            continue
        out.append(
            {
                "slot": dev.slot,
                "oid": f"0x{o:04x}",
                "name": p.name,
                "active": p.display,
                "severity": p.severity,
            }
        )
    return out


def card(dev: Device) -> dict:
    d = dev.to_dict()
    d["parameters"] = [
        x for x, p in zip(d["parameters"], _ordered(dev), strict=True) if not is_layout(p)
    ]
    al = alarms(dev)
    d["alarms"] = al
    worst = max((a["severity"] for a in al), default=0)
    d["health"] = SEVERITY.get(worst, str(worst))
    return d


def _ordered(dev: Device):
    return [dev.params[o] for o in dev.oids if o in dev.params] + [
        p for o, p in dev.params.items() if o not in dev.oids
    ]


def snapshot(tree: Tree, host: Optional[str] = None, unanswered: Iterable[dict] = ()) -> dict:
    """The frame as plain data. ``unanswered`` (``Frame.unanswered``) are
    the requests the frame never answered: what this snapshot lacks or
    may hold only from an earlier report."""
    ctl = tree.controller
    devices = [card(ctl)] + [card(c) for c in tree.cards]
    worst = max((a["severity"] for d in devices for a in d["alarms"]), default=0)
    return {
        "host": host,
        "taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "frame": {
            "controller": ctl.product,
            "health": SEVERITY.get(worst, str(worst)),
            "alarms": [a for d in devices for a in d["alarms"] if a["severity"]],
            "slots": [d["slot"] for d in devices[1:]],
        },
        "controller": devices[0],
        "cards": devices[1:],
        "unanswered": [dict(u) for u in unanswered],
    }
