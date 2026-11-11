# SPDX-License-Identifier: MIT
"""The parameter tree of one frame, built from OGP replies and reports.

``Tree.apply(message)`` takes any message from the frame and files what
it says: descriptors, values, OID lists, menus, external objects and
pushed changes. The client feeds it every message it receives; a
captured DashBoard session fed through it gives the tree DashBoard got.
Nothing here touches a network.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import _protocol as P

#: Widget 14 on an int32 is an IPv4 address on the controller (IP Address,
#: Subnet Mask, Default Gateway, NTP Server: all four, nothing else).
WIDGET_IP = 14


def slot_of(address: int) -> int:
    """Frame slot of a device address: 0 is the frame controller.

    address = 0x10 + slot (og-param does the same; the capture's ten
    DRA-8804s on full-width rear modules sit at 0x12, 0x14 … 0x24, every
    second slot, as two-slot rear modules must).
    """
    return address - P.CONTROLLER


def address_of(slot: int) -> int:
    return P.CONTROLLER + slot


@dataclass
class Change:
    """A value that changed, from a report (pushed) or a read."""

    address: int
    oid: int
    name: str
    old: Any
    new: Any
    pushed: bool
    at: float

    @property
    def slot(self) -> int:
        return slot_of(self.address)


@dataclass
class Parameter:
    oid: int
    descriptor: Optional[P.Descriptor] = None
    raw: Optional[bytes] = None
    #: The constraint with any external object resolved.
    constraint: Optional[P.Constraint] = None

    @property
    def name(self) -> str:
        return self.descriptor.name if self.descriptor else ""

    @property
    def value(self) -> Any:
        if self.raw is None or self.descriptor is None:
            return None
        return P.decode_value(self.descriptor, self.raw)

    @property
    def display(self) -> Any:
        """The value as DashBoard shows it: choice labels, active alarm
        names, IP addresses; otherwise the value itself."""
        v = self.value
        c = self.constraint
        if v is None or c is None:
            return v
        if c.kind in ("choice", "string-choice"):
            labels = {ch.value: ch.label for ch in c.choices}
            if isinstance(v, list):
                return [labels.get(x, x) for x in v]
            return labels.get(v, v)
        if c.kind == "alarm" and isinstance(v, int):
            return [a.name for a in c.alarms if v >> a.bit & 1]
        d = self.descriptor
        if d.type == P.T_INT32 and d.widget == WIDGET_IP:
            return P.ipv4(v)
        return v

    @property
    def severity(self) -> Optional[int]:
        """Highest severity among active alarm bits (0 ok, 1 warn, 2 error)."""
        c = self.constraint
        v = self.value
        if c is None or c.kind != "alarm" or not isinstance(v, int):
            return None
        active = [a.severity for a in c.alarms if v >> a.bit & 1]
        return max(active) if active else 0

    def to_dict(self) -> dict:
        d = self.descriptor
        out = {"oid": f"0x{self.oid:04x}", "name": self.name}
        if d is not None:
            out.update(
                type=d.type_name,
                access="read-write" if d.writable else "read-only",
                widget=d.widget,
            )
            if d.precision:
                out["precision"] = d.precision
        out["value"] = self.value
        disp = self.display
        if disp != out["value"]:
            out["display"] = disp
        sev = self.severity
        if sev is not None:
            out["severity"] = sev
        c = self.constraint
        if c is not None and c.kind != "none":
            out["constraint"] = constraint_dict(c)
        return out


def constraint_dict(c: P.Constraint) -> dict:
    out: Dict[str, Any] = {"kind": c.kind}
    if c.kind == "range":
        out.update(minimum=c.minimum, maximum=c.maximum)
        if c.step is not None:
            out["step"] = c.step
    elif c.kind in ("choice", "string-choice"):
        out["choices"] = [{"value": ch.value, "label": ch.label} for ch in c.choices]
    elif c.kind == "alarm":
        out["alarms"] = [{"bit": a.bit, "severity": a.severity, "name": a.name} for a in c.alarms]
    elif c.kind == "external":
        out["object"] = c.object_id
    else:
        out["type"] = c.type_id
        out["raw"] = c.raw.hex()
    return out


@dataclass
class Device:
    address: int
    count: Optional[int] = None
    oids: List[int] = field(default_factory=list)
    params: Dict[int, Parameter] = field(default_factory=dict)
    menusets: Dict[int, str] = field(default_factory=dict)
    menus: Dict[Tuple[int, int], P.Menu] = field(default_factory=dict)
    external: Dict[int, bytes] = field(default_factory=dict)
    _chunks: Dict[int, Dict[int, bytes]] = field(default_factory=dict, repr=False)

    @property
    def slot(self) -> int:
        return slot_of(self.address)

    def param(self, oid: int) -> Parameter:
        p = self.params.get(oid)
        if p is None:
            p = self.params[oid] = Parameter(oid)
        return p

    def find(self, key) -> Parameter:
        """A parameter by OID (int or "0x0b04") or by exact name.

        Names repeat (the DRA-8804 has four "Input"); a repeated name
        raises, use the OID.
        """
        if isinstance(key, str) and key.lower().startswith("0x"):
            key = int(key, 16)
        if isinstance(key, int):
            if key in self.params:
                return self.params[key]
            raise KeyError(f"slot {self.slot} has no OID 0x{key:04x}")
        hits = [p for p in self.params.values() if p.name == key]
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise KeyError(f"slot {self.slot} has no parameter named {key!r}")
        oids = ", ".join(f"0x{p.oid:04x}" for p in hits)
        raise KeyError(f"{key!r} is ambiguous in slot {self.slot}: {oids}")

    def value(self, key, default=None):
        try:
            return self.find(key).value
        except KeyError:
            return default

    @property
    def product(self) -> str:
        return self.value(0x0105, "") or ""

    @property
    def described(self) -> bool:
        return bool(self.oids) and all(
            o in self.params and self.params[o].descriptor for o in self.oids
        )

    def resolve(self) -> None:
        """Attach external objects to the constraints that point at them."""
        for p in self.params.values():
            d = p.descriptor
            if d is None:
                continue
            c = d.constraint
            if c.kind == "external" and c.object_id in self.external:
                p.constraint = P.external_constraint(self.external[c.object_id], d.type)
            else:
                p.constraint = c

    def external_ids(self) -> List[int]:
        return sorted(
            {
                p.descriptor.constraint.object_id
                for p in self.params.values()
                if p.descriptor and p.descriptor.constraint.kind == "external"
            }
        )

    def to_dict(self) -> dict:
        ordered = [self.params[o] for o in self.oids if o in self.params]
        extra = [p for o, p in self.params.items() if o not in self.oids]
        menus = [
            {
                "menuset": s,
                "menuset_name": self.menusets.get(s, ""),
                "name": m.name,
                "oids": [f"0x{o:04x}" for o in m.oids],
            }
            for (s, _), m in sorted(self.menus.items())
        ]
        return {
            "slot": self.slot,
            "address": f"0x{self.address:02x}",
            "product": self.product,
            "parameters": [p.to_dict() for p in ordered + extra],
            "menus": menus,
        }


class Tree:
    """Every device of one frame, as far as the messages so far tell."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self.devices: Dict[int, Device] = {}
        self.clock = clock
        #: Addresses in the order the frame first spoke for them.
        self.heard: List[int] = []
        self.unhandled: int = 0

    def device(self, address: int) -> Device:
        d = self.devices.get(address)
        if d is None:
            d = self.devices[address] = Device(address)
        return d

    def apply(self, m: P.Message) -> Optional[Change]:
        """File one message from the frame. Returns a Change for a value."""
        if m.src not in self.heard:
            self.heard.append(m.src)
        dev = self.device(m.src)
        t = m.type
        try:
            if t in (P.REPORT_PARAM, P.GET_PARAM | P.RESPONSE_BIT, P.SET_PARAM | P.RESPONSE_BIT):
                oid, raw = P.parse_param(m)
                return self._value(dev, oid, raw, t == P.REPORT_PARAM)
            if t == P.GET_DESCRIPTOR | P.RESPONSE_BIT:
                d = P.parse_descriptor(m)
                p = dev.param(d.oid)
                p.descriptor = d
                p.constraint = d.constraint
                if d.constraint.kind == "external":
                    dev.resolve()
                return None
            if t == P.GET_NUMPARAMS | P.RESPONSE_BIT:
                dev.count = P.parse_numparams(m).count
            elif t == P.GET_PARAM_OIDS | P.RESPONSE_BIT:
                first, oids = P.parse_param_oids(m)
                dev.oids[first:] = oids
            elif t == P.GET_MENUSET_NAME | P.RESPONSE_BIT:
                s, _, name = P.parse_menuset_name(m)
                dev.menusets[s] = name
            elif t == P.GET_MENU_NAME | P.RESPONSE_BIT:
                menu = P.parse_menu_name(m)
                old = dev.menus.get((menu.menuset, menu.index))
                if old:
                    menu.oids, menu.state = old.oids, old.state
                dev.menus[(menu.menuset, menu.index)] = menu
            elif t == P.GET_MENU_OIDS | P.RESPONSE_BIT:
                s, i, oids = P.parse_menu_oids(m)
                dev.menus.setdefault((s, i), P.Menu(s, i, "")).oids = oids
            elif t == P.GET_MENU_STATE | P.RESPONSE_BIT:
                s, i, st = P.parse_menu_state(m)
                dev.menus.setdefault((s, i), P.Menu(s, i, "")).state = st
            elif t == P.GET_EXTERNAL_OBJECT | P.RESPONSE_BIT:
                ch = P.parse_external_object(m)
                parts = dev._chunks.setdefault(ch.object_id, {})
                parts[ch.offset] = ch.data
                if ch.next == 0:
                    dev.external[ch.object_id] = b"".join(parts[k] for k in sorted(parts))
                    dev.resolve()
            elif t in (P.GET_MENU_COUNT | P.RESPONSE_BIT, P.GET_ARRAY_ELEMENT | P.RESPONSE_BIT):
                pass  # nothing new for the tree: counts and copies of values
            else:
                self.unhandled += 1
        except P.RemoteError:
            pass  # e.g. a menu set the device doesn't have: nothing to file
        return None

    def _value(self, dev: Device, oid: int, raw: bytes, pushed: bool) -> Optional[Change]:
        p = dev.param(oid)
        old = p.value if p.raw is not None else None
        changed = p.raw != raw
        p.raw = raw
        if not changed and not pushed:
            return None
        return Change(dev.address, oid, p.name, old, p.value, pushed, self.clock())

    @property
    def cards(self) -> List[Device]:
        return [d for a, d in sorted(self.devices.items()) if a != P.CONTROLLER]

    @property
    def controller(self) -> Device:
        return self.device(P.CONTROLLER)
