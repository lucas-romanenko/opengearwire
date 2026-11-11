# SPDX-License-Identifier: MIT
"""Descriptors kept between connections, so a later read asks for values only.

A parameter's descriptor (name, type, access, widget, choices, alarm
table) and the external objects its constraint points at are fixed by
the card's firmware: the same product at the same software revision
with the same OID list describes itself the same way every time. Values
are not: they are never kept here.

``Frame(..., descriptors=store)`` takes any mapping (a dict for one
process; an app can back it with its database). For each device the
frame reads the OID list and the Product and Software Rev values, looks
up ``key(device)`` and, on a hit, files the descriptors from the entry
instead of asking for them; on a miss it asks as usual and stores a new
entry. Either way every VALUE is read from the frame on this connection.

An entry also lists the requests the device never answered (after every
retry and the final round): later reads skip them instead of waiting
them out, until a read with ``skip_unanswered=False`` asks again.

An entry is plain data (str, int, lists, dicts), fit for ``json.dumps``.
"""

import hashlib
from typing import Optional, Tuple

from . import _protocol as P
from .model import Device, Tree

#: Bumped when the entry layout changes; other versions count as a miss.
VERSION = 1

#: "Product" and "Software Rev": the same OIDs on the controller and the
#: cards of the capture.
PRODUCT = 0x0105
SOFTWARE_REV = 0x010B

Key = Tuple[str, str, str]


def _text(dev: Device, oid: int) -> Optional[str]:
    p = dev.params.get(oid)
    if p is None or p.raw is None:
        return None
    return P.cstr(p.raw)


def key(dev: Device) -> Optional[Key]:
    """(product, software rev, digest of the OID list), or None when the
    device's OID list or product is not known yet."""
    if not dev.oids:
        return None
    product = _text(dev, PRODUCT) if PRODUCT in dev.oids else ""
    rev = _text(dev, SOFTWARE_REV) if SOFTWARE_REV in dev.oids else ""
    if product is None or rev is None:
        return None
    digest = hashlib.sha1(b"".join(o.to_bytes(2, "big") for o in dev.oids)).hexdigest()[:16]
    return (product, rev, digest)


def entry(dev: Device, unanswered=()) -> dict:
    """What to keep of a device: descriptors and external objects, never
    a value. ``unanswered`` are OIDs whose requests got no answer."""
    return {
        "version": VERSION,
        "descriptors": {
            f"0x{o:04x}": p.descriptor_raw.hex()
            for o, p in sorted(dev.params.items())
            if p.descriptor_raw is not None
        },
        "external": {str(k): v.hex() for k, v in sorted(dev.external.items())},
        "unanswered": sorted(f"0x{o:04x}" for o in set(unanswered)),
    }


def install(tree: Tree, dev: Device, e: dict) -> bool:
    """File an entry's descriptors and external objects into the tree, as
    if the frame had just sent them. False if the entry is not usable."""
    if not isinstance(e, dict) or e.get("version") != VERSION:
        return False
    try:
        for o, raw in e.get("descriptors", {}).items():
            m = P.Message(
                dev.address, P.CLIENT, P.GET_DESCRIPTOR | P.RESPONSE_BIT, bytes.fromhex(raw)
            )
            if P.parse_descriptor(m).oid != int(o, 16):
                return False
            tree.apply(m)
        for k, raw in e.get("external", {}).items():
            dev.external[int(k)] = bytes.fromhex(raw)
    except (ValueError, TypeError, P.ProtocolError):
        return False
    dev.resolve()
    return True


def unanswered(e: dict) -> set:
    """The OIDs an entry says the device does not answer for."""
    try:
        return {int(o, 16) for o in e.get("unanswered", [])}
    except (ValueError, TypeError, AttributeError):
        return set()
