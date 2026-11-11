# SPDX-License-Identifier: MIT
"""Turn a DashBoard capture into a sanitized test fixture.

    python tools/fixture_from_capture.py CAPTURE.pcapng OUT.jsonl

Writes one JSON object per OGP message, in wire order:
``{"t": seconds from the first message, "d": "c2s" | "s2c", "m": hex}``.

Sanitizing: the capture's own values say what is identifying. Serial
numbers, the MAC address, the frame name, passwords and every IPv4
field are replaced in place with made-up values of the same length (so
every length byte stays true), and the script then refuses to write if
any original value, or any 6+ digit run of one, is still anywhere in
the output. No real address, serial or name is in this script either:
they are found by reading the capture.
"""

import bisect
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pcap import conversation

from opengearwire import _protocol as P
from opengearwire.model import WIDGET_IP, Tree

SENSITIVE_NAMES = re.compile(r"S/N|Serial|MAC Address|Frame Name|Password|Node", re.I)


def timed(conv, d):
    starts = [o for o, _ in conv[d + "_times"]]
    msgs, left = P.split_stream(conv[d])
    if left:
        raise SystemExit(f"{d}: {left} bytes do not frame")
    out, off = [], 0
    for m in msgs:
        last = off + 9 + len(m.content) - 1
        out.append((conv[d + "_times"][bisect.bisect_right(starts, last) - 1][1], d, m))
        off += 9 + len(m.content)
    return out


def fake_string(orig: str, n: int) -> str:
    """A made-up value of the same length and shape as ``orig``."""
    if re.fullmatch(r"[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}", orig):
        return orig[2].join(["00", "00", "5E", "00", "53", f"{n:02X}"])  # RFC 7042
    pos = [i for i, c in enumerate(orig) if c.isdigit()]
    if not pos:
        return "x" * len(orig)
    chars = ["0" if c.isdigit() else c for c in orig]
    # The counter goes in the last digits so equal-length values stay distinct.
    tail = str(n)[-len(pos) :]
    for i, c in zip(pos[-len(tail) :], tail, strict=True):
        chars[i] = c
    return "".join(chars)


def main(src, dst):
    conv = conversation(src, 5253)
    if conv["gaps"]:
        raise SystemExit(f"capture is missing {conv['gaps']} bytes")
    msgs = sorted(timed(conv, "c2s") + timed(conv, "s2c"), key=lambda x: x[0])
    tree = Tree()
    for _, d, m in msgs:
        if d == "s2c":
            tree.apply(m)

    # (address, oid) -> {original raw value: replacement raw value}
    swap = {}
    originals = set()
    n = 0
    ips = {}
    for dev in tree.devices.values():
        for p in dev.params.values():
            d = p.descriptor
            if d is None:
                continue
            if d.type == P.T_INT32 and d.widget == WIDGET_IP:
                swap[(dev.address, p.oid)] = "ip"
            elif d.type == P.T_STRING and SENSITIVE_NAMES.search(d.name):
                swap[(dev.address, p.oid)] = "str"

    def replace_value(addr, oid, raw):
        nonlocal n
        kind = swap[(addr, oid)]
        if kind == "ip":
            v = struct.unpack(">I", raw)[0]
            if v == 0 or v >> 24 == 0xFF:  # unset, or a netmask
                return raw
            if v not in ips:
                ips[v] = 0xC0000200 | (len(ips) + 1)  # 192.0.2.x, RFC 5737
                originals.add(raw)
            return struct.pack(">I", ips[v])
        text = raw.split(b"\0", 1)[0]
        if not text:
            return raw
        originals.add(text)
        n += 1
        new = fake_string(text.decode("latin-1"), n).encode("latin-1")
        return new + raw[len(text) :]

    seen = {}
    lines = []
    t0 = msgs[0][0]
    for ts, d, m in msgs:
        c = m.content
        if d == "s2c" and m.type in (P.REPORT_PARAM, 0xC9, 0xCA) and len(c) >= 4:
            oid = struct.unpack_from(">H", c, 1)[0]
            if (m.src, oid) in swap:
                key = (m.src, oid, c[4:])
                if key not in seen:
                    seen[key] = replace_value(m.src, oid, c[4:])
                c = c[:4] + seen[key]
        lines.append(
            {"t": round(ts - t0, 6), "d": d, "m": P.Message(m.src, m.dst, m.type, c).encode().hex()}
        )

    blob = bytes.fromhex("".join(x["m"] for x in lines))
    for o in originals:
        if o in blob:
            raise SystemExit(f"sanitizing missed {o!r}")
        for run in re.findall(rb"\d{6,}", o):
            if run in blob:
                raise SystemExit(f"sanitizing missed a digit run {run!r}")
    with open(dst, "w") as f:
        for x in lines:
            f.write(json.dumps(x, separators=(",", ":")) + "\n")
    print(f"{len(lines)} messages, {len(originals)} values replaced -> {dst}")


if __name__ == "__main__":
    main(*sys.argv[1:3])
