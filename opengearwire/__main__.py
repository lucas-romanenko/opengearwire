# SPDX-License-Identifier: MIT
"""opengearwire HOST COMMAND: read a frame from the command line.

    opengearwire 192.0.2.10 slots            occupied slots and their products
    opengearwire 192.0.2.10 params 4         every parameter of slot 4
    opengearwire 192.0.2.10 read 4 0x0b04    fresh value(s) by OID or name
    opengearwire 192.0.2.10 watch 10         pushed changes for 10 s
    opengearwire 192.0.2.10 snapshot         the whole frame as JSON

Slot 0 is the frame controller. Every command opens one connection,
does what it says and closes; nothing is ever written to the frame.
"""

import argparse
import json
import sys

from . import _protocol as P
from .client import PORT, Frame, FrameError


def _fmt(v) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="opengearwire", description=__doc__.split("\n")[0])
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="seconds of silence from the frame before giving up (default 5)",
    )
    ap.add_argument("--json", action="store_true", help="JSON output")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("slots")
    p = sub.add_parser("params")
    p.add_argument("slot", type=int)
    p = sub.add_parser("read")
    p.add_argument("slot", type=int)
    p.add_argument("keys", nargs="+", help="OIDs (0x0b04) or exact names")
    p = sub.add_parser("watch")
    p.add_argument("seconds", type=float)
    sub.add_parser("snapshot")
    a = ap.parse_args(argv)

    try:
        with Frame(a.host, a.port, timeout=a.timeout) as f:
            return _run(f, a)
    except (OSError, FrameError, P.ProtocolError) as e:
        print(f"opengearwire: {a.host}: {e}", file=sys.stderr)
        return 1


def _run(f: Frame, a) -> int:
    out = sys.stdout
    if a.cmd == "slots":
        f.discover()
        rows = list(f.identify().items())
        if a.json:
            json.dump([{"slot": s, "product": p} for s, p in rows], out, indent=2)
            out.write("\n")
        else:
            for s, p in rows:
                out.write(f"{s:>3}  {p}\n")
    elif a.cmd == "params":
        f.describe([a.slot])
        dev = f.device(a.slot)
        if a.json:
            json.dump(dev.to_dict(), out, indent=2)
            out.write("\n")
        else:
            for o in dev.oids:
                p = dev.params[o]
                d = p.descriptor
                rw = "rw" if d and d.writable else "ro"
                kind = d.type_name if d else "?"
                out.write(f"0x{o:04x} {rw} {kind:9} {p.name!r:32} {_fmt(p.display)}\n")
    elif a.cmd == "read":
        keys = [int(k, 16) if k.lower().startswith("0x") else k for k in a.keys]
        if all(isinstance(k, int) for k in keys):
            f.describe_oids(a.slot, keys)  # descriptors decode the values
        else:
            f.describe([a.slot], menus=False)  # names need the whole list
        vals = f.read(a.slot, *keys)
        dev = f.device(a.slot)
        rows = [(o, dev.params[o]) for o in vals]
        if a.json:
            json.dump([p.to_dict() for _, p in rows], out, indent=2)
            out.write("\n")
        else:
            for o, p in rows:
                out.write(f"0x{o:04x} {p.name!r}: {_fmt(p.display)}\n")
    elif a.cmd == "watch":
        f.discover()
        for ch in f.watch(a.seconds):
            if a.json:
                out.write(
                    json.dumps(
                        {
                            "slot": ch.slot,
                            "oid": f"0x{ch.oid:04x}",
                            "name": ch.name,
                            "old": ch.old,
                            "new": ch.new,
                        }
                    )
                    + "\n"
                )
            else:
                out.write(f"slot {ch.slot} 0x{ch.oid:04x} {ch.name!r}: {ch.old!r} -> {ch.new!r}\n")
    elif a.cmd == "snapshot":
        f.discover()
        f.describe()
        json.dump(f.snapshot(), out, indent=2)
        out.write("\n")
    if f.unanswered:
        print(f"opengearwire: {len(f.unanswered)} request(s) never answered", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
