# SPDX-License-Identifier: MIT
"""opengearwire HOST COMMAND: read a frame from the command line.

    opengearwire 192.0.2.10 slots            occupied slots and their products
    opengearwire 192.0.2.10 params 4         every parameter of slot 4
    opengearwire 192.0.2.10 read 4 0x0b04    fresh value(s) by OID or name
    opengearwire 192.0.2.10 watch 10         pushed changes for 10 s
    opengearwire 192.0.2.10 snapshot         the whole frame as JSON
    opengearwire 192.0.2.10 hello-test       what the frame answers to a hello
                                             (run it with DashBoard open)

Slot 0 is the frame controller. Every command opens one connection,
does what it says and closes; nothing is ever written to the frame.
The frame takes one client at a time: close DashBoard first (except for
hello-test, which is about exactly that).

hello-test sends DashBoard's hello and prints every byte the frame
answers until it hangs up or goes quiet. With ``--force`` it then tries
the two "displace the other client" hellos og-param uses (first word 1):
if the frame honours them, the OTHER client (DashBoard) is cut off, so
warn whoever is using it first. Nothing else is sent; no setting changes.
"""

import argparse
import json
import socket
import sys
import time

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
    p = sub.add_parser("hello-test")
    p.add_argument(
        "--force",
        action="store_true",
        help="also try the hellos that may cut another client (DashBoard) off",
    )
    p.add_argument("--listen", type=float, default=3.0, help="seconds to listen after each hello")
    a = ap.parse_args(argv)
    if a.cmd == "hello-test":
        return hello_test(a.host, a.port, a.force, a.listen)

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
        for u in f.unanswered:
            what = u.get("oid") or ", ".join(
                f"{k} {u[k]}" for k in ("menuset", "menu", "object", "offset") if k in u
            )
            name = f" {u['name']!r}" if "name" in u else ""
            print(f"  slot {u['slot']} {u['request']} {what}{name}", file=sys.stderr)
    return 0


HELLOS = (
    ("DashBoard's hello (force 0)", lambda: P.hello("opengearwire hello-test")),
    ("DashBoard's layout, first word 1 (force)", lambda: P.hello("opengearwire hello-test", 1)),
    ("og-param's forced hello: 00 01 00 00", lambda: P.hello_value(b"\x00\x01\x00\x00")),
)


def hello_test(host: str, port: int, force: bool, listen: float, out=None) -> int:
    """Send each hello on its own connection; print what comes back."""
    out = out or sys.stdout
    for name, make in HELLOS[: 3 if force else 1]:
        req = make()
        out.write(f"== {name}\n   sent {req.encode().hex()}\n")
        try:
            s = socket.create_connection((host, port), 5.0)
        except OSError as e:
            out.write(f"   connect failed: {e}\n")
            return 1
        d = P.Deframer()
        t0 = time.monotonic()
        how = f"still open after {listen:g} s (we close it)"
        try:
            s.sendall(req.encode())
            s.settimeout(0.2)
            while time.monotonic() - t0 < listen:
                try:
                    data = s.recv(65536)
                except TimeoutError:
                    continue
                except OSError as e:
                    how = f"reset by the frame after {time.monotonic() - t0:.2f} s ({e})"
                    break
                if not data:
                    how = f"closed by the frame after {time.monotonic() - t0:.2f} s"
                    break
                for m in d.feed(data):
                    t = time.monotonic() - t0
                    label = P.NAMES.get(m.type & 0x7F, hex(m.type))
                    words = ""
                    if m.type == P.SET_PARAM | P.RESPONSE_BIT:
                        try:
                            words = f" -> hello reply words {P.parse_hello_reply(m)}"
                        except P.ProtocolError:
                            pass
                    reply = " reply" if m.is_reply else ""
                    out.write(
                        f"   {t:5.2f} s from 0x{m.src:02x} {label}{reply}"
                        f" {m.content.hex()}{words}\n"
                    )
        finally:
            s.close()
        out.write(f"   connection {how}\n")
        time.sleep(1.0)
    out.write(
        "Paste all of this back. If a forced hello was answered and DashBoard lost the"
        " frame, the takeover works on this controller.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
