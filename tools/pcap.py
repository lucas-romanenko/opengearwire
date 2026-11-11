# SPDX-License-Identifier: MIT
"""Just enough pcap/pcapng reading to pull one TCP conversation out.

Standard library only, so a capture can be turned into a fixture on any
machine. Ethernet (and 802.1Q), BSD loopback and raw IPv4 link types.
"""

import struct


def packets(path):
    """(timestamp, linktype, frame bytes) for every packet."""
    data = open(path, "rb").read()
    out = []
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        off, e = 0, "<"
        links, res = [], []
        while off + 12 <= len(data):
            if data[off : off + 4] == b"\x0a\x0d\x0d\x0a":
                e = "<" if data[off + 8 : off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
                links, res = [], []
            btype, blen = struct.unpack_from(e + "II", data, off)
            body = data[off + 8 : off + blen - 4]
            if btype == 1:  # interface description
                links.append(struct.unpack_from(e + "H", body, 0)[0])
                r, o = 1e-6, 8
                while o + 4 <= len(body):
                    code, ln = struct.unpack_from(e + "HH", body, o)
                    if code == 0:
                        break
                    if code == 9:
                        v = body[o + 4]
                        r = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0**-v
                    o += 4 + ((ln + 3) & ~3)
                res.append(r)
            elif btype == 6:  # enhanced packet
                ifid, hi, lo, cap, _ = struct.unpack_from(e + "IIIII", body, 0)
                out.append((((hi << 32) | lo) * res[ifid], links[ifid], body[20 : 20 + cap]))
            off += blen
        return out
    e = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    link = struct.unpack_from(e + "I", data, 20)[0]
    off = 24
    while off + 16 <= len(data):
        s, frac, cap, _ = struct.unpack_from(e + "IIII", data, off)
        out.append((s + frac * (1e-9 if nano else 1e-6), link, data[off + 16 : off + 16 + cap]))
        off += 16 + cap
    return out


def _ipv4(link, frame):
    if link == 1:
        et, off = struct.unpack_from(">H", frame, 12)[0], 14
        while et == 0x8100:
            et, off = struct.unpack_from(">H", frame, off + 2)[0], off + 4
        return frame[off:] if et == 0x0800 else None
    if link in (0, 108):
        return frame[4:] if struct.unpack_from("<I", frame, 0)[0] == 2 else None
    if link == 101:
        return frame
    return None


def conversation(path, port):
    """The first TCP connection to ``port``, reassembled.

    Returns {"c2s": bytes, "s2c": bytes, "c2s_times": [(offset, ts)],
    "s2c_times": [...], "gaps": n} where offsets index the stream and
    ``gaps`` counts bytes missing from the capture (0 = complete).
    """
    segs = {"c2s": {}, "s2c": {}}
    isn = {}
    conn = None
    for ts, link, frame in packets(path):
        ip = _ipv4(link, frame)
        if ip is None or ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        tcp = ip[ihl : struct.unpack_from(">H", ip, 2)[0]]
        sport, dport, seq = struct.unpack_from(">HHI", tcp, 0)
        flags = tcp[13]
        payload = tcp[(tcp[12] >> 4) * 4 :]
        ends = (bytes(ip[12:16]), sport, bytes(ip[16:20]), dport)
        if dport == port:
            key, d = ends, "c2s"
        elif sport == port:
            key, d = (ends[2], ends[3], ends[0], ends[1]), "s2c"
        else:
            continue
        if conn is None:
            conn = key
        if key != conn:
            continue
        if flags & 0x02:
            isn[d] = seq + 1
        if payload:
            isn.setdefault(d, seq)
            segs[d].setdefault((seq - isn[d]) & 0xFFFFFFFF, (ts, payload))
    out = {"gaps": 0}
    for d in ("c2s", "s2c"):
        buf, times = bytearray(), []
        for rel, (ts, pl) in sorted(segs[d].items()):
            if rel > len(buf):
                out["gaps"] += rel - len(buf)
                buf.extend(b"\0" * (rel - len(buf)))
            if rel + len(pl) > len(buf):
                times.append((len(buf), ts))
                buf.extend(pl[len(buf) - rel :])
        out[d], out[d + "_times"] = bytes(buf), times
    return out
