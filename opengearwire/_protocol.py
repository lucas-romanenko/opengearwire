# SPDX-License-Identifier: MIT
"""OGP (openGear Protocol, binary) framing and message codecs.

Everything here was checked byte for byte against a capture of Ross
DashBoard 10.0.0 reading an OGX frame (an MFC-8322-S controller and ten
DRA-8804 cards) over TCP 5253: every message in both directions parses
with no byte left over. Message names come from Ross's public
application note "Methods for OGP Developers to Speed Up Device
Initialization" where it names them; the others are named for what the
capture shows them doing. ``docs/PROTOCOL.md`` is the long form.

A message on the wire::

    BA D2 AC E5  src  dst  type  len(BE16)  content[len]

Requests have ``type < 0x80``; the reply to a request is ``type | 0x80``
and starts with a one-byte return code (0 = OK). All multi-byte
integers are big-endian.
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

SYNC = b"\xba\xd2\xac\xe5"
HEADER_LEN = 9
RESPONSE_BIT = 0x80

#: The client's own address. DashBoard sends from 0x00.
CLIENT = 0x00
#: The frame controller card (the network card in the frame).
CONTROLLER = 0x10
#: The destination of unsolicited reports (0x10, 0x11) in the capture.
#: Read as "every connected client"; not documented.
BROADCAST = 0x02

# Request types (the reply is type | 0x80).
GET_NUMPARAMS = 0x45  # named in Ross's application note
GET_PARAM_OIDS = 0x46
GET_DESCRIPTOR = 0x47  # reply named in Ross's application note
GET_PARAM = 0x49  # reply named in Ross's application note
SET_PARAM = 0x4A
GET_ARRAY_ELEMENT = 0x4C
GET_MENUSET_NAME = 0x50  # named in Ross's application note
GET_MENU_COUNT = 0x51  # named in Ross's application note
GET_MENU_NAME = 0x52  # named in Ross's application note
GET_MENU_OIDS = 0x53  # named in Ross's application note
GET_EXTERNAL_OBJECT = 0x59
GET_MENU_STATE = 0x5A  # named in Ross's application note
START_INIT_BLAST = 0x4E  # in the note; not seen in the capture

# Unsolicited, card → clients.
REPORT_PARAM = 0x10
REPORT_0x11 = 0x11  # one byte of content; meaning unknown

#: Writing this OID on the controller is how a client introduces itself.
CONNECTION_OID = 0xFF03

NAMES = {
    GET_NUMPARAMS: "GET_NUMPARAMS",
    GET_PARAM_OIDS: "GET_PARAM_OIDS",
    GET_DESCRIPTOR: "GET_DESCRIPTOR",
    GET_PARAM: "GET_PARAM",
    SET_PARAM: "SET_PARAM",
    GET_ARRAY_ELEMENT: "GET_ARRAY_ELEMENT",
    GET_MENUSET_NAME: "GET_MENUSET_NAME",
    GET_MENU_COUNT: "GET_MENU_COUNT",
    GET_MENU_NAME: "GET_MENU_NAME",
    GET_MENU_OIDS: "GET_MENU_OIDS",
    GET_EXTERNAL_OBJECT: "GET_EXTERNAL_OBJECT",
    GET_MENU_STATE: "GET_MENU_STATE",
    START_INIT_BLAST: "START_INIT_BLAST",
    REPORT_PARAM: "REPORT_PARAM",
    REPORT_0x11: "REPORT_0x11",
}

# Return codes. OK and the three in Ross's note are documented; 0x11 is
# what the controller answered for a menu set it doesn't have.
RC_OK = 0x00
RC_UNSUPPORTED = 0x01
RC_INVALID_LENGTH = 0x02
RC_RESPONSE_DENIED = 0x03
RC_NO_SUCH_MENUSET = 0x11

# Parameter types (descriptor byte 1).
T_INT16 = 2
T_INT32 = 4
T_FLOAT32 = 6
T_STRING = 7
T_INT16_ARRAY = 12
T_INT32_ARRAY = 14
T_FLOAT32_ARRAY = 16
T_STRING_ARRAY = 17
T_BINARY = 18
TYPE_NAMES = {
    T_INT16: "int16",
    T_INT32: "int32",
    T_FLOAT32: "float32",
    T_STRING: "string",
    T_INT16_ARRAY: "int16[]",
    T_INT32_ARRAY: "int32[]",
    T_FLOAT32_ARRAY: "float32[]",
    T_STRING_ARRAY: "string[]",
    T_BINARY: "binary",
}

# Constraint types (the byte after the name).
C_NONE = 0
C_RANGE = 1
C_CHOICE = 2
C_CHOICE_WIDE = 3
C_STRING_CHOICE = 4
C_RANGE_STEP = 5
C_ALARM = 10
C_EXTERNAL = 11


class ProtocolError(ValueError):
    """A message that does not parse the way every captured one did."""


class RemoteError(ProtocolError):
    """The device answered with a non-zero return code."""

    def __init__(self, code: int, message_type: int):
        self.code = code
        self.message_type = message_type
        super().__init__(
            f"{NAMES.get(message_type & 0x7F, hex(message_type))} returned code 0x{code:02x}"
        )


# --------------------------------------------------------------- framing


@dataclass(frozen=True)
class Message:
    src: int
    dst: int
    type: int
    content: bytes

    @property
    def is_reply(self) -> bool:
        return bool(self.type & RESPONSE_BIT)

    @property
    def rc(self) -> int:
        return self.content[0] if self.content else -1

    def encode(self) -> bytes:
        if len(self.content) > 0xFFFF:
            raise ProtocolError("content longer than 65535 bytes")
        return (
            SYNC
            + bytes((self.src, self.dst, self.type))
            + struct.pack(">H", len(self.content))
            + bytes(self.content)
        )


class Deframer:
    """Turns a TCP byte stream into messages.

    ``feed`` takes whatever ``recv`` returned and yields every complete
    message; a partial one waits for the next feed. Bytes before a sync
    word are counted in ``skipped`` and dropped (none were seen in the
    capture: every byte belonged to a message).
    """

    def __init__(self):
        self._buf = bytearray()
        self.skipped = 0

    def feed(self, data: bytes):
        self._buf += data
        while True:
            start = self._buf.find(SYNC)
            if start < 0:
                keep = len(SYNC) - 1
                if len(self._buf) > keep:
                    self.skipped += len(self._buf) - keep
                    del self._buf[: len(self._buf) - keep]
                return
            if start:
                self.skipped += start
                del self._buf[:start]
            if len(self._buf) < HEADER_LEN:
                return
            n = struct.unpack_from(">H", self._buf, 7)[0]
            if len(self._buf) < HEADER_LEN + n:
                return
            m = Message(self._buf[4], self._buf[5], self._buf[6], bytes(self._buf[9 : 9 + n]))
            del self._buf[: HEADER_LEN + n]
            yield m

    @property
    def pending(self) -> int:
        return len(self._buf)


def split_stream(data: bytes) -> Tuple[List[Message], int]:
    """Every message in a whole captured stream, and the unparsed byte count."""
    d = Deframer()
    msgs = list(d.feed(data))
    return msgs, d.skipped + d.pending


# -------------------------------------------------------------- requests


def _req(dst: int, mtype: int, content: bytes) -> Message:
    return Message(CLIENT, dst, mtype, content)


def get_numparams(dst: int) -> Message:
    # DashBoard sends 00 01; the second byte is read as "I understand
    # string OIDs" (the reply then carries the long form).
    return _req(dst, GET_NUMPARAMS, b"\x00\x01")


def get_param_oids(dst: int, first: int = 0, count: int = 0) -> Message:
    # count 0 = "all from `first`": that is all DashBoard ever sent.
    return _req(dst, GET_PARAM_OIDS, struct.pack(">BHB", 0, first, count))


def get_descriptor(dst: int, oid: int) -> Message:
    return _req(dst, GET_DESCRIPTOR, struct.pack(">BH", 0, oid))


def get_param(dst: int, oid: int) -> Message:
    return _req(dst, GET_PARAM, struct.pack(">BH", 0, oid))


def get_array_element(dst: int, oid: int, index: int) -> Message:
    return _req(dst, GET_ARRAY_ELEMENT, struct.pack(">BHH", 0, oid, index))


def get_menuset_name(dst: int, menuset: int) -> Message:
    return _req(dst, GET_MENUSET_NAME, bytes((0, menuset)))


def get_menu_count(dst: int, menuset: int) -> Message:
    return _req(dst, GET_MENU_COUNT, bytes((0, menuset)))


def get_menu_name(dst: int, menuset: int, menu: int) -> Message:
    return _req(dst, GET_MENU_NAME, bytes((0, menuset, menu)))


def get_menu_oids(dst: int, menuset: int, menu: int) -> Message:
    return _req(dst, GET_MENU_OIDS, bytes((0, menuset, menu)))


def get_menu_state(dst: int, menuset: int, menu: int) -> Message:
    return _req(dst, GET_MENU_STATE, bytes((0, menuset, menu)))


def get_external_object(dst: int, object_id: int, offset: int = 0) -> Message:
    return _req(dst, GET_EXTERNAL_OBJECT, struct.pack(">BHH", 0, object_id, offset))


def hello(client_name: str) -> Message:
    """The connection introduction DashBoard sends first: SET_PARAM of
    OID 0xFF03 on the controller. The only write the library sends; it
    changes no setting (the controller answers with a status value)."""
    name = client_name.encode("utf-8") + b"\x00"
    value = struct.pack(">HHBH", 0, 0, 1, len(name)) + name
    return _req(CONTROLLER, SET_PARAM, struct.pack(">BHB", 0, CONNECTION_OID, len(value)) + value)


# ------------------------------------------------------------ structures


@dataclass
class Choice:
    value: Union[int, float, str]
    label: str


@dataclass
class Alarm:
    bit: int
    severity: int
    name: str


@dataclass
class Constraint:
    kind: str  # none | range | choice | string-choice | alarm | external | unknown
    type_id: int = 0
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    display_minimum: Optional[float] = None
    display_maximum: Optional[float] = None
    step: Optional[float] = None
    choices: List[Choice] = field(default_factory=list)
    alarms: List[Alarm] = field(default_factory=list)
    object_id: Optional[int] = None
    raw: bytes = b""


@dataclass
class Descriptor:
    oid: int
    version: int
    type: int
    size: int
    access: int  # 0 read-only, 1 read-write
    precision: int
    widget: int
    name: str
    constraint: Constraint
    #: Bytes after the constraint. Seen only on the two int32[] "Custom
    #: Color" descriptors of the controller (two zero bytes); meaning unknown.
    extra: bytes = b""

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"type{self.type}")

    @property
    def writable(self) -> bool:
        return self.access == 1


@dataclass
class NumParams:
    count: int
    xml_url: str = ""
    string_oids: int = 0
    blast: Optional[int] = None


@dataclass
class Menu:
    menuset: int
    index: int
    name: str
    oids: List[int] = field(default_factory=list)
    state: Optional[int] = None
    tail: bytes = b""  # bytes after the name (seen empty)


@dataclass
class ExternalChunk:
    object_id: int
    offset: int
    next: int
    data: bytes


# --------------------------------------------------------------- decoding


def _check(m: Message) -> bytes:
    c = m.content
    if not c:
        raise ProtocolError(f"empty reply 0x{m.type:02x}")
    if c[0] != RC_OK:
        raise RemoteError(c[0], m.type)
    return c


def cstr(b: bytes) -> str:
    """A NUL-terminated string (DashBoard's devices send Latin-1 safe text)."""
    if not b or b[-1] != 0:
        raise ProtocolError(f"string not NUL-terminated: {b[:40]!r}")
    return b[:-1].decode("utf-8", "replace")


def _counted(b: bytes, off: int) -> Tuple[str, int]:
    n = b[off]
    end = off + 1 + n
    if end > len(b):
        raise ProtocolError("counted string runs past the end")
    return cstr(b[off + 1 : end]), end


def parse_numparams(m: Message) -> NumParams:
    c = _check(m)
    count = struct.unpack_from(">H", c, 1)[0]
    if len(c) == 3:
        return NumParams(count)
    n = c[3]
    url = cstr(c[4 : 4 + n]) if n else ""
    off = 4 + n
    string_oids = struct.unpack_from(">i", c, off)[0]
    off += 4
    blast = c[off] if off < len(c) else None
    if off + (1 if blast is not None else 0) != len(c):
        raise ProtocolError("GET_NUMPARAMS reply has trailing bytes")
    return NumParams(count, url, string_oids, blast)


def parse_param_oids(m: Message) -> Tuple[int, List[int]]:
    c = _check(m)
    first, count = struct.unpack_from(">HB", c, 1)
    if len(c) != 4 + 2 * count:
        raise ProtocolError("GET_PARAM_OIDS reply length does not match its count")
    return first, list(struct.unpack_from(f">{count}H", c, 4))


def _number(t: int, b: bytes) -> Union[int, float]:
    if t in (T_INT16, T_INT16_ARRAY):
        return struct.unpack(">h", b)[0]
    if t in (T_INT32, T_INT32_ARRAY):
        return struct.unpack(">i", b)[0]
    if t in (T_FLOAT32, T_FLOAT32_ARRAY):
        return struct.unpack(">f", b)[0]
    raise ProtocolError(f"numeric constraint on type {t}")


def _width(t: int) -> int:
    return 2 if t in (T_INT16, T_INT16_ARRAY) else 4


def parse_constraint(ctype: int, data: bytes, ptype: int) -> Constraint:
    if ctype == C_NONE:
        if data:
            raise ProtocolError("empty constraint has data")
        return Constraint("none", ctype)
    if ctype in (C_RANGE, C_RANGE_STEP):
        w = _width(ptype)
        vals = [_number(ptype, data[i : i + w]) for i in range(0, len(data), w)]
        base = 3 if ctype == C_RANGE_STEP else 2
        if len(data) % w or len(vals) not in (base, base + 2):
            raise ProtocolError("range has an unexpected length")
        c = Constraint("range", ctype, minimum=vals[0], maximum=vals[1], raw=data)
        rest = vals[2:]
        if len(rest) >= 2 and len(vals) == base + 2:
            c.display_minimum, c.display_maximum = rest[0], rest[1]
            rest = rest[2:]
        if ctype == C_RANGE_STEP:
            c.step = rest[0]
        return c
    if ctype in (C_CHOICE, C_CHOICE_WIDE):
        w = _width(ptype)
        if ctype == C_CHOICE_WIDE:
            count, off = struct.unpack_from(">H", data, 0)[0], 2
        else:
            count, off = data[0], 1
        choices = []
        for _ in range(count):
            v = _number(ptype, data[off : off + w])
            off += w
            label, off = _counted(data, off)
            choices.append(Choice(v, label))
        if off != len(data):
            raise ProtocolError("choice list has trailing bytes")
        return Constraint("choice", ctype, choices=choices, raw=data)
    if ctype == C_STRING_CHOICE:
        count, off = struct.unpack_from(">H", data, 0)[0], 2
        choices = []
        for _ in range(count):
            s, off = _counted(data, off)
            choices.append(Choice(s, s))
        if off != len(data):
            raise ProtocolError("string choice list has trailing bytes")
        return Constraint("string-choice", ctype, choices=choices, raw=data)
    if ctype == C_ALARM:
        count, off = data[0], 1
        alarms = []
        for _ in range(count):
            bit, sev = data[off], data[off + 1]
            name, off = _counted(data, off + 2)
            alarms.append(Alarm(bit, sev, name))
        if off != len(data):
            raise ProtocolError("alarm table has trailing bytes")
        return Constraint("alarm", ctype, alarms=alarms, raw=data)
    if ctype == C_EXTERNAL:
        if len(data) != 2:
            raise ProtocolError("external constraint is not one object id")
        return Constraint("external", ctype, object_id=struct.unpack(">H", data)[0], raw=data)
    return Constraint("unknown", ctype, raw=data)


def parse_descriptor(m: Message) -> Descriptor:
    c = _check(m)
    oid, dlen = struct.unpack_from(">HB", c, 1)
    if dlen != len(c) - 4:
        raise ProtocolError(f"descriptor 0x{oid:04x}: length byte {dlen} != {len(c) - 4}")
    version, ptype, size, access, precision, widget, nlen = c[4:11]
    name = cstr(c[11 : 11 + nlen])
    off = 11 + nlen
    ctype, clen = c[off], c[off + 1]
    data = c[off + 2 : off + 2 + clen]
    if len(data) != clen:
        raise ProtocolError(f"descriptor 0x{oid:04x}: constraint runs past the end")
    return Descriptor(
        oid,
        version,
        ptype,
        size,
        access,
        precision,
        widget,
        name,
        parse_constraint(ctype, data, ptype),
        c[off + 2 + clen :],
    )


def parse_param(m: Message) -> Tuple[int, bytes]:
    """GET_PARAM reply, REPORT_PARAM and SET_PARAM reply: (oid, raw value)."""
    c = m.content if m.type == REPORT_PARAM else _check(m)
    oid, n = struct.unpack_from(">HB", c, 1)
    if len(c) != 4 + n:
        raise ProtocolError(f"value of 0x{oid:04x}: length byte {n} != {len(c) - 4}")
    return oid, c[4:]


def parse_array_element(m: Message) -> Tuple[int, int, bytes]:
    c = _check(m)
    oid, index, n = struct.unpack_from(">HHB", c, 1)
    if len(c) != 6 + n:
        raise ProtocolError("array element length does not match")
    return oid, index, c[6:]


def parse_menuset_name(m: Message) -> Tuple[int, int, str]:
    """(menuset, flags byte, name). Raises RemoteError for an absent set."""
    c = _check(m)
    menuset, flags, n = c[1], c[2], c[3]
    if len(c) != 4 + n:
        raise ProtocolError("menu set name length does not match")
    return menuset, flags, cstr(c[4:])


def parse_menu_count(m: Message) -> Tuple[int, int]:
    c = _check(m)
    if len(c) != 3:
        raise ProtocolError("menu count is not 3 bytes")
    return c[1], c[2]


def parse_menu_name(m: Message) -> Menu:
    c = _check(m)
    menuset, menu, n = c[1], c[2], c[3]
    name = cstr(c[4 : 4 + n])
    return Menu(menuset, menu, name, tail=c[4 + n :])


def parse_menu_oids(m: Message) -> Tuple[int, int, List[int]]:
    c = _check(m)
    menuset, menu, count = c[1], c[2], c[3]
    if len(c) != 4 + 2 * count:
        raise ProtocolError("menu OID list length does not match")
    return menuset, menu, list(struct.unpack_from(f">{count}H", c, 4))


def parse_menu_state(m: Message) -> Tuple[int, int, int]:
    c = _check(m)
    if len(c) != 4:
        raise ProtocolError("menu state is not 4 bytes")
    return c[1], c[2], c[3]


def parse_external_object(m: Message) -> ExternalChunk:
    c = _check(m)
    oid, off, nxt, n = struct.unpack_from(">HHHB", c, 1)
    if len(c) != 8 + n:
        raise ProtocolError("external object chunk length does not match")
    return ExternalChunk(oid, off, nxt, c[8:])


def parse_hello_reply(m: Message) -> Tuple[int, ...]:
    oid, v = parse_param(m)
    if oid != CONNECTION_OID or len(v) % 2:
        raise ProtocolError("hello reply is not 16-bit words on 0xFF03")
    return struct.unpack(f">{len(v) // 2}H", v)


# ----------------------------------------------------------------- values


def decode_value(d: Descriptor, raw: bytes):
    """A raw value as Python data, by the descriptor's type."""
    t = d.type
    if t == T_STRING:
        return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    if t in (T_INT16, T_INT32, T_FLOAT32):
        if len(raw) != _width(t):
            raise ProtocolError(f"0x{d.oid:04x}: {len(raw)} bytes for {d.type_name}")
        return _number(t, raw)
    if t in (T_INT16_ARRAY, T_INT32_ARRAY, T_FLOAT32_ARRAY):
        w = _width(t)
        return [_number(t, raw[i : i + w]) for i in range(0, len(raw), w)]
    if t == T_STRING_ARRAY:
        # Each element is a counted string: length (incl. NUL), bytes, NUL.
        out, off = [], 0
        while off < len(raw):
            s, off = _counted(raw, off)
            out.append(s)
        return out
    return raw.hex()


def ipv4(value: int) -> str:
    """An int32 IP field (widget 14 on the controller) as dotted quad."""
    return ".".join(str(b) for b in struct.pack(">i", value))


def external_constraint(data: bytes, ptype: int) -> Constraint:
    """The joined data of a GET_EXTERNAL_OBJECT read, as a constraint.

    Layout seen: kind u16 (1 = a constraint), constraint type u8, a length
    byte (the constraint bytes carried in the *first* chunk only; not used,
    the chunks are simply joined), then the constraint body.
    """
    if len(data) < 4:
        raise ProtocolError("external object shorter than its header")
    kind = struct.unpack_from(">H", data, 0)[0]
    if kind != 1:
        return Constraint("unknown", 0, raw=data)
    return parse_constraint(data[2], data[4:], ptype)
