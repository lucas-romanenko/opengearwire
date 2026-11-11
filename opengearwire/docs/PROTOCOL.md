# OGP over TCP 5253: the wire format

What Ross DashBoard says to an openGear frame, and what the frame says
back, decoded from one capture. **The capture is the authority**: where
it and any document disagree, the capture wins. Anything marked
*unknown* is shown raw by the library, never guessed.

## Sources

- **The capture.** DashBoard 10.0.0 (macOS) opening an OGX frame for 60
  seconds: the frame, its MFC-8322-S controller (software 3.04a) and ten
  DRA-8804 reclocking DAs (software 1.05, 8320AR-302 rear modules), and
  clicking through Signal, Setup and Alarms. One TCP connection to port
  5253 plus one HTTP GET. 3,941 OGP messages, 89,940 bytes, no gaps in
  either direction. The sanitized copy is
  `opengearwire/fixtures/dashboard-session.jsonl`.
- **Ross, "DashBoard Application Note: Methods for OGP Developers to
  Speed Up Device Initialization"** (public PDF on
  documentation.rossvideo.com, openGear Partners / DEV DEVELOPMENT
  GUIDES). Names `OGP_GET_NUMPARAMS` 0x45/0xC5 and its reply layout,
  `OGP_GET_DESCRIPTOR` reply 0xC7, `OGP_GET_PARAM` reply 0xC9, the menu
  replies 0xD0–0xD3 and 0xDA, `OGP_START_INIT_BLAST` 0x4E/0xCE and the
  return codes OK 0x00, UNSUPPORTED 0x01, RESPONSE_DENIED 0x03. It refers
  to "openGear Development Guide Part II – Software (8200DR-006)", which
  is partner-only and was not read.
- **og-param** (github.com/Lomzem/og-param, Rust, Aug 2026; no licence
  file, so read for cross-checking only, no code taken). Its framing,
  descriptor and constraint layouts agree with the capture byte for
  byte; it names 0x46, 0x4A, 0x59 and the constraint and type numbers,
  and maps slot to address as `0x10 + slot`.
- **Ross manuals** for the DRA-8804, MFC-OG3 and OGX-FR (parameter
  meanings; the 8320AR-302 rear module takes two slots).

## Transport

- Plain TCP to port **5253**, no TLS, no login. DashBoard opens **one**
  connection and keeps it.
- Before (here: 10 s after) the OGP session DashBoard also fetched
  `http://FRAME/connect/connection-props.xml` (a Java properties file:
  `equipmentType` = `opengearlite`, `address`, `port` 5253, `node-id` =
  the frame serial, `node-name`). The library does not need it.
- **No keepalive from the client.** The frame reports on its own (see
  *Reports*), the controller's frame status every second, so silence
  means a dead link.
- **One client at a time on the MFC-8322-S.** With DashBoard connected,
  a second client is hung up on: the frame closes the TCP connection
  right after it opens, whatever name the hello carries (DashBoard's own
  name string was tried too). With the library connected, DashBoard is
  locked out the same way. Seen on the first live runs (2026-11) and
  confirmed both ways by hand, on one frame. It matches Ross's *MFC-OG3-N
  and MFC-8322-S User Guide* (v10-rev3), Table 1 Feature Comparison
  Chart, which ticks "Supports more than one concurrent TCP Control
  connections, such as DashBoard, or a control panel" for the MFC-OG3-N
  only. The live run also reported Active Connections = 1 while the
  library was connected. *Unknown*: whether the frame says anything
  before hanging up (no capture of the refusal yet); the hello reply's
  "allowed" word may be where a refusal would show.

  For users of the library this means: **connect, read, disconnect
  quickly.** Every held connection (a long `watch`, a service keeping a
  `Frame` open) locks DashBoard out for that long, and an open DashBoard
  locks the library out. The library raises `FrameBusy` when the frame
  hangs up before answering anything after the hello.

## Framing

```
BA D2 AC E5   src   dst   type   length (u16 BE)   content[length]
```

- 9-byte header. The length counts the content only. Every byte of both
  directions of the capture belongs to a message (no padding, no
  checksums, no junk).
- **All integers are big-endian.** (An earlier note said the length was
  little-endian; the bytes say otherwise.)
- `src`/`dst` are device addresses: **0x00** the client, **0x10** the
  frame controller, **0x10 + slot** a card, **0x02** the destination of
  every unsolicited report (read as "all clients").
- A request has `type < 0x80`; its reply is `type | 0x80`, comes back
  with src and dst swapped, and its first content byte is a **return
  code** (0x00 OK). Requests also start with one byte, always 0x00 (the
  note calls it "placeholder for return code").

### Slots and addresses

`slot = address − 0x10`. The capture's cards answer at 0x12, 0x14 …
0x24: slots 2, 4 … 20, because each DRA-8804 sits on a 8320AR-302 full
rear module that takes two of the frame's 20 slots. A single-width card
can sit in any slot, odd ones included; the library assumes no layout
and lists whichever addresses speak. Confirm the numbering against the
"Slot N" labels in DashBoard's tree when convenient.

## Messages seen

Counts are from the capture (client → frame / frame → client).

| Type | Reply | Name | Count | Request content | Reply content after rc |
|---|---|---|---|---|---|
| 0x45 | 0xC5 | GET_NUMPARAMS | 11/11 | `00 01` | `count u16` (the note's long form adds an XML URL, string-OID count and blast flag; this frame sends the short form) |
| 0x46 | 0xC6 | GET_PARAM_OIDS | 12/11 | `00 first u16 count u8` (DashBoard: 0, 0 = all) | `first u16, n u8, n × oid u16` |
| 0x47 | 0xC7 | GET_DESCRIPTOR | 605/601 | `00 oid u16` | descriptor, below |
| 0x49 | 0xC9 | GET_PARAM | 605/601 | `00 oid u16` | `oid u16, len u8, value[len]` |
| 0x4A | 0xCA | SET_PARAM | 1/1 | `00 oid u16, len u8, value[len]` | `oid u16, len u8, value[len]` |
| 0x4C | 0xCC | GET_ARRAY_ELEMENT | 11/11 | `00 oid u16, index u16` | `oid u16, index u16, len u8, value` |
| 0x50 | 0xD0 | GET_MENUSET_NAME | 33/33 | `00 set u8` | `set u8, flags u8 (unknown, 0xAD), len u8, name\0` |
| 0x51 | 0xD1 | GET_MENU_COUNT | 22/22 | `00 set u8` | `set u8, count u8` |
| 0x52 | 0xD2 | GET_MENU_NAME | 57/57 | `00 set u8, menu u8` | `set, menu, len u8, name\0` |
| 0x53 | 0xD3 | GET_MENU_OIDS | 57/57 | `00 set u8, menu u8` | `set, menu, n u8, n × oid u16` |
| 0x59 | 0xD9 | GET_EXTERNAL_OBJECT | 20/20 | `00 object u16, from u16` | `object u16, from u16, next u16, len u8, data` |
| 0x5A | 0xDA | GET_MENU_STATE | 57/57 | `00 set u8, menu u8` | `set, menu, state u8` (always 2; meaning unknown) |
| — | 0x10 | REPORT_PARAM | –/967 | | `00, oid u16, len u8, value` (same as a GET_PARAM reply) |
| — | 0x11 | REPORT_0x11 | –/1 | | `01`, sent once by the controller right after the hello. *Unknown.* |

The unmatched requests (12 vs 11, 605 vs 601) are DashBoard's
**retries**: nine requests sent in the first 0.5 s, while it was talking
to all eleven devices at once, got no answer, and DashBoard sent each
again **2.50 s** later; every retry was answered within 10 ms.

Not seen: `START_INIT_BLAST` 0x4E (in the note; this frame's short
GET_NUMPARAMS reply carries no blast flag), and og-param's string-OID
family 0x66/0x67/0x69/0x6A/0x73 and REPORT_STRING 0x14.

Return codes seen: 0x00, and **0x11** for GET_MENUSET_NAME of set 2 on
every device (no third menu set). The note documents 0x01, 0x02
(og-param: invalid length), 0x03.

### How much is understood

- **Messages:** 3,940 of 3,941 parse completely (every field's position
  and size known, every length checked). The one opaque message is
  REPORT_0x11 (10 bytes).
- **Bytes:** 114 of 89,940 sit in fields whose *meaning* is unknown
  (structure known): menu state bytes (57), menu-set flag bytes (22),
  REPORT_0x11 (10), the external-object length byte (10), the hello's
  words (11), two descriptor trailers (4). **99.87 %** understood.

## Parameter descriptor (0xC7 content)

```
rc u8 | oid u16 | dlen u8 (= bytes that follow)
version u8 (2) | type u8 | size u8 | access u8 | precision u8 | widget u8
name_len u8 | name\0
constraint_type u8 | constraint_len u8 | constraint[constraint_len]
[trailer]
```

- **version** is 2 on all 601 descriptors.
- **type**: 2 int16, 4 int32, 6 float32, 7 string, 12 int16[],
  14 int32[], 16 float32[], 17 string[], 18 binary. Seen: int16 280,
  string 209, int16[] 63, int32 27, string[] 20, int32[] 2.
- **size** is the value's size in bytes: the string's maximum length,
  or element size × count for arrays (int16[] of size 4 = two
  elements: the DRA-8804's per-channel settings are `[channel A,
  channel B]`).
- **access**: 0 read-only, 1 read-write (118 of 601 are read-write).
- **precision**: 0 except on string[] (30 on the DRA-8804's BNC lists,
  read as maximum element length).
- **widget** is DashBoard's control. Seen (type, widget → examples):
  int16 0 plain number; 7 combo (Channel Options, Reclocker Rate);
  8 checkbox (Enable Equalizer, Notify on …); 9 radio (Addressing Mode,
  SLP Daemon); 10 (LED Mode); 11 (Factory Settings); 12 button (blank
  name, choice Apply/Cancel/Test …); 13 toggle (Locate Frame); int16[]
  15/16 blank-named table headers; int32 14 **IPv4 address** (IP
  Address, Subnet Mask, Default Gateway, NTP Server); int32[] 33 colour
  (Custom Color); string 0 text; 4 password; 6/10 headers and
  separators; 11 Frame Name; 13 notes. The library decodes int32 widget
  14 as an IP address and treats string widgets 5–8, 10, 13 as layout.
- **trailer**: two zero bytes after an empty constraint on the
  controller's two int32[] "Custom Color" descriptors (0x0753, 0x0755).
  *Unknown*; kept as `Descriptor.extra`.

### Constraints

| Type | Meaning | Body |
|---|---|---|
| 0 | none | empty |
| 1 | range | min, max [, display min, display max], each at the value's width |
| 2 | choice list | `n u8`, then n × (`value` at width, `len u8`, `label\0`) |
| 3 | long choice list | as 2 with `n u16` (not seen) |
| 4 | string choices | `n u16`, n × counted strings (not seen) |
| 5 | range with step | as 1 plus step (not seen) |
| 10 | alarm table | `n u8`, n × (`bit u8`, `severity u8`, `len u8`, `name\0`) |
| 11 | external | `object u16`: the body lives in an external object |

Seen: none 319, choice 177, alarm 55, external 50.

**Alarm tables** name bits of an int16 value; a set bit is an active
alarm. Severity 0 = OK/info, 1 = warning, 2 = error (DashBoard's
green/yellow/red). Example, DRA-8804 Channel A Status: bit 0 OK (0),
bit 2 No input (0), bit 1 Unlocked (0), bit 4 No input (2), bit 3
Unlocked (2). A channel with no signal reads 16 (bit 4: red) when Alarm
on Loss of Input is Notify.

**External objects** (GET_EXTERNAL_OBJECT) carry big constraints in
chunks. Each reply gives `from` (the index of the first item in this
chunk) and `next` (the index to ask for next; 0 = done). The joined data
is `kind u16` (1 = constraint), `constraint_type u8`, one length byte
(the constraint bytes in the *first* chunk only; *unknown purpose*, not
needed), then the constraint body. On the DRA-8804, object 0 is the
14-entry input-signal list (No signal, <125mB/s signal, MADI signal, SD
signal, HD signal, 3G signal, …, 6G signal (backup)) used by every
"Input" parameter; it arrived in two chunks (items 0–12, then 13).

## Values

Value bytes as the descriptor's type says: int16/int32/float32
big-endian; strings NUL-terminated (the length byte includes the NUL);
arrays are back-to-back elements; **string[] elements are counted
strings** (`len u8` including the NUL, bytes, NUL). IPv4 fields are a
big-endian int32 of the four octets.

## Menus

Each device has menu sets 0 "Status" and 1 "Config" (set 2 answers
0x11). Each set has menus (controller: Product, Network, Hardware,
Power; Setup, Network, Frame Glow; DRA-8804: Signal, Hardware, Product;
Setup, Alarms), each a list of OIDs in display order. An OID can appear
in several menus.

## The connect sequence

1. TCP connect.
2. **Hello**: SET_PARAM of OID **0xFF03** on the controller, value
   `00 00 00 00 01 00 21 "Version 10.0.0 2026-08-27 T14:22\0"` (the
   name's length as u16 before it; the five bytes before that are
   *unknown*, DashBoard sends zeros and a 1). The controller answers with
   value `00 01 00 01 00 00` (og-param reads: allowed = 1, "URM state" =
   1, refusal reason = 0) and then sends REPORT_0x11 `01`.
3. **Cards announce themselves**: within a second every card has sent a
   report (they report their current draw every second), and DashBoard
   starts on each device the moment it first hears it. It never sends a
   request to an empty slot. The controller's "Active Cards" (0x0717)
   says how many to expect.
4. Per device, **one request at a time**, all devices in parallel:
   GET_NUMPARAMS → GET_PARAM_OIDS → for each OID GET_DESCRIPTOR then
   GET_PARAM → GET_EXTERNAL_OBJECT for each external constraint → menu
   sets 0, 1, 2 (name; count; per menu name, OIDs, state). DashBoard also
   asked GET_ARRAY_ELEMENT index 0 of the blank-named int16[] header
   parameters (0x0751 on the controller, 0x0B01 on each card); the
   answers repeat values already read, so the library skips them.
5. A request with no answer after 2.5 s is sent again.

The library does the same, with one difference: a request still
unanswered after its retries is skipped, asked again in one final round
once everything else is done, and only then reported (`Frame.unanswered`,
the snapshot's `unanswered` list). On the first live run, three
requests stayed unanswered after four sends each; the snapshot still had
every parameter, descriptor, option list and menu the capture has, so
they were requests whose answer the snapshot does not show (a menu
state, a parameter count) or a value the frame also reports on its own.
Which ones is *unknown*; the next run lists them.

Each device was fully read 0.5–6.0 s after connecting (601 parameters
in all); the late ones were those that waited out a 2.5 s retry. After
6 s DashBoard sent **nothing**: clicking through Signal, Setup and
Alarms only showed what it had already read, and the remaining 54 s of
the capture are the frame's own reports.

## Reports (pushed changes)

REPORT_PARAM from a device to 0x02, unasked. On the capture, without
any client activity:

- controller: Frame status every 1 s; Bus Load, the two blank notes and
  Current DIP Switch every 5 s; PSU currents, fan speed, fan door,
  frame power, CPU headroom every 10 s; temperatures, PSU models,
  serials and statuses, fan RPM every 30 s;
- every card: Current (mA) every 1 s, Voltage every 5 s, CPU headroom
  and RAM every 30 s;
- on change: e.g. a card's Input Cable Length, Uptime.

So a client learns of changes without polling, and the 1 s frame-status
report doubles as a liveness signal.

## Writes

The only write in the capture is the hello (SET_PARAM 0xFF03, above).
SET_PARAM's layout is the same as the GET_PARAM reply, and the reply
echoes the value now in force. **No setting change has been captured**,
so this library sends no write but the hello. Before adding writes,
capture DashBoard changing one harmless setting and changing it back
(e.g. a card's Reclocker Rate, or Locate Frame on the controller) and
check: the request layout for an int16[] element (whole array or one
element?), the reply, and the reports that follow.

## Security notes

- No login: the frame's Access Mode was **Open**; anyone who can reach
  TCP 5253 can read and (presumably) write every parameter.
- The controller sends its connection **password in clear text** as an
  ordinary readable parameter (0xFE02, 0xFE0A; the factory default on
  the capture).
