# opengearwire

Python library for **openGear frames** (Ross OGX and the partner cards in
them) over the openGear Protocol, OGP, on TCP 5253: the frame's health
and every card's parameters, read the way Ross DashBoard reads them.

[![CI](https://github.com/lucas-romanenko/opengearwire/actions/workflows/ci.yml/badge.svg)](https://github.com/lucas-romanenko/opengearwire/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)

Everything here was decoded from a packet capture of DashBoard 10 reading
a real frame, checked against Ross's public OGP application note, and is
tested by replaying that capture (sanitized) against the client. The
wire format is in [`opengearwire/docs/PROTOCOL.md`](opengearwire/docs/PROTOCOL.md).

## Status

- **0.3.0, read-only.** Verified against one capture: an OGX frame with
  an MFC-8322-S controller and ten DRA-8804 reclocking DAs. 3,940 of its
  3,941 messages decode completely; the client rebuilds the same
  parameter tree DashBoard got.
- **No writes** except the connection hello DashBoard itself sends
  (it sets nothing). Setting changes come once one is captured.
- Run against the live frame: its snapshot has every parameter the
  capture has.

## One client at a time

An **MFC-8322-S controller takes one control connection at a time**.
While DashBoard is connected, the frame hangs up on this library, and
while the library is connected, DashBoard is locked out. Confirmed both
ways on a live frame; Ross's MFC manual (Table 1, Feature Comparison)
lists more than one concurrent TCP control connection for the MFC-OG3-N
only.

So: **connect, read, disconnect quickly.** Keep a `Frame` open only
while someone is looking at what it reads, never in the background, and
keep `watch` short; close DashBoard before running the CLI. When the frame hangs up before answering anything after the hello,
the library raises `FrameBusy` (a `FrameError`) saying so; a hang-up
later in a read is the plain `FrameError`.

## Install

```sh
pip install opengearwire
```

Python 3.10 or newer. Standard library only.

## Usage

```python
from opengearwire import Frame

with Frame("192.0.2.10") as f:
    f.discover()  # [0, 2, 4, ...]: slots that answered (0 = controller)
    f.identify()  # {0: "MFC-8322-S", 2: "DRA-8804", ...}
    f.describe()  # every parameter, value and menu of every slot
    card = f.device(4)
    print(card.find("Enable Equalizer").display)  # ['Enabled', 'Enabled']  (channel A, B)
    print(card.find(0x0704).display)  # 'Locked - 1.5G'
    for change in f.watch(10):  # what the frame pushed in 10 s
        print(change.slot, change.name, change.old, "->", change.new)
    snap = f.snapshot()  # plain dicts: frame health + every card, json.dumps-ready
```

- `Frame(host, port=5253, timeout=5.0, retry_after=2.5, retries=3)`.
  `timeout` is **no-progress**: seconds without a byte from the frame
  (which reports its status every second), not a total. An unanswered
  request is resent after `retry_after` seconds, as DashBoard does;
  after `retries` the rest goes on, and it is asked again in one final
  round at the end. What still has no answer is listed in
  `Frame.unanswered` (slot, request, OID and name, or menu / object) and
  in the snapshot's `unanswered`.
- `discover()` listens: every card reports on its own within about a
  second, and it stops as soon as the controller's Active Cards count is
  reached. It assumes no layout: any of the 20 slots, single- or
  double-width cards.
- `describe(slots=None, menus=True)`, `describe_oids(slot, oids)`,
  `read(slot, *oids_or_names)` (fresh values), `watch(seconds)`,
  `snapshot()`.
- `Parameter.value` is the decoded value; `.display` is what DashBoard
  shows (choice labels, active alarm names, IP addresses); `.severity`
  is 0/1/2 for alarm tables. In the snapshot each parameter has
  `value` and, where they differ, `display` beside it (Channel A Status:
  `"value": 16, "display": ["No input"]`).
- `Tree.apply(message)` builds the same tree from any message source (a
  capture, a test), with no network.

Nothing runs on a timer: each call does what it says on one connection
and returns. One request in flight per device, all devices in parallel.

## Command line

```sh
opengearwire 192.0.2.10 slots            # occupied slots and their products
opengearwire 192.0.2.10 params 4         # every parameter of slot 4
opengearwire 192.0.2.10 read 4 0x0b04    # fresh value(s) by OID or exact name
opengearwire 192.0.2.10 watch 10         # pushed changes for 10 s
opengearwire 192.0.2.10 snapshot         # the whole frame as JSON
```

`--json` for machine output, `--timeout` for the silence limit.
Requests the frame never answered are listed on stderr (and in the
snapshot's `unanswered`).
`python -m opengearwire` works too.

## Testing without a frame

`opengearwire.testing` is a fake frame for your own tests and for
developing an app: it listens on 127.0.0.1 and answers from the bundled
capture (sanitized), including the frame's one-client-at-a-time
behaviour.

```python
from opengearwire import Frame, FrameBusy
from opengearwire.testing import FakeFrame

fake = FakeFrame()  # a free port on 127.0.0.1: fake.port
with Frame("127.0.0.1", fake.port) as f:
    f.discover()
    fake.report(18, 0x0705, b"12 (1694A) / 8 (1855A)\x00")  # a card pushes a change
    print(f.watch(0.5))
fake.busy = True  # "DashBoard is connected": every client is turned away (FrameBusy)
fake.close()
```

```sh
python -m opengearwire.testing --port 5253   # a fake frame to point an app at
```

## Development

```sh
pip install -e ".[dev]"
python -m pytest
ruff check . && ruff format --check .
```

The suite needs no hardware: it runs `opengearwire.testing`'s fake
frame on 127.0.0.1, answering from the captured session. To make a
fixture from a new capture (it replaces serials, MAC, names, passwords and
IP addresses and refuses to write if any original survives):

```sh
python tools/fixture_from_capture.py CAPTURE.pcapng opengearwire/fixtures/NAME.jsonl
```

Raw captures never go into git (`.gitignore` blocks them).

A release is a tag `v<version>` matching `project.version`, built
(`python -m build`) and uploaded to PyPI from that tag with `twine`; no
token lives in this repository.

Not affiliated with or endorsed by Ross Video Ltd. openGear, DashBoard
and OGX are trademarks of Ross Video.
