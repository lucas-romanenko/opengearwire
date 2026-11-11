# opengearwire: notes for future sessions

The openGear (Ross OGX) wire layer for AV Server. Protocol only: no UI,
no web app; the frontend lives in AV Server. Not part of bmdwire
(bmdwire is Blackmagic only).

- **The capture is the authority.** Protocol knowledge comes from
  captures of DashBoard against real frames, then Ross's public notes.
  Never guess a field: show it raw and mark it unknown in
  `opengearwire/docs/PROTOCOL.md`.
- **Read-only until a write is captured.** The only write sent is the
  0xFF03 hello DashBoard sends. Add setting changes only from a capture
  of DashBoard making that change.
- **Network rules.** Nothing on a timer against a frame; each call
  touches only what it says; one request in flight per device; timeouts
  are no-progress (silence), never fixed totals.
- **No real identities in the repo.** No site or company names, real
  IPs, MACs, serials or frame names in code, tests, docs or commits.
  Raw captures stay out of git; fixtures are made with
  `tools/fixture_from_capture.py`, which sanitizes and checks.
- Style follows bmdwire's ultimattewire: standard library only, small
  modules, tests beside the package, `ruff check` and `ruff format`
  clean, CI on 3.10/3.12/3.14.
