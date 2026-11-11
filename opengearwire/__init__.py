# SPDX-License-Identifier: MIT
"""opengearwire: read openGear frames (Ross OGX and partners) over OGP.

Read-only for now. ``Frame`` connects and reads; ``Tree`` holds what was
read; ``snapshot`` turns it into plain data. ``docs/PROTOCOL.md`` is the
wire format.
"""

__version__ = "0.3.0"

from ._protocol import ProtocolError, RemoteError
from .client import Frame, FrameBusy, FrameError
from .model import Change, Device, Parameter, Tree, address_of, slot_of
from .snapshot import snapshot

__all__ = [
    "Change",
    "Device",
    "Frame",
    "FrameBusy",
    "FrameError",
    "Parameter",
    "ProtocolError",
    "RemoteError",
    "Tree",
    "address_of",
    "slot_of",
    "snapshot",
]
