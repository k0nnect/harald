"""The d-bus errors that mean bluez is out of reach, for both linux paths.

On linux, bleak (bluetooth le) and `harald.classic_linux` (bluetooth classic) both ask
bluetoothd over the system d-bus. When it is not running, or d-bus will not let this
user talk to it, the call fails with a d-bus error whose name says why. bleak raises
it as `BleakDBusError` and dbus-fast as `DBusError`; each path reads the name here.
"""

from __future__ import annotations

NOT_RUNNING = (  # nothing on the system bus owns org.bluez
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
)
# dbus-daemon could not start bluetoothd for us: on debian and its kin it asks
# systemd, which refuses a disabled or masked unit (NoSuchUnit, UnitMasked)
NOT_STARTED = ("org.freedesktop.systemd1.", "org.freedesktop.DBus.Error.Spawn.")
ACCESS_DENIED = "org.freedesktop.DBus.Error.AccessDenied"


def not_running(name: str) -> bool:
    """True if the d-bus error `name` means bluetoothd is not running."""
    return name in NOT_RUNNING or name.startswith(NOT_STARTED)
