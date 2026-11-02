class HaraldError(Exception):
    """Base error. `hint` tells the user or agent what to do next."""

    def __init__(self, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class WriteDenied(HaraldError):
    """A write was refused because the device is not armed for it."""


class DeviceNotFound(HaraldError):
    """No device matched the given address or name."""


class BluetoothUnavailable(HaraldError):
    """The Bluetooth adapter is off, missing, or not permitted."""


class CaptureFormatError(HaraldError):
    """A capture file could not be parsed."""


class ToolMissing(HaraldError):
    """An external tool harald depends on is not installed."""


class LibraryError(HaraldError):
    """A device library entry is missing or invalid."""


class ProtectedChannel(HaraldError):
    """A bluetooth classic channel carries a standard profile harald never opens."""
