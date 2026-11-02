"""The human text that depends on where harald runs: a mac, linux, or neither.

Each function reads `sys.platform` when it is called, so one process (or test) can
word things for either platform. On a mac the text is what harald has always said.
On linux the hints name the commands a person can run (`bluetoothctl`, `rfkill`,
`systemctl`); harald never runs them itself.
"""

from __future__ import annotations

import sys


def is_linux() -> bool:
    return sys.platform == "linux"


def here() -> str:
    """The machine harald runs on, as in "paired with this mac"."""
    return "this computer" if is_linux() else "this mac"


def machine() -> str:
    """The machine harald runs on, as in "the mac would not open a channel"."""
    return "this computer" if is_linux() else "the mac"


def bluetooth_off_message() -> str:
    """The error that goes with `bluetooth_off`'s hint."""
    if is_linux():
        return "bluetooth is off or bluetoothd is not running"
    return "bluetooth is off or not allowed for this app"


def bluetooth_off() -> str:
    if is_linux():
        return (
            "turn bluetooth on with bluetoothctl power on (first rfkill unblock "
            "bluetooth if it is blocked); bluetoothd must be running: "
            "systemctl status bluetooth, and if it is disabled, "
            "sudo systemctl enable --now bluetooth"
        )
    return (
        "turn bluetooth on and allow your terminal app in "
        "system settings > privacy & security > bluetooth"
    )


def permission() -> str:
    if is_linux():
        return (
            "add yourself to the bluetooth group, then log out and back in; if harald "
            "runs in a sandbox such as snap or flatpak, run it outside"
        )
    return "allow your terminal app in system settings > privacy & security > bluetooth"


def pair(address: str) -> str:
    """How to pair `address` when it is not paired."""
    if is_linux():
        return f"pair it: {_bluetoothctl_pair(address)}"
    return "pair it in system settings > bluetooth, then run: harald classic devices"


def pair_one() -> str:
    """How to pair a device when none is paired."""
    if is_linux():
        return f"pair one: {_bluetoothctl_pair('<address>')}"
    return "pair one in system settings > bluetooth"


def repair(address: str) -> str:
    """How to pair `address` again once it has forgotten this machine's key."""
    if is_linux():
        return (
            f"pair it again: bluetoothctl remove {address}, "
            f"then {_bluetoothctl_pair(address)}"
        )
    return "forget it in system settings > bluetooth and pair it again"


def connect() -> str:
    if is_linux():
        return "turn it on, bring it close and disconnect it from your phone"
    return "turn it on and connect it to this mac in system settings > bluetooth"


def stuck() -> str:
    if is_linux():
        return (
            "bluetoothd may be stuck: restart it with "
            "sudo systemctl restart bluetooth, then try again"
        )
    return (
        "the mac's bluetooth is stuck: turn bluetooth off and on "
        "in the menu bar, then try again"
    )


def timeout() -> str:
    if is_linux():
        return (
            "move closer and try again; if it keeps happening, "
            "restart bluetooth with sudo systemctl restart bluetooth"
        )
    return (
        "move closer and try again; if it keeps happening, "
        "turn the mac's bluetooth off and on"
    )


def no_bluetooth_support() -> tuple[str, str]:
    """The message and hint for a linux whose kernel has no bluetooth at all (btsock's
    EAFNOSUPPORT), for bluetooth classic and le alike: no bluetoothd could help."""
    return (
        "this linux has no bluetooth support",
        "containers and wsl usually don't; run harald where the radio is",
    )


def unsupported_classic() -> tuple[str, str]:
    """The message and hint when bluetooth classic cannot run here.

    A mac lacks pyobjc's IOBluetooth, linux lacks bluetooth in its kernel (btsock's
    EAFNOSUPPORT), and any other os lacks a backend.
    """
    if sys.platform == "darwin":
        return (
            "bluetooth classic needs pyobjc's iobluetooth",
            "uv tool install --reinstall harald",
        )
    if is_linux():
        return no_bluetooth_support()
    return (
        "bluetooth classic needs macos or linux",
        "use a mac or a linux machine, or the bluetooth le tools",
    )


def _bluetoothctl_pair(address: str) -> str:
    # without pairable on, bluez makes a bond that is gone after the next disconnect;
    # it pairs only a device it has discovered, and `remove` forgets the device
    return (
        "bluetoothctl pairable on, bluetoothctl scan on until the gadget shows up, "
        f"then bluetoothctl pair {address} and bluetoothctl trust {address}"
    )
