"""harald.hints: the human text that depends on the platform.

On a mac every function returns the text harald 0.2 printed, byte for byte. On linux
the text names the commands the person can run. The platform is read when each
function is called, so these tests set `sys.platform` with the `on_mac` and
`on_linux` fixtures.
"""

import sys

import pytest

from harald import hints

ADDRESS = "aa:bb:cc:11:22:33"


def test_is_linux_reads_the_platform_when_called(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert hints.is_linux() is True
    monkeypatch.setattr(sys, "platform", "darwin")
    assert hints.is_linux() is False
    monkeypatch.setattr(sys, "platform", "win32")
    assert hints.is_linux() is False


@pytest.mark.usefixtures("on_mac")
def test_mac_text_is_what_harald_always_printed():
    assert hints.here() == "this mac"
    assert hints.machine() == "the mac"
    assert hints.bluetooth_off_message() == (
        "bluetooth is off or not allowed for this app"
    )
    assert hints.bluetooth_off() == (
        "turn bluetooth on and allow your terminal app in "
        "system settings > privacy & security > bluetooth"
    )
    assert hints.pair(ADDRESS) == (
        "pair it in system settings > bluetooth, then run: harald classic devices"
    )
    assert hints.pair_one() == "pair one in system settings > bluetooth"
    assert hints.connect() == (
        "turn it on and connect it to this mac in system settings > bluetooth"
    )
    assert hints.stuck() == (
        "the mac's bluetooth is stuck: turn bluetooth off and on "
        "in the menu bar, then try again"
    )
    assert hints.timeout() == (
        "move closer and try again; if it keeps happening, "
        "turn the mac's bluetooth off and on"
    )


@pytest.mark.usefixtures("on_mac")
def test_mac_text_for_the_codes_new_in_this_version():
    assert hints.permission() == (
        "allow your terminal app in system settings > privacy & security > bluetooth"
    )
    assert hints.repair(ADDRESS) == (
        "forget it in system settings > bluetooth and pair it again"
    )


@pytest.mark.usefixtures("on_linux")
def test_linux_text_names_the_commands():
    assert hints.here() == "this computer"
    assert hints.machine() == "this computer"
    assert hints.bluetooth_off_message() == (
        "bluetooth is off or bluetoothd is not running"
    )
    off = hints.bluetooth_off()
    for command in (
        "bluetoothctl power on",
        "rfkill unblock bluetooth",
        "systemctl status bluetooth",
        "sudo systemctl enable --now bluetooth",  # for a disabled bluetoothd
    ):
        assert command in off
    # a snap or flatpak may hide bluez's d-bus api whatever groups the person is in
    assert hints.permission() == (
        "add yourself to the bluetooth group, then log out and back in; if harald "
        "runs in a sandbox such as snap or flatpak, run it outside"
    )
    assert hints.pair(ADDRESS) == (
        "pair it: bluetoothctl pairable on, bluetoothctl scan on until the gadget "
        f"shows up, then bluetoothctl pair {ADDRESS} and bluetoothctl trust {ADDRESS}"
    )
    assert hints.pair_one() == (
        "pair one: bluetoothctl pairable on, bluetoothctl scan on until the gadget "
        "shows up, then bluetoothctl pair <address> and bluetoothctl trust <address>"
    )
    assert hints.repair(ADDRESS) == (
        f"pair it again: bluetoothctl remove {ADDRESS}, then bluetoothctl pairable "
        "on, bluetoothctl scan on until the gadget shows up, then "
        f"bluetoothctl pair {ADDRESS} and bluetoothctl trust {ADDRESS}"
    )
    assert "bring it close" in hints.connect()


@pytest.mark.usefixtures("on_linux")
def test_linux_pairing_scans_before_it_pairs():
    # bluez pairs only a device it has discovered, and remove forgets it
    steps = [
        "bluetoothctl pairable on",
        "bluetoothctl scan on",
        f"bluetoothctl pair {ADDRESS}",
        f"bluetoothctl trust {ADDRESS}",
    ]
    for text in (hints.pair(ADDRESS), hints.repair(ADDRESS)):
        at = [text.index(step) for step in steps]
        assert at == sorted(at)
    repair = hints.repair(ADDRESS)
    assert repair.index(f"bluetoothctl remove {ADDRESS}") < repair.index(steps[0])
    assert "disconnect it from your phone" in hints.connect()
    assert "sudo systemctl restart bluetooth" in hints.stuck()
    assert "sudo systemctl restart bluetooth" in hints.timeout()
    assert hints.timeout().startswith("move closer and try again")


@pytest.mark.usefixtures("on_linux")
def test_linux_text_never_mentions_the_mac():
    texts = [
        hints.here(),
        hints.machine(),
        hints.bluetooth_off_message(),
        hints.bluetooth_off(),
        hints.permission(),
        hints.pair(ADDRESS),
        hints.pair_one(),
        hints.repair(ADDRESS),
        hints.connect(),
        hints.stuck(),
        hints.timeout(),
        *hints.unsupported_classic(),
    ]
    for text in texts:
        assert "mac" not in text
        assert "system settings" not in text
        assert "menu bar" not in text
        assert text == text.lower()


@pytest.mark.parametrize(
    ("platform", "message", "hint"),
    [
        (
            "darwin",
            "bluetooth classic needs pyobjc's iobluetooth",
            "uv tool install --reinstall harald",
        ),
        (
            "linux",
            "this linux has no bluetooth support",
            "containers and wsl usually don't; run harald where the radio is",
        ),
        (
            "win32",
            "bluetooth classic needs macos or linux",
            "use a mac or a linux machine, or the bluetooth le tools",
        ),
    ],
)
def test_unsupported_classic_by_platform(monkeypatch, platform, message, hint):
    monkeypatch.setattr(sys, "platform", platform)
    assert hints.unsupported_classic() == (message, hint)


def test_no_bluetooth_support_is_linuxs_unsupported_text(on_linux):
    # a kernel with no bluetooth at all: what classic and ble both say on linux
    assert hints.no_bluetooth_support() == (
        "this linux has no bluetooth support",
        "containers and wsl usually don't; run harald where the radio is",
    )
    assert hints.no_bluetooth_support() == hints.unsupported_classic()
