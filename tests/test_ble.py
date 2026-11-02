import pytest
from bleak.exc import (
    BleakBluetoothNotAvailableError,
    BleakBluetoothNotAvailableReason,
    BleakDBusError,
    BleakDeviceNotFoundError,
    BleakError,
)
from fakes import CHR, SVC, FakeChar, FakeClient, FakeScanner, FakeService, advert

from harald import ble, btsock, hints
from harald.arm import arm, status
from harald.errors import BluetoothUnavailable, DeviceNotFound, HaraldError, WriteDenied

ADDR = "AA-11"
DFU_SVC = "0000fe59-0000-1000-8000-00805f9b34fb"
DFU_CHR = "8ec90001-f315-4f60-9fb8-838830daea50"
# what harald 0.2 said on a mac when bluetooth was off or not allowed
MAC_OFF = (
    "bluetooth is off or not allowed for this app",
    (
        "turn bluetooth on and allow your terminal app in "
        "system settings > privacy & security > bluetooth"
    ),
)
LINUX_OFF = "bluetooth is off or bluetoothd is not running"
POWERED_OFF = BleakBluetoothNotAvailableReason.POWERED_OFF
NO_BLUETOOTH = BleakBluetoothNotAvailableReason.NO_BLUETOOTH


async def connected(**config) -> ble.Session:
    if config:
        FakeClient.reset(**config)
    session = ble.Session(ADDR, client_cls=FakeClient)
    await session.connect()
    return session


async def test_scan_sorts_by_rssi():
    FakeScanner.reset(
        adverts=[
            advert("AA-11", "lamp", -70, ["0000FFE0-0000-1000-8000-00805F9B34FB"]),
            advert("BB-22", "scale", -40, manufacturer_data={0x004C: b"\x02\x15"}),
            advert("CC-33", None, -90),
        ]
    )
    devices = await ble.scan(timeout=0.1, scanner_cls=FakeScanner)
    assert [d.address for d in devices] == ["BB-22", "AA-11", "CC-33"]
    assert [d.rssi for d in devices] == [-40, -70, -90]
    assert devices[0].manufacturer_data == {0x004C: "0215"}
    assert devices[1].service_uuids == [SVC]
    assert devices[2].name is None


async def test_write_requires_arm():
    session = await connected()
    with pytest.raises(WriteDenied):
        await session.write(CHR, b"\x01\x02")
    assert FakeClient.writes == []


async def test_write_after_arm_reaches_client():
    arm(ADDR)
    session = await connected()
    assert await session.write(CHR, b"\x01\x02") == 49
    # the default fake characteristic allows write-without-response, so that is used
    assert FakeClient.writes == [(CHR, b"\x01\x02", False)]


async def test_write_with_response_when_the_char_is_write_only():
    arm(ADDR)
    session = await connected(
        services=[FakeService(SVC, [FakeChar(CHR, 0x0012, ["write"])])]
    )
    await session.write(CHR, b"\x01")
    assert FakeClient.writes == [(CHR, b"\x01", True)]


async def test_write_type_can_be_chosen():
    arm(ADDR)
    session = await connected()
    await session.write(CHR, b"\x01", response=True)
    await session.write(CHR, b"\x02", response=False)
    assert FakeClient.writes == [(CHR, b"\x01", True), (CHR, b"\x02", False)]


async def test_write_gate_sees_real_parent_service():
    arm(ADDR)
    session = await connected(
        services=[FakeService(DFU_SVC, [FakeChar(DFU_CHR, 0x0010, ["write"])])]
    )
    with pytest.raises(WriteDenied, match="firmware-update"):
        await session.write(DFU_CHR.upper(), b"\x01")
    assert FakeClient.writes == []


@pytest.mark.parametrize("uuid", ["0000aaaa-0000-1000-8000-00805f9b34fb", "aaaa"])
async def test_write_to_unknown_char_fails_closed(uuid):
    arm(ADDR, writes=5)
    session = await connected()
    with pytest.raises(HaraldError) as e:
        await session.write(uuid, b"\x01")
    assert "0000aaaa-0000-1000-8000-00805f9b34fb" in e.value.message
    assert "services" in e.value.hint
    assert FakeClient.writes == []
    assert status()[0].writes_left == 5


async def test_write_to_char_in_two_services_fails_closed():
    arm(ADDR, writes=5)
    session = await connected(
        services=[
            FakeService(SVC, [FakeChar(CHR, 0x0012, ["write"])]),
            FakeService(DFU_SVC, [FakeChar(CHR, 0x0020, ["write"])]),
        ]
    )
    with pytest.raises(HaraldError, match="more than one service"):
        await session.write(CHR, b"\x01")
    assert FakeClient.writes == []
    assert status()[0].writes_left == 5


async def test_write_before_connect_fails_closed():
    arm(ADDR, writes=5)
    session = ble.Session(ADDR, client_cls=FakeClient)
    with pytest.raises(HaraldError):
        await session.write(CHR, b"\x01")
    assert FakeClient.writes == []
    assert status()[0].writes_left == 5


async def test_bluetooth_off_maps_to_friendly_error(on_mac):
    FakeClient.reset(connect_error=BleakError("Bluetooth device is turned off"))
    session = ble.Session(ADDR, client_cls=FakeClient)
    with pytest.raises(BluetoothUnavailable) as e:
        await session.connect()
    assert e.value.hint == (
        "turn bluetooth on and allow your terminal app in "
        "system settings > privacy & security > bluetooth"
    )


async def test_scan_with_bluetooth_unauthorized_maps_to_friendly_error(on_mac):
    FakeScanner.reset(error=BleakError("Bluetooth is unauthorized"))
    with pytest.raises(BluetoothUnavailable) as e:
        await ble.scan(timeout=0.1, scanner_cls=FakeScanner)
    assert "privacy & security" in e.value.hint


async def test_bluetooth_off_hint_on_linux_names_bluetoothctl(on_linux):
    FakeClient.reset(connect_error=BleakError("Bluetooth device is turned off"))
    session = ble.Session(ADDR, client_cls=FakeClient)
    with pytest.raises(BluetoothUnavailable) as e:
        await session.connect()
    assert e.value.message == LINUX_OFF
    assert "bluetoothctl power on" in e.value.hint
    assert "system settings" not in e.value.hint


async def connect_error(error: Exception) -> HaraldError:
    """What connecting raises when bleak fails with `error`."""
    FakeClient.reset(connect_error=error)
    with pytest.raises(HaraldError) as e:
        await ble.Session(ADDR, client_cls=FakeClient).connect()
    return e.value


@pytest.mark.parametrize(
    "error",
    [
        BleakError("Bluetooth device is turned off"),
        BleakError("Bluetooth is unauthorized"),
        BleakError("Bluetooth device is not authorized"),
        BleakBluetoothNotAvailableError("Bluetooth is turned off", POWERED_OFF),
    ],
)
async def test_bluetooth_off_on_a_mac_is_the_0_2_text(on_mac, error):
    off = await connect_error(error)
    assert type(off) is BluetoothUnavailable
    assert (off.message, off.hint) == MAC_OFF


# bluez's d-bus errors, as bleak raises them on linux: the name, then the body
@pytest.mark.parametrize(
    "error",
    [
        BleakDBusError("org.bluez.Error.NotReady", []),  # the adapter is off
        BleakDBusError("org.bluez.Error.NotReady", ["Resource Not Ready"]),
        BleakError("No Bluetooth adapters found."),  # bleak before 2.0
        BleakBluetoothNotAvailableError("No Bluetooth adapters found.", NO_BLUETOOTH),
        # bluetoothd is not running, and d-bus could not start it
        BleakDBusError(
            "org.freedesktop.DBus.Error.ServiceUnknown",
            ["The name org.bluez was not provided by any .service files"],
        ),
        BleakDBusError("org.freedesktop.DBus.Error.NameHasNoOwner", []),
        BleakDBusError("org.freedesktop.systemd1.NoSuchUnit", []),  # disabled
        BleakDBusError("org.freedesktop.systemd1.UnitMasked", []),
        BleakDBusError("org.freedesktop.DBus.Error.Spawn.ChildExited", []),
    ],
)
async def test_bluez_bluetooth_off_errors_on_linux(on_linux, error):
    off = await connect_error(error)
    assert type(off) is BluetoothUnavailable
    assert (off.message, off.hint) == (LINUX_OFF, hints.bluetooth_off())
    assert "bluetoothctl power on" in off.hint


async def test_scan_with_the_adapter_off_on_linux(on_linux):
    FakeScanner.reset(error=BleakDBusError("org.bluez.Error.NotReady", []))
    with pytest.raises(BluetoothUnavailable) as e:
        await ble.scan(timeout=0.1, scanner_cls=FakeScanner)
    assert (e.value.message, e.value.hint) == (LINUX_OFF, hints.bluetooth_off())


@pytest.mark.parametrize(
    "error",
    [
        BleakDBusError("org.bluez.Error.NotPermitted", []),
        BleakDBusError("org.bluez.Error.NotAuthorized", []),
        # the body alone would read as the mac's "bluetooth is not authorized"
        BleakDBusError("org.bluez.Error.NotAuthorized", ["Not Authorized"]),
        BleakDBusError(
            "org.freedesktop.DBus.Error.AccessDenied",
            ['Rejected send message, 1 matched rules; interface="org.bluez.Adapter1"'],
        ),
    ],
)
async def test_bluez_permission_errors_on_linux(on_linux, error):
    denied = await connect_error(error)
    assert type(denied) is BluetoothUnavailable
    assert denied.message == "permission denied for bluetooth"
    assert denied.hint == hints.permission()
    assert "bluetooth group" in denied.hint


async def test_bluez_in_progress_is_busy(on_linux):
    error = BleakDBusError(
        "org.bluez.Error.InProgress", ["Operation already in progress"]
    )
    busy = await connect_error(error)
    assert type(busy) is HaraldError
    assert busy.message == "bluetooth is busy with another operation"
    assert "try again" in busy.hint
    assert busy.hint == busy.hint.lower()


# what bleak raises on linux when its system d-bus connect fails: no socket there
# (a container, wsl), or nothing listening on it
NO_BUS = [
    FileNotFoundError(2, "No such file or directory"),
    ConnectionRefusedError(111, "Connection refused"),
]


def kernel(monkeypatch, has_bluetooth: bool) -> list[bool]:
    """Stand in for btsock's probe of the kernel; returns a list of its answers."""
    asked: list[bool] = []

    def probe() -> bool:
        asked.append(has_bluetooth)
        return has_bluetooth

    monkeypatch.setattr(btsock, "kernel_has_bluetooth", probe)
    return asked


async def scan_error(error: Exception) -> BaseException:
    """What scanning raises when bleak fails with `error`."""
    FakeScanner.reset(error=error)
    with pytest.raises(BaseException) as e:
        await ble.scan(timeout=0.1, scanner_cls=FakeScanner)
    return e.value


@pytest.mark.parametrize("error", NO_BUS)
async def test_no_system_bus_on_linux_is_bluetooth_off(on_linux, monkeypatch, error):
    asked = kernel(monkeypatch, has_bluetooth=True)
    for raised in (await scan_error(error), await connect_error(error)):
        assert type(raised) is BluetoothUnavailable
        assert (raised.message, raised.hint) == (LINUX_OFF, hints.bluetooth_off())
        assert raised.__cause__ is error
    assert asked == [True, True]


@pytest.mark.parametrize("error", NO_BUS)
async def test_no_system_bus_on_a_linux_without_bluetooth_says_so(
    on_linux, monkeypatch, error
):
    # wsl, or a container: no bluetoothd could help, so its hint would mislead
    kernel(monkeypatch, has_bluetooth=False)
    for raised in (await scan_error(error), await connect_error(error)):
        assert type(raised) is BluetoothUnavailable
        assert (raised.message, raised.hint) == hints.no_bluetooth_support()
        assert "systemctl" not in raised.hint


@pytest.mark.parametrize("error", NO_BUS)
async def test_no_system_bus_on_a_mac_passes_through(on_mac, monkeypatch, error):
    asked = kernel(monkeypatch, has_bluetooth=False)
    assert await scan_error(error) is error
    FakeClient.reset(connect_error=error)
    with pytest.raises(OSError) as e:
        await ble.Session(ADDR, client_cls=FakeClient).connect()
    assert e.value is error
    assert asked == []


@pytest.mark.parametrize(
    "error",
    [
        OSError(5, "Input/output error"),
        ConnectionResetError(104, "Connection reset by peer"),
    ],
)
async def test_other_os_errors_on_linux_pass_through(on_linux, monkeypatch, error):
    asked = kernel(monkeypatch, has_bluetooth=False)
    assert await scan_error(error) is error
    FakeClient.reset(connect_error=error)
    with pytest.raises(OSError) as e:
        await ble.Session(ADDR, client_cls=FakeClient).connect()
    assert e.value is error
    assert asked == []


@pytest.mark.parametrize(
    "error",
    [
        BleakDBusError("org.bluez.Error.Failed", ["le-connection-abort-by-local"]),
        BleakError("Not connected"),
    ],
)
async def test_other_bleak_errors_pass_through(on_linux, error):
    FakeClient.reset(connect_error=error)
    with pytest.raises(BleakError) as e:
        await ble.Session(ADDR, client_cls=FakeClient).connect()
    assert e.value is error


@pytest.mark.parametrize(
    "error",
    [
        BleakDeviceNotFoundError(ADDR, f"Device with address {ADDR} was not found"),
        TimeoutError(),
    ],
)
async def test_unknown_device_maps_to_not_found(error):
    FakeClient.reset(connect_error=error)
    session = ble.Session(ADDR, client_cls=FakeClient)
    with pytest.raises(DeviceNotFound) as e:
        await session.connect()
    assert ADDR in e.value.message
    assert "harald scan" in e.value.hint


async def test_services_lists_properties():
    session = await connected()
    services = await session.services()
    assert services == [
        ble.ServiceInfo(
            uuid=SVC,
            chars=[
                ble.CharInfo(
                    uuid=CHR,
                    handle=0x0012,
                    properties=["write-without-response", "notify"],
                )
            ],
        )
    ]


async def test_read_returns_bytes():
    session = await connected(reads={CHR: b"\x0a\x0b"})
    assert await session.read("FFE1") == b"\x0a\x0b"


async def test_subscribe_collects_timed_notifications():
    session = await connected(notifications={CHR: [b"\x01", b"\x02"]})
    events = await session.subscribe(CHR, 0)
    assert [value for _, value in events] == [b"\x01", b"\x02"]
    assert all(isinstance(t, float) and t >= 0 for t, _ in events)


async def test_subscribe_keeps_events_when_stop_notify_fails():
    session = await connected(
        notifications={CHR: [b"\x01", b"\x02"]},
        stop_notify_error=BleakError("Not connected"),
    )
    events = await session.subscribe(CHR, 0)
    assert [value for _, value in events] == [b"\x01", b"\x02"]
