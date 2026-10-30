import pytest
from bleak.exc import BleakDeviceNotFoundError, BleakError
from fakes import CHR, SVC, FakeChar, FakeClient, FakeScanner, FakeService, advert

from harald import ble
from harald.arm import arm, status
from harald.errors import BluetoothUnavailable, DeviceNotFound, HaraldError, WriteDenied

ADDR = "AA-11"
DFU_SVC = "0000fe59-0000-1000-8000-00805f9b34fb"
DFU_CHR = "8ec90001-f315-4f60-9fb8-838830daea50"


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


async def test_bluetooth_off_maps_to_friendly_error():
    FakeClient.reset(connect_error=BleakError("Bluetooth device is turned off"))
    session = ble.Session(ADDR, client_cls=FakeClient)
    with pytest.raises(BluetoothUnavailable) as e:
        await session.connect()
    assert "privacy & security" in e.value.hint


async def test_scan_with_bluetooth_unauthorized_maps_to_friendly_error():
    FakeScanner.reset(error=BleakError("Bluetooth is unauthorized"))
    with pytest.raises(BluetoothUnavailable) as e:
        await ble.scan(timeout=0.1, scanner_cls=FakeScanner)
    assert "privacy & security" in e.value.hint


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
