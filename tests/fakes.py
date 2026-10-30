"""Stand-ins for bleak's BleakScanner and BleakClient, so no test needs a radio.

Front ends build their own client instances (`client_cls(address)`), so the fakes are
configured and inspected on the class. conftest.py calls `reset()` before every test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakCharacteristicNotFoundError, BleakError

SVC = "0000ffe0-0000-1000-8000-00805f9b34fb"
CHR = "0000ffe1-0000-1000-8000-00805f9b34fb"


@dataclass
class FakeChar:
    uuid: str
    handle: int
    properties: list[str]


@dataclass
class FakeService:
    uuid: str
    characteristics: list[FakeChar] = field(default_factory=list)


def default_services() -> list[FakeService]:
    return [
        FakeService(SVC, [FakeChar(CHR, 0x0012, ["write-without-response", "notify"])])
    ]


def advert(
    address: str,
    name: str | None,
    rssi: int,
    service_uuids: list[str] | None = None,
    manufacturer_data: dict[int, bytes] | None = None,
) -> tuple[BLEDevice, AdvertisementData]:
    """One entry of `BleakScanner.discover(return_adv=True)`, built from real bleak types."""
    adv = AdvertisementData(
        local_name=name,
        manufacturer_data=manufacturer_data or {},
        service_data={},
        service_uuids=service_uuids or [],
        tx_power=None,
        rssi=rssi,
        platform_data=(),
    )
    return BLEDevice(address, name, None), adv


def default_adverts() -> list[tuple[BLEDevice, AdvertisementData]]:
    return [
        advert("AA-11", "lamp", -70, [SVC], {0x004C: b"\x02\x15"}),
        advert("BB-22", "scale", -40),
        advert("CC-33", None, -90),
    ]


class FakeScanner:
    adverts: ClassVar[list[tuple[BLEDevice, AdvertisementData]]]
    error: ClassVar[Exception | None]

    @classmethod
    def reset(cls, *, adverts=None, error: Exception | None = None) -> None:
        cls.adverts = default_adverts() if adverts is None else list(adverts)
        cls.error = error

    @classmethod
    async def discover(
        cls, timeout: float = 5.0, *, return_adv: bool = False, **kwargs
    ):
        if cls.error is not None:
            raise cls.error
        if return_adv:
            return {device.address: (device, adv) for device, adv in cls.adverts}
        return [device for device, _ in cls.adverts]


class FakeClient:
    """Configure with `FakeClient.reset(services=..., reads=..., notifications=...,
    connect_error=...)`; inspect `FakeClient.writes` afterwards."""

    service_list: ClassVar[list[FakeService]]
    reads: ClassVar[dict[str, bytes]]
    notifications: ClassVar[dict[str, list[bytes]]]
    connect_error: ClassVar[Exception | None]
    writes: ClassVar[list[tuple[str, bytes, bool | None]]]

    @classmethod
    def reset(
        cls,
        *,
        services: list[FakeService] | None = None,
        reads: dict[str, bytes] | None = None,
        notifications: dict[str, list[bytes]] | None = None,
        connect_error: Exception | None = None,
    ) -> None:
        cls.service_list = default_services() if services is None else list(services)
        cls.reads = dict(reads or {})
        cls.notifications = dict(notifications or {})
        cls.connect_error = connect_error
        cls.writes = []

    def __init__(self, address_or_ble_device: Any, **kwargs: Any) -> None:
        self.address = str(address_or_ble_device)
        self.connected = False

    async def connect(self, **kwargs: Any) -> None:
        if type(self).connect_error is not None:
            raise type(self).connect_error
        self.connected = True

    async def disconnect(self) -> None:
        self.connected = False

    @property
    def services(self) -> list[FakeService]:
        if not self.connected:
            raise BleakError("Service Discovery has not been performed yet")
        return type(self).service_list

    async def read_gatt_char(self, char: str, **kwargs: Any) -> bytearray:
        if char not in type(self).reads:
            raise BleakCharacteristicNotFoundError(char)
        return bytearray(type(self).reads[char])

    async def write_gatt_char(
        self, char: str, data: bytes, response: bool | None = None
    ) -> None:
        type(self).writes.append((char, bytes(data), response))

    async def start_notify(self, char: str, callback, **kwargs: Any) -> None:
        for value in type(self).notifications.get(char, []):
            callback(char, bytearray(value))

    async def stop_notify(self, char: str) -> None:
        pass


FakeScanner.reset()
FakeClient.reset()
