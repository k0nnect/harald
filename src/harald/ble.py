"""Thin bleak wrapper: scan, connect, list services, read, subscribe and gated writes.

The bleak classes are injectable (`scanner_cls`, `client_cls`) so tests and front ends
can swap in fakes. Every write spends the human's arm budget before it reaches the
device, keyed by the characteristic's real parent service.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from bleak import BleakClient, BleakScanner
from bleak.exc import (
    BleakBluetoothNotAvailableError,
    BleakDeviceNotFoundError,
    BleakError,
)
from bleak.uuids import normalize_uuid_str

from harald.arm import consume_write
from harald.errors import BluetoothUnavailable, DeviceNotFound, HaraldError

BLUETOOTH_HINT = (
    "turn bluetooth on and allow your terminal app in "
    "system settings > privacy & security > bluetooth"
)
NOT_FOUND_HINT = (
    "move closer, close the vendor app on your phone "
    "(gadgets accept one connection), then run harald scan"
)
_UNAVAILABLE_WORDS = ("turned off", "not authorized", "unauthorized")


@dataclass
class DeviceInfo:
    address: str
    name: str | None
    rssi: int
    service_uuids: list[str]
    manufacturer_data: dict[int, str]  # company id -> payload hex


@dataclass
class CharInfo:
    uuid: str
    handle: int
    properties: list[str]


@dataclass
class ServiceInfo:
    uuid: str
    chars: list[CharInfo]


async def scan(timeout: float = 5.0, *, scanner_cls=BleakScanner) -> list[DeviceInfo]:
    """Scan for `timeout` seconds; return what was seen, strongest signal first."""
    try:
        found = await scanner_cls.discover(timeout=timeout, return_adv=True)
    except (BleakError, TimeoutError) as exc:
        friendly = _friendly_error(exc, None)
        if friendly is None:
            raise
        raise friendly from exc
    devices = [
        DeviceInfo(
            address=device.address,
            name=adv.local_name or device.name,
            rssi=adv.rssi,
            service_uuids=[uuid.lower() for uuid in adv.service_uuids],
            manufacturer_data={
                cid: data.hex() for cid, data in adv.manufacturer_data.items()
            },
        )
        for device, adv in found.values()
    ]
    return sorted(devices, key=lambda d: d.rssi, reverse=True)


class Session:
    """One connection to one device."""

    def __init__(self, address: str, *, client_cls=BleakClient) -> None:
        self.address = address
        self._client = client_cls(address)

    async def connect(self) -> None:
        try:
            await self._client.connect()
        except (BleakError, TimeoutError) as exc:
            friendly = _friendly_error(exc, self.address)
            if friendly is None:
                raise
            raise friendly from exc

    async def services(self) -> list[ServiceInfo]:
        return [
            ServiceInfo(
                uuid=service.uuid.lower(),
                chars=[
                    CharInfo(
                        uuid=char.uuid.lower(),
                        handle=char.handle,
                        properties=list(char.properties),
                    )
                    for char in service.characteristics
                ],
            )
            for service in self._client.services
        ]

    async def read(self, char_uuid: str) -> bytes:
        return bytes(await self._client.read_gatt_char(normalize_uuid_str(char_uuid)))

    async def write(
        self, char_uuid: str, data: bytes, response: bool | None = None
    ) -> int:
        """Spend one armed write, then write. Returns the writes left in the budget.

        `response` None writes without response when the characteristic's properties
        include write-without-response, and with response otherwise.
        """
        char_uuid = normalize_uuid_str(char_uuid)
        service_uuid, char = await self._locate(char_uuid)
        grant = consume_write(self.address, service_uuid, char_uuid)
        if response is None:
            response = "write-without-response" not in char.properties
        await self._client.write_gatt_char(char_uuid, data, response=response)
        return grant.writes_left

    async def subscribe(
        self, char_uuid: str, seconds: float
    ) -> list[tuple[float, bytes]]:
        """Collect notifications for `seconds`, as (seconds since start, value) pairs."""
        char_uuid = normalize_uuid_str(char_uuid)
        events: list[tuple[float, bytes]] = []
        start = time.monotonic()

        def on_notify(_char, data: bytearray) -> None:
            events.append((time.monotonic() - start, bytes(data)))

        await self._client.start_notify(char_uuid, on_notify)
        try:
            await asyncio.sleep(seconds)
        finally:
            await self._client.stop_notify(char_uuid)
        return events

    async def close(self) -> None:
        await self._client.disconnect()

    async def _locate(self, char_uuid: str) -> tuple[str, CharInfo]:
        """The uuid of the one service holding `char_uuid`, and the characteristic.

        Fails closed when no service or more than one holds it.
        """
        try:
            services = await self.services()
        except BleakError:  # not connected, so no services discovered
            services = []
        owners = [(s.uuid, c) for s in services for c in s.chars if c.uuid == char_uuid]
        if len(owners) == 1:
            return owners[0]
        if owners:
            message = f"characteristic {char_uuid} is in more than one service on {self.address}"
        else:
            message = f"characteristic {char_uuid} not found on {self.address}"
        raise HaraldError(
            message,
            hint="connect to the device and list its services, "
            "then use a characteristic uuid from that list",
        )


def _friendly_error(exc: Exception, address: str | None) -> HaraldError | None:
    """Map a bleak or timeout error to a harald error with a hint, or None if unknown."""
    text = str(exc).lower()
    if isinstance(exc, BleakBluetoothNotAvailableError) or any(
        word in text for word in _UNAVAILABLE_WORDS
    ):
        return BluetoothUnavailable(
            "bluetooth is off or not allowed for this app", hint=BLUETOOTH_HINT
        )
    if isinstance(exc, (BleakDeviceNotFoundError, TimeoutError)):
        message = f"device {address} not found" if address else "no device found"
        return DeviceNotFound(message, hint=NOT_FOUND_HINT)
    return None
