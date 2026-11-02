"""A fake dual-mode bluetooth gadget for harald's linux rig. It runs inside the vm.

It is a bumble host driving the second virtual controller of bluez's emulator
(`btvirt -l1 -t` serves it over tcp h4 on 127.0.0.1:45550). The same btvirt process
gives the kernel hci0, which bluetoothd and harald use, so the two controllers can
inquire, page, pair, scan and connect each other.

classic, at the controller's public address (00:AA:01:01:00:43 for the first
client of a fresh btvirt), name harald-gadget:
  sdp 0x00010001  vendor 956c7b26-d49a-4ba8-b03f-b17d393cb6e2  rfcomm ch 9
  sdp 0x00010002  spp 0x1101                                    rfcomm ch 3
  sdp 0x00010003  hands-free 0x111e                             rfcomm ch 7
  ch 9 and ch 3 echo each chunk back behind the byte ee, and hang up on de ad.
  ch 3 says hello as soon as it opens. on ch 9, a chunk that starts with 3e
  switches the channel to sony's mdr framing (devices/wh-1000xm5/protocol.md):
  the gadget acks each frame and answers the handshake, the battery read (62%,
  not charging) and the noise control read (noise cancelling on).
  ch 7 only logs that it opened: harald must never open it.
  pairing: ssp, no input no output (just works), bonding; link keys are kept in
  $HARALD_GADGET_KEYS (default /opt/rig/gadget-keys.json).

ble, random static address C0:DE:CA:FE:00:01, same name:
  service 68617261-6c64-4000-8000-000000000000
    ...0001  read             -> b"harald-read"
    ...0002  write, with or without response
    ...0003  notify           -> b"hello" on subscribe, then ee + each write

usage: python gadget.py [transport]   (default tcp-client:127.0.0.1:45550)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from bumble import data_types, rfcomm, sdp
from bumble.core import UUID, AdvertisingData
from bumble.device import Device, DeviceConfiguration
from bumble.gatt import Characteristic, CharacteristicValue, Service
from bumble.hci import Address, OwnAddressType
from bumble.keys import JsonKeyStore
from bumble.pairing import PairingConfig, PairingDelegate
from bumble.transport import open_transport

NAME = "harald-gadget"
LE_ADDRESS = "C0:DE:CA:FE:00:01"
VENDOR_UUID = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"
SPP_UUID16 = 0x1101
HANDS_FREE_UUID16 = 0x111E
VENDOR_CHANNEL = 9
SPP_CHANNEL = 3
HANDS_FREE_CHANNEL = 7
ECHO_PREFIX = b"\xee"
GREETING = b"hello"
HANG_UP = b"\xde\xad"
KEYS_FILE = os.environ.get("HARALD_GADGET_KEYS", "/opt/rig/gadget-keys.json")

GATT_SERVICE = "68617261-6c64-4000-8000-000000000000"
GATT_READ = "68617261-6c64-4000-8000-000000000001"
GATT_WRITE = "68617261-6c64-4000-8000-000000000002"
GATT_NOTIFY = "68617261-6c64-4000-8000-000000000003"

# sony's mdr framing, as much of it as the wh-1000xm5 driver needs
MDR_START, MDR_END, MDR_ESC = 0x3E, 0x3C, 0x3D
MDR_DATA, MDR_ACK = 0x0C, 0x01
MDR_REPLIES = {
    bytes.fromhex("0000"): bytes.fromhex("0100030020160000"),  # handshake
    bytes.fromhex("2200"): bytes([0x23, 0x00, 62, 0x00]),  # battery 62%, an escaped 3e
    bytes.fromhex("6617"): bytes.fromhex("67170101000000"),  # noise cancelling on
}

log = logging.getLogger("gadget")


def rfcomm_record(
    handle: int, channel: int, uuid: UUID, name: str, profile: UUID | None
) -> list[sdp.ServiceAttribute]:
    attrs = rfcomm.make_service_sdp_records(handle, channel, uuid)
    attrs.append(  # LanguageBaseAttributeIDList: en, utf-8, base 0x0100
        sdp.ServiceAttribute(
            sdp.SDP_LANGUAGE_BASE_ATTRIBUTE_ID_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.unsigned_integer_16(0x656E),
                    sdp.DataElement.unsigned_integer_16(0x006A),
                    sdp.DataElement.unsigned_integer_16(0x0100),
                ]
            ),
        )
    )
    attrs.append(  # ServiceName: language base 0x0100 + offset 0
        sdp.ServiceAttribute(0x0100, sdp.DataElement.text_string(name.encode()))
    )
    if profile is not None:
        attrs.append(
            sdp.ServiceAttribute(
                sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                sdp.DataElement.sequence(
                    [
                        sdp.DataElement.sequence(
                            [
                                sdp.DataElement.uuid(profile),
                                sdp.DataElement.unsigned_integer_16(0x0102),
                            ]
                        )
                    ]
                ),
            )
        )
    return attrs


def mdr_frame(data_type: int, seq: int, payload: bytes) -> bytes:
    body = bytes([data_type, seq]) + len(payload).to_bytes(4, "big") + payload
    body += bytes([sum(body) & 0xFF])
    out = bytearray([MDR_START])
    for byte in body:
        if byte in (MDR_START, MDR_END, MDR_ESC):
            out += bytes([MDR_ESC, byte & 0xEF])
        else:
            out.append(byte)
    out.append(MDR_END)
    return bytes(out)


class Mdr:
    """The headphones' side of the mdr framing on one channel: every data frame is
    acked with 1 minus its seq, and the ones in MDR_REPLIES get their answer."""

    def __init__(self, dlc: rfcomm.DLC) -> None:
        self.dlc = dlc
        self.buffer = bytearray()
        self.seq = 0

    def feed(self, data: bytes) -> None:
        self.buffer += data
        while (end := self.buffer.find(MDR_END)) >= 0:
            start = self.buffer.rfind(MDR_START, 0, end)
            raw = bytes(self.buffer[start + 1 : end]) if start >= 0 else b""
            del self.buffer[: end + 1]
            self.on_frame(raw)

    def on_frame(self, raw: bytes) -> None:
        body, escaped = bytearray(), False
        for byte in raw:
            if escaped:
                body.append(byte | 0x10)
                escaped = False
            elif byte == MDR_ESC:
                escaped = True
            else:
                body.append(byte)
        if len(body) < 7 or sum(body[:-1]) & 0xFF != body[-1]:
            log.info("mdr bad frame %s", raw.hex())
            return
        data_type, seq, payload = body[0], body[1], bytes(body[6:-1])
        log.info("mdr rx type %02x seq %d %s", data_type, seq, payload.hex())
        if data_type != MDR_DATA:
            return
        self.dlc.write(mdr_frame(MDR_ACK, 1 - seq, b""))
        reply = MDR_REPLIES.get(payload[:2])
        if reply is not None:
            self.dlc.write(mdr_frame(MDR_DATA, self.seq, reply))
            self.seq ^= 1


def echo_acceptor(channel: int, greeting: bytes = b""):
    def accept(dlc: rfcomm.DLC) -> None:
        peer = dlc.multiplexer.l2cap_channel.connection.peer_address
        log.info("rfcomm ch %d open from %s", channel, peer)
        mdr: Mdr | None = None

        def sink(data: bytes) -> None:
            nonlocal mdr
            log.info("rfcomm ch %d rx %s", channel, data.hex())
            if data == HANG_UP:
                log.info("rfcomm ch %d hanging up", channel)
                asyncio.get_running_loop().create_task(dlc.disconnect())
                return
            if channel == VENDOR_CHANNEL and (mdr or data[:1] == bytes([MDR_START])):
                mdr = mdr or Mdr(dlc)
                mdr.feed(data)
                return
            dlc.write(ECHO_PREFIX + data)

        dlc.sink = sink
        if greeting:
            dlc.write(greeting)

    return accept


def refusing_acceptor(channel: int):
    def accept(dlc: rfcomm.DLC) -> None:
        peer = dlc.multiplexer.l2cap_channel.connection.peer_address
        log.info("rfcomm ch %d open from %s", channel, peer)
        dlc.sink = lambda data: log.info("rfcomm ch %d rx %s", channel, data.hex())

    return accept


async def main(transport: str) -> None:
    async with await open_transport(transport) as (source, sink):
        config = DeviceConfiguration()
        config.name = NAME
        config.address = Address(LE_ADDRESS)
        config.classic_enabled = True
        config.le_enabled = True
        config.class_of_device = 0x240404  # audio / wearable headset
        config.io_capability = PairingDelegate.IoCapability.NO_OUTPUT_NO_INPUT
        config.advertising_data = bytes(
            AdvertisingData(
                [data_types.Flags(0x06), data_types.CompleteLocalName(NAME)]
            )
        )
        config.scan_response_data = bytes(
            AdvertisingData(
                [data_types.CompleteListOf128BitServiceUUIDs([UUID(GATT_SERVICE)])]
            )
        )
        device = Device.from_config_with_hci(config, source, sink)
        # link keys outlive a rig restart, as bluetoothd's bond on hci0 does, so a
        # bond made once keeps working (a forgotten key makes bluez fail with EACCES)
        device.keystore = JsonKeyStore("harald-gadget", KEYS_FILE)
        device.pairing_config_factory = lambda _conn: PairingConfig(
            sc=True,
            mitm=False,
            bonding=True,
            delegate=PairingDelegate(
                io_capability=PairingDelegate.IoCapability.NO_OUTPUT_NO_INPUT
            ),
        )

        # --- sdp + rfcomm ---------------------------------------------------------
        def short(value: int) -> UUID:
            return UUID.from_16_bits(value)

        device.sdp_service_records = {
            0x00010001: rfcomm_record(
                0x00010001, VENDOR_CHANNEL, UUID(VENDOR_UUID), "Serial HPC", None
            ),
            0x00010002: rfcomm_record(
                0x00010002,
                SPP_CHANNEL,
                short(SPP_UUID16),
                "Serial Port",
                short(SPP_UUID16),
            ),
            0x00010003: rfcomm_record(
                0x00010003,
                HANDS_FREE_CHANNEL,
                short(HANDS_FREE_UUID16),
                "Hands-Free unit",
                short(HANDS_FREE_UUID16),
            ),
        }
        server = rfcomm.Server(device)
        acceptors = {
            VENDOR_CHANNEL: echo_acceptor(VENDOR_CHANNEL),
            SPP_CHANNEL: echo_acceptor(SPP_CHANNEL, GREETING),
            HANDS_FREE_CHANNEL: refusing_acceptor(HANDS_FREE_CHANNEL),
        }
        for channel, acceptor in acceptors.items():
            got = server.listen(acceptor, channel)
            assert got == channel, f"rfcomm channel {channel} unavailable"

        # --- gatt -----------------------------------------------------------------
        notify_char = Characteristic(
            GATT_NOTIFY,
            Characteristic.Properties.NOTIFY | Characteristic.Properties.READ,
            Characteristic.READABLE,
            b"",
        )

        def on_write(connection, value: bytes) -> None:
            log.info("gatt write %s", bytes(value).hex())
            asyncio.get_running_loop().create_task(
                device.notify_subscribers(notify_char, ECHO_PREFIX + bytes(value))
            )

        read_char = Characteristic(
            GATT_READ,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            b"harald-read",
        )
        write_char = Characteristic(
            GATT_WRITE,
            Characteristic.Properties.WRITE
            | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
            Characteristic.WRITEABLE,
            CharacteristicValue(write=on_write),
        )
        device.add_service(Service(GATT_SERVICE, [read_char, write_char, notify_char]))

        def on_subscription(bearer, notify_enabled, indicate_enabled) -> None:
            log.info("notify subscription %s %s", notify_enabled, indicate_enabled)
            if notify_enabled:
                asyncio.get_running_loop().create_task(
                    device.notify_subscribers(notify_char, GREETING)
                )

        notify_char.on("subscription", on_subscription)

        def on_connection(connection) -> None:
            log.info(
                "connection %s from %s", connection.transport, connection.peer_address
            )
            connection.on("disconnection", lambda why: log.info("disconnected %s", why))
            connection.on(
                "pairing", lambda keys: log.info("paired %s", connection.peer_address)
            )
            connection.on(
                "pairing_failure", lambda why: log.info("pairing failed %s", why)
            )

        device.on("connection", on_connection)

        await device.power_on()
        await device.set_discoverable(True)
        await device.set_connectable(True)
        await device.start_advertising(
            own_address_type=OwnAddressType.RANDOM, auto_restart=True
        )
        print(
            f"READY classic={device.public_address.to_string(False)} "
            f"le={device.random_address.to_string(False)} name={NAME}",
            flush=True,
        )
        await asyncio.get_running_loop().create_future()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )
    logging.getLogger("bumble").setLevel(logging.WARNING)
    asyncio.run(
        main(sys.argv[1] if len(sys.argv) > 1 else "tcp-client:127.0.0.1:45550")
    )
