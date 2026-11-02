"""Bluetooth classic facts from a real Sony WH-1000XM5, so no test needs headphones.

XM5_RECORDS are the headphones' rfcomm service records as the mac caches them
(design §2). Channel 2 carries two records, one per service class. Uuids are full
lowercase 128-bit strings; 16-bit classes are expanded onto the bluetooth base uuid.

FakeBackend and FakeChannel stand in for `classic.Backend` and `classic.Channel`, so
no test needs a radio or the mac backend.
"""

from __future__ import annotations

import threading
import time

from harald.classic import BackendError, ClassicDevice, ServiceRecord

XM5_ADDRESS = "aa:bb:cc:11:22:33"

XM5_RECORDS = [
    ServiceRecord("Hands-Free unit", ["0000111e-0000-1000-8000-00805f9b34fb"], 1),
    ServiceRecord("Headset", ["00001203-0000-1000-8000-00805f9b34fb"], 2),
    ServiceRecord("Headset", ["00001108-0000-1000-8000-00805f9b34fb"], 2),
    ServiceRecord("Serial HPC", ["956c7b26-d49a-4ba8-b03f-b17d393cb6e2"], 9),
    ServiceRecord("Serial MC", ["764cbf0d-bbcb-438f-a8bb-6b92759d6053"], 11),
    ServiceRecord("BT_SAR_AP", ["f76acb00-7cab-495f-bb1a-e664598fd77f"], 12),
    ServiceRecord("BT_SAR_SE", ["45c93e07-d90d-4b93-a9db-91e5dd734e35"], 13),
    ServiceRecord(None, ["f8d1fbe4-7966-4334-8024-ff96c9330e15"], 19),
    ServiceRecord("GSOUND_BT_AUDIO", ["81c2e72a-0591-443e-a1ff-05f988593351"], 20),
    ServiceRecord("Airoha_APP", ["8901dfa8-5c7e-4d8f-9f0c-c2b70683f5f0"], 21),
    ServiceRecord(None, ["931c7e8a-540f-4686-b798-e8df0a2ad9f7"], 22),
    ServiceRecord("BTFASTPAIR", ["df21fe2c-2515-4fdb-8886-f12c4d67927c"], 23),
    ServiceRecord("BTSPOTIFY", ["9b26d8c0-a8ed-440b-95b0-c4714a518bcc"], 25),
    ServiceRecord(None, ["f7a96061-a1b3-40de-aff0-e78ec45a151e"], 26),
    ServiceRecord(None, ["2573f2dd-a2f8-486c-8476-a63734909acb"], 27),
    ServiceRecord("Airoha_IAP2", ["00000000-deca-fade-deca-deafdecacaff"], 30),
]


class FakeChannel:
    """An open rfcomm channel. `drain` returns what is queued at once, never sleeping,
    each chunk stamped with a fake `time.monotonic()` later than the one before.

    With the backend's `slow_drain`, a drain of more than 0 s blocks until `close` is
    called from another thread, as `classic.Channel` requires a real one to allow.
    """

    def __init__(self, backend: FakeBackend, queued: list[bytes]) -> None:
        self.backend = backend
        self.queued = list(queued)
        self.closed = False
        self.drains: list[float] = []
        self.drain_returned = threading.Event()
        self._closing = threading.Event()
        self._clock = time.monotonic()

    def write(self, data: bytes) -> None:
        backend = self.backend
        backend.writes.append(data)
        if backend.write_error_at == len(backend.writes):
            raise backend.write_error or BackendError("failed", "fake write error")
        self.queued.extend(backend.replies.get(data, []))

    def drain(self, seconds: float) -> list[tuple[float, bytes]]:
        backend = self.backend
        self.drains.append(seconds)
        if backend.drain_error_at == len(self.drains):
            raise backend.drain_error or BackendError("failed", "fake drain error")
        if backend.slow_drain and seconds:
            self._closing.wait(5)
        received = []
        for data in self.queued:
            self._clock = max(self._clock, time.monotonic()) + 0.01
            received.append((self._clock, data))
        self.queued.clear()
        self.drain_returned.set()
        return received

    def close(self) -> None:
        self.closed = True
        self._closing.set()
        if self.backend.close_error is not None:
            raise self.backend.close_error


class FakeBackend:
    """Configure in the constructor; inspect `asked`, `opened`, `writes` and `channels`
    afterwards. `replies` maps a written message to the chunks the device answers with;
    `on_open` chunks are waiting as soon as the channel opens. `write_error_at` and
    `drain_error_at` count calls from 1 (the drain right after the open is drain 1).
    `open_gate` holds `open` until it is set, so a test can cancel mid-open."""

    def __init__(
        self,
        *,
        devices: list[ClassicDevice] | None = None,
        records: list[ServiceRecord] | None = None,
        on_open: list[bytes] | None = None,
        replies: dict[bytes, list[bytes]] | None = None,
        open_error: BackendError | None = None,
        write_error_at: int | None = None,
        write_error: BackendError | None = None,
        drain_error_at: int | None = None,
        drain_error: BackendError | None = None,
        slow_drain: bool = False,
        close_error: Exception | None = None,
        open_gate: threading.Event | None = None,
    ) -> None:
        self.devices = list(devices or [])
        self.service_records = list(XM5_RECORDS if records is None else records)
        self.on_open = list(on_open or [])
        self.replies = dict(replies or {})
        self.open_error = open_error
        self.write_error_at = write_error_at
        self.write_error = write_error
        self.drain_error_at = drain_error_at
        self.drain_error = drain_error
        self.slow_drain = slow_drain
        self.close_error = close_error
        self.open_gate = open_gate
        self.asked: list[tuple[str, bool]] = []
        self.opened: list[tuple[str, int]] = []
        self.writes: list[bytes] = []
        self.channels: list[FakeChannel] = []

    @property
    def channel(self) -> FakeChannel:
        return self.channels[-1]

    def paired(self) -> list[ClassicDevice]:
        return list(self.devices)

    def records(self, address: str, refresh: bool) -> list[ServiceRecord]:
        self.asked.append((address, refresh))
        return list(self.service_records)

    def open(self, address: str, channel: int) -> FakeChannel:
        self.opened.append((address, channel))
        if self.open_gate is not None:
            self.open_gate.wait(5)
        if self.open_error is not None:
            raise self.open_error
        self.channels.append(FakeChannel(self, self.on_open))
        return self.channel
