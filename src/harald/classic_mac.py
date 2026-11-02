"""The mac's bluetooth classic backend: rfcomm through IOBluetooth, via pyobjc.

IOBluetooth calls back (open complete, data, write complete, closed, sdp complete)
only on the main thread's run loop, so every IOBluetooth call is made there too.
`run_main` runs the program (asyncio and all) on a background thread while the main
thread pumps its run loop in 10 ms slices and runs the work queued to it.

`MacBackend` and `MacChannel` are called from executor threads. Each call queues its
IOBluetooth work to the main thread (`on_main_thread`), then waits for the delegate
on its own thread, so the main thread keeps pumping. Called on the main thread with
no `run_main` (a plain script), the work runs inline and the wait pumps the run loop
itself. Called off the main thread with no `run_main`, it fails at once rather than
hang.

pyobjc is imported here only, and harald imports this module only for the backend,
so it loads without pyobjc: `uuid_text`, `open_failure` and `service_record` still
work, and `run_main` just calls its function.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import functools
import queue
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

from harald.arm import normalize_uuid
from harald.classic import BackendError, ClassicDevice, ServiceRecord, normalize_address
from harald.errors import HaraldError

try:  # a mac-only dependency
    import objc
    from Foundation import NSDate, NSDefaultRunLoopMode, NSObject, NSRunLoop
    from IOBluetooth import IOBluetoothDevice
except ImportError:
    objc = None

T = TypeVar("T")

SLICE = 0.01  # one run-loop slice, seconds
CALL_TIMEOUT = 15.0  # for work queued to the main thread; a page alone takes ~5 s
PAGE_TIMEOUT = 8000  # baseband slots of 0.625 ms: about 5 s
SDP_WAIT = 10.0
OPEN_WAIT = 5.0
WRITE_WAIT = 3.0
CLOSE_WAIT = 1.0

# IOReturn values (IOKit/IOReturn.h)
_ERROR = 0xE00002BC
_BUSY = 0xE00002D5
_TIMEOUT = 0xE00002D6

_NEEDS_RUN_LOOP = "bluetooth classic needs harald's main-thread run loop"

# Every delegate callback changes state under this, then wakes every waiter; close
# and run_main's end wake them too.
_changed = threading.Condition()

# IOBluetooth does not retain its delegates, and a late callback into a freed one
# would crash the process, so delegates (and their channels) live until exit.
_KEEP_ALIVE: list[Any] = []


def uuid_text(raw: bytes) -> str:
    """A 2-, 4- or 16-byte uuid as a lowercase 128-bit string."""
    raw = bytes(raw)
    if len(raw) in (2, 4):
        return normalize_uuid(raw.hex())
    if len(raw) == 16:
        return str(uuid.UUID(bytes=raw))
    raise ValueError(f"a uuid is 2, 4 or 16 bytes, not {len(raw)}")


def open_failure(status: int, connected: bool) -> str:
    """The BackendError code for an rfcomm open that failed with IOReturn `status`.

    pyobjc hands IOReturn over signed (0xe00002bc arrives as -0x1ffffd44), so the
    status is masked to 32 bits first.
    """
    status &= 0xFFFFFFFF
    if status == _ERROR and connected:
        return "stuck"
    if status == _BUSY:
        return "busy"
    if status == _TIMEOUT:
        return "stuck" if connected else "not_connected"
    return "failed" if connected else "not_connected"


def service_record(record: Any) -> ServiceRecord:
    """A ServiceRecord from an IOBluetoothSDPServiceRecord."""
    status, channel = record.getRFCOMMChannelID_(None)
    name = record.getServiceName()
    classes = (record.attributes() or {}).get(1)  # ServiceClassIDList
    return ServiceRecord(
        name=str(name) if name else None,
        uuids=[] if classes is None else _uuids(classes),
        channel=int(channel) if status == 0 else None,
    )


def _uuids(element: Any) -> list[str]:
    """The uuids in an sdp data element, walking into sequences."""
    kind = element.getTypeDescriptor()
    if kind == 3:  # uuid
        value = element.getUUIDValue()
        full = value.getUUIDWithLength_(16) or value
        try:
            return [uuid_text(bytes(full))]
        except ValueError:
            return []
    if kind in (6, 7):  # sequence, alternative
        return [u for child in element.getArrayValue() or [] for u in _uuids(child)]
    return []


def _hex(status: int) -> str:
    return f"{status & 0xFFFFFFFF:#x}"


# --- the main thread ----------------------------------------------------------


class _Pump:
    """Work queued for the main thread, run while `run_main` pumps its run loop."""

    def __init__(self) -> None:
        self.jobs: queue.SimpleQueue[tuple[concurrent.futures.Future, Callable]] = (
            queue.SimpleQueue()
        )
        self.lock = threading.Lock()
        self.serving = False

    def submit(self, fn: Callable[[], T]) -> concurrent.futures.Future[T]:
        future: concurrent.futures.Future[T] = concurrent.futures.Future()
        with self.lock:
            if not self.serving:
                raise BackendError("failed", _NEEDS_RUN_LOOP)
            self.jobs.put((future, fn))
        return future

    def start(self) -> None:
        with self.lock:
            self.serving = True

    def stop(self) -> None:
        """Stop taking work, cancel what is queued, and wake every waiter."""
        with self.lock:
            self.serving = False
        while True:
            try:
                future, _ = self.jobs.get_nowait()
            except queue.Empty:
                break
            # a bare cancel() doesn't wake concurrent.futures.wait; this does
            future.cancel()
            future.set_running_or_notify_cancel()
        with _changed:
            _changed.notify_all()

    def run_jobs(self, wait: float = 0.0) -> None:
        """Run every queued job; with `wait`, wait that long for the first."""
        try:
            job = self.jobs.get(timeout=wait) if wait else self.jobs.get_nowait()
        except queue.Empty:
            return
        while True:
            future, fn = job
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(fn())
                except BaseException as exc:
                    if isinstance(exc, Exception):
                        future.set_exception(exc)
                    else:  # ctrl-c: free the caller, then stop
                        future.set_exception(BackendError("failed", "interrupted"))
                        raise
            try:
                job = self.jobs.get_nowait()
            except queue.Empty:
                return


_pump = _Pump()


def _on_main() -> bool:
    return threading.current_thread() is threading.main_thread()


def _spin(done: Callable[[], bool], deadline: float | None) -> bool:
    """On the main thread: pump the run loop and run queued work until done() or
    the deadline. Returns done()."""
    loop = NSRunLoop.currentRunLoop()
    while not done():
        if deadline is not None and time.monotonic() >= deadline:
            return False
        with objc.autorelease_pool():
            _pump.run_jobs()
            ran = loop.runMode_beforeDate_(
                NSDefaultRunLoopMode, NSDate.dateWithTimeIntervalSinceNow_(SLICE)
            )
            if not ran:
                # nothing is attached to the run loop yet, so it returned at once;
                # wait out the slice on the job queue instead of spinning
                _pump.run_jobs(SLICE)
    return True


def run_main(fn: Callable[[], T]) -> T:
    """Run `fn` on a background thread while the main thread pumps its run loop and
    runs the IOBluetooth work queued to it; return what fn returns, or raise what it
    raises.

    harald's entry points wrap their asyncio program in it, as in
    `run_main(lambda: asyncio.run(main()))`. Without pyobjc, off the main thread, or
    inside another run_main, it just calls fn.
    """
    if objc is None or not _on_main() or _pump.serving:
        return fn()
    outcome: list[tuple[Any, BaseException | None]] = []

    def side() -> None:
        try:
            outcome.append((fn(), None))
        # anything fn raises, SystemExit included, is raised on the main thread
        except BaseException as exc:  # noqa: BLE001
            outcome.append((None, exc))

    _pump.start()
    try:
        threading.Thread(target=side, name="harald-run", daemon=True).start()
        _spin(lambda: bool(outcome), None)
    finally:
        _pump.stop()
    result, error = outcome[0]
    if error is not None:
        raise error
    return result


def on_main_thread(
    fn: Callable[[], T],
    timeout: float | None = None,
    abandon: Callable[[T], object] | None = None,
) -> T:
    """Run fn on the main thread and return its result (inline if this is it).

    Off the main thread this needs `run_main` pumping; without it, BackendError.
    Waiting longer than `timeout` (CALL_TIMEOUT by default) raises BackendError
    ("timeout"). If fn is running by then it can't be stopped, so `abandon` gets
    what it returns: `open` passes one that closes the channel nobody will take.
    """
    if _on_main():
        return fn()
    timeout = CALL_TIMEOUT if timeout is None else timeout
    future = _pump.submit(fn)
    concurrent.futures.wait([future], timeout)
    if not future.done() and future.cancel():  # it never started
        raise BackendError("timeout", f"the main thread was busy for {timeout:g} s")
    if not future.done():
        if abandon is not None:
            future.add_done_callback(functools.partial(_abandoned, abandon))
        raise BackendError(
            "timeout", f"the main thread did not answer in {timeout:g} s"
        )
    try:
        return future.result()  # it finished, even if only as the wait gave up
    except concurrent.futures.CancelledError:  # run_main ended before running it
        raise BackendError("failed", _NEEDS_RUN_LOOP) from None


def _abandoned(
    abandon: Callable[[Any], object], future: concurrent.futures.Future
) -> None:
    """Hand what a job returned after its caller stopped waiting to `abandon`."""
    if future.cancelled() or future.exception() is not None:
        return
    with contextlib.suppress(Exception):
        abandon(future.result())


def _wait_until(done: Callable[[], bool], seconds: float) -> bool:
    """Wait up to `seconds` for done(), which a delegate callback (or a close) makes
    true. On the main thread this pumps the run loop, where callbacks arrive; off it,
    it sleeps until woken, and gives up early if run_main stops. Returns done()."""
    if _on_main():
        return _spin(done, time.monotonic() + seconds)
    with _changed:
        _changed.wait_for(lambda: done() or not _pump.serving, seconds)
        return done()


# --- IOBluetooth --------------------------------------------------------------

if objc is not None:

    class HaraldRFCOMMDelegate(NSObject):
        """Records IOBluetooth's callbacks for one rfcomm channel or sdp query.

        Callbacks run on the main thread. Each only stores what it is given, under
        `_changed`, and wakes the waiters: a python error must never unwind into
        IOBluetooth.
        """

        def init(self):
            this = objc.super(HaraldRFCOMMDelegate, self).init()
            if this is None:
                return None
            this.open_status = None
            this.given_up = False  # harald stopped waiting for the open
            this.writes_done = 0
            this.write_status = 0
            this.closed = False
            this.sdp_status = None
            this.received = []  # (time.monotonic() at arrival, data)
            return this

        def rfcommChannelOpenComplete_status_(self, channel, status):
            with _changed:
                self.open_status = status
                late = self.given_up and status == 0
                _changed.notify_all()
            if late:
                # an open harald gave up on (and closed) completed anyway, which
                # leaves the channel open: close it again, here on the main thread
                with contextlib.suppress(Exception):
                    channel.closeChannel()

        def rfcommChannelData_data_length_(self, channel, data, length):
            at = time.monotonic()
            try:
                chunk = bytes(data[:length])
            except (TypeError, ValueError):  # no data pointer: nothing to keep
                return
            with _changed:
                self.received.append((at, chunk))
                _changed.notify_all()

        def rfcommChannelWriteComplete_refcon_status_(self, channel, refcon, status):
            with _changed:
                self.write_status = status
                self.writes_done += 1
                _changed.notify_all()

        def rfcommChannelClosed_(self, channel):
            with _changed:
                self.closed = True
                _changed.notify_all()

        def sdpQueryComplete_status_(self, device, status):
            with _changed:
                self.sdp_status = status
                _changed.notify_all()

        @objc.python_method
        def take(self) -> list[tuple[float, bytes]]:
            """Everything received since the last take."""
            with _changed:
                received, self.received = self.received, []
            return received


def _new_delegate() -> Any:
    delegate = HaraldRFCOMMDelegate.alloc().init()
    _KEEP_ALIVE.append(delegate)
    return delegate


def _paired_device(address: str) -> Any:
    device = IOBluetoothDevice.deviceWithAddressString_(address.replace(":", "-"))
    if device is None or not device.isPaired():
        raise BackendError("not_paired", address)
    return device


def _paired() -> list[ClassicDevice]:
    devices = IOBluetoothDevice.pairedDevices()
    if devices is None:
        raise BackendError("bluetooth_off")
    found = []
    for device in devices:
        try:
            address = normalize_address(str(device.addressString() or ""))
        except HaraldError:
            continue  # no usable address, so nothing harald could open
        name = device.name()
        found.append(
            ClassicDevice(
                address, str(name) if name else None, bool(device.isConnected())
            )
        )
    return found


class MacBackend:
    """`classic.Backend` over IOBluetooth. Constructing it starts nothing."""

    def __init__(self) -> None:
        if objc is None:
            raise BackendError("unsupported", "pyobjc-framework-IOBluetooth is missing")

    def paired(self) -> list[ClassicDevice]:
        return on_main_thread(_paired)

    def records(self, address: str, refresh: bool) -> list[ServiceRecord]:
        """The device's cached sdp records; with `refresh`, or none cached, it asks
        the device first."""

        def cached() -> tuple[Any, list[ServiceRecord] | None, Any]:
            device = _paired_device(address)
            services = device.services()
            if services and not refresh:
                return device, [service_record(r) for r in services], None
            delegate = _new_delegate()
            status = device.performSDPQuery_(delegate)
            if status != 0:
                code = "failed" if device.isConnected() else "not_connected"
                raise BackendError(code, f"sdp query status {_hex(status)}")
            return device, None, delegate

        device, records, delegate = on_main_thread(cached)
        if records is not None:
            return records
        if not _wait_until(lambda: delegate.sdp_status is not None, SDP_WAIT):
            raise BackendError("timeout", f"no sdp answer in {SDP_WAIT:.0f} s")
        if delegate.sdp_status != 0:
            code = "failed" if _still_connected(device) else "not_connected"
            raise BackendError(code, f"sdp query status {_hex(delegate.sdp_status)}")
        return on_main_thread(
            lambda: [service_record(r) for r in device.services() or []]
        )

    def open(self, address: str, channel: int) -> MacChannel:
        """Open rfcomm `channel` on `address`, paging the device first if the link
        is down."""

        def start() -> tuple[Any, Any, Any]:
            device = _paired_device(address)
            if not device.isConnected():
                status = device.openConnection_withPageTimeout_authenticationRequired_(
                    None, PAGE_TIMEOUT, False
                )
                if status != 0 or not device.isConnected():
                    raise BackendError("not_connected", f"page status {_hex(status)}")
            delegate = _new_delegate()
            status, rfcomm = device.openRFCOMMChannelAsync_withChannelID_delegate_(
                None, channel, delegate
            )
            if rfcomm is not None:
                _KEEP_ALIVE.append(rfcomm)
            if status != 0:
                if rfcomm is not None:
                    _close_quietly(rfcomm)
                code = open_failure(status, _still_connected(device))
                raise BackendError(code, f"open status {_hex(status)}")
            return device, rfcomm, delegate

        # A channel nobody takes stays open, and the mac then refuses every later
        # open until bluetooth is toggled, so each path that does not return it
        # closes it: a caller that gave up on `start`, a failed follow-up call, a
        # failed or unfinished open. An unfinished open can still complete later
        # (fatal in `harald mcp`, which lives on), so the delegate closes it then.
        device, rfcomm, delegate = on_main_thread(
            start, abandon=lambda opened: _give_up(opened[1], opened[2])
        )
        try:
            finished = _wait_until(lambda: delegate.open_status is not None, OPEN_WAIT)
            status = delegate.open_status
            if finished and status == 0:
                mtu = int(on_main_thread(rfcomm.getMTU))
                return MacChannel(rfcomm, delegate, mtu=mtu)
        except BaseException:
            _give_up(rfcomm, delegate)
            raise
        _give_up(rfcomm, delegate)  # first, then ask about the link
        connected = _still_connected(device)
        if not finished:
            # the stuck-mac signature: the link is up and the open never completes
            code = "stuck" if connected else "not_connected"
            raise BackendError(code, f"channel {channel} never finished opening")
        code = open_failure(status, connected)
        raise BackendError(code, f"open complete status {_hex(status)}")


def _give_up(rfcomm: Any, delegate: Any) -> None:
    """Close a channel harald won't use. Its delegate is marked first, so an open
    that still completes later is closed by the open-complete callback."""
    with _changed:
        delegate.given_up = True
    _close_quietly(rfcomm)


def _close_quietly(rfcomm: Any) -> None:
    """Close a channel nobody will use; if that fails there is nothing more to do."""
    with contextlib.suppress(Exception):
        on_main_thread(rfcomm.closeChannel)


def _still_connected(device: Any) -> bool:
    """Whether the link is up. If even that can't be asked (run_main stopping, say),
    yes, so the code still comes from the failure being reported."""
    try:
        return bool(on_main_thread(device.isConnected))
    except BackendError:
        return True


class MacChannel:
    """`classic.Channel` over an open IOBluetoothRFCOMMChannel."""

    def __init__(self, rfcomm: Any, delegate: Any, mtu: int) -> None:
        self._rfcomm = rfcomm
        self._delegate = delegate
        self._mtu = mtu
        self._closing = False

    def write(self, data: bytes) -> None:
        """Write `data` in mtu-sized pieces, each waiting for its write-complete."""
        size = self._mtu if self._mtu > 0 else max(len(data), 1)
        for start in range(0, len(data), size):
            self._write(bytes(data[start : start + size]))

    def _write(self, piece: bytes) -> None:
        rfcomm, delegate = self._rfcomm, self._delegate
        if self._closing or delegate.closed:
            raise BackendError("failed", "the channel is closed")
        before = delegate.writes_done
        status = on_main_thread(
            lambda: rfcomm.writeAsync_length_refcon_(piece, len(piece), None)
        )
        if status != 0:
            raise BackendError("failed", f"write status {_hex(status)}")
        _wait_until(
            lambda: delegate.writes_done > before or delegate.closed or self._closing,
            WRITE_WAIT,
        )
        if delegate.writes_done > before:
            if delegate.write_status != 0:
                raise BackendError(
                    "failed", f"write status {_hex(delegate.write_status)}"
                )
        elif delegate.closed or self._closing:
            raise BackendError("failed", "the channel closed")
        else:
            raise BackendError("timeout", f"no write-complete in {WRITE_WAIT:.0f} s")

    def drain(self, seconds: float) -> list[tuple[float, bytes]]:
        """Wait `seconds` (less if closed meanwhile), then return what arrived."""
        if seconds > 0:
            _wait_until(lambda: self._closing, seconds)
        return self._delegate.take()

    def close(self) -> None:
        """Close the channel, waking any blocked write or drain. Never raises."""
        with _changed:
            already, self._closing = self._closing, True
            _changed.notify_all()
        if already:
            return
        rfcomm, delegate = self._rfcomm, self._delegate
        with contextlib.suppress(Exception):
            on_main_thread(rfcomm.closeChannel)
            _wait_until(lambda: delegate.closed, CLOSE_WAIT)
