"""The mac backend's pure parts, plus darwin-only checks that never touch a device.

Nothing here opens, pages or lists a bluetooth device: the IOBluetooth objects a
real run would hand the backend are stood in for by small fakes.
"""

import concurrent.futures
import subprocess
import sys
import threading
import time

import pytest

from harald.classic import BackendError, ClassicDevice, ServiceRecord
from harald.classic_mac import open_failure, service_record, uuid_text

SPP = "00001101-0000-1000-8000-00805f9b34fb"
HPC = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"


def test_uuid_text_expands_short_uuids_onto_the_base_uuid():
    assert uuid_text(bytes.fromhex("1101")) == SPP
    assert uuid_text(bytes.fromhex("00001101")) == SPP
    assert uuid_text(bytes.fromhex("12345678")) == "12345678" + SPP[8:]


def test_uuid_text_keeps_a_full_uuid():
    assert uuid_text(bytes.fromhex(HPC.replace("-", ""))) == HPC


def test_uuid_text_refuses_other_lengths():
    with pytest.raises(ValueError):
        uuid_text(b"\x11\x01\x00")


def test_open_failure_codes():
    # pyobjc hands IOReturn over signed: -0x1ffffd44 is 0xe00002bc (error)
    assert open_failure(-0x1FFFFD44, True) == "stuck"
    assert open_failure(0xE00002BC, True) == "stuck"
    assert open_failure(0xE00002D5, True) == "busy"
    assert open_failure(0xE00002D5, False) == "busy"
    assert open_failure(0xE00002D6, True) == "stuck"
    assert open_failure(0xE00002D6, False) == "not_connected"
    assert open_failure(0xE00002BC, False) == "not_connected"
    assert open_failure(0xE00002C2, False) == "not_connected"
    assert open_failure(0xE00002C2, True) == "failed"


class Element:
    """An IOBluetoothSDPDataElement: type 3 is a uuid, 6 and 7 are sequences."""

    def __init__(self, kind, value):
        self.kind, self.value = kind, value

    def getTypeDescriptor(self):
        return self.kind

    def getUUIDValue(self):
        return Uuid(self.value)

    def getArrayValue(self):
        return self.value


class Uuid:
    """An IOBluetoothSDPUUID: bytes, widened to 16 by getUUIDWithLength_."""

    def __init__(self, raw):
        self.raw = raw

    def getUUIDWithLength_(self, length):
        assert length == 16
        if len(self.raw) == 16:
            return self
        if len(self.raw) not in (2, 4):
            return None
        return Uuid(bytes.fromhex(uuid_text(self.raw).replace("-", "")))

    def __bytes__(self):
        return self.raw


class Record:
    """An IOBluetoothSDPServiceRecord."""

    def __init__(self, name, classes, channel):
        self.name, self.classes, self.channel = name, classes, channel

    def getServiceName(self):
        return self.name

    def attributes(self):
        return {} if self.classes is None else {1: self.classes}

    def getRFCOMMChannelID_(self, out):
        assert out is None
        return (0, self.channel) if self.channel else (-0x1FFFFD3E, 0)


def test_service_record_walks_the_service_class_list():
    classes = Element(
        6,
        [
            Element(3, bytes.fromhex(HPC.replace("-", ""))),
            Element(7, [Element(3, bytes.fromhex("1101")), Element(1, 5)]),
            Element(8, "a string, not a uuid"),
        ],
    )
    record = service_record(Record("Serial HPC", classes, 9))
    assert record == ServiceRecord("Serial HPC", [HPC, SPP], 9)


def test_service_record_without_classes_or_rfcomm():
    assert service_record(Record(None, None, 0)) == ServiceRecord(None, [], None)


def test_service_record_skips_a_malformed_uuid():
    classes = Element(6, [Element(3, b"\x11\x01\x00"), Element(3, b"\x11\x01")])
    assert service_record(Record("x", classes, 3)).uuids == [SPP]


# --- darwin only: real pyobjc, still no device ------------------------------


@pytest.fixture
def mac():
    pytest.importorskip("IOBluetooth")
    from harald import classic_mac

    return classic_mac


def test_service_record_reads_real_sdp_data_elements(mac):
    # pure data objects: building them involves no device or radio
    from Foundation import NSData
    from IOBluetooth import IOBluetoothSDPDataElement, IOBluetoothSDPUUID

    def element(value):
        return IOBluetoothSDPDataElement.withElementValue_(value)

    hpc = bytes.fromhex(HPC.replace("-", ""))
    classes = element(
        [
            element(IOBluetoothSDPUUID.uuidWithBytes_length_(hpc, 16)),
            element(IOBluetoothSDPUUID.uuid16_(0x1101)),
            element(NSData.dataWithBytes_length_(b"\x01", 1)),
        ]
    )
    assert classes.getTypeDescriptor() == 6
    record = service_record(Record("Serial HPC", classes, 9))
    assert record.uuids == [HPC, SPP]


def test_mac_backend_constructs_without_starting_a_thread(mac):
    before = threading.active_count()
    mac.MacBackend()
    assert threading.active_count() == before


def test_run_main_returns_what_fn_returns(mac):
    ran_on = []

    def fn():
        ran_on.append(threading.current_thread())
        return 42

    assert mac.run_main(fn) == 42
    assert ran_on[0] is not threading.main_thread()


def test_run_main_raises_what_fn_raises(mac):
    def fn():
        raise KeyError("boom")

    with pytest.raises(KeyError, match="boom"):
        mac.run_main(fn)


def test_run_main_passes_on_system_exit(mac):
    with pytest.raises(SystemExit) as e:
        mac.run_main(lambda: sys.exit(3))
    assert e.value.code == 3


def test_run_main_runs_queued_work_on_the_main_thread(mac):
    def fn():
        return mac.on_main_thread(lambda: threading.current_thread())

    assert mac.run_main(fn) is threading.main_thread()


def test_main_thread_work_without_run_main_fails_fast_off_the_main_thread(mac):
    errors = []

    def call():
        try:
            mac.on_main_thread(lambda: None)
        except BackendError as exc:
            errors.append(exc)

    worker = threading.Thread(target=call)
    worker.start()
    worker.join(2)
    assert not worker.is_alive()
    assert errors[0].code == "failed"
    assert "main-thread run loop" in errors[0].detail


def test_main_thread_work_runs_inline_on_the_main_thread(mac):
    assert mac.on_main_thread(lambda: threading.current_thread()) is (
        threading.main_thread()
    )


class FakeRFCOMM:
    """An IOBluetoothRFCOMMChannel that completes each write at once, unless told
    to hang or fail, and calls back closed when closed. An exception as `mtu` is
    raised by getMTU, as a failed main-thread call would be."""

    def __init__(self, delegate, write_status=0, complete=True, mtu=4, log=None):
        self.delegate = delegate
        self.write_status = write_status
        self.complete = complete
        self.mtu = mtu
        self.log = [] if log is None else log
        self.writes = []
        self.closes = 0
        self.closed = threading.Event()

    def getMTU(self):
        if isinstance(self.mtu, Exception):
            raise self.mtu
        return self.mtu

    def writeAsync_length_refcon_(self, data, length, refcon):
        assert refcon is None
        self.writes.append(bytes(data[:length]))
        if self.complete:
            self.delegate.rfcommChannelWriteComplete_refcon_status_(
                self, None, self.write_status
            )
        return 0

    def closeChannel(self):
        self.closes += 1
        self.log.append("close")
        self.delegate.rfcommChannelClosed_(self)
        self.closed.set()
        return 0


def channel_pair(mac, **kwargs):
    delegate = mac.HaraldRFCOMMDelegate.alloc().init()
    rfcomm = FakeRFCOMM(delegate, **kwargs)
    return mac.MacChannel(rfcomm, delegate, mtu=4), rfcomm, delegate


def test_write_splits_by_mtu(mac):
    channel, rfcomm, _ = channel_pair(mac)
    channel.write(bytes(range(10)))
    assert rfcomm.writes == [bytes(range(4)), bytes(range(4, 8)), bytes(range(8, 10))]


def test_write_status_failure(mac):
    channel, _, _ = channel_pair(mac, write_status=-0x1FFFFD44)
    with pytest.raises(BackendError) as e:
        channel.write(b"\x01")
    assert e.value.code == "failed"


def test_drain_returns_what_arrived_with_arrival_times(mac):
    channel, _, delegate = channel_pair(mac)
    before = time.monotonic()
    delegate.rfcommChannelData_data_length_(None, b"\x01\x02\x03", 2)
    delegate.rfcommChannelData_data_length_(None, b"\x03", 1)
    drained = channel.drain(0.0)
    assert [data for _, data in drained] == [b"\x01\x02", b"\x03"]
    assert before <= drained[0][0] <= drained[1][0] <= time.monotonic()
    assert channel.drain(0.0) == []


def test_close_wakes_a_blocked_drain_and_write(mac):
    def fn():
        channel, rfcomm, _ = channel_pair(mac, complete=False)
        outcome = {}

        def drain():
            outcome["drain"] = channel.drain(30)

        def write():
            try:
                channel.write(b"\x01")
            except BackendError as exc:
                outcome["write"] = exc.code

        threads = [threading.Thread(target=drain), threading.Thread(target=write)]
        for thread in threads:
            thread.start()
        time.sleep(0.2)
        started = time.monotonic()
        channel.close()
        for thread in threads:
            thread.join(2)
        return outcome, rfcomm.closes, time.monotonic() - started

    outcome, closes, took = mac.run_main(fn)
    assert outcome == {"drain": [], "write": "failed"}
    assert closes == 1
    assert took < 1.5


def test_close_never_raises_without_a_run_loop(mac):
    channel, rfcomm, _ = channel_pair(mac)
    worker = threading.Thread(target=channel.close)
    worker.start()
    worker.join(2)
    assert not worker.is_alive()
    assert rfcomm.closes == 0  # nothing ran the close; it gave up quietly


def test_harald_does_not_import_the_mac_backend():
    check = (
        "import sys, harald, harald.classic, harald.cli, harald.server; "
        "assert 'harald.classic_mac' not in sys.modules; "
        "assert 'IOBluetooth' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", check], check=True)


# --- MacBackend's decisions, over a fake IOBluetoothDevice ----------------------

ADDRESS = "aa:bb:cc:11:22:33"
ERROR, BUSY, TIMEOUT, BAD_ARGUMENT = 0xE00002BC, 0xE00002D5, 0xE00002D6, 0xE00002C2
LOST = BackendError("failed", "bluetooth classic needs harald's main-thread run loop")


class FakeDevice:
    """An IOBluetoothDevice that calls its delegate back at once, unless the
    callback is told never to come (None). An exception as `connected` is raised by
    isConnected, as a failed main-thread call would be; `connected_after_open`
    replaces `connected` once an open has started."""

    def __init__(
        self,
        *,
        paired=True,
        connected=True,
        cached=(),
        fresh=(),
        sdp_start=0,
        sdp=0,
        page=0,
        page_connects=True,
        open_start=0,
        open_complete=0,
        connected_after_open=None,
        mtu=4,
        open_delay=0.0,
    ):
        self.paired, self.connected = paired, connected
        self.cached, self.fresh = list(cached), list(fresh)
        self.sdp_start, self.sdp = sdp_start, sdp
        self.page, self.page_connects = page, page_connects
        self.open_start, self.open_complete = open_start, open_complete
        self.connected_after_open = connected_after_open
        self.mtu, self.open_delay = mtu, open_delay
        self.log, self.queries, self.pages, self.opened = [], 0, 0, []
        self.rfcomm = None

    def isPaired(self):
        return self.paired

    def isConnected(self):
        self.log.append("connected?")
        if isinstance(self.connected, Exception):
            raise self.connected
        return self.connected

    def services(self):
        return self.cached

    def performSDPQuery_(self, delegate):
        self.queries += 1
        if self.sdp_start:
            return self.sdp_start
        if self.sdp == 0:
            self.cached = self.fresh
        if self.sdp is not None:
            delegate.sdpQueryComplete_status_(self, self.sdp)
        return 0

    def openConnection_withPageTimeout_authenticationRequired_(
        self, target, slots, auth
    ):
        assert (target, slots, auth) == (None, 8000, False)
        self.pages += 1
        if self.page == 0 and self.page_connects:
            self.connected = True
        return self.page

    def openRFCOMMChannelAsync_withChannelID_delegate_(self, target, channel, delegate):
        assert target is None
        self.opened.append(channel)
        time.sleep(self.open_delay)
        self.rfcomm = FakeRFCOMM(delegate, mtu=self.mtu, log=self.log)
        if not self.open_start and self.open_complete is not None:
            delegate.rfcommChannelOpenComplete_status_(self.rfcomm, self.open_complete)
        if self.connected_after_open is not None:
            self.connected = self.connected_after_open
        return self.open_start, self.rfcomm


class Listed:
    """A device as IOBluetoothDevice.pairedDevices() lists it."""

    def __init__(self, address, name, connected):
        self.address, self._name, self.connected = address, name, connected

    def addressString(self):
        return self.address

    def name(self):
        return self._name

    def isConnected(self):
        return self.connected


class FakeIOBluetoothDevice:
    """Stands in for the IOBluetoothDevice class: lookups and the paired list."""

    def __init__(self, device, paired):
        self.device, self.paired, self.addresses = device, paired, []

    def deviceWithAddressString_(self, text):
        self.addresses.append(text)
        return self.device

    def pairedDevices(self):
        return self.paired


@pytest.fixture
def bluetooth(mac, monkeypatch):
    """Install a fake IOBluetoothDevice (no device api is reached) and short waits."""
    for name, seconds in [
        ("OPEN_WAIT", 0.05),
        ("SDP_WAIT", 0.05),
        ("WRITE_WAIT", 0.05),
    ]:
        monkeypatch.setattr(mac, name, seconds)

    def install(device=None, paired=()):
        fake = FakeIOBluetoothDevice(device, paired)
        monkeypatch.setattr(mac, "IOBluetoothDevice", fake)
        return mac.MacBackend(), fake

    return install


def code_of(call):
    with pytest.raises(BackendError) as e:
        call()
    return e.value.code


def test_paired_lists_devices_and_skips_unusable_addresses(bluetooth):
    backend, _ = bluetooth(
        paired=[
            Listed("AA-BB-CC-11-22-33", "WH-1000XM5", True),
            Listed(None, "no address", False),
            Listed("00-11-22-33-44-55", None, False),
        ]
    )
    assert backend.paired() == [
        ClassicDevice(ADDRESS, "WH-1000XM5", True),
        ClassicDevice("00:11:22:33:44:55", None, False),
    ]


def test_paired_with_bluetooth_off(bluetooth):
    backend, _ = bluetooth(paired=None)
    assert code_of(backend.paired) == "bluetooth_off"


def test_records_read_the_cache_without_asking(bluetooth):
    device = FakeDevice(cached=[Record("Serial HPC", None, 9)])
    backend, fake = bluetooth(device)
    assert backend.records(ADDRESS, False) == [ServiceRecord("Serial HPC", [], 9)]
    assert device.queries == 0
    assert fake.addresses == ["aa-bb-cc-11-22-33"]


@pytest.mark.parametrize("refresh, cached", [(True, ["old"]), (False, [])])
def test_records_ask_the_device_on_refresh_or_an_empty_cache(
    bluetooth, refresh, cached
):
    old = [Record("old", None, 1)] if cached else []
    device = FakeDevice(cached=old, fresh=[Record("new", None, 2)])
    backend, _ = bluetooth(device)
    assert backend.records(ADDRESS, refresh) == [ServiceRecord("new", [], 2)]
    assert device.queries == 1


@pytest.mark.parametrize("device", [None, FakeDevice(paired=False)])
def test_records_and_open_need_a_paired_device(bluetooth, device):
    backend, _ = bluetooth(device)
    assert code_of(lambda: backend.records(ADDRESS, False)) == "not_paired"
    assert code_of(lambda: backend.open(ADDRESS, 9)) == "not_paired"


@pytest.mark.parametrize(
    "failure, connected, code",
    [
        ({"sdp_start": ERROR}, True, "failed"),
        ({"sdp_start": ERROR}, False, "not_connected"),
        ({"sdp": TIMEOUT}, True, "failed"),
        ({"sdp": TIMEOUT}, False, "not_connected"),
        ({"sdp": None}, True, "timeout"),  # sdp-complete never comes
    ],
)
def test_records_query_failures(bluetooth, failure, connected, code):
    backend, _ = bluetooth(FakeDevice(connected=connected, **failure))
    assert code_of(lambda: backend.records(ADDRESS, True)) == code


def test_open_returns_a_channel(bluetooth):
    device = FakeDevice(mtu=2)
    backend, _ = bluetooth(device)
    channel = backend.open(ADDRESS, 9)
    channel.write(b"\x01\x02\x03")
    assert device.opened == [9]
    assert device.pages == 0
    assert device.rfcomm.writes == [b"\x01\x02", b"\x03"]
    assert device.rfcomm.closes == 0


def test_open_pages_a_device_whose_link_is_down(bluetooth):
    device = FakeDevice(connected=False)
    backend, _ = bluetooth(device)
    backend.open(ADDRESS, 9)
    assert device.pages == 1
    assert device.opened == [9]


@pytest.mark.parametrize("page, connects", [(TIMEOUT, False), (0, False)])
def test_open_when_the_page_fails(bluetooth, page, connects):
    device = FakeDevice(connected=False, page=page, page_connects=connects)
    backend, _ = bluetooth(device)
    assert code_of(lambda: backend.open(ADDRESS, 9)) == "not_connected"
    assert device.opened == []


@pytest.mark.parametrize(
    "status, connected_after_open, code",
    [
        (BUSY, None, "busy"),
        (ERROR, None, "stuck"),
        (-0x1FFFFD44, None, "stuck"),  # ERROR, signed as pyobjc hands it over
        (BAD_ARGUMENT, None, "failed"),
        (ERROR, False, "not_connected"),
    ],
)
def test_open_start_failure_maps_the_status_and_closes(
    bluetooth, status, connected_after_open, code
):
    device = FakeDevice(open_start=status, connected_after_open=connected_after_open)
    backend, _ = bluetooth(device)
    assert code_of(lambda: backend.open(ADDRESS, 9)) == code
    assert device.rfcomm.closes == 1


@pytest.mark.parametrize(
    "status, connected_after_open, code",
    [
        (BUSY, None, "busy"),
        (ERROR, None, "stuck"),
        (TIMEOUT, False, "not_connected"),
        (BAD_ARGUMENT, None, "failed"),
        (BAD_ARGUMENT, False, "not_connected"),
    ],
)
def test_open_complete_failure_maps_the_status_and_closes(
    bluetooth, status, connected_after_open, code
):
    device = FakeDevice(open_complete=status, connected_after_open=connected_after_open)
    backend, _ = bluetooth(device)
    assert code_of(lambda: backend.open(ADDRESS, 9)) == code
    assert device.rfcomm.closes == 1


@pytest.mark.parametrize("connected, code", [(True, "stuck"), (False, "not_connected")])
def test_open_that_never_completes_closes_then_asks_about_the_link(
    bluetooth, connected, code
):
    device = FakeDevice(open_complete=None, connected_after_open=connected)
    backend, _ = bluetooth(device)
    assert code_of(lambda: backend.open(ADDRESS, 9)) == code
    assert device.rfcomm.closes == 1
    assert device.log[-2:] == ["close", "connected?"]


def test_an_open_that_completes_after_harald_gave_up_is_closed(bluetooth):
    # in `harald mcp` the process lives on, so a channel that opens after the wait
    # ran out would stay open until exit: the stuck-mac failure
    device = FakeDevice(open_complete=None)
    backend, _ = bluetooth(device)
    assert code_of(lambda: backend.open(ADDRESS, 9)) == "stuck"
    rfcomm = device.rfcomm
    assert rfcomm.closes == 1  # the close as harald gave up
    rfcomm.delegate.rfcommChannelOpenComplete_status_(rfcomm, 0)
    assert rfcomm.closes == 2  # the late open closed exactly once more


def test_a_late_failed_open_complete_closes_nothing_more(bluetooth):
    device = FakeDevice(open_complete=None)
    backend, _ = bluetooth(device)
    assert code_of(lambda: backend.open(ADDRESS, 9)) == "stuck"
    device.rfcomm.delegate.rfcommChannelOpenComplete_status_(device.rfcomm, ERROR)
    assert device.rfcomm.closes == 1


def test_a_late_open_complete_never_raises_into_iobluetooth(mac):
    delegate = mac.HaraldRFCOMMDelegate.alloc().init()
    delegate.given_up = True

    class Unclosable:
        def closeChannel(self):
            raise RuntimeError("closing failed")

    delegate.rfcommChannelOpenComplete_status_(Unclosable(), 0)
    assert delegate.open_status == 0


def test_an_open_harald_waits_for_is_not_closed_by_its_open_complete(bluetooth):
    device = FakeDevice()
    backend, _ = bluetooth(device)
    backend.open(ADDRESS, 9)
    assert device.rfcomm.closes == 0


# --- channels nobody takes are closed -------------------------------------------


def test_open_closes_the_channel_when_reading_the_mtu_fails(bluetooth):
    device = FakeDevice(mtu=LOST)
    backend, _ = bluetooth(device)
    assert code_of(lambda: backend.open(ADDRESS, 9)) == "failed"
    assert device.rfcomm.closes == 1


@pytest.mark.parametrize("open_complete, code", [(ERROR, "stuck"), (None, "stuck")])
def test_a_failed_link_check_keeps_the_open_failure_code(
    bluetooth, open_complete, code
):
    # once the open has started, asking isConnected fails (run_main stopping)
    device = FakeDevice(open_complete=open_complete, connected_after_open=LOST)
    backend, _ = bluetooth(device)
    assert code_of(lambda: backend.open(ADDRESS, 9)) == code
    assert device.rfcomm.closes == 1


def test_open_closes_a_channel_its_caller_stopped_waiting_for(
    mac, bluetooth, monkeypatch
):
    monkeypatch.setattr(mac, "CALL_TIMEOUT", 0.1)
    device = FakeDevice(open_delay=0.4)  # the open job outlives the caller's wait
    backend, _ = bluetooth(device)

    def fn():
        code = code_of(lambda: backend.open(ADDRESS, 9))
        deadline = time.monotonic() + 2
        while device.rfcomm is None and time.monotonic() < deadline:
            time.sleep(0.01)  # the job is still running on the main thread
        return code, device.rfcomm is not None and device.rfcomm.closed.wait(2)

    assert mac.run_main(fn) == ("timeout", True)
    assert device.rfcomm.closes == 1


# --- on_main_thread's timeouts ------------------------------------------------


def test_on_main_thread_keeps_a_result_that_lands_as_the_wait_gives_up(
    mac, monkeypatch
):
    # every timed wait, whichever way it is made, ends just as the job finishes:
    # it reports a timeout, yet the job is done
    real_wait = concurrent.futures.wait

    def late_wait(futures, timeout=None):
        real_wait(futures)
        return set(), set(futures)

    class LateFuture(concurrent.futures.Future):
        def result(self, timeout=None):
            value = super().result()
            if timeout is not None:
                raise TimeoutError
            return value

    monkeypatch.setattr(concurrent.futures, "wait", late_wait)
    monkeypatch.setattr(concurrent.futures, "Future", LateFuture)
    assert mac.run_main(lambda: mac.on_main_thread(lambda: 7, timeout=0.01)) == 7


def test_on_main_thread_timeout_before_the_job_starts(mac):
    ran = []

    def fn():
        busy = threading.Thread(
            target=mac.on_main_thread, args=(lambda: time.sleep(0.4),)
        )
        busy.start()
        time.sleep(0.05)  # the main thread is now inside the slow job
        code = code_of(lambda: mac.on_main_thread(lambda: ran.append(1), timeout=0.1))
        busy.join(2)
        return code

    assert mac.run_main(fn) == "timeout"
    assert ran == []  # cancelled before it started, so it never runs


def test_a_queued_call_fails_at_once_when_the_run_loop_stops(mac, monkeypatch):
    monkeypatch.setattr(mac, "CALL_TIMEOUT", 2.0)
    ran, outcome = [], {}

    def call():
        started = time.monotonic()
        try:
            mac.on_main_thread(lambda: ran.append(1))
        except BackendError as exc:
            outcome["code"] = exc.code
        outcome["took"] = time.monotonic() - started

    mac._pump.start()  # serving, but nothing runs the queue: the job stays queued
    try:
        caller = threading.Thread(target=call)
        caller.start()
        deadline = time.monotonic() + 2
        while mac._pump.jobs.empty() and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.1)
    finally:
        mac._pump.stop()
    caller.join(3)
    assert outcome["code"] == "failed"
    assert outcome["took"] < 1.0  # not the whole CALL_TIMEOUT
    assert ran == []
