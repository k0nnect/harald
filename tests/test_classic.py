import asyncio
import math
import sys
import threading
import time

import anyio
import pytest
from classic_fakes import XM5_ADDRESS, FakeBackend

from harald import classic
from harald.arm import arm, disarm, live_grant
from harald.classic import (
    BackendError,
    ClassicDevice,
    listen,
    paired_devices,
    send,
    services,
)
from harald.errors import (
    BluetoothUnavailable,
    DeviceNotFound,
    HaraldError,
    ProtectedChannel,
    WriteDenied,
)

HYPHEN = "AA-BB-CC-11-22-33"
HPC = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"  # channel 9
M1 = bytes.fromhex("3e0c00000000020000103c")
M2 = bytes.fromhex("3e0c01000000020600163c")
ACK = bytes.fromhex("3e010100000000023c")
HELLO = bytes.fromhex("3e0c000000000801000300201600004f3c")
TAIL = bytes.fromhex("3e0d00000000020601163c")


def received(chunks):
    return [(chunk.after, chunk.data) for chunk in chunks]


async def eventually(condition, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition never came true"
        await asyncio.sleep(0.005)


async def test_send_spends_one_write_per_message():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend(replies={M1: [ACK], M2: [TAIL]})
    result = await send(XM5_ADDRESS, "9", [M1, M2], backend=backend)
    assert result.sent == 2
    assert result.writes_left == 3
    assert result.stopped == ""
    assert backend.writes == [M1, M2]
    assert backend.opened == [(XM5_ADDRESS, 9)]
    assert backend.channel.closed is True
    assert backend.channel.drains == [0.0, 2.0, 2.0]
    assert received(result.chunks) == [(1, ACK), (2, TAIL)]
    # seconds count from the open
    assert 0 <= result.chunks[0].seconds < result.chunks[1].seconds < 1
    assert live_grant(XM5_ADDRESS).writes_left == 3


async def test_send_unarmed_opens_nothing():
    backend = FakeBackend()
    with pytest.raises(WriteDenied, match="are locked") as e:
        await send(XM5_ADDRESS, "9", [M1], backend=backend)
    assert f"harald arm {XM5_ADDRESS} --writes 50 --minutes 30" in e.value.hint
    assert backend.asked == []
    assert backend.opened == []


async def test_send_needs_a_message():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend()
    with pytest.raises(HaraldError, match="nothing to send") as e:
        await send(XM5_ADDRESS, "9", [], backend=backend)
    assert e.value.hint == "pass at least one hex message"
    assert backend.asked == []
    assert backend.opened == []


async def test_send_refuses_an_empty_message_before_spending_a_write():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend()
    with pytest.raises(HaraldError) as e:
        await send(XM5_ADDRESS, "9", [M1, b""], backend=backend)
    assert e.value.message == "empty message"
    assert e.value.hint == "each message needs at least one byte of hex"
    assert backend.asked == []
    assert backend.opened == []
    assert live_grant(XM5_ADDRESS).writes_left == 5


@pytest.mark.parametrize(
    ("seconds", "shown"),
    [
        (30.5, "30.5"),
        (31, "31"),
        (-0.1, "-0.1"),
        (float("inf"), "inf"),
        (math.nan, "nan"),
    ],
)
async def test_listening_is_capped_at_30_seconds_before_anything_opens(seconds, shown):
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend()
    with pytest.raises(HaraldError) as e:
        await send(XM5_ADDRESS, "9", [M1], seconds, backend=backend)
    assert e.value.message == f"listen must be from 0 to 30 s, got {shown}"
    assert e.value.hint == "harald listens for at most 30 s at a time"
    with pytest.raises(HaraldError) as e:
        await listen(XM5_ADDRESS, "9", seconds, backend=backend)
    assert e.value.message == f"seconds must be from 0 to 30 s, got {shown}"
    assert backend.asked == []
    assert backend.opened == []
    assert live_grant(XM5_ADDRESS).writes_left == 5


@pytest.mark.parametrize("seconds", [0, 30, 30.0])
async def test_listening_from_0_to_30_seconds_is_allowed(seconds):
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend()
    await send(XM5_ADDRESS, "9", [M1], seconds, backend=backend)
    await listen(XM5_ADDRESS, "9", seconds, backend=backend)
    assert [c.drains for c in backend.channels] == [[0.0, seconds], [seconds]]


async def test_budget_out_midway_keeps_what_was_received():
    arm(XM5_ADDRESS, writes=1)
    backend = FakeBackend(on_open=[HELLO], replies={M1: [ACK, TAIL], M2: [ACK]})
    result = await send(XM5_ADDRESS, "9", [M1, M2], backend=backend)
    assert result.sent == 1
    assert result.writes_left == 0
    assert "locked" in result.stopped
    assert f"harald arm {XM5_ADDRESS}" in result.stopped
    assert received(result.chunks) == [(0, HELLO), (1, ACK), (1, TAIL)]
    assert backend.writes == [M1]
    assert backend.channel.closed is True


async def test_data_before_first_message_kept():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend(on_open=[HELLO], replies={M1: [ACK]})
    result = await send(XM5_ADDRESS, "9", [M1], backend=backend)
    assert received(result.chunks) == [(0, HELLO), (1, ACK)]
    assert 0 <= result.chunks[0].seconds < result.chunks[1].seconds


async def test_protected_never_opened():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend()
    with pytest.raises(ProtectedChannel):
        await send(XM5_ADDRESS, "2", [M1], backend=backend)
    with pytest.raises(ProtectedChannel):
        await listen(XM5_ADDRESS, "1", 1.0, backend=backend)
    assert backend.opened == []
    assert live_grant(XM5_ADDRESS).writes_left == 5


async def test_firmware_channel_needs_allow_dfu():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend()
    with pytest.raises(WriteDenied, match="firmware-update service blocked") as e:
        await send(XM5_ADDRESS, "21", [M1], backend=backend)
    assert f"harald arm {XM5_ADDRESS} --allow-dfu" in e.value.hint
    assert backend.opened == []
    assert live_grant(XM5_ADDRESS).writes_left == 5

    arm(XM5_ADDRESS, writes=5, allow_dfu=True)
    result = await send(XM5_ADDRESS, "21", [M1], backend=backend)
    assert result.sent == 1
    assert result.writes_left == 4
    assert backend.opened == [(XM5_ADDRESS, 21)]
    assert backend.writes == [M1]


async def test_listen_needs_no_arm():
    backend = FakeBackend(on_open=[HELLO, ACK])
    chunks = await listen(XM5_ADDRESS, HPC, 5.0, backend=backend)
    assert received(chunks) == [(0, HELLO), (0, ACK)]
    assert backend.opened == [(XM5_ADDRESS, 9)]
    assert backend.channel.drains == [5.0]
    assert backend.writes == []
    assert backend.channel.closed is True
    assert live_grant(XM5_ADDRESS) is None


@pytest.mark.parametrize(
    ("code", "error", "message", "hint"),
    [
        (
            "unsupported",
            HaraldError,
            "bluetooth classic is mac-only in this version",
            "use a mac, or the bluetooth le tools",
        ),
        (
            "bluetooth_off",
            BluetoothUnavailable,
            "bluetooth is off or not allowed for this app",
            "system settings > privacy & security > bluetooth",
        ),
        (
            "not_paired",
            DeviceNotFound,
            f"{XM5_ADDRESS} is not paired with this mac",
            "then run: harald classic devices",
        ),
        (
            "not_connected",
            DeviceNotFound,
            f"{XM5_ADDRESS} is not connected",
            "connect it to this mac in system settings > bluetooth",
        ),
        (
            "stuck",
            HaraldError,
            f"the mac would not open a channel to {XM5_ADDRESS}",
            "turn bluetooth off and on in the menu bar",
        ),
        (
            "busy",
            HaraldError,
            f"channel 9 on {XM5_ADDRESS} is busy",
            "close the vendor app on your phone",
        ),
        (
            "timeout",
            HaraldError,
            f"{XM5_ADDRESS} stopped answering",
            "move closer and try again",
        ),
        ("failed", HaraldError, "bluetooth error: kIOReturnNoMemory", ""),
    ],
)
async def test_backend_errors_map_to_hints(code, error, message, hint):
    backend = FakeBackend(open_error=BackendError(code, "kIOReturnNoMemory"))
    with pytest.raises(HaraldError) as e:
        await listen(XM5_ADDRESS, "9", 1.0, backend=backend)
    assert type(e.value) is error
    assert e.value.message == message
    assert hint in e.value.hint

    arm(XM5_ADDRESS, writes=5)
    with pytest.raises(HaraldError) as e:
        await send(XM5_ADDRESS, "9", [M1], backend=backend)
    assert type(e.value) is error
    assert e.value.message == message
    assert backend.opened == [(XM5_ADDRESS, 9)] * 2


async def test_unknown_backend_code_is_a_bluetooth_error():
    backend = FakeBackend(open_error=BackendError("odd"))
    with pytest.raises(HaraldError) as e:
        await listen(XM5_ADDRESS, "9", 1.0, backend=backend)
    assert type(e.value) is HaraldError
    assert e.value.message == "bluetooth error: odd"


async def test_channel_closed_on_every_path():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend(write_error_at=1, write_error=BackendError("timeout"))
    with pytest.raises(HaraldError, match="stopped answering"):
        await send(XM5_ADDRESS, "9", [M1, M2], backend=backend)
    assert backend.writes == [M1]
    assert backend.channel.closed is True

    # a close that raises replaces neither the original error nor a result
    backend = FakeBackend(
        write_error_at=1,
        write_error=BackendError("timeout"),
        close_error=BackendError("failed", "close"),
    )
    with pytest.raises(HaraldError, match="stopped answering"):
        await send(XM5_ADDRESS, "9", [M1], backend=backend)
    assert backend.channel.closed is True

    backend = FakeBackend(replies={M1: [ACK]}, close_error=OSError("gone"))
    result = await send(XM5_ADDRESS, "9", [M1], backend=backend)
    assert result.sent == 1
    assert received(result.chunks) == [(1, ACK)]
    assert backend.channel.closed is True

    backend = FakeBackend(on_open=[HELLO], close_error=BackendError("timeout"))
    assert received(await listen(XM5_ADDRESS, "9", 1.0, backend=backend)) == [
        (0, HELLO)
    ]
    assert backend.channel.closed is True

    # the grant runs out while the channel opens: the first write is refused
    backend = FakeBackend()
    opener = backend.open

    def open_after_disarm(address, channel):
        disarm(address)
        return opener(address, channel)

    backend.open = open_after_disarm
    with pytest.raises(WriteDenied, match="are locked"):
        await send(XM5_ADDRESS, "9", [M1], backend=backend)
    assert backend.writes == []
    assert backend.channel.closed is True


async def test_services_are_marked():
    backend = FakeBackend()
    records = await services(XM5_ADDRESS, backend=backend)
    on = {
        channel: [r for r in records if r.channel == channel] for channel in (2, 9, 21)
    }
    assert len(on[2]) == 2
    assert all(r.protected and not r.firmware_update for r in on[2])
    assert all(r.firmware_update and not r.protected for r in on[21])
    assert all(not r.protected and not r.firmware_update for r in on[9])
    assert backend.asked == [(XM5_ADDRESS, False)]

    await services(XM5_ADDRESS, refresh=True, backend=backend)
    assert backend.asked[-1] == (XM5_ADDRESS, True)


async def test_paired_devices_come_from_the_backend():
    xm5 = ClassicDevice(XM5_ADDRESS, "WH-1000XM5", True)
    backend = FakeBackend(devices=[xm5])
    assert await paired_devices(backend=backend) == [xm5]


async def test_hyphen_address_reaches_backend_in_colon_form():
    arm(HYPHEN, writes=5)
    backend = FakeBackend()
    await services(HYPHEN, backend=backend)
    result = await send(HYPHEN, "9", [M1], backend=backend)
    await listen(HYPHEN, "9", 1.0, backend=backend)
    assert backend.asked == [(XM5_ADDRESS, False)] * 3
    assert backend.opened == [(XM5_ADDRESS, 9)] * 2
    assert result.writes_left == 4


async def test_default_backend_off_mac(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delitem(sys.modules, "harald.classic_mac", raising=False)
    with pytest.raises(BackendError) as raw:
        classic.default_backend()
    assert raw.value.code == "unsupported"

    with pytest.raises(HaraldError, match="mac-only") as e:
        await paired_devices()
    assert e.value.hint == "use a mac, or the bluetooth le tools"
    with pytest.raises(HaraldError, match="mac-only"):
        await services(XM5_ADDRESS)
    with pytest.raises(HaraldError, match="mac-only"):
        await listen(XM5_ADDRESS, "9", 1.0)
    assert "harald.classic_mac" not in sys.modules


async def test_backend_error_after_a_write_keeps_the_partial_send():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend(
        on_open=[HELLO],
        replies={M1: [ACK]},
        write_error_at=2,
        write_error=BackendError("timeout"),
    )
    result = await send(XM5_ADDRESS, "9", [M1, M2, M1], backend=backend)
    assert result.sent == 1
    # message 2's write was spent before it failed, so the grant has 3 left
    assert result.writes_left == 3
    assert live_grant(XM5_ADDRESS).writes_left == 3
    assert result.stopped == (
        f"{XM5_ADDRESS} stopped answering; move closer and try again; "
        "if it keeps happening, turn the mac's bluetooth off and on"
    )
    assert received(result.chunks) == [(0, HELLO), (1, ACK)]
    assert backend.writes == [M1, M2]
    assert backend.channel.closed is True

    # a drain that fails after message 1 counts the same way
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend(
        replies={M1: [ACK]},
        drain_error_at=2,
        drain_error=BackendError("failed", "gone"),
    )
    result = await send(XM5_ADDRESS, "9", [M1, M2], backend=backend)
    assert result.sent == 1
    assert result.writes_left == 4
    assert result.stopped == "bluetooth error: gone"
    assert backend.writes == [M1]
    assert backend.channel.closed is True


async def test_backend_error_before_any_write_raises():
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend(write_error_at=1, write_error=BackendError("timeout"))
    with pytest.raises(HaraldError, match="stopped answering"):
        await send(XM5_ADDRESS, "9", [M1, M2], backend=backend)
    assert backend.writes == [M1]
    assert live_grant(XM5_ADDRESS).writes_left == 4  # the spent write stays spent
    assert backend.channel.closed is True

    # the drain right after the open comes before any write too
    backend = FakeBackend(drain_error_at=1, drain_error=BackendError("busy"))
    with pytest.raises(HaraldError, match=f"channel 9 on {XM5_ADDRESS} is busy"):
        await send(XM5_ADDRESS, "9", [M1], backend=backend)
    assert backend.writes == []
    assert backend.channel.closed is True


@pytest.mark.parametrize("call", ["send", "listen"])
async def test_cancel_during_open_closes_the_channel(call):
    arm(XM5_ADDRESS, writes=5)
    gate = threading.Event()
    backend = FakeBackend(open_gate=gate)
    if call == "send":
        session = send(XM5_ADDRESS, "9", [M1], backend=backend)
    else:
        session = listen(XM5_ADDRESS, "9", 1.0, backend=backend)
    task = asyncio.create_task(session)
    await eventually(lambda: backend.opened)  # the open is in its thread, held
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    gate.set()  # the open finishes after its caller has gone
    await eventually(lambda: backend.channels and backend.channel.closed)
    assert backend.writes == []


async def test_cancel_during_drain_still_closes():
    backend = FakeBackend(slow_drain=True)
    task = asyncio.create_task(listen(XM5_ADDRESS, "9", 30.0, backend=backend))
    await eventually(lambda: backend.channels and backend.channel.drains)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await eventually(lambda: backend.channel.closed)
    assert backend.channel.drain_returned.wait(2)  # close let the drain go

    # anyio (the mcp server's runtime) cancels every await in a cancelled scope,
    # including the one in send's finally
    arm(XM5_ADDRESS, writes=5)
    backend = FakeBackend(slow_drain=True)
    with anyio.move_on_after(0.05) as scope:
        await send(XM5_ADDRESS, "9", [M1], listen=30.0, backend=backend)
    assert scope.cancelled_caught
    await eventually(lambda: backend.channel.closed)
    assert backend.channel.drain_returned.wait(2)
    assert backend.writes == [M1]
