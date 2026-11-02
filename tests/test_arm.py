import os
import subprocess
import sys

import pytest

from harald.arm import (
    ArmGrant,
    arm,
    check_write,
    consume_write,
    device_key,
    disarm,
    live_grant,
    status,
)
from harald.errors import WriteDenied

SVC = "0000ffe0-0000-1000-8000-00805f9b34fb"
CHR = "0000ffe1-0000-1000-8000-00805f9b34fb"
XM5 = "aa:bb:cc:11:22:33"
AIROHA = "8901dfa8-5c7e-4d8f-9f0c-c2b70683f5f0"


def test_denied_when_not_armed(home):
    with pytest.raises(WriteDenied) as e:
        consume_write(
            "AA-11",
            "0000ffe0-0000-1000-8000-00805f9b34fb",
            "0000ffe1-0000-1000-8000-00805f9b34fb",
            now=0,
        )
    assert "harald arm AA-11" in str(e.value.hint)


def test_budget_counts_down_and_runs_out(home):
    arm("AA-11", writes=2, minutes=10, now=0)
    assert consume_write("aa-11", SVC, CHR, now=1).writes_left == 1
    consume_write("AA-11", SVC, CHR, now=2)
    with pytest.raises(WriteDenied):
        consume_write("AA-11", SVC, CHR, now=3)


def test_expiry(home):
    arm("AA-11", writes=5, minutes=1, now=0)
    with pytest.raises(WriteDenied):
        consume_write("AA-11", SVC, CHR, now=61)


def test_other_device_not_covered(home):
    arm("AA-11", now=0)
    with pytest.raises(WriteDenied):
        consume_write("BB-22", SVC, CHR, now=1)


def test_dfu_blocked_unless_allowed(home):
    arm("AA-11", now=0)
    with pytest.raises(WriteDenied):
        consume_write("AA-11", "0000fe59-0000-1000-8000-00805f9b34fb", CHR, now=1)
    arm("AA-11", allow_dfu=True, now=0)
    consume_write("AA-11", "0000fe59-0000-1000-8000-00805f9b34fb", CHR, now=1)


def test_state_shared_across_processes(home):
    arm("AA-11", writes=3, now=0)
    code = "from harald.arm import consume_write as c; c('AA-11','x','y',now=1)"
    subprocess.run([sys.executable, "-c", code], check=True, env={**os.environ})
    assert status(now=2)[0].writes_left == 2


def test_disarm_locks_writes_again(home):
    arm("AA-11", now=0)
    disarm("aa-11")
    assert status(now=1) == []
    with pytest.raises(WriteDenied):
        consume_write("AA-11", SVC, CHR, now=1)


@pytest.mark.parametrize(
    "svc", ["0000FE59-0000-1000-8000-00805F9B34FB", "fe59", "FE59"]
)
def test_dfu_blocked_in_any_uuid_form(home, svc):
    arm("AA-11", now=0)
    with pytest.raises(WriteDenied):
        consume_write("AA-11", svc, CHR, now=1)


def test_device_key():
    assert device_key("AA-BB-CC-11-22-33") == XM5
    assert device_key("AA:BB:CC:11:22:33") == XM5
    assert device_key("AA-11") == "aa-11"
    assert device_key("1D2E3F40-AAAA-BBBB-CCCC-DDDDEEEEFFFF") == (
        "1d2e3f40-aaaa-bbbb-cccc-ddddeeeeffff"
    )


def test_hyphen_and_colon_addresses_share_a_grant(home):
    arm("AA-BB-CC-11-22-33", writes=5, now=0)
    assert consume_write(XM5, SVC, CHR, now=1).writes_left == 4
    assert [g.device for g in status(now=2)] == [XM5]

    arm(XM5, writes=5, now=0)
    assert consume_write("AA-BB-CC-11-22-33", SVC, CHR, now=1).writes_left == 4
    assert [g.device for g in status(now=2)] == [XM5]

    disarm("aa-bb-cc-11-22-33")
    assert status(now=3) == []


def test_airoha_tooling_needs_allow_dfu(home):
    arm(XM5, now=0)
    with pytest.raises(WriteDenied, match="firmware-update service blocked"):
        consume_write(XM5, AIROHA, CHR, now=1)
    arm(XM5, allow_dfu=True, now=0)
    assert consume_write(XM5, AIROHA.upper(), CHR, now=1).writes_left == 49


def test_live_grant(home):
    assert live_grant("AA-11", now=0) is None
    arm("AA-11", writes=3, minutes=10, now=0)
    grant = live_grant("aa-11", now=1)
    assert grant is not None
    assert (grant.device, grant.writes_left) == ("aa-11", 3)
    assert live_grant("AA-11", now=2).writes_left == 3  # looking spends nothing
    assert live_grant("AA-11", now=601) is None  # expired


def test_check_write_words_every_refusal():
    with pytest.raises(WriteDenied, match="writes to AA-11 are locked") as e:
        check_write("AA-11", None)
    assert (
        e.value.hint
        == "ask the human to run: harald arm AA-11 --writes 50 --minutes 30"
    )
    grant = ArmGrant("aa-11", writes_left=1, expires_at=10.0, allow_dfu=False)
    assert check_write("AA-11", grant) is grant
    assert check_write("AA-11", grant, SVC) is grant
    with pytest.raises(WriteDenied, match="firmware-update service blocked") as e:
        check_write("AA-11", grant, AIROHA)
    assert e.value.hint == "only a human can allow this: harald arm AA-11 --allow-dfu"
    grant.allow_dfu = True
    assert check_write("AA-11", grant, AIROHA) is grant
