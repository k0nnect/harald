import os
import subprocess
import sys

import pytest

from harald.arm import arm, consume_write, disarm, status
from harald.errors import WriteDenied

SVC = "0000ffe0-0000-1000-8000-00805f9b34fb"
CHR = "0000ffe1-0000-1000-8000-00805f9b34fb"


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
