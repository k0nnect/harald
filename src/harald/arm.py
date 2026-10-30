"""Write gate: an agent may only write to a device the human armed with `harald arm`.

Grants live in `$HARALD_HOME/arm.json` (default `~/.harald/arm.json`) so the cli,
the mcp server and agent-written drivers in other processes all see the same budget.
Every read-modify-write holds an exclusive `fcntl.flock` on the sibling `arm.lock`.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

from harald.errors import WriteDenied

DFU_UUIDS: frozenset[str] = frozenset(
    {
        "00001530-1212-efde-1523-785feabcd123",  # nordic legacy dfu
        "0000fe59-0000-1000-8000-00805f9b34fb",  # nordic secure dfu
        "1d14d6ee-fd63-4fa1-bfa4-8f47b42119f0",  # silicon labs ota
        "f000ffc0-0451-4000-b000-000000000000",  # ti oad
    }
)

_BASE_UUID_TAIL = "-0000-1000-8000-00805f9b34fb"
_HEX = frozenset("0123456789abcdef")


@dataclass
class ArmGrant:
    device: str
    writes_left: int
    expires_at: float
    allow_dfu: bool

    def live(self, now: float) -> bool:
        return self.writes_left > 0 and now < self.expires_at


def state_path() -> Path:
    home = os.environ.get("HARALD_HOME") or "~/.harald"
    return Path(home).expanduser() / "arm.json"


def arm(
    device: str,
    writes: int = 50,
    minutes: int = 30,
    allow_dfu: bool = False,
    *,
    now: float | None = None,
) -> ArmGrant:
    """Grant `writes` writes to `device` for `minutes`, replacing any earlier grant."""
    now = _now(now)
    grant = ArmGrant(
        device=device,
        writes_left=writes,
        expires_at=now + minutes * 60,
        allow_dfu=allow_dfu,
    )
    with _locked_state(now) as grants:
        grants[device.lower()] = grant
    return grant


def consume_write(
    device: str, service_uuid: str, char_uuid: str, *, now: float | None = None
) -> ArmGrant:
    """Spend one write from the device's budget, or raise WriteDenied."""
    now = _now(now)
    with _locked_state(now) as grants:
        grant = grants.get(device.lower())
        if grant is None:
            raise WriteDenied(
                f"writes to {device} are locked",
                hint=f"ask the human to run: harald arm {device} --writes 50 --minutes 30",
            )
        if _normalize_uuid(service_uuid) in DFU_UUIDS and not grant.allow_dfu:
            raise WriteDenied(
                "firmware-update service blocked",
                hint=f"only a human can allow this: harald arm {device} --allow-dfu",
            )
        grant.writes_left -= 1
        return grant


def disarm(device: str) -> None:
    with _locked_state(_now(None)) as grants:
        grants.pop(device.lower(), None)


def status(*, now: float | None = None) -> list[ArmGrant]:
    """Return the grants that are still live (budget left and not expired)."""
    now = _now(now)
    with _locked_state(now) as grants:
        return list(grants.values())


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def _normalize_uuid(uuid: str) -> str:
    """Lowercase, and expand 16/32-bit short uuids to the bluetooth base uuid."""
    uuid = uuid.strip().lower()
    if len(uuid) in (4, 8) and set(uuid) <= _HEX:
        return uuid.rjust(8, "0") + _BASE_UUID_TAIL
    return uuid


@contextmanager
def _locked_state(now: float) -> Iterator[dict[str, ArmGrant]]:
    """Yield the live grants under an exclusive lock; write them back on clean exit.

    Dead grants (expired or out of writes) are dropped on load, so callers only
    ever see live ones. A missing or unreadable state file means nothing is armed.
    """
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path.with_name("arm.lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            grants = {
                key: grant for key, grant in _load(path).items() if grant.live(now)
            }
            yield grants
            _save(path, grants)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _load(path: Path) -> dict[str, ArmGrant]:
    try:
        raw = json.loads(path.read_text())
        return {key: ArmGrant(**value) for key, value in raw.items()}
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def _save(path: Path, grants: dict[str, ArmGrant]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({key: asdict(g) for key, g in grants.items()}, indent=2))
    os.replace(tmp, path)
