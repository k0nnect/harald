from dataclasses import replace
from pathlib import Path

import pytest

from harald.errors import LibraryError
from harald.library import (
    devices_root,
    driver_path,
    list_devices,
    load_device,
    protocol_path,
)
from harald.workspace import append_note

FIXTURES = Path(__file__).parent / "fixtures" / "devices"
REPO = Path(__file__).resolve().parents[1]
KEY = "00112233445566778899aabbccddeeff"


@pytest.fixture
def root():
    return FIXTURES


def write_entry(root: Path, slug: str, toml: str) -> None:
    entry = root / slug
    entry.mkdir(parents=True)
    (entry / "device.toml").write_text(toml)


def test_loads_app_wide_key_device(root):
    meta = load_device("demo-lamp", root=root)
    assert meta.slug == "demo-lamp"
    assert meta.key_scope == "app-wide"
    assert meta.key_hex == KEY
    assert meta.cipher == "aes-ecb"
    assert meta.service_uuids == ["0000ffe0-0000-1000-8000-00805f9b34fb"]
    assert driver_path("demo-lamp", root=root) == root / "demo-lamp" / "driver.py"
    assert driver_path("demo-lamp", root=root).is_file()
    assert protocol_path("demo-lamp", root=root) == root / "demo-lamp" / "protocol.md"
    assert protocol_path("demo-lamp", root=root).is_file()


def test_per_unit_key_rejected(tmp_path):
    write_entry(
        tmp_path,
        "leaky",
        'name = "leaky"\nvendor = "x"\nstatus = "decoded"\n'
        f'key_scope = "none"\nkey_hex = "{KEY}"\n',
    )
    with pytest.raises(LibraryError) as e:
        load_device("leaky", root=tmp_path)
    assert "per-unit keys must not be published" in e.value.message
    assert "app-wide" in e.value.hint


@pytest.mark.parametrize(
    ("line", "message", "hint"),
    [
        ('cipher = "aes-128-ecb"', "unknown cipher: 'aes-128-ecb'", "aes-ecb"),
        ('cipher = "None"', "unknown cipher: 'None'", "leave cipher out"),
        ('status = "done"', "unknown status: 'done'", "in progress"),
        ('key_scope = "per-unit"', "unknown key_scope: 'per-unit'", "app-wide"),
        ('transport = "usb"', "unknown transport: 'usb'", "use ble or classic"),
    ],
)
def test_fields_with_fixed_values_are_checked(tmp_path, line, message, hint):
    field = line.split(" = ")[0]
    fields = {
        "name": '"lamp"',
        "vendor": '"x"',
        "status": '"decoded"',
        "key_scope": '"none"',
    }
    toml = "".join(f"{k} = {v}\n" for k, v in fields.items() if k != field) + line
    write_entry(tmp_path, "lamp", toml + "\n")
    with pytest.raises(LibraryError) as e:
        load_device("lamp", root=tmp_path)
    assert e.value.message == f"lamp: {message}"
    assert hint in e.value.hint


@pytest.mark.parametrize("cipher", ["aes-ecb", "aes-cbc-zero-iv"])
def test_every_driver_cipher_is_accepted(tmp_path, cipher):
    write_entry(
        tmp_path,
        "lamp",
        'name = "lamp"\nvendor = "x"\nstatus = "decoded"\nkey_scope = "app-wide"\n'
        f'key_hex = "{KEY}"\ncipher = "{cipher}"\n',
    )
    assert load_device("lamp", root=tmp_path).cipher == cipher


def test_cipher_none_is_the_same_as_leaving_it_out(tmp_path):
    entry = 'name = "lamp"\nvendor = "x"\nstatus = "wanted"\nkey_scope = "none"\n'
    write_entry(tmp_path, "lamp", entry + 'cipher = "none"\n')
    write_entry(tmp_path, "bare", entry)
    meta = load_device("lamp", root=tmp_path)
    assert meta.cipher is None
    assert meta == replace(load_device("bare", root=tmp_path), slug="lamp")


def test_missing_transport_means_ble(root):
    meta = load_device("demo-lamp", root=root)
    assert meta.transport == "ble"
    assert meta.name_hint == ""


def test_classic_transport_and_name_hint_load(tmp_path):
    write_entry(
        tmp_path,
        "headset",
        'name = "headset"\nvendor = "x"\nstatus = "wanted"\nkey_scope = "none"\n'
        'transport = "classic"\nname_hint = "acme hs"\n',
    )
    meta = load_device("headset", root=tmp_path)
    assert meta.transport == "classic"
    assert meta.name_hint == "acme hs"


def test_wanted_device_without_key_ok(root):
    meta = load_device("demo-fan", root=root)
    assert meta.status == "wanted"
    assert meta.key_scope == "none"
    assert meta.key_hex is None
    assert meta.cipher is None
    assert meta.service_uuids == []


def test_missing_required_field_raises(tmp_path):
    write_entry(
        tmp_path,
        "nameless",
        'vendor = "x"\nstatus = "wanted"\nkey_scope = "none"\n',
    )
    with pytest.raises(LibraryError) as e:
        load_device("nameless", root=tmp_path)
    assert "missing name" in e.value.message


def test_unknown_slug_raises_with_hint(root):
    with pytest.raises(LibraryError) as e:
        load_device("nope", root=root)
    assert "unknown device: nope" in e.value.message
    assert "harald devices" in e.value.hint


def test_list_devices_sorted(root):
    assert [d.slug for d in list_devices(root=root)] == ["demo-fan", "demo-lamp"]


def test_devices_root_resolves_in_dev_checkout():
    assert (REPO / "pyproject.toml").is_file()
    assert devices_root() == REPO / "devices"


def check_entries(root: Path | None = None) -> None:
    """The ci gate on a library: loading enforces the keys rule and the allowed
    values, and a decoded entry needs its protocol.md and driver.py. an entry that
    is wanted or in progress may be a device.toml alone."""
    for meta in list_devices(root=root):
        if meta.status == "decoded":
            assert driver_path(meta.slug, root=root).is_file(), meta.slug
            assert protocol_path(meta.slug, root=root).is_file(), meta.slug


def test_shipped_entries_valid():
    check_entries()  # the real devices/ library


def test_entry_gate_needs_files_only_when_decoded(tmp_path):
    base = 'name = "x"\nvendor = "x"\nkey_scope = "none"\n'
    write_entry(tmp_path, "fan", base + 'status = "wanted"\n')
    write_entry(tmp_path, "kettle", base + 'status = "in progress"\n')
    check_entries(tmp_path)
    write_entry(tmp_path, "lamp", base + 'status = "decoded"\n')
    (tmp_path / "lamp" / "driver.py").write_text("")
    with pytest.raises(AssertionError, match="lamp"):  # no protocol.md
        check_entries(tmp_path)
    (tmp_path / "lamp" / "protocol.md").write_text("")
    check_entries(tmp_path)


@pytest.mark.parametrize("slug", ["../x", "/tmp/x", "a/b", "", "Upper"])
def test_bad_slug_rejected_without_escaping_root(tmp_path, slug):
    root = tmp_path / "root"
    root.mkdir()
    target = root / slug
    target_existed = target.exists()
    before = sorted(tmp_path.rglob("*"))
    with pytest.raises(LibraryError) as e:
        load_device(slug, root=root)
    assert "invalid device slug" in e.value.message
    assert "lowercase letters" in e.value.hint
    with pytest.raises(LibraryError) as e:
        append_note(slug, "should not land anywhere", root=root, now=0)
    assert "invalid device slug" in e.value.message
    assert sorted(tmp_path.rglob("*")) == before
    assert target.exists() == target_existed
