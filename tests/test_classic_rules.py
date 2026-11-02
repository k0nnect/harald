import pytest
from classic_fakes import XM5_ADDRESS, XM5_RECORDS

from harald.classic import (
    PROTECTED_CLASSES,
    ServiceRecord,
    mark,
    normalize_address,
    normalize_uuid,
    resolve,
)
from harald.errors import HaraldError, ProtectedChannel

HPC = "956c7b26-d49a-4ba8-b03f-b17d393cb6e2"
AIROHA = "8901dfa8-5c7e-4d8f-9f0c-c2b70683f5f0"
SPP = "00001101-0000-1000-8000-00805f9b34fb"


def test_normalize_address():
    assert normalize_address("AA-BB-CC-11-22-33") == "aa:bb:cc:11:22:33"
    assert normalize_address(" aa:bb:cc:11:22:33 ") == "aa:bb:cc:11:22:33"
    with pytest.raises(HaraldError, match="not a bluetooth classic address") as e:
        normalize_address("AA-11")
    assert "aa:bb:cc:11:22:33" in e.value.hint


def test_normalize_uuid():
    assert normalize_uuid("1101") == SPP
    assert normalize_uuid("0000111E") == "0000111e-0000-1000-8000-00805f9b34fb"
    assert normalize_uuid(HPC.upper()) == HPC


def test_protected_classes_are_full_uuids():
    assert "0000111e-0000-1000-8000-00805f9b34fb" in PROTECTED_CLASSES
    assert "00000000-deca-fade-deca-deafdecacaff" in PROTECTED_CLASSES
    assert SPP not in PROTECTED_CLASSES
    assert all(len(uuid) == 36 and uuid == uuid.lower() for uuid in PROTECTED_CLASSES)


def test_resolve_by_uuid_and_by_channel():
    t = resolve(XM5_RECORDS, "956C7B26-D49A-4BA8-B03F-B17D393CB6E2", XM5_ADDRESS)
    assert (t.channel, t.service_uuid, t.firmware_update) == (9, HPC, False)
    assert resolve(XM5_RECORDS, "9", XM5_ADDRESS).service_uuid == HPC


@pytest.mark.parametrize(
    "service, channel",
    [("1", 1), ("2", 2), ("30", 30), ("0x1e", 30)],  # hfp, headset, iap2, iap2 in hex
)
def test_protected_channels_refused(service, channel):
    with pytest.raises(ProtectedChannel) as e:
        resolve(XM5_RECORDS, service, XM5_ADDRESS)
    assert (
        e.value.message == f"channel {channel} on {XM5_ADDRESS} is a standard profile"
    )
    assert e.value.hint == (
        "harald only talks to vendor and serial-port channels; "
        f"pick another from: harald classic services {XM5_ADDRESS}"
    )


def test_unlisted_channel_and_unknown_uuid_refused():
    with pytest.raises(HaraldError) as e:
        resolve(XM5_RECORDS, "29", XM5_ADDRESS)
    assert e.value.message == f"channel 29 is not in {XM5_ADDRESS}'s service records"
    assert e.value.hint == f"run: harald classic services {XM5_ADDRESS} --refresh"

    with pytest.raises(HaraldError) as e:
        resolve(XM5_RECORDS, "1101", XM5_ADDRESS)  # spp, which the xm5 lacks
    assert e.value.message == f"service {SPP} not found on {XM5_ADDRESS}"
    assert e.value.hint == f"run: harald classic services {XM5_ADDRESS} --refresh"


def test_numbers_above_30_are_uuids():
    with pytest.raises(ProtectedChannel, match="channel 2 on"):
        resolve(XM5_RECORDS, "1108", XM5_ADDRESS)


@pytest.mark.parametrize("service", ["0", "31", "0x1f"])
def test_numbers_outside_channel_range_are_not_channels(service):
    with pytest.raises(HaraldError, match=f"service {service} not found on"):
        resolve(XM5_RECORDS, service, XM5_ADDRESS)


def test_uuid_on_more_than_one_channel_refused():
    records = [ServiceRecord("a", [HPC], 3), ServiceRecord("b", [HPC], 4)]
    with pytest.raises(HaraldError) as e:
        resolve(records, HPC, XM5_ADDRESS)
    assert e.value.message == (
        f"service {HPC} is on more than one channel of {XM5_ADDRESS}"
    )
    assert e.value.hint == "name the channel number instead"
    assert resolve(records, "4", XM5_ADDRESS).channel == 4


def test_airoha_channel_is_firmware_update_class():
    t = resolve(XM5_RECORDS, "21", XM5_ADDRESS)
    assert t.firmware_update and t.service_uuid == AIROHA
    assert resolve(XM5_RECORDS, AIROHA, XM5_ADDRESS).channel == 21


def test_firmware_update_uuid_wins_over_the_named_one():
    records = [ServiceRecord("vendor", [HPC], 5), ServiceRecord("tool", [AIROHA], 5)]
    t = resolve(records, HPC, XM5_ADDRESS)
    assert (t.channel, t.service_uuid, t.firmware_update) == (5, AIROHA, True)


def test_short_uuids_in_records_are_judged_by_their_full_form():
    records = [ServiceRecord("hfp", ["111E"], 5)]
    with pytest.raises(ProtectedChannel):
        resolve(records, "5", XM5_ADDRESS)
    assert mark(records)[0].protected


def test_channel_with_no_service_class_refused():
    records = [ServiceRecord("bare", [], 5)]
    with pytest.raises(HaraldError, match="channel 5 on .* lists no service class"):
        resolve(records, "5", XM5_ADDRESS)


def test_mark_flags_every_record_on_a_protected_channel():
    marked = mark(XM5_RECORDS)
    by_channel = {}
    for record in marked:
        by_channel.setdefault(record.channel, []).append(record)
    assert [r.protected for r in by_channel[2]] == [True, True]
    assert [(r.protected, r.firmware_update) for r in by_channel[9]] == [(False, False)]
    assert [(r.protected, r.firmware_update) for r in by_channel[21]] == [(False, True)]
    assert all(not r.protected for r in XM5_RECORDS)  # the input is left alone
