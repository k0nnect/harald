"""harald.btsock: address packing, the errno table, and the connect dance.

Nothing here opens a bluetooth socket. The connect tests run on a fake socket through
the `_new_socket` and `_connect` seams, with `sys.platform` and `select.select`
patched; the one real libc call is made on an AF_UNIX socket.
"""

import errno
import os
import select
import socket
import struct
import sys

import pytest

from harald import btsock
from harald.classic import BackendError

ADDRESS = "aa:bb:cc:11:22:33"
FD = 7
ERFKILL = getattr(errno, "ERFKILL", 132)  # linux's value; the mac has none
EBADE = getattr(errno, "EBADE", 52)  # linux's value; the mac has none
REJECTED = "the gadget rejected the pairing key"


def test_constants():
    assert btsock.AF_BLUETOOTH == 31
    assert btsock.BTPROTO_L2CAP == 0
    assert btsock.BTPROTO_RFCOMM == 3
    assert btsock.SDP_PSM == 1


def test_bdaddr_reverses_the_printed_address():
    assert btsock.bdaddr(ADDRESS) == bytes.fromhex("332211ccbbaa")
    assert btsock.bdaddr("AA-BB-CC-11-22-33") == bytes.fromhex("332211ccbbaa")


def test_bdaddr_refuses_a_non_address():
    with pytest.raises(ValueError):
        btsock.bdaddr("aa:bb:cc:11:22")


def test_sockaddr_rc_layout():
    # struct sockaddr_rc: u16 family, bdaddr_t, u8 channel, one pad byte
    addr = btsock.sockaddr_rc(ADDRESS, 5)
    assert len(addr) == 10
    assert addr == struct.pack("<H6sBx", 31, btsock.bdaddr(ADDRESS), 5)
    assert addr == bytes.fromhex("1f00 332211ccbbaa 05 00")


def test_sockaddr_l2_layout():
    # struct sockaddr_l2: u16 family, le16 psm, bdaddr_t, le16 cid, u8 type, one pad
    addr = btsock.sockaddr_l2(ADDRESS, btsock.SDP_PSM)
    assert len(addr) == 14
    assert addr == struct.pack("<HH6sHBx", 31, 1, btsock.bdaddr(ADDRESS), 0, 0)
    assert addr == bytes.fromhex("1f00 0100 332211ccbbaa 0000 00 00")


CLOSED = "the channel is closed"


@pytest.mark.parametrize(
    ("err", "code", "detail"),
    [
        (errno.EAFNOSUPPORT, "unsupported", None),
        (errno.EPROTONOSUPPORT, "unsupported", None),
        (errno.ENODEV, "bluetooth_off", None),
        (errno.EADDRNOTAVAIL, "bluetooth_off", None),
        (errno.ENETDOWN, "bluetooth_off", None),
        (ERFKILL, "bluetooth_off", None),
        (errno.EHOSTDOWN, "not_connected", None),
        (errno.EHOSTUNREACH, "not_connected", None),
        (errno.EBUSY, "busy", None),
        (errno.EADDRINUSE, "busy", None),
        (errno.EALREADY, "busy", None),
        (errno.ETIMEDOUT, "timeout", None),
        (errno.EACCES, "permission", None),  # e.g. a sandbox refusing the socket
        (errno.EPERM, "permission", None),
        (errno.ECONNREFUSED, "failed", "the gadget refused the connection"),
        (errno.ECONNRESET, "failed", CLOSED),
        (errno.EPIPE, "failed", CLOSED),
        (errno.ENOTCONN, "failed", CLOSED),
        (errno.EIO, "failed", os.strerror(errno.EIO).lower()),
        (errno.EINVAL, "failed", os.strerror(errno.EINVAL).lower()),
    ],
)
def test_error_code(err, code, detail):
    got_code, got_detail = btsock.error_code(err)
    assert got_code == code
    assert got_detail and got_detail == got_detail.lower()
    if detail is not None:
        assert got_detail == detail


@pytest.mark.parametrize(
    ("err", "code", "detail"),
    [
        # a gadget that forgot the bond refuses the link key: hci 0x05 is EACCES,
        # 0x06 (pin or key missing) is EBADE
        (errno.EACCES, "pairing", REJECTED),
        (EBADE, "pairing", "the gadget is missing the pairing key"),
        (errno.EPERM, "permission", None),
        (errno.EHOSTDOWN, "not_connected", None),
        (errno.ECONNREFUSED, "failed", "the gadget refused the connection"),
    ],
)
def test_error_code_on_connect(err, code, detail):
    got_code, got_detail = btsock.error_code(err, connecting=True)
    assert got_code == code
    if detail is not None:
        assert got_detail == detail


def test_unsupported_errnos_name_a_kernel_without_bluetooth():
    for err in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
        detail = btsock.error_code(err)[1]
        assert "kernel" in detail and "bluetooth" in detail


class FakeSocket:
    def __init__(self) -> None:
        self.so_error = 0
        self.blocking = True
        self.closed = False

    def setblocking(self, flag: bool) -> None:
        self.blocking = flag

    def fileno(self) -> int:
        return FD

    def getsockopt(self, level: int, option: int) -> int:
        assert (level, option) == (socket.SOL_SOCKET, socket.SO_ERROR)
        return self.so_error

    def close(self) -> None:
        self.closed = True


class Rig:
    """Stands in for the kernel: records what btsock asks for, answers as told."""

    def __init__(self) -> None:
        self.sock = FakeSocket()
        self.later: list[FakeSocket] = []  # what each new socket after the first is
        self.socket_error: OSError | None = None
        self.connect_errno = 0
        self.connect_errnos: list[int] = []  # for the first connects, before that one
        self.writable = True
        self.wait_error: BaseException | None = None
        self.opened: list[tuple[int, int]] = []
        self.connects: list[tuple[int, bytes, bool]] = []  # fd, addr, blocking then
        self.waits: list[float] = []

    def new_socket(self, type_: int, proto: int) -> FakeSocket:
        self.opened.append((type_, proto))
        if self.socket_error:
            raise self.socket_error
        if len(self.opened) > 1:
            self.sock = self.later.pop(0)
        return self.sock

    def connect(self, fd: int, addr: bytes) -> int:
        self.connects.append((fd, addr, self.sock.blocking))
        if self.connect_errnos:
            return self.connect_errnos.pop(0)
        return self.connect_errno

    def select(self, rlist, wlist, xlist, timeout):
        assert (rlist, xlist) == ([], []) and wlist == [self.sock]
        self.waits.append(timeout)
        if self.wait_error:
            raise self.wait_error
        return [], (wlist if self.writable else []), []


@pytest.fixture
def rig(monkeypatch):
    rig = Rig()
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(btsock, "_new_socket", rig.new_socket)
    monkeypatch.setattr(btsock, "_connect", rig.connect)
    monkeypatch.setattr(select, "select", rig.select)
    return rig


def test_connect_rfcomm_opens_a_stream_socket(rig):
    sock = btsock.connect_rfcomm(ADDRESS, 5, timeout=3.0)
    assert sock is rig.sock
    assert rig.opened == [(socket.SOCK_STREAM, btsock.BTPROTO_RFCOMM)]
    assert rig.connects == [(FD, btsock.sockaddr_rc(ADDRESS, 5), False)]
    assert rig.waits == []  # connected at once: nothing to wait for
    assert sock.blocking and not sock.closed


def test_connect_l2cap_waits_for_a_connect_in_progress(rig):
    rig.connect_errno = errno.EINPROGRESS
    sock = btsock.connect_l2cap(ADDRESS, btsock.SDP_PSM, timeout=4.0)
    assert sock is rig.sock
    assert rig.opened == [(socket.SOCK_SEQPACKET, btsock.BTPROTO_L2CAP)]
    assert rig.connects == [(FD, btsock.sockaddr_l2(ADDRESS, 1), False)]
    assert rig.waits == [4.0]
    assert sock.blocking and not sock.closed


def test_a_connect_that_never_finishes_times_out(rig):
    rig.connect_errno = errno.EINPROGRESS
    rig.writable = False
    with pytest.raises(BackendError) as caught:
        btsock.connect_rfcomm(ADDRESS, 5, timeout=2.5)
    assert caught.value.code == "timeout"
    assert rig.waits == [2.5]
    assert rig.sock.closed


def test_so_error_goes_through_the_table(rig):
    rig.connect_errno = errno.EINPROGRESS
    rig.sock.so_error = errno.EHOSTDOWN
    with pytest.raises(BackendError) as caught:
        btsock.connect_rfcomm(ADDRESS, 5, timeout=2.0)
    assert caught.value.code == "not_connected"
    assert rig.sock.closed


def test_an_immediate_connect_error_closes_the_socket(rig):
    rig.connect_errno = errno.ECONNREFUSED
    with pytest.raises(BackendError) as caught:
        btsock.connect_l2cap(ADDRESS, btsock.SDP_PSM, timeout=2.0)
    assert caught.value.code == "failed"
    assert caught.value.detail == "the gadget refused the connection"
    assert rig.sock.closed


@pytest.mark.parametrize("err", [errno.EACCES, EBADE])
def test_an_immediate_connect_refused_for_its_key_is_pairing(rig, err):
    rig.connect_errno = err
    with pytest.raises(BackendError) as caught:
        btsock.connect_rfcomm(ADDRESS, 5, timeout=2.0)
    assert caught.value.code == "pairing"
    assert rig.sock.closed


@pytest.mark.parametrize("err", [errno.EACCES, EBADE])
def test_so_error_refused_for_its_key_is_pairing(rig, err):
    rig.connect_errno = errno.EINPROGRESS
    rig.sock.so_error = err
    with pytest.raises(BackendError) as caught:
        btsock.connect_l2cap(ADDRESS, btsock.SDP_PSM, timeout=2.0)
    assert caught.value.code == "pairing"
    assert rig.sock.closed


@pytest.mark.parametrize("err", [errno.EACCES, errno.EPERM])
def test_a_refused_socket_is_permission_not_pairing(rig, err):
    # a sandbox (apparmor, snap, selinux) that denies socket(AF_BLUETOOTH, ...)
    rig.socket_error = OSError(err, os.strerror(err))
    with pytest.raises(BackendError) as caught:
        btsock.connect_rfcomm(ADDRESS, 5, timeout=2.0)
    assert caught.value.code == "permission"
    assert rig.connects == []


def test_an_interrupted_wait_closes_the_socket(rig):
    rig.connect_errno = errno.EINPROGRESS
    rig.wait_error = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        btsock.connect_rfcomm(ADDRESS, 5, timeout=2.0)
    assert rig.sock.closed


@pytest.fixture
def pauses(monkeypatch):
    pauses: list[float] = []
    monkeypatch.setattr(btsock.time, "sleep", pauses.append)
    return pauses


def test_a_connect_reset_by_a_closing_link_is_made_once_more(rig, pauses):
    # closing the last channel to a gadget ends the rfcomm session under it, and a
    # connect made meanwhile joins that session and is reset with it (seen on the
    # linux rig, opening a channel right after closing one)
    first, again = rig.sock, FakeSocket()
    rig.later = [again]
    rig.connect_errno = errno.EINPROGRESS
    first.so_error = errno.ECONNRESET
    sock = btsock.connect_rfcomm(ADDRESS, 5, timeout=3.0)
    assert sock is again and sock.blocking and not sock.closed
    assert first.closed
    assert len(rig.connects) == 2 and pauses == [btsock.RETRY_PAUSE]
    assert rig.waits[0] == 3.0 and 0 <= rig.waits[1] <= 3.0  # one timeout for both


def test_a_connect_reset_twice_is_given_up(rig, pauses):
    again = FakeSocket()
    again.so_error = rig.sock.so_error = errno.ECONNRESET
    rig.later = [again]
    rig.connect_errno = errno.EINPROGRESS
    with pytest.raises(BackendError) as caught:
        btsock.connect_rfcomm(ADDRESS, 5, timeout=3.0)
    assert caught.value.code == "failed"
    assert len(rig.connects) == 2 and again.closed
    assert pauses == [btsock.RETRY_PAUSE]


def test_a_channel_harald_is_still_closing_is_opened_once_more(rig, pauses):
    # a closed channel stays the kernel's until the gadget confirms the close, so a
    # connect to it at once is refused with EBUSY (seen on the linux rig)
    first, again = rig.sock, FakeSocket()
    rig.later = [again]
    rig.connect_errnos = [errno.EBUSY]
    sock = btsock.connect_rfcomm(ADDRESS, 5, timeout=3.0)
    assert sock is again and sock.blocking and not sock.closed
    assert first.closed
    assert len(rig.connects) == 2 and pauses == [btsock.RETRY_PAUSE]


def test_a_channel_busy_twice_is_busy(rig, pauses):
    rig.later = [FakeSocket()]
    rig.connect_errno = errno.EBUSY
    with pytest.raises(BackendError) as caught:
        btsock.connect_rfcomm(ADDRESS, 5, timeout=3.0)
    assert caught.value.code == "busy"
    assert len(rig.connects) == 2 and rig.sock.closed
    assert pauses == [btsock.RETRY_PAUSE]


def test_a_kernel_without_bluetooth_is_unsupported(rig):
    rig.socket_error = OSError(errno.EAFNOSUPPORT, os.strerror(errno.EAFNOSUPPORT))
    with pytest.raises(BackendError) as caught:
        btsock.connect_rfcomm(ADDRESS, 5, timeout=2.0)
    assert caught.value.code == "unsupported"
    assert "kernel" in caught.value.detail and "bluetooth" in caught.value.detail
    assert rig.connects == []


def test_kernel_has_bluetooth_makes_one_socket_and_closes_it(rig):
    # an rfcomm socket that is made and closed at once: nothing goes over the radio
    assert btsock.kernel_has_bluetooth() is True
    assert rig.opened == [(socket.SOCK_STREAM, btsock.BTPROTO_RFCOMM)]
    assert rig.sock.closed
    assert rig.connects == []


@pytest.mark.parametrize("err", [errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT])
def test_a_kernel_without_bluetooth_has_none(rig, err):
    rig.socket_error = OSError(err, os.strerror(err))
    assert btsock.kernel_has_bluetooth() is False
    assert rig.connects == []


@pytest.mark.parametrize("err", [errno.EACCES, errno.EPERM, errno.EMFILE])
def test_any_other_socket_failure_is_no_proof_of_a_kernel_without_bluetooth(rig, err):
    rig.socket_error = OSError(err, os.strerror(err))
    assert btsock.kernel_has_bluetooth() is True


def test_off_linux_is_unsupported(rig, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    for connect, port in ((btsock.connect_rfcomm, 5), (btsock.connect_l2cap, 1)):
        with pytest.raises(BackendError) as caught:
            connect(ADDRESS, port, timeout=2.0)
        assert caught.value.code == "unsupported"
    assert rig.opened == []


def test_connect_reports_libc_errno():
    # a real connect(2) through ctypes, on a socket that can never take this address
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        err = btsock._connect(sock.fileno(), btsock.sockaddr_rc(ADDRESS, 1))
    assert err in errno.errorcode
