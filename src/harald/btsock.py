"""Bluetooth sockets on linux, on any python, through ctypes.

uv's standalone pythons (what `uvx harald` usually runs on) are built without
`socket.AF_BLUETOOTH`, and python's own `connect` cannot pack an address for a family
it was built without. So harald never relies on it: a socket is made from the numeric
constants, which any linux python accepts, and connected through libc's `connect` with
a hand-packed `sockaddr_rc` or `sockaddr_l2`. Once connected it is a plain socket:
`send`, `recv` and `settimeout` work as usual.

The connect is non-blocking: `select` waits up to `timeout` for it, then `SO_ERROR`
says how it went. Every errno becomes a `BackendError` code through one table
(`error_code`), except that a connect refused with EACCES or EBADE means the gadget
rejected the pairing key (hci status 0x05 or 0x06), not a permission problem. A
connect refused with EBUSY or reset with ECONNRESET is made once more on a new socket,
within the same `timeout`: a closed channel stays the kernel's until the gadget
confirms the close (EBUSY until then), and closing the last channel to a gadget ends
the rfcomm session under it, so a connect made meanwhile is reset with it. The module
imports anywhere; connecting off linux raises `unsupported`.

`kernel_has_bluetooth` tells a linux with no bluetooth at all (a container, wsl) from
one whose bluetoothd is out of reach: it makes an rfcomm socket and closes it at once,
which sends nothing over the radio.
"""

from __future__ import annotations

import ctypes
import errno
import functools
import os
import select
import socket
import struct
import sys
import time
from collections.abc import Callable

from harald.arm import MAC_ADDRESS
from harald.classic import BackendError

AF_BLUETOOTH = 31
BTPROTO_L2CAP = 0
BTPROTO_RFCOMM = 3
SDP_PSM = 1
RETRY_PAUSE = 0.2  # seconds before a busy or reset connect is made again

_AGAIN = (errno.EBUSY, errno.ECONNRESET)  # worth one more try: see the docstring
_ERFKILL = getattr(errno, "ERFKILL", 132)  # linux's value; the mac has none
_EBADE = getattr(errno, "EBADE", 52)  # linux's value; the mac has none
NO_KERNEL_BLUETOOTH = "this linux kernel has no bluetooth support"
_CLOSED = "the channel is closed"

_CODES = {
    errno.EAFNOSUPPORT: "unsupported",
    errno.EPROTONOSUPPORT: "unsupported",
    errno.ENODEV: "bluetooth_off",
    errno.EADDRNOTAVAIL: "bluetooth_off",
    errno.ENETDOWN: "bluetooth_off",
    _ERFKILL: "bluetooth_off",
    errno.EHOSTDOWN: "not_connected",
    errno.EHOSTUNREACH: "not_connected",
    errno.EBUSY: "busy",
    errno.EADDRINUSE: "busy",
    errno.EALREADY: "busy",
    errno.ETIMEDOUT: "timeout",
    errno.EACCES: "permission",
    errno.EPERM: "permission",
}
_DETAILS = {
    errno.EAFNOSUPPORT: NO_KERNEL_BLUETOOTH,
    errno.EPROTONOSUPPORT: NO_KERNEL_BLUETOOTH,
    errno.ECONNREFUSED: "the gadget refused the connection",
    errno.ECONNRESET: _CLOSED,
    errno.EPIPE: _CLOSED,
    errno.ENOTCONN: _CLOSED,
}
# what a connect's errno means instead: a gadget that has forgotten the bond
_ON_CONNECT = {
    errno.EACCES: ("pairing", "the gadget rejected the pairing key"),
    _EBADE: ("pairing", "the gadget is missing the pairing key"),
}


def bdaddr(address: str) -> bytes:
    """The 6-byte `bdaddr_t` for a printed address: the kernel stores it reversed."""
    if not MAC_ADDRESS.fullmatch(address):
        raise ValueError(f"not a bluetooth address: {address!r}")
    return bytes.fromhex(address.replace(":", "").replace("-", ""))[::-1]


def sockaddr_rc(address: str, channel: int) -> bytes:
    """`struct sockaddr_rc`: family, bdaddr, channel, one pad byte (10 bytes)."""
    return struct.pack("<H6sBx", AF_BLUETOOTH, bdaddr(address), channel)


def sockaddr_l2(address: str, psm: int) -> bytes:
    """`struct sockaddr_l2`: family, psm, bdaddr, cid 0, br/edr type, a pad (14)."""
    return struct.pack("<HH6sHBx", AF_BLUETOOTH, psm, bdaddr(address), 0, 0)


def error_code(err: int, *, connecting: bool = False) -> tuple[str, str]:
    """The `BackendError` code and detail for errno `err` from a bluetooth socket;
    `connecting` when it came from `connect`, where it may be about the pairing key."""
    if connecting and err in _ON_CONNECT:
        return _ON_CONNECT[err]
    return _CODES.get(err, "failed"), _DETAILS.get(err) or os.strerror(err).lower()


def kernel_has_bluetooth() -> bool:
    """False if this kernel has no bluetooth sockets (EAFNOSUPPORT, EPROTONOSUPPORT).
    The rfcomm socket made to see is closed at once; any other failure to make it is
    no proof either way, so True."""
    try:
        sock = _new_socket(socket.SOCK_STREAM, BTPROTO_RFCOMM)
    except OSError as exc:
        return exc.errno not in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT)
    sock.close()
    return True


def connect_rfcomm(address: str, channel: int, *, timeout: float) -> socket.socket:
    """A blocking rfcomm stream socket connected to `channel` on `address`."""
    addr = sockaddr_rc(address, channel)
    return _open(socket.SOCK_STREAM, BTPROTO_RFCOMM, addr, timeout)


def connect_l2cap(address: str, psm: int, *, timeout: float) -> socket.socket:
    """A blocking l2cap seqpacket socket connected to `psm` on `address`."""
    addr = sockaddr_l2(address, psm)
    return _open(socket.SOCK_SEQPACKET, BTPROTO_L2CAP, addr, timeout)


def _open(type_: int, proto: int, addr: bytes, timeout: float) -> socket.socket:
    if sys.platform != "linux":
        raise BackendError("unsupported", "bluetooth sockets need linux")
    deadline = time.monotonic() + timeout
    retried = False
    while True:
        try:
            sock = _new_socket(type_, proto)
        except OSError as exc:
            raise BackendError(*error_code(exc.errno or 0)) from None
        try:
            sock.setblocking(False)
            err = _connect(sock.fileno(), addr)
            if err == errno.EINPROGRESS:
                left = max(0.0, deadline - time.monotonic()) if retried else timeout
                _, writable, _ = select.select([], [sock], [], left)
                if not writable:
                    raise BackendError("timeout", f"no connection in {timeout:g} s")
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err in _AGAIN and not retried:
                retried = True
                sock.close()
                time.sleep(RETRY_PAUSE)
                continue
            if err:
                raise BackendError(*error_code(err, connecting=True))
            sock.setblocking(True)
            return sock
        except BaseException:
            sock.close()
            raise


def _new_socket(type_: int, proto: int) -> socket.socket:
    return socket.socket(AF_BLUETOOTH, type_, proto)


@functools.cache
def _libc_connect() -> Callable[[int, bytes, int], int]:
    connect = ctypes.CDLL(None, use_errno=True).connect
    connect.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
    connect.restype = ctypes.c_int
    return connect


def _connect(fd: int, addr: bytes) -> int:
    """libc `connect(2)`: 0 once connected, else the errno it set."""
    return 0 if _libc_connect()(fd, addr, len(addr)) == 0 else ctypes.get_errno()
