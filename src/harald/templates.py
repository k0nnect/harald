"""Output templates: a protocol write-up and a standalone driver for one gadget.

Once an agent has verified a gadget's commands, it fills a `DriverSpec` and renders
`protocol.md` with `render_protocol` and `driver.py` with `render_driver`. Both come
from `string.Template` files in the `templates/` folder beside this module. The
driver is one self-contained script: inline script metadata, so that
`uv run driver.py ...` installs bleak and cryptography, its own argparse cli, and no
import of harald.
"""

from __future__ import annotations

import ast
import keyword
import re
from dataclasses import dataclass, replace
from importlib.resources import files
from string import Template

from bleak.uuids import normalize_uuid_str

from harald.analyze import AES_KEY_SIZES, MODES
from harald.errors import HaraldError
from harald.library import check_slug

_COMMAND_NAME = re.compile(r"[a-z][a-z0-9-]*")
_RESERVED_PARAMS = ("address", "command")  # the driver's own argparse names
_CIPHER_NAMES = {
    "aes-ecb": "aes in ecb mode",
    "aes-cbc-zero-iv": "aes in cbc mode with an all-zero iv",
}


@dataclass
class DriverCommand:
    """One verified command: a subcommand of the driver and how to build its payload.

    `payload_py` is one python expression over `params`, which arrive as strings from
    the command line, giving the plaintext bytes, for example
    `b"\\x7e\\x00\\x01" + bytes([int(level)])`. It may call `rgb_bytes(value)`, which
    turns a colour name such as pink, or 6-digit hex, into three bytes r, g, b.
    """

    name: str
    params: list[str]
    payload_py: str


@dataclass
class DriverSpec:
    """Everything both templates need.

    `cipher` is None, "aes-ecb" or "aes-cbc-zero-iv". With a cipher, `key_hex` is the
    aes key and every plaintext must be whole 16-byte blocks, since the driver adds
    no padding. An empty `address_hint` makes the driver scan for `service_uuid`.
    """

    slug: str
    name: str
    vendor: str
    address_hint: str
    service_uuid: str
    write_char_uuid: str
    cipher: str | None
    key_hex: str | None
    commands: list[DriverCommand]


def render_driver(spec: DriverSpec) -> str:
    """The standalone `driver.py` for `spec`, with one subcommand per command."""
    spec = _checked(spec)
    table = "\n".join(
        f"    {_literal(c.name)}: ({_function_name(c)}, {_literal(tuple(c.params))}),"
        for c in spec.commands
    )
    return _template("driver.py.tmpl").substitute(
        device=_literal(spec.name),
        vendor=_literal(spec.vendor),
        address_hint=_literal(spec.address_hint),
        service_uuid=_literal(spec.service_uuid),
        write_char_uuid=_literal(spec.write_char_uuid),
        cipher=_literal(spec.cipher),
        key_hex=_literal(spec.key_hex),
        commands="\n\n\n".join(_function_source(c) for c in spec.commands),
        command_table=table,
    )


def render_protocol(spec: DriverSpec) -> str:
    """The lowercase `protocol.md` for `spec`: uuids, cipher and each command's payload."""
    spec = _checked(spec)
    if spec.cipher is None:
        encryption = "none. payloads are written as they are."
        payload_note = "the result is written as it is."
    else:
        encryption = (
            f"- cipher: {spec.cipher} ({_CIPHER_NAMES[spec.cipher]})\n"
            f"- key: `{spec.key_hex}`\n"
            "- padding: none, so every plaintext is whole 16-byte blocks"
        )
        payload_note = (
            "the result is the plaintext, encrypted as above before it is written."
        )
    return _template("protocol.md.tmpl").substitute(
        slug=spec.slug,
        name=" ".join(spec.name.split()),
        vendor=" ".join(spec.vendor.split()) or "unknown",
        service_uuid=spec.service_uuid,
        write_char_uuid=spec.write_char_uuid,
        encryption=encryption,
        payload_note=payload_note,
        commands="\n\n".join(_protocol_section(c) for c in spec.commands),
    )


def _template(name: str) -> Template:
    path = files("harald") / "templates" / name
    return Template(path.read_text(encoding="utf-8"))


def _literal(value: str | tuple[str, ...] | None) -> str:
    """A python literal for `value`, in double quotes where repr would use single."""
    if isinstance(value, tuple):
        items = [_literal(item) for item in value]
        return f"({items[0]},)" if len(items) == 1 else f"({', '.join(items)})"
    text = repr(value)
    if isinstance(value, str) and not {'"', "'"} & set(value):
        text = f'"{text[1:-1]}"'  # no quotes inside, so only the delimiters change
    return text


def _function_name(command: DriverCommand) -> str:
    return "cmd_" + command.name.replace("-", "_")


def _function_source(command: DriverCommand) -> str:
    params = ", ".join(command.params)
    payload = command.payload_py.strip()
    return f"def {_function_name(command)}({params}):\n    return {payload}"


def _protocol_section(command: DriverCommand) -> str:
    usage = " ".join(["driver.py", command.name, *(f"<{p}>" for p in command.params)])
    payload = command.payload_py.strip()
    return f"### {command.name}\n\nusage: `{usage}`\n\n```python\n{payload}\n```"


def _checked(spec: DriverSpec) -> DriverSpec:
    """`spec` with full lowercase uuids and key, after refusing anything that would
    render a broken file."""
    check_slug(spec.slug)
    if spec.cipher is not None and spec.cipher not in MODES:
        raise HaraldError(
            f"unknown cipher: {spec.cipher}", hint=f"use None, {' or '.join(MODES)}"
        )
    key_hex = spec.key_hex or None
    if spec.cipher is None and key_hex is not None:
        raise HaraldError(
            "key_hex is set but cipher is None",
            hint=f"set cipher to {' or '.join(MODES)}, or leave key_hex as None",
        )
    if spec.cipher is not None:
        key_hex = _checked_key(spec.cipher, key_hex)
    if not spec.commands:
        raise HaraldError(
            "the driver needs at least one command",
            hint="add a DriverCommand for each command you verified",
        )
    names = [command.name for command in spec.commands]
    if len(set(names)) != len(names):
        raise HaraldError(
            "command names repeat", hint="give each DriverCommand its own name"
        )
    for command in spec.commands:
        _check_command(command)
    return replace(
        spec,
        service_uuid=_checked_uuid(spec.service_uuid),
        write_char_uuid=_checked_uuid(spec.write_char_uuid),
        key_hex=key_hex,
    )


def _checked_key(cipher: str, key_hex: str | None) -> str:
    try:
        key = bytes.fromhex(key_hex or "")
    except ValueError:
        key = b""
    if len(key) not in AES_KEY_SIZES:
        sizes = ", ".join(str(size) for size in AES_KEY_SIZES)
        raise HaraldError(
            f"{cipher} needs key_hex: an aes key of {sizes} bytes, as hex",
            hint="use the key that try_keys confirmed",
        )
    return key.hex()


def _checked_uuid(value: str) -> str:
    try:
        return normalize_uuid_str(value)
    except ValueError:
        raise HaraldError(
            f"invalid uuid: {value!r}",
            hint="use a uuid from connect, e.g. 0000ffe1-0000-1000-8000-00805f9b34fb",
        ) from None


def _check_command(command: DriverCommand) -> None:
    if not _COMMAND_NAME.fullmatch(command.name):
        raise HaraldError(
            f"invalid command name: {command.name!r}",
            hint="use lowercase letters, digits and hyphens, e.g. brightness",
        )
    for param in command.params:
        if (
            not param.isidentifier()
            or keyword.iskeyword(param)
            or param in _RESERVED_PARAMS
            or command.params.count(param) > 1
        ):
            raise HaraldError(
                f"invalid param for {command.name}: {param!r}",
                hint="use distinct python names such as level or color, "
                "other than address and command",
            )
    try:
        ast.parse(command.payload_py.strip(), mode="eval")
        compile(_function_source(command), command.name, "exec")
    except (SyntaxError, ValueError):  # ValueError: a null byte
        raise HaraldError(
            f"payload_py for {command.name} is not one python expression over its params",
            hint='e.g. b"\\x01\\x02" + bytes([int(level)])',
        ) from None
