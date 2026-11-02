# contributing

the most useful thing you can send is a device: a bluetooth le or classic gadget whose
protocol you worked out, so the next owner can control it without starting from
nothing. bug fixes and clearer docs are welcome too.

## adding a device

each device is one folder, `devices/<slug>/`. the slug uses lowercase letters, digits
and hyphens, for example `demo-lamp`. the folder holds three files:

- `device.toml`: what the device is.
- `protocol.md`: the protocol, written up: service and characteristic uuids (the
  rfcomm service uuid for a bluetooth classic gadget), the cipher if there is one,
  and each command's payload.
- `driver.py`: a standalone driver with its own small cli. it must not import harald.

```toml
name = "demo lamp"
vendor = "example co"
status = "decoded"            # decoded, in progress or wanted
transport = "ble"             # ble or classic; ble when left out
key_scope = "app-wide"        # app-wide, or none when there is no key
key_hex = "00112233445566778899aabbccddeeff"
cipher = "aes-ecb"            # aes-ecb or aes-cbc-zero-iv; leave out when there is none
service_uuids = ["0000ffe0-0000-1000-8000-00805f9b34fb"]
name_hint = "DEMO-LAMP"       # optional: the start of the name the gadget shows
summary = "rgb lamp whose colour writes are encrypted with an app-wide key"
```

a bluetooth classic gadget sets `transport = "classic"`, and its `service_uuids` holds
the vendor's rfcomm service uuid, the one `harald classic services` lists for its
control channel. set `name_hint` to the start of its paired name, without any serial
number:

```toml
name = "demo speaker"
vendor = "example co"
status = "decoded"
transport = "classic"
key_scope = "none"
service_uuids = ["5d2f8a10-7c3e-4b9a-a6d1-0e4f2c8b9a37"]
name_hint = "DEMO-SPK"
summary = "speaker whose volume and eq are set over a vendor rfcomm channel"
```

the playbook leaves your agent's work in `harald-work/<slug>/` (`protocol.md` and
`driver.py`); copy those over and add `device.toml`. before you open a pull request:

1. set `ADDRESS_HINT` in `driver.py` to `""`, so it scans instead of using your own
   unit's address. the scan looks for the service uuid, and for a name starting with
   `NAME_HINT` when that is set, for gadgets that don't advertise their service. a
   classic driver looks through the devices paired with this computer instead, on a
   mac or linux: for a name starting with `NAME_HINT`, else for the one device that
   lists the service uuid.
2. from your checkout, run `uv run harald drive <slug> <command>` against the real
   gadget, using values the vendor app's capture never contained. replaying captured
   bytes does not count as decoded.
3. run `uv run pytest -q`. a test loads every entry in `devices/`, so a broken entry,
   a decoded entry without its `protocol.md` or `driver.py`, or a key that breaks the
   keys rule fails ci. a `wanted` or `in progress` entry may be a `device.toml` alone.

## the keys rule

some gadgets encrypt their commands. a `devices/` entry may carry a key only when it
is app-wide: identical on every unit, and shipped inside the vendor app that anyone
can download. set `key_scope = "app-wide"` for it.

never publish per-unit keys or pairing keys. that includes keys derived from one
unit's address or serial, keys created when you pair, and keys a vendor server hands
out. they stay in your own `harald-work/<slug>/`. harald refuses to load an entry
that has a key with any other scope, and reviewers check every entry by hand as well.

## takedowns

every device lives entirely inside its own folder, and nothing else in harald depends
on it. if a vendor asks for an entry to be taken down, it is handled by removing that
one folder. vendors can open an issue naming the folder.

## code changes

```sh
uv sync
uv run pytest -q
uv run ruff check
```

tests use fakes and recorded captures; ci never touches a radio. keep `src/harald/`
free of hints about any one device (a test checks), and keep every cli and mcp message
lowercase with no emojis.

## commits

commits on `main` are authored as `k0nnect`, the maintainer. please write yours in the
same style: lowercase conventional messages such as `feat: add demo-lamp driver` or
`fix: keep generated driver help lowercase`, and no ai attribution lines, so no
`co-authored-by` trailers for tools.
