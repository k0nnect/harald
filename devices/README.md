# devices

the harald device library: bluetooth le and classic gadgets whose protocol has been
worked out. it ships inside the wheel as `harald/devices/`.

one entry per `devices/<slug>/`:

- `device.toml` - name, vendor, status (`decoded`, `in progress`, `wanted`), key scope, service uuids, summary,
  transport (`ble` or `classic`; leave it out for `ble`), and an optional `name_hint`, the
  start of the name the gadget shows, for finding it without an address
- `protocol.md` - the protocol, written up
- `driver.py` - a standalone driver, run with `harald drive <slug> ...`

keys rule: an entry may only carry an app-wide key (`key_scope = "app-wide"`), one
that is identical on every unit and shipped in the vendor app. never publish
per-unit keys or pairing keys. harald refuses to load an entry that does.
