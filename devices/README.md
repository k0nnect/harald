# devices

the harald device library: gadgets whose bluetooth le protocol has been worked out.
it ships inside the wheel as `harald/devices/`.

one entry per `devices/<slug>/`:

- `device.toml` - name, vendor, status (`decoded`, `in progress`, `wanted`), key scope, service uuids, summary
- `protocol.md` - the protocol, written up
- `driver.py` - a standalone driver, run with `harald drive <slug> ...`

keys rule: an entry may only carry an app-wide key (`key_scope = "app-wide"`), one
that is identical on every unit and shipped in the vendor app. never publish
per-unit keys or pairing keys. harald refuses to load an entry that does.
