# harald

these instructions are for codex. when the user wants to control a bluetooth le
gadget they own from their own code instead of the vendor's app, follow this method
to work out its protocol. it uses harald's mcp tools (`scan`, `connect`,
`open_capture`, `diff`, `try_keys` and the rest) and the `harald` cli, which the
human runs in their own terminal. if the tools are missing, ask the human to add
harald's mcp server (`harald mcp`) to codex's config.

follow the steps in order. nothing here is specific to one device.

## before you start

- scope: harald is for gadgets the user owns, for interoperability and research.
  do not use it on anyone else's device.
- writes need the human. `write_char` is refused until the human runs
  `harald arm <address> --writes n --minutes m` in their own terminal. no tool can
  arm, so ask, and never try to get around the gate. each write spends one from the
  budget. firmware-update services stay blocked; never ask for `--allow-dfu`.
- never run `harald arm`, `harald write`, `harald drive` or a generated driver from
  your own shell, even if you can; the human runs them.
- one connection per call. `connect`, `read_char`, `write_char` and `subscribe` each
  open their own connection and close it afterwards. gadgets often accept only one
  connection at a time, so the vendor app on the phone must be closed while you
  work. a `subscribe` call cannot see the reply to a write made by another call.
- keys rule: only app-wide keys may ever go into `devices/`. these are keys that are
  identical on every unit and ship in the vendor app. per-unit keys and pairing keys
  never go there; they stay in the user's own `harald-work/<slug>/`.
- failures come back as `{"error": ..., "hint": ...}` from tools and as `error:` and
  `hint:` lines from the cli. act on the hint.
- pick a slug for the gadget early: lowercase letters, digits and hyphens, e.g.
  `demo-lamp`. record findings with `save_note` as you go, and call `read_notes`
  first when you pick the work up again.
- the human does the physical steps: phone, app, apk and arming. give them one
  instruction at a time and wait for them.

## the method

1. check harald's `devices/` library and known prior art before anything else.
   ask the human what the gadget is and to switch it on. call `scan` to find it and
   `connect` to list its services. call `list_devices`, and `load_device` for any
   entry whose name or service uuids match. a `decoded` entry means the work is
   done: the human runs `harald drive <slug> ...` and you stop here. otherwise look
   for prior art: open-source drivers, integrations or write-ups for the same model
   or the same vendor app. treat what you find as hypotheses to check in step 6.

2. have the human record the vendor app talking to the gadget.
   a computer cannot overhear phone-to-gadget traffic without extra hardware, so the
   log comes from the phone itself. walk the human through it:
   - install apple's bluetooth logging profile on the iphone, from apple's
     developer "profiles and logs" page.
   - record with packetlogger (in additional tools for xcode, choose new ios trace
     from the file menu, with the iphone connected by cable), or with
     `idevicebtlogger`.
   - in the vendor app, do one action at a time, a few seconds apart, in an order
     you agreed on beforehand. use several distinct values per control, for example
     three colours and three brightness levels, plus off and on.
   - stop, save the `.pklg` file and give you its path.
   if packetlogger records nothing, removing and reinstalling the logging profile
   usually fixes it. a btsnoop log from an android phone works too.

3. open the capture and find the writes.
   call `open_capture` with the path; the human can run `harald capture open <path>`
   to see the same timeline. look for `phone->device` writes (`write_req` or
   `write_cmd`) at the moment of each action, usually all on one handle. narrow with
   `handle` and page with `limit` and `offset`. match each write to the agreed
   action list by order and timing, and note its characteristic uuid.
   `device->phone` notifications show the gadget's replies and state. if the
   timeline warns that there was no gatt discovery, handles are shown raw: ask the
   human to toggle the phone's bluetooth off and on, open the app, and capture again.

4. compare payloads and name their parts.
   group the writes by control and call `diff` on each group, for example every
   colour write. constant bytes are usually headers, opcodes and lengths; varying
   bytes carry the value. call `guess_checks` on single payloads to spot a trailing
   checksum or a length byte. save one hypothesis per command with `save_note`:
   layout, value encoding and checksum. if `diff` reports `looks_encrypted` as true,
   do step 5 next; otherwise skip it.

5. if the payloads look encrypted, recover an app-wide key from the vendor app.
   ask the human for the apk of the vendor app they already use. they can download
   it from apkmirror, which verifies signatures, or with `apkeep`. harald never
   downloads apps. call `analyze_apk` on the file; the human can run
   `harald apk <path>`. for a native app it lists gatt uuids and file:line
   candidates under the jadx output: open them and look for aes keys,
   `SecretKeySpec` and the code that builds commands. flutter and react native apps
   compile their logic, so the jadx output will not contain it, and `harald apk`
   says so. then tell the human, and do not widen the scope on your own.
   test candidate keys with `try_keys`, passing several distinct payloads, for
   example different colours or levels. one payload, or identical copies, makes
   every key look right. the right key gives plaintexts with clear structure; run
   step 4 on them. a key built into the app and the same on every unit is app-wide.
   a key derived per unit, from pairing or from the device address, or fetched from
   a server, is not, and never goes into `devices/`.

6. ask the human to arm, then prove real control with new values.
   ask the human to close the vendor app and run
   `harald arm <address> --writes 20 --minutes 15` in their own terminal, with the
   address from `scan`. wait until they say it is done. build payloads for values
   the capture never contained, for example a colour or level nobody picked in the
   app, encode them the way you worked out (checksum, encryption), and send them
   with `write_char`. ask the human what the gadget did. replaying captured bytes
   proves nothing, so it does not count. start with harmless, reversible commands,
   write only to the characteristic you identified, and after a few failed writes
   stop and rethink instead of trying variations. if the budget runs out, ask the
   human to arm again.

7. write the protocol and a standalone driver.
   fill harald's templates (`harald.templates`: a `DriverSpec` with one
   `DriverCommand` per verified command, rendered by `render_protocol` and
   `render_driver`) to produce `harald-work/<slug>/protocol.md` and a standalone
   `harald-work/<slug>/driver.py`. the protocol lists the service and
   characteristic uuids, the cipher and each command's payload layout. the driver
   has its own small cli, for example `on`, `off` and `brightness 50`, and does not
   import harald. include only commands you verified in step 6. the human runs it
   with `uv run harald-work/<slug>/driver.py <command>` and tells you what the
   gadget did. if they want to share it, it can become a `devices/<slug>/` entry
   (`device.toml`, `protocol.md`, `driver.py`) under the keys rule: an app-wide key,
   or no key at all.
