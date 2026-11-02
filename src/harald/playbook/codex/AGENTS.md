# harald

these instructions are for codex. when the user wants to control a bluetooth le or
bluetooth classic gadget they own from their own code instead of the vendor's app,
follow this method to work out its protocol. it uses harald's mcp tools (`scan`,
`connect`, `open_capture`, `diff`, `try_keys`, `classic_send` and the rest) and the
`harald` cli, which the human runs in their own terminal. if the tools are missing,
ask the human to add harald's mcp server (`harald mcp`) to codex's config.

follow the steps in order. nothing here is specific to one device.

## before you start

- scope: harald is for gadgets the user owns, for interoperability and research.
  do not use it on anyone else's device.
- install: the human runs `uv tool install harald` once, which puts the `harald` cli
  on their path; the commands below assume it. `uvx harald ...` runs harald without
  installing it, for a quick try.
- writes need the human. `write_char` and `classic_send` are refused until the
  human runs `harald arm <address> --writes n --minutes m` in their own terminal. no
  tool can arm, so ask, and never try to get around the gate. each write spends one
  from the budget, and so does each message `classic_send` sends. firmware-update
  services and channels stay blocked; never ask for `--allow-dfu`.
- never run `harald arm`, `harald write`, `harald drive` or a generated driver from
  your own shell, even if you can; the human runs them. never run
  `harald classic send` from your own shell either; use the `classic_send` tool.
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
- the human does the physical steps: phone, app, apk, pairing and arming. give them
  one instruction at a time and wait for them.

## the method

1. check harald's `devices/` library and known prior art before anything else.
   ask the human what the gadget is and to switch it on. call `scan` to find it and
   `connect` to list its services. a gadget that never shows in `scan` but does show
   in system settings > bluetooth on a mac, or on linux when the human runs
   `bluetoothctl scan on`, is most likely bluetooth classic: follow the classic
   branch at the end, which changes each step below. call `list_devices`, and
   `load_device` for any entry whose name or service uuids match. a `decoded` entry
   means the work is done: the human runs `harald drive <slug> ...` and you stop
   here. otherwise look for prior art: open-source drivers, integrations or write-ups
   for the same model or the same vendor app. treat what you find as hypotheses to
   check in step 6.

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
   `write_cmd`) at the moment of each action, usually all on one handle. a capture
   can also hold the phone's other connections, such as a watch; each line shows
   its connection as `c=0x...`, and handles only mean something within one
   connection. narrow with `conn` and `handle`, and page with `limit` and `offset`.
   match each write to the agreed action list by order and timing, and note its
   characteristic uuid. `device->phone` notifications show the gadget's replies and
   state. if the timeline warns that the gadget's connection had no gatt discovery,
   its handles are shown raw: ask the human to toggle the phone's bluetooth off and
   on, open the app, and capture again.

4. compare payloads and name their parts.
   group the writes by control and call `diff` on each group, for example every
   colour write. constant bytes are usually headers, opcodes and lengths; varying
   bytes carry the value. call `guess_checks` on single payloads to spot a trailing
   checksum or a length byte. many protocols wrap each message in a start byte and
   an end byte; for those, `guess_checks` also checks the byte before the end marker
   against the bytes after the start marker and reports `sum8 at -2 (framed)` or
   `xor8 at -2 (framed)`. if a frame escapes bytes that look like a marker, undo the
   escaping before `diff` and `guess_checks`. save one hypothesis per command with
   `save_note`: layout, value encoding and checksum. if `diff` reports
   `looks_encrypted` as true, or the varying bytes look random (they change with no
   pattern that follows the values you set), do step 5 next; otherwise skip it.

5. if the payloads look encrypted or their varying bytes look random, recover an
   app-wide key from the vendor app.
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
   harald lives in its own environment, as a uv tool or through uvx, so a plain
   `import harald` fails on your path. write a small python script, for example
   `harald-work/<slug>/render.py`, that builds a `DriverSpec` from
   `harald.templates` with one `DriverCommand` per command you verified in step 6,
   renders it with `render_protocol` and `render_driver`, and writes the results to
   `harald-work/<slug>/protocol.md` and `harald-work/<slug>/driver.py`. run it with
   `uvx --from harald python <script>`.
   a `DriverCommand` has a `name`, its `params` and a `payload_py`: one python
   expression over the params, which arrive as strings, giving the plaintext bytes.
   it may call `rgb_bytes(value)`, which turns a colour name such as pink, or
   6-digit hex, into three bytes. set `cipher` to `"aes-ecb"` or
   `"aes-cbc-zero-iv"` with the key in `key_hex`, or leave both `None`. the driver
   encrypts but never pads, so an encrypted plaintext must be whole 16-byte blocks.
   set `address_hint` to the address from `scan`; when it is empty the driver scans
   for `service_uuid`. compare the gadget's advertised `service_uuids` from `scan`
   with your `service_uuid`: many gadgets do not advertise their service, and then
   that scan cannot find them, so set `name_hint` to the start of the name `scan`
   showed, without any serial number, and the driver also matches by name. the
   protocol lists the service and characteristic uuids, the cipher and each
   command's payload. the driver has its own small cli, for example `on`, `off` and
   `brightness 50`, and does not import harald. the human runs it with
   `uv run harald-work/<slug>/driver.py <command>` and tells you what the gadget
   did. if they want to share it, it can become a `devices/<slug>/` entry
   (`device.toml`, `protocol.md`, `driver.py`) under the keys rule, so with an
   app-wide key or no key at all, and with an empty `address_hint`.

## bluetooth classic gadgets

some gadgets, often headphones, speakers and serial gadgets, are controlled over
bluetooth classic instead of bluetooth le. their vendor app talks to an rfcomm
channel, a plain byte stream, rather than to gatt characteristics. harald reaches
them on a mac or linux, through `classic_devices`, `classic_services`,
`classic_send` and `classic_listen`. follow the method above with these changes to
its steps; the rules in "before you start" still hold.

1. pair the gadget, then list its services.
   ask the human to pair the gadget. on a mac, they pair it in system settings >
   bluetooth and keep it connected there. on linux, they run these in their own
   terminal, in this order: `bluetoothctl pairable on` (without it, bluez makes a
   bond that is gone after the next disconnect), `bluetoothctl scan on` until the
   gadget shows up, then `bluetoothctl pair <address>` and
   `bluetoothctl trust <address>`. a gadget that has forgotten the pairing has to be
   paired again, on linux after `bluetoothctl remove <address>`; harald's hint says
   so. harald does not search for or pair classic devices, and `scan` only sees
   bluetooth le. call `classic_devices` for its address and whether it is connected
   now, then `classic_services` with that address; the human can run
   `harald classic devices` and `harald classic services <address>` to see the same.
   a mac reads the records from its own cache; on linux harald asks the gadget, so
   it has to be on and in range the first time. each record has a name, its service
   uuids, an rfcomm channel, and `protected` and `firmware_update` flags. protected
   channels carry standard profiles, such as hands-free, headset, file transfer
   (obex), phonebook, messages, sim access, dial-up and apple iap2, and harald never
   opens them. channels missing from `classic_services` are refused too, and
   `firmware_update` channels stay blocked; never ask for `--allow-dfu`. what is
   left is usually a few vendor services, each with its own 128-bit uuid, and the
   vendor app's control channel is one of them. if the records look empty or out of
   date, call `classic_services` again with `refresh=true`. then check
   `list_devices` and prior art as in step 1, matching on the name and on these
   service uuids.

2. capture the vendor app on an android phone.
   classic captures come from an android phone's btsnoop log. an iphone capture of a
   classic gadget shows only apple's iap2 wrapper, which harald can't unwrap yet;
   `open_capture` warns when it finds it. walk the human through it:
   - turn on developer options on the phone (tap the build number seven times in
     its about screen), then the bluetooth hci snoop log in them, choosing enabled
     rather than filtered if it asks.
   - with the vendor app closed, turn the phone's bluetooth off and on, so the log
     is running before the app opens its channel.
   - open the vendor app and do the agreed actions one at a time, as in step 2.
   - with usb debugging on, get the log off the phone, for example with
     `adb bugreport`, whose zip holds `btsnoop_hci.log`, and give you that file's
     path.
   - afterwards, turn the bluetooth hci snoop log and usb debugging off again, and
     share only the extracted `btsnoop_hci.log`: a bugreport zip holds personal data
     from all over the phone.
   with no android phone there is no capture: go to step 5 below and lean on the apk
   and on prior art.

3. find the messages in the capture.
   `open_capture` shows rfcomm events alongside att ones: `rfcomm_open` and
   `rfcomm_close` when a channel opens and closes, and `rfcomm` for data, each with
   its server channel as `ch=N`. narrow with `channel` as well as `conn`. captures
   hold no service uuids, so match `ch=` to the channel `classic_services` lists for
   each vendor service. look for `phone->device` data at the moment of each action
   and for the gadget's `device->phone` replies. if the timeline warns that rfcomm
   traffic has no captured setup, ask the human to capture again, with the log
   running before they open the app.

4. compare payloads as in step 4.
   classic protocols often frame each message with start and end bytes and a
   checksum, escape bytes that look like a marker, and number their data messages so
   the other side can ack each one. tell data messages from acks, and note how the
   phone acks the gadget's messages: you will have to do the same. a gadget often
   sends an unacked message again after a moment, so the same frame twice in a row
   is a resend, not a new message.

5. read the apk when there is no capture or the payloads look encrypted.
   `analyze_apk` works as in step 5 and also flags `rfcomm-uuid` candidates, the
   uuids the app hands to rfcomm, and `rfcomm-socket` candidates, the calls that
   open the socket. match those uuids against `classic_services`, then follow the
   socket to the code that writes to it: that is where the app builds, frames and
   acks its messages.

6. ask the human to arm, then prove control with `classic_send`.
   ask the human to close the vendor app on the phone, which may hold the channel,
   and to run `harald arm <address> --writes 20 --minutes 15` in their own terminal,
   with the address from `classic_devices`. `classic_send` takes that address, a
   `service` (the service uuid or channel number from `classic_services`),
   `messages_hex` and `listen`. every message spends one write, a query too, because
   classic has no read. all messages go over one connection, in order, with `listen`
   seconds of listening after each, so a handshake, the command and the acks you owe
   the gadget all go in as extra messages of one call. `received` lists what came
   back, each chunk with `after`, the message it followed (0 means before the
   first), its `seconds` and its `value_hex`. `writes_left` is the budget that
   remains, and `stopped` says why a call ended early: the budget ran out, or the
   link failed. each message goes out only after the previous one's `listen`
   seconds, and a gadget that wants acks sends its message again when the ack is
   late, so when your messages include acks, keep `listen` short, for example 0.3.
   the last message's `listen` must still be long enough to cover its reply, which
   is lost once the channel closes; a late ack is harmless, because the gadget just
   sends its frame again.
   `classic_listen` opens the channel, sends nothing and needs no arm: use it to
   hear what the gadget says on its own. it opens its own connection, so it cannot
   see the replies to a `classic_send`.
   the rest of step 6 holds: new values only, harmless and reversible commands
   first, and stop to rethink after a few failures. never repeat a command whose
   purpose you don't know; some gadgets take firmware over the same channel. never
   send anything that looks like a firmware update or a reset, even if the app or
   prior art has it. if the channel keeps failing to open on a mac, ask the human
   to check that the gadget is connected to the mac, then to turn the mac's
   bluetooth off and on; on linux, ask them to do what harald's hint says.

7. render a classic driver.
   build the `DriverSpec` as in step 7, with `transport="classic"`, `service_uuid`
   set to the vendor service's uuid from `classic_services` and `write_char_uuid`
   left empty. set `name_hint` to the start of the paired name without any serial
   number, and `address_hint` to the address from `classic_devices`, or leave it
   empty. `init_payloads` lists hex messages the driver writes as they are, never
   encrypted, right after opening the channel and before the command's payload, for
   example a fixed handshake. `reply_seconds`, from 0 to 30, is how long the driver
   waits to print what the gadget sends back; 0 prints nothing. the driver finds the
   gadget by `address_hint`, else by a paired name that starts with `name_hint`,
   else by `service_uuid` when exactly one paired device lists it. it runs on a mac
   or linux, with the gadget paired, and on a mac connected too. a rendered driver
   sends fixed bytes, so it keeps no state: a protocol with changing sequence
   numbers, acks for the gadget's messages, or a handshake whose reply decides what
   comes next needs a hand-written driver instead. start from a rendered one and
   keep its shape: the uv script header, its own small cli, no harald import, and no
   firmware or reset commands. say in `protocol.md` what state it keeps.
