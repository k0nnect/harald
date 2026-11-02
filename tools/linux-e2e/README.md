# linux end-to-end rig

harald's linux support, run for real against a fake gadget, with no bluetooth hardware and without touching the mac's own bluetooth. a lima vm runs ubuntu with bluez. bluez's emulator, `btvirt`, makes two linked virtual controllers: one is the vm's `hci0`, which bluetoothd and harald use; the other is driven by `gadget.py`, a bumble host that plays a dual-mode gadget. harald is installed from your working tree into a venv made from uv's own cpython 3.13, which has no `socket.AF_BLUETOOTH`, the python `uvx harald` usually gets.

## run it

on a mac with lima (`brew install lima`), from the repo root:

```sh
tools/linux-e2e/run.sh          # everything; exit 0 only if every check passed
tools/linux-e2e/run.sh down     # stop the gadget and btvirt (the vm keeps running)
tools/linux-e2e/run.sh shell    # a shell in the vm
limactl stop harald-linux       # stop the vm; limactl delete harald-linux removes it
```

`run.sh` creates the vm `harald-linux` if it is missing (`template:ubuntu-26.04`, vz, 4 cpus, 4 GiB, nothing from the mac mounted) and starts it if it is stopped. it then copies in the files git tracks or would track (`git ls-files -co --exclude-standard`, uncommitted edits included, ignored files never), provisions the vm once, restarts btvirt and the gadget, installs harald from the copied tree and runs `check.py`. set `HARALD_E2E_VM` to use another vm name and `LIMACTL` to use another limactl.

a run takes about 80 seconds with the vm up and set up. creating and provisioning a new vm adds about a minute when lima has the ubuntu image cached, plus its download the first time.

## the files

- `run.sh`: the mac side, described above.
- `vm.sh`: the vm side. `setup` installs bluez, bluez-test-tools (btvirt), uv and the rig's own venv with bumble 0.0.236 and bleak 3.0.2 (pinned); it runs again only when its own steps change. `up` (re)starts the transient units `harald-btvirt` (`btvirt -l1 -t`, root) and `harald-gadget`, `down` stops them, `check` installs harald and runs `check.py`.
- `gadget.py`: the fake gadget. classic `00:AA:01:01:00:43`, le `C0:DE:CA:FE:00:01`, named `harald-gadget`. its sdp records: a vendor service `956c7b26-d49a-4ba8-b03f-b17d393cb6e2` on rfcomm channel 9, spp (0x1101) on channel 3 and hands-free (0x111e) on channel 7. channels 9 and 3 echo each chunk behind the byte `ee` and hang up on `de ad`; channel 3 says `hello` when it opens; channel 9 also answers enough of sony's mdr framing for the wh-1000xm5 driver. its gatt service `68617261-6c64-4000-8000-000000000000` has a read (`harald-read`), a write and a notify characteristic.
- `check.py`: the checks.

the addresses stay the same because a fresh btvirt numbers its clients from 1, and `up` always restarts btvirt and the gadget together. the gadget keeps its link keys in `/opt/rig/gadget-keys.json`.

## what it checks

each check prints `PASS` or `FAIL` and a short detail; a table follows at the end.

- the python is uv's cpython 3.13 and lacks `socket.AF_BLUETOOTH`; the installed harald matches the copied tree.
- rig setup: the gadget is forgotten, then paired (just works) and trusted with `bluetoothctl`, as a person would.
- `harald classic devices` lists the gadget as paired.
- `harald classic services` shows the vendor, spp and hands-free records on channels 9, 3 and 7, hands-free flagged protected.
- `harald classic send` gets the gadget's echo for each message and spends exactly one arm write per message, by service uuid and by channel number.
- `harald classic listen` hears the spp greeting and spends nothing.
- hands-free is refused as protected (send by uuid and by number, listen), and the gadget never sees that channel open.
- a send with nothing armed is refused before it reaches the gadget.
- the gadget hanging up partway through a send keeps what was sent and received.
- `harald mcp` over stdio: `classic_services`, `classic_send` (echo, one write), and both refusals.
- a classic driver rendered from a `DriverSpec` for the vendor service runs under `uv run` on uv's python: found by name over d-bus, its channel over sdp, then rfcomm.
- `harald drive wh-1000xm5 --address 00:aa:01:01:00:43 battery` and `status` against the gadget's mdr framing.
- ble: `harald scan` finds the gadget, `harald connect` lists its service, `harald read`, `harald write` refused unarmed and allowed once armed, and the mcp `subscribe` tool gets a notification.
- closing a linux channel: the whole `classic send --listen 0` command, and in process an idle close, a close that wakes a blocked drain, a close mid-reply and a cancelled `classic.send`, each under 1 s with no reader thread or file descriptor left behind. then twelve `classic.send` calls back to back on one backend, as an mcp server makes them, each opening the channel the last one has only just closed.
- with the adapter powered off, `classic devices` and `scan` give a hint, never a traceback.

arming happens inside `check.py` with `harald.arm.arm()` and a throwaway `HARALD_HOME`, which the harald commands it runs share. nothing runs `harald arm` or answers its prompt; a second, empty `HARALD_HOME` gives the unarmed checks.

## limits

a virtual controller is not a radio: no timing, link loss or chip quirks, instant inquiry and paging, and just works pairing only. the le side uses its own random address, so dual-mode gadgets that share one address are not covered. btvirt, the transient units and the journal need root in the vm; harald itself runs unprivileged.
