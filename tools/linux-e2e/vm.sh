#!/bin/sh
# The vm side of harald's linux rig. run.sh calls it inside the vm, as the lima user;
# it uses sudo for the rig itself (packages, modules, btvirt), never for harald.
#
#   sh vm.sh setup   install bluez, btvirt, uv and the rig's venv (skipped once done)
#   sh vm.sh up      (re)start btvirt and the gadget; wait until both are ready
#   sh vm.sh down    stop the gadget and btvirt
#   sh vm.sh check   install harald from the shipped tree with uv's python 3.13,
#                    then run check.py with it; exit 0 only if every check passed
#
# btvirt (bluez's emulator) owns two linked virtual controllers in one process:
#   hci0                      -> the kernel, through /dev/vhci; bluetoothd and harald
#   tcp 127.0.0.1:45550 (h4)  -> a second controller, which gadget.py drives
# Both run as transient systemd units: harald-btvirt (root) and harald-gadget (lima
# user). Logs: sudo journalctl -u harald-gadget -u harald-btvirt
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(cd "$HERE/../.." && pwd)"
RIG=/opt/rig
UV="$HOME/.local/bin/uv"
export PATH="$HOME/.local/bin:$PATH"
BUMBLE="bumble==0.0.236"
BLEAK="bleak==3.0.2"

setup() {
  stamp="$RIG/setup.stamp"
  want="$({ grep -E '^(BUMBLE|BLEAK)=' "$0"; sed -n '/^setup() {/,/^}/p' "$0"; } |
    sha256sum | cut -c1-16)"
  if [ "$(cat "$stamp" 2>/dev/null)" = "$want" ]; then
    echo "setup: already done"
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -qq
  # bluez: bluetoothd and bluetoothctl; bluez-test-tools: btvirt, the emulator
  sudo apt-get install -y -qq bluez bluez-test-tools curl >/dev/null
  # bluetooth core, rfcomm sockets and /dev/vhci. ubuntu 26.04's -generic kernel
  # ships them in linux-modules; older or cloud kernels need linux-modules-extra
  if ! sudo modprobe -a bluetooth rfcomm hci_vhci 2>/dev/null; then
    sudo apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null
    sudo modprobe -a bluetooth rfcomm hci_vhci
  fi
  printf 'bluetooth\nrfcomm\nhci_vhci\n' |
    sudo tee /etc/modules-load.d/harald-rig.conf >/dev/null
  sudo systemctl enable --now bluetooth
  if [ ! -x "$UV" ]; then
    curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
  fi
  sudo mkdir -p "$RIG"
  sudo chown "$(id -u):$(id -g)" "$RIG"
  # the gadget's host stack (bumble) and the ble client it was proven with (bleak)
  [ -x "$RIG/venv/bin/python" ] ||
    "$UV" venv -q --managed-python --python 3.13 "$RIG/venv"
  "$UV" pip install -q --python "$RIG/venv/bin/python" "$BUMBLE" "$BLEAK"
  "$UV" python install -q 3.13
  echo "$want" >"$stamp"
  echo "setup: kernel $(uname -r), $(bluetoothctl --version), $BUMBLE, $BLEAK"
}

up() {
  sudo modprobe -a bluetooth rfcomm hci_vhci
  sudo systemctl start bluetooth
  down
  # a fresh btvirt numbers its tcp clients from 1 again, so the gadget's classic
  # address is always 00:AA:01:01:00:43 (and hci0's 00:AA:01:00:00:00)
  sudo systemd-run --quiet --unit=harald-btvirt "$(command -v btvirt)" -l1 -t
  i=0
  until bluetoothctl list 2>/dev/null | grep -q 00:AA:01:00:00:00 &&
    ss -ltn 2>/dev/null | grep -q 127.0.0.1:45550; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || { echo "up: hci0 or btvirt did not come up"; exit 1; }
    sleep 0.1
  done
  bluetoothctl pairable on >/dev/null # else the kernel pairs with "no bonding"
  bluetoothctl power on >/dev/null
  since="$(date '+%Y-%m-%d %H:%M:%S')"
  sudo systemd-run --quiet --unit=harald-gadget --uid="$(id -u)" --gid="$(id -g)" \
    --setenv=PYTHONUNBUFFERED=1 --setenv=HARALD_GADGET_KEYS="$RIG/gadget-keys.json" \
    "$RIG/venv/bin/python" "$HERE/gadget.py"
  i=0
  until sudo journalctl -u harald-gadget --since "$since" -o cat 2>/dev/null |
    grep -q '^READY'; do
    i=$((i + 1))
    if [ "$i" -ge 150 ]; then
      echo "up: the gadget did not become ready"
      sudo journalctl -u harald-gadget -n 30 -o cat
      exit 1
    fi
    sleep 0.1
  done
  echo "up: $(sudo journalctl -u harald-gadget --since "$since" -o cat | grep '^READY')"
}

down() {
  for unit in harald-gadget harald-btvirt; do
    sudo systemctl stop "$unit" 2>/dev/null || true
    sudo systemctl reset-failed "$unit" 2>/dev/null || true
  done
}

check() {
  venv="$RIG/harald-venv"
  rm -rf "$venv"
  # uv's own cpython, built without socket.AF_BLUETOOTH: what `uvx harald` runs on
  "$UV" venv -q --managed-python --python 3.13 "$venv"
  # refreshed, so a cached build of an older tree is never reused
  "$UV" pip install -q --python "$venv/bin/python" --refresh-package harald "$TREE"
  # the drivers check.py runs with `uv run` must get uv's python too
  UV_PYTHON_PREFERENCE=only-managed UV_PYTHON=3.13 \
    "$venv/bin/python" "$HERE/check.py" --tree "$TREE"
}

case "${1:-}" in
  setup) setup ;;
  up) up ;;
  down) down ;;
  check) check ;;
  *)
    sed -n '4,9p' "$0"
    exit 2
    ;;
esac
