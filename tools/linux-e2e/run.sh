#!/bin/sh
# harald's emulated linux end-to-end rig, run from the mac. see README.md.
#
#   tools/linux-e2e/run.sh          create and provision the vm if needed, (re)start
#                                   the rig, ship this working tree in, run every
#                                   check; exit 0 only if all of them passed
#   tools/linux-e2e/run.sh down     stop the gadget and btvirt (the vm keeps running)
#   tools/linux-e2e/run.sh shell    open a shell in the vm
#
# needs lima (brew install lima). the vm is $HARALD_E2E_VM (default harald-linux).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VM="${HARALD_E2E_VM:-harald-linux}"
LIMACTL="${LIMACTL:-limactl}"
VM_SH='sh "$HOME/harald-e2e/tree/tools/linux-e2e/vm.sh"'

if ! command -v "$LIMACTL" >/dev/null 2>&1; then
  echo "run.sh: limactl not found; install lima: brew install lima" >&2
  exit 2
fi

in_vm() { "$LIMACTL" shell --workdir / "$VM" -- sh -c "$1"; }

ensure_vm() {
  if ! "$LIMACTL" list -q 2>/dev/null | grep -qx "$VM"; then
    echo "== creating the vm $VM"
    # nothing from the mac is mounted: the tree is copied in by ship_tree
    "$LIMACTL" create --tty=false --name="$VM" --vm-type=vz \
      --cpus=4 --memory=4 --disk=20 --containerd=none --mount-none \
      template:ubuntu-26.04
  fi
  if [ "$("$LIMACTL" list --format '{{.Status}}' "$VM")" != Running ]; then
    echo "== starting the vm $VM"
    "$LIMACTL" start --tty=false "$VM"
  fi
}

ship_tree() {
  # the files git tracks or would track (so never .superpowers/ or docs/superpowers/,
  # which are ignored), as they are in the working tree, uncommitted edits included
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  (
    cd "$REPO"
    git -c core.quotePath=false ls-files -co --exclude-standard |
      grep -v -e '^\.superpowers/' -e '^docs/superpowers/' |
      while IFS= read -r path; do
        if [ -f "$path" ]; then printf '%s\n' "$path"; fi
      done
  ) >"$tmp/files"
  COPYFILE_DISABLE=1 tar -C "$REPO" -czf "$tmp/tree.tgz" -T "$tmp/files"
  echo "== shipping $(wc -l <"$tmp/files" | tr -d ' ') files to $VM"
  "$LIMACTL" copy "$tmp/tree.tgz" "$VM:/tmp/harald-tree.tgz"
  in_vm 'set -e; rm -rf "$HOME/harald-e2e/tree"; mkdir -p "$HOME/harald-e2e/tree"
    tar -xzf /tmp/harald-tree.tgz -C "$HOME/harald-e2e/tree" --warning=no-unknown-keyword
    rm -f /tmp/harald-tree.tgz'
}

case "${1:-}" in
  "")
    start=$(date +%s)
    ensure_vm
    ship_tree
    in_vm "$VM_SH setup"
    in_vm "$VM_SH up"
    status=0
    in_vm "$VM_SH check" || status=$?
    echo "== run.sh took $(($(date +%s) - start)) s, exit $status"
    exit "$status"
    ;;
  down) in_vm "$VM_SH down" ;;
  shell) "$LIMACTL" shell --workdir / "$VM" ;;
  *)
    sed -n '4,9p' "$0"
    exit 2
    ;;
esac
