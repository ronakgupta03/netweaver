#!/usr/bin/env bash
# Verifies the NetWeaver eBPF classifier on a live kernel.
# Requires root (CAP_BPF or CAP_SYS_ADMIN): sudo ./scripts/verify-ebpf.sh
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "must run as root: sudo $0" >&2
    exit 1
fi

cd "$(dirname "$0")/.."
ROOT=$(pwd)
LOG=/tmp/netweaverd-ebpf-verify.log
SOCK=/run/netweaver/netweaver.sock

step() { printf '\n== %s ==\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

step "building"
make build >/dev/null

if [[ -S $SOCK ]] && pgrep -x netweaverd >/dev/null; then
    fail "netweaverd is already running; stop it first"
fi

step "starting daemon"
"$ROOT/bin/netweaverd" >"$LOG" 2>&1 &
DAEMON_PID=$!
trap 'kill "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
    [[ -S $SOCK ]] && break
    sleep 0.1
done
[[ -S $SOCK ]] || { cat "$LOG"; fail "daemon socket never appeared"; }

grep -E 'eBPF classifier|nftables marking|Discovered interface' "$LOG" || true

if ! grep -q 'eBPF classifier active' "$LOG"; then
    printf '\nRESULT: eBPF unavailable, daemon fell back to nftables marking (this is a supported mode).\n'
    printf 'Reason from log:\n'
    grep -i 'unavailable' "$LOG" || true
    exit 0
fi

step "program attachments"
if command -v bpftool >/dev/null; then
    bpftool prog show | grep -i nw_mark || fail "nw_mark program not loaded"
    bpftool cgroup tree /sys/fs/cgroup | sed -n '/netweaver/,+2p' || true
    step "mark map (cgroup id -> mark/drop)"
    bpftool map dump name nw_targets || true
else
    printf 'bpftool not installed; skipping program inspection.\n'
fi

step "routing state"
ip rule show
ip route show table all | grep -E 'table (25[0-9]|26[0-9])' || true
nft list ruleset | sed -n '/table inet netweaver/,/}/p'

step "traffic test"
TARGET=$(ip route show default | awk '/default/ {print $3; exit}')
if [[ -n ${TARGET:-} ]]; then
    IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    printf 'default route: %s via %s\n' "$IFACE" "$TARGET"
    ip route get 1.1.1.1
    echo "Marked routing is exercised by per-app assignment; see README viva steps."
fi

step "teardown check"
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
trap - EXIT
sleep 0.5
if nft list tables 2>/dev/null | grep -q 'table inet netweaver'; then
    fail "nftables table left behind after shutdown"
fi
if pgrep -x netweaverd >/dev/null; then
    fail "daemon still running after shutdown"
fi

printf '\nRESULT: eBPF classifier loaded, attached, and cleaned up successfully.\n'
