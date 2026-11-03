#!/usr/bin/env bash
# scripts/teardown-veth-test.sh
set -euo pipefail

echo "[*] Cleaning up test namespaces and veth devices..."
ip netns del ns-eth 2>/dev/null || true
ip netns del ns-wifi 2>/dev/null || true
ip link del veth-eth0 2>/dev/null || true
ip link del veth-wifi0 2>/dev/null || true
echo "[*] Cleanup complete."
