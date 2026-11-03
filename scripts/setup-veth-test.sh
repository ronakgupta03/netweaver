#!/usr/bin/env bash
# scripts/setup-veth-test.sh
set -euo pipefail

echo "[*] Creating network namespaces and veth pairs for NetWeaver testing..."

# Clean old test namespaces if any
ip netns del ns-eth 2>/dev/null || true
ip netns del ns-wifi 2>/dev/null || true

# Create namespaces
ip netns add ns-eth
ip netns add ns-wifi

# Create veth pairs
ip link add veth-eth0 type veth peer name veth-eth-peer
ip link add veth-wifi0 type veth peer name veth-wifi-peer

# Move peers to namespaces
ip link set veth-eth-peer netns ns-eth
ip link set veth-wifi-peer netns ns-wifi

# Configure Host IPs
ip addr add 10.10.1.1/24 dev veth-eth0
ip link set veth-eth0 up

ip addr add 10.10.2.1/24 dev veth-wifi0
ip link set veth-wifi0 up

# Configure Namespace IPs and loopbacks
ip netns exec ns-eth ip addr add 10.10.1.2/24 dev veth-eth-peer
ip netns exec ns-eth ip link set veth-eth-peer up
ip netns exec ns-eth ip link set lo up

ip netns exec ns-wifi ip addr add 10.10.2.2/24 dev veth-wifi-peer
ip netns exec ns-wifi ip link set veth-wifi-peer up
ip netns exec ns-wifi ip link set lo up

echo "[*] Network namespaces created successfully."
echo "    Interface 1: veth-eth0  (10.10.1.1 -> peer 10.10.1.2)"
echo "    Interface 2: veth-wifi0 (10.10.2.1 -> peer 10.20.2.2)"
