# NetWeaver

> **Per-Application Network Interface Routing System in Go for Linux**

NetWeaver is a Linux network utility that enables per-application network interface binding on the fly. You can route specific applications (e.g. Firefox, Steam, Discord) through specific physical or virtual network interfaces (Ethernet `eno1`, Wi-Fi `wlan0`, USB tethering `usb0`) without restarting applications or changing the system's global default gateway.

---

## Architecture

- **`netweaverd` (Root Daemon):** Manages Linux Policy-Based Routing (PBR) tables, unified `cgroups v2` trees (`/sys/fs/cgroup/netweaver/<iface>`), and `nftables` socket cgroupv2 marking. Exposes a Unix Domain Socket at `/run/netweaver/netweaver.sock`.
- **`netweaver` (User Client):** Unprivileged terminal utility offering:
  - An interactive Charmbracelet Bubbletea terminal dashboard (TUI).
  - CLI subcommands (`list`, `interfaces`, `assign`, `reset`, `run`).

---

## Build

Requirements:
- Linux kernel 6.x+ with cgroups v2 (`/sys/fs/cgroup`)
- `nftables` (`nft`) and `iproute2` (`ip`)
- Go 1.22+

```bash
make build
```
This produces two binaries in `bin/`:
- `bin/netweaverd` (Root daemon)
- `bin/netweaver` (CLI / TUI client)

---

## Running NetWeaver

### 1. Start the Daemon (Root)
```bash
sudo ./bin/netweaverd
```
*(Or install as systemd service: `sudo cp scripts/netweaver.service /etc/systemd/system/ && sudo systemctl enable --now netweaver`)*

### 2. Launch the Interactive TUI (Unprivileged User)
```bash
./bin/netweaver
```
- **`[↑/↓]` / `[j/k]`**: Navigate process list
- **`[Enter]`**: Re-route highlighted process to another interface
- **`[Space]`**: Revert process to default gateway
- **`[q]`**: Quit TUI

### 3. CLI Subcommands
```bash
# List all running user processes and their assigned interfaces
./bin/netweaver list

# Show detected network adapters and routing tables
./bin/netweaver interfaces

# Assign a process to an interface (e.g., PID 1234 to wlan0)
./bin/netweaver assign 1234 wlan0

# Reset a process back to default route
./bin/netweaver reset 1234

# Launch a new command directly routed through an interface
./bin/netweaver run -i wlan0 firefox
```

---

## Demonstration for College Evaluation / Viva

1. **Verify Interface Routing Tables:**
   ```bash
   ip rule show
   ip route show table all
   sudo nft list ruleset
   ```
2. **Dual-Interface Network Namespace Simulation:**
   Run `sudo scripts/setup-veth-test.sh` to simulate two network connections on dummy interfaces without physical cables.
3. **Traffic Verification:**
   Launch two curl instances or tcpdump commands to prove packets leave exclusively through the assigned interface:
   ```bash
   sudo tcpdump -i wlan0 -n
   ```
