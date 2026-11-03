# NetWeaver: Per-Application Network Interface Routing System
**Date:** 2026-11-04
**Target Platform:** Linux (Arch Linux / Linux 6.x+, cgroups v2, nftables, iproute2)
**Language:** Go (1.22+)

---

## 1. System Overview & Problem Statement

### 1.1 Problem Statement
By default, the Linux networking stack routes all outbound internet traffic using destination IP addresses against a single global default gateway in the `main` routing table. When multiple physical or virtual network interfaces are concurrently active (e.g., Ethernet `eno1`, internal Wi-Fi `wlan0`, USB tethering `usb0`, secondary Wi-Fi adapter, or VPN tunnels), an operating system user cannot natively select which application uses which network interface on the fly without changing the global default route or terminating the application.

### 1.2 Solution: NetWeaver
NetWeaver is a Linux network management and policy-routing utility written in Go. It enables dynamic, real-time per-application network interface binding without requiring applications to restart. A privileged background daemon (`netweaverd`) configures Linux Policy-Based Routing (PBR), unified `cgroups v2`, and `nftables` packet marking. An unprivileged terminal client (`netweaver`) provides both an interactive Charmbracelet Bubbletea TUI and scriptable CLI commands.

---

## 2. System Architecture

```
+-------------------------------------------------------------------------+
|                        User Space (Unprivileged)                        |
|                                                                         |
|     netweaver TUI (Bubbletea/Lipgloss)        netweaver CLI             |
|     - Live process routing table             - Run wrapper              |
|     - Real-time bandwidth counters           - Quick assign/reset       |
|     - Interactive interface picker           - Daemon status            |
+------------------------------------+------------------------------------+
                                     |
                Unix Domain Socket: /run/netweaver/netweaver.sock
                Protocol: JSON-RPC 2.0 / Bidirectional Event Stream
                                     |
+------------------------------------v------------------------------------+
|                         Root Daemon: netweaverd                         |
|                                                                         |
|  +------------------------+                  +-----------------------+  |
|  |       IPC Server       |                  |   Interface Monitor   |  |
|  | - Unix socket listener |                  | - netlink link/addr   |  |
|  | - Method dispatcher   |                  | - Gateway discovery   |  |
|  +-----------+------------+                  +-----------+-----------+  |
|              |                                           |              |
|  +-----------v------------+                  +-----------v-----------+  |
|  |     Process Manager    |                  |    Routing Engine     |  |
|  | - procfs / gopsutil    |                  | - PBR table manager   |  |
|  | - cgroup v2 migrator   |                  | - ip rule controller  |  |
|  | - PID tree resolver    |                  | - nftables manager    |  |
|  +-----------+------------+                  +-----------+-----------+  |
|              |                                           |              |
+--------------+-------------------------------------------+--------------+
               |                                           |
+--------------v-------------------------------------------v--------------+
|                     Linux Kernel Subsystems                             |
|                                                                         |
|  [ cgroups v2 unified tree ]          [ nftables mangle hook ]          |
|  /sys/fs/cgroup/netweaver/<iface> ->  socket cgroupv2 level 2 match     |
|                                       sets meta mark = 0x100+N          |
|                                                  |                      |
|                                       [ Policy-Based Routing ]          |
|                                       ip rule: fwmark 0x100+N           |
|                                       lookup table 100+N                |
|                                       (default via <GW> dev <iface>)    |
+-------------------------------------------------------------------------+
```

---

## 3. Kernel Networking Specification

### 3.1 Policy-Based Routing (PBR) Tables
- For each network interface that has an active IPv4/IPv6 default gateway, `netweaverd` allocates a dedicated routing table ID:
  $$\text{Table ID} = 100 + \text{ifindex}$$
  *(e.g., if `eno1` has index 2, Table ID is 102; if `wlan0` has index 3, Table ID is 103).*
- Each dedicated table contains:
  ```bash
  ip route replace default via <gateway_ip> dev <iface_name> src <local_ip> table <table_id>
  ```
- Priority rules are registered in the kernel FIB rule database:
  ```bash
  ip rule add fwmark <table_id> lookup <table_id> priority 1000
  ```

### 3.2 Unified cgroups v2 Hierarchy
- NetWeaver uses the native unified cgroups v2 controller mounted at `/sys/fs/cgroup`.
- On startup, `netweaverd` initializes the directory structure:
  ```
  /sys/fs/cgroup/netweaver/
  ├── cgroup.procs
  ├── default/
  │   └── cgroup.procs
  └── <iface_name>/       (e.g., eno1, wlan0, usb0)
      └── cgroup.procs
  ```
- Moving an application to an interface requires writing its PID (and any child PIDs) to `/sys/fs/cgroup/netweaver/<iface_name>/cgroup.procs`.

### 3.3 nftables Packet Marking & Masquerading
`netweaverd` creates and manages a dedicated table `inet netweaver`:
```nft
table inet netweaver {
    chain output {
        type route hook output priority mangle; policy accept;
        # For each interface configured under NetWeaver:
        socket cgroupv2 level 2 "netweaver/eno1" meta mark set 0x102
        socket cgroupv2 level 2 "netweaver/wlan0" meta mark set 0x103
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # Source address rewriting (MASQUERADE) to avoid martian packet drops:
        oifname "eno1" meta mark 0x102 masquerade
        oifname "wlan0" meta mark 0x103 masquerade
    }
}
```

### 3.4 DNS Resolution & Leak Prevention
- Applications using standard glibc/musl `getaddrinfo()` invoke DNS queries through UDP/TCP port 53. Because these queries originate from the process's own sockets, the socket inherits the process cgroup membership.
- The outbound DNS packet is tagged with the corresponding fwmark and leaves via the assigned interface's routing table to that interface's upstream resolver.

---

## 4. Daemon Architecture (`netweaverd`)

### 4.1 Subsystems
1. **Interface Monitor:**
   - Subscribes to netlink route and link multicast groups (`RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE`).
   - Dynamically detects newly attached interfaces (USB tethering, Wi-Fi dongles), allocates table IDs, creates corresponding cgroup slices, and configures routing rules.
   - Triggers failover when an interface drops carrier or loses its IP address.
2. **Process Manager:**
   - Reads `/proc` and queries system process state via `gopsutil/process`.
   - Filters out kernel worker threads (`PPID == 2`), systemd core units, and root services by matching user UID.
   - Traverses process trees: if PID $P$ is moved, all descendant threads and child processes are recursively added to the cgroup.
3. **Routing Engine:**
   - Manages kernel route tables, ip rules, and nftables using netlink and native netlink nftables APIs.
   - Cleans up state completely upon exit.
4. **IPC Server:**
   - Listens on `/run/netweaver/netweaver.sock`.
   - Sets file permissions `0660` with group `wheel` or current invoking user.

### 4.2 IPC API Methods (JSON-RPC 2.0)
- `system.status`: Returns daemon uptime, active interface count, managed process count.
- `interfaces.list`: Returns `[]InterfaceInfo` (Name, Index, IP, Gateway, Status, Speed, TableID, RxBytes, TxBytes).
- `processes.list`: Returns `[]ProcessInfo` (PID, Name, Cmdline, UID, AssignedInterface, RxRate, TxRate).
- `route.assign`: Parameters `{ pid: int, interface: string, persistent: bool }`. Returns `{ success: bool }`.
- `route.reset`: Parameters `{ pid: int }`. Returns `{ success: bool }`.
- `route.list_rules`: Returns persistent application assignment rules.
- `stream.events`: Persistent JSON stream emitting interface hotplug events, link drops, and per-process traffic telemetry every 1000ms.

---

## 5. Client Architecture (`netweaver`)

### 5.1 Interactive Terminal UI (TUI)
- Developed with Charmbracelet `bubbletea`, `lipgloss`, and `bubbles`.
- **Screen Composition:**
  - **Header:** System status bar (Daemon connected, Total RX/TX bandwidth, Active Interfaces count).
  - **Left / Main Table (Process View):**
    - Columns: `PID | Application | Interface | Download Rate | Upload Rate | Status`
    - Filterable via `/` search bar (fuzzy filtering by process name).
  - **Right Sidebar (Network Interfaces):**
    - Cards for each active interface showing link state (`UP`/`DOWN`), local IP, gateway IP, and total data transferred.
  - **Bottom Footer:**
    - Keybinding indicators: `[↑/↓] Navigate`, `[Enter] Change Route`, `[Space] Toggle Default`, `[r] Run Command`, `[q] Quit`.
  - **Interactive Modal:**
    - Hitting `Enter` on a process opens a clean fuzzy-selector overlay listing detected interfaces + `[Default Gateway]`. Selecting an entry calls `route.assign` over the Unix socket.

### 5.2 CLI Command Interface
- `netweaver list`: Prints an ASCII table of active processes and their assigned interfaces.
- `netweaver interfaces`: Prints detected network adapters, IPs, gateways, and routing tables.
- `netweaver assign <pid|app_name> <interface>`: Direct command-line binding.
- `netweaver reset <pid|app_name>`: Reverts binding to default.
- `netweaver run -i <interface> <command...>`: Runs the specified command directly within the interface's cgroup.
- `netweaver daemon start | stop | status`: Controls systemd or standalone daemon.

---

## 6. Error Handling, Network Failover & Cleanup

### 6.1 Interface Disconnection Fallback
- When an interface drops carrier (e.g. unplugging phone tethering):
  1. The netlink listener detects `RTM_DELLINK` or link down flag within 100ms.
  2. The daemon identifies all processes currently assigned to the dropped interface.
  3. Depending on policy (configured in `/etc/netweaver/config.json`):
     - **Default Fallback (Safe):** Moves processes back to `netweaver/default` (main routing table) and notifies the TUI.
     - **Kill-Switch (Strict):** Drops packets for those processes until the interface is restored (prevents leaking traffic).

### 6.2 Daemon Graceful Shutdown
- Catches `SIGINT`, `SIGTERM`, and `SIGHUP`.
- Teardown sequence:
  1. Move all processes in `/sys/fs/cgroup/netweaver/*` to root `/sys/fs/cgroup/cgroup.procs`.
  2. Delete all NetWeaver `ip rule` entries matching fwmark range `0x100-0x1FF`.
  3. Flush all routing tables created by NetWeaver (`ip route flush table 100..`).
  4. Delete nftables table `inet netweaver`.
  5. Remove socket `/run/netweaver/netweaver.sock`.
  6. Exit cleanly with return code 0.

---

## 7. Project Directory Structure

```
netweaver/
├── cmd/
│   ├── netweaverd/               # Root daemon entrypoint
│   │   └── main.go
│   └── netweaver/                # User CLI & TUI entrypoint
│       └── main.go
├── internal/
│   ├── api/                      # JSON-RPC IPC types and client/server
│   │   ├── client.go
│   │   ├── server.go
│   │   └── types.go
│   ├── cgroups/                  # cgroups v2 manager
│   │   ├── manager.go
│   │   └── manager_test.go
│   ├── config/                   # Configuration store
│   │   └── config.go
│   ├── interfaces/               # Netlink interface discovery and monitoring
│   │   ├── monitor.go
│   │   └── types.go
│   ├── process/                  # Process scanning and PID tree tracking
│   │   ├── scanner.go
│   │   └── scanner_test.go
│   ├── routing/                  # Policy-based routing and nftables
│   │   ├── nftables.go
│   │   ├── pbr.go
│   │   └── engine.go
│   └── tui/                      # Bubbletea terminal user interface
│       ├── app.go
│       ├── keys.go
│       ├── model.go
│       ├── styles.go
│       └── views/
│           ├── header.go
│           ├── interfaces.go
│           ├── modal.go
│           └── processes.go
├── docs/
│   └── superpowers/specs/
│       └── 2026-11-04-netweaver-design.md
├── scripts/
│   ├── netweaver.service        # Systemd unit file
│   └── setup-veth-test.sh       # Dummy network test script for development
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## 8. Verification & Testing Strategy

### 8.1 Unit Testing
- Test cgroup tree path sanitization and PID assignment logic.
- Test routing table ID calculation and command encoding.
- Test IPC request/response serialization.

### 8.2 Integration Testing (Network Namespaces)
- Run `scripts/setup-veth-test.sh`:
  - Creates two network namespaces: `ns-eth0` and `ns-wifi0`.
  - Connects them via `veth` pairs to the main host namespace with distinct subnets (`10.10.1.0/24` and `10.10.2.0/24`).
  - Runs `netweaverd` in test mode.
  - Launches `netweaver run -i veth-test1 curl -s http://10.10.1.1` and captures packets via `tcpdump -i veth-test1` to verify zero traffic escapes onto `veth-test2`.

### 8.3 College Viva & Demonstration Verification Checklist
1. **Initial Inspection:** Show `ip rule show` and `nft list ruleset` cleanly managed by NetWeaver.
2. **Multi-Interface Demo:** Run two curl or speedtest commands simultaneously, showing one using Ethernet and another using Wi-Fi.
3. **Live Migration Demo:** Launch a long-running download process in the TUI, switch its interface live via `[Enter]`, and show traffic transitioning to the new interface on the TUI bandwidth graph and `tcpdump`.
