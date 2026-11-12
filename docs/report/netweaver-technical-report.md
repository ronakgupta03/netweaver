---
title: "NetWeaver — Per-Application Network Interface Routing on Linux"
subtitle: "Design, Implementation and Operations Report"
author: "Ronak Gupta"
date: "2026-11-13"
lang: en
---


# 1. Project Overview & Core Objective

## 1.1 The problem

A Linux host with more than one uplink (Ethernet, Wi-Fi, USB tethering, VPN) selects a
route per **destination**, never per **application**. The routing table sees a packet,
not the process that produced it. Everything a user runs — a browser, a game launcher, a
backup job, a torrent client — is squeezed through the same default gateway, chosen by
route metric. The usual workarounds are all deficient:

| Workaround | Why it falls short |
|---|---|
| Change the global default route | Affects every process; must be reverted manually |
| Bind the socket to a source address | Application must support it (`curl --interface`); browsers do not |
| `LD_PRELOAD` shim intercepting `connect()` | Per-runtime, breaks with static binaries, races, no IPv6 coverage |
| One network namespace per app | Requires a veth pair, NAT rules and DNS plumbing per app; heavyweight and destroys host sockets |
| Proxy (SOCKS/HTTP) per app | Requires app support, adds a user-space hop, breaks UDP/QUIC |

NetWeaver solves this at the **kernel policy level**: a process is placed into a
`cgroups v2` group, packets originating from that group are stamped with a routing-table
mark, and `ip rule` sends marked packets into a dedicated routing table whose default
gateway belongs to the chosen interface. The application is untouched, never restarted,
and the system default gateway is not modified.

## 1.2 Core objective

> Give the operator a single control surface — TUI, CLI, or browser — to bind any running
> application to any network interface, live, with persistence, failure handling, and
> observable traffic.

## 1.3 Capabilities (implemented)

| Capability | Mechanism | Surface |
|---|---|---|
| Per-application interface binding | cgroup membership + fwmark + PBR table | TUI, CLI, dashboard |
| Live re-routing without restart | writing PID to another `cgroup.procs` | all |
| Process-tree aware binding | recursive child walk before assignment | daemon |
| Packet marking | eBPF `cgroup_skb/egress`, nftables fallback | daemon |
| Automatic IPv6 policy routing | `ip -6 rule` + per-table `default` or `unreachable` | daemon |
| Default-route priority enforcement | Ethernet 50 > Wi-Fi 100 > USB 700 | daemon |
| Live per-application throughput | TCP socket counters from `ss`, delta rate | TUI, dashboard, CLI |
| Per-interface throughput and totals | `/sys/class/net/*/statistics` | TUI, dashboard, CLI |
| Persistent auto-routing rules | `/etc/netweaver/rules.json` + `/proc` watcher | CLI, dashboard |
| Failover on interface loss | move processes to best survivor | daemon |
| Strict kill-switch | quarantine cgroup, packets dropped | daemon |
| Local web dashboard | loopback HTTP proxy to daemon UDS | `netweaver web` |

**Non-goals.** NetWeaver is not a firewall, not a VPN, and not a traffic shaper. It does
not inspect packet contents and does not require a kernel module. It targets Linux only.

## 1.4 Measured size

| Metric | Value |
|---|---|
| Go source | 4,952 lines across 41 files |
| Inline assets (BPF C, dashboard HTML) | 368 lines |
| Packages | 16 (`cmd/…` ×2, `internal/…` ×14) |
| Test files / test functions | 14 / 41 |
| External Go dependencies | `bubbletea`, `lipgloss`, `gopsutil/v3`, `cilium/ebpf`, `golang.org/x/sys` |


# 2. Tech Stack & Architectural Decisions

## 2.1 Stack and rationale

| Layer | Choice | Version | Rationale (vs. alternative) |
|---|---|---|---|
| Language | **Go** | 1.22+ | Single static binary for a root daemon; goroutines map cleanly onto three independent watchers (interfaces 2 s, rules 2 s, telemetry 1 s); `os/exec` and `syscall` access without CGO. Chosen over C (manual memory management for a long-lived root daemon) and Rust (slower iteration for a 5 kLOC prototype with heavy shell-tool integration). |
| Process isolation | **cgroups v2** | kernel 6.x | The only kernel object that is (a) inherited by children, (b) visible to nftables as `socket cgroupv2`, and (c) visible to eBPF as `bpf_get_current_cgroup_id()`. Network namespaces were rejected: per-app netns plus veth plus NAT plus DNS is materially more code and breaks loopback IPC. |
| Route selection | **Policy-based routing** (`ip rule`, `ip route`) | iproute2 | Marks are matched by `fwmark` rules at priority 1000, earlier than the main table (32766). A user-space proxy was rejected because it breaks UDP/QUIC and requires app cooperation. |
| Marking (primary) | **eBPF `cgroup_skb/egress`** | `cilium/ebpf` v0.22 | Sets `skb->mark` in the socket send path with one map lookup, no rule explosion, no nftables per-packet traversal of a long chain. Pure-Go loader, no CGO, object embedded with `go:embed`. Rejected bcc (Python runtime dependency) and libbpfgo (CGO). |
| Marking (fallback) | **nftables `socket cgroupv2`** | nft ≥ 0.9.8 | Works on kernels without BPF privileges and is auditable with `nft list ruleset` during a viva. Rejected iptables `xt_cgroup` (deprecated, per-interface chains). |
| PBR / interface mutation | **`ip` and `nft` executed via `os/exec`** | — | Explicit, replayable, and visible in shell history during evaluation. Netlink libraries would remove fork/exec overhead but hide the exact commands from the operator; at ≤ 3 invocations per interface change the cost is irrelevant. |
| Telemetry (per app) | **`ss -tinp` parsing** | iproute2 | `ss` exposes `bytes_acked` / `bytes_received` per TCP socket plus the owning PID, via `INET_DIAG`. Chosen over a pcap sniffer (`AF_PACKET`, root-only, high CPU) and over a full netlink `INET_DIAG` client (≈400 lines of marshalling for the same data). Limitation: TCP only — documented in §5.6. |
| Telemetry (per interface) | **sysfs counters** | — | `rx_bytes` / `tx_bytes` are exact, cheap, and protocol-agnostic; sampled at 1 Hz. |
| IPC | **JSON over Unix domain socket** | — | `encoding/json` + `net.Listen("unix")`. gRPC was rejected (protoc toolchain, schema drift for a 9-method API). D-Bus was rejected (desktop-session coupling, root daemon would need policy files). |
| TUI | **Bubbletea + Lipgloss** | v1.3.10 / v1.1.0 | Elm-style `Model/Update/View` gives deterministic rendering with a 1 s tick — no manual terminal state machine. Rejected `tview` (imperative callbacks, harder to test `Update`) and raw `termios`/curses. |
| Web UI | **`net/http` + one embedded HTML file** | stdlib | No Node toolchain, no bundler, offline-capable; the page polls a JSON state endpoint every 1.5 s. React/Vite rejected as disproportionate for one screen. |
| Persistence | **JSON files with atomic rename** | — | `/etc/netweaver/rules.json` and `settings.json` are small, human-editable and diff-friendly. SQLite rejected (CGO or pure-Go driver for two documents); no external service. |
| Process enumeration | **gopsutil v3 + direct procfs** | v3.24.5 | gopsutil for `Children()`/`Name()` convenience in the scanner; direct `/proc` reads on the hot paths (auto-router at 2 s) to avoid allocation churn. |
| Packaging | **Makefile + systemd unit** | — | `make build`, `make test`, `make bpf`; `scripts/netweaver.service` with `KillMode=process`. |
| Verification | **`go test`, user netns (`unshare -rn`)** | — | Routing behaviour is proven on real veth pairs inside an unprivileged network namespace, not mocked. |

## 2.2 Key architectural decisions

**D1 — Split privileges.** All kernel mutation (cgroups, routes, nftables, BPF) lives in
`netweaverd` (root). The client binary never runs as root; it speaks JSON over a `0666`
Unix socket. This keeps the frequently-invoked UI path unprivileged and gives one audit
point for privileged operations.

**D2 — Bind at the cgroup, not at the socket.** Assignment writes a PID into
`/sys/fs/cgroup/netweaver/<iface>/cgroup.procs`. The kernel moves the whole thread group;
children spawned later inherit the cgroup. Routing therefore survives application restarts
of child workers (browser renderers, Electron helpers) with no per-PID bookkeeping.

**D3 — One routing table per interface, not per application.** Tables are keyed by
interface (`TableID = 0x100 + ifindex`) because the route set only depends on the uplink.
Applications scale into tables via marks, so N apps × M interfaces produces N cgroup
writes and M tables — not N×M rules.

**D4 — Two marking engines behind one interface.** `routing.Engine` renders nftables;
`classifier.Classifier` loads eBPF. The daemon prefers eBPF and falls back to nftables on
any load/attach failure, re-applying a NAT-only nftables ruleset so masquerading never
regresses.

**D5 — Declarative reconciliation.** Every mutation path recomputes desired state and
converges: `buildRuleset` filters by cgroup existence and re-renders the table from
scratch; `classifier.Apply` diffs desired cgroups against attached links; the interface
watcher diffs previous and current snapshots. Nothing relies on incremental bookkeeping
being correct after a crash.


# 3. System Architecture & Project Structure

## 3.1 Component diagram

```
┌─────────────────────────────┐
│ browser                     │
└─────────────────────────────┘
               │                UDS + JSON
┌──────────────▼──────────────┐        ┌────────────────────────────────────────────┐
│ netweaver web (:8088)       │───────▶│ netweaverd  (root daemon)                  │
└─────────────────────────────┘        │                                            │
                                       │  api.Server  ·  9 JSON methods             │
┌─────────────────────────────┐        │   ├─ process.Scanner                       │
│ netweaver TUI / CLI         │───────▶│   ├─ cgroups.Manager                       │
└─────────────────────────────┘        │   ├─ routing.Engine                        │
                                       │   ├─ telemetry.Engine                      │
                                       │   ├─ rules.Store                           │
                                       │   ├─ autoroute.Router                      │
                                       │   ├─ policy.Manager                        │
                                       │   └─ classifier (eBPF)                     │
                                       └──────────────────────┬─────────────────────┘
                                                              │ exec / syscalls
                                       ┌──────────────────────▼─────────────────────┐
                                       │ Linux kernel                               │
                                       │  cgroups v2 · nftables · FIB rules         │
                                       │  eBPF cgroup_skb · net devices             │
```

Three independent producers push into the same snapshot space, and every client reads a
projection of it:

| Producer | Period | Output |
|---|---|---|
| `interfaces.Monitor.StartWatch` | 2 s | full `[]InterfaceInfo` snapshot |
| `telemetry.Engine.Start` | 1 s | per-PID and per-interface rates and totals |
| `autoroute.Router.Start` | 2 s | rule matches applied to new PIDs |

## 3.2 End-to-end packet path

```
 write() on a socket
        │
        ├─ (A) cgroup_skb/egress eBPF  ──► skb->mark = 0x104      [preferred]
        └─ (B) nft output/mangle chain ──► meta mark set 0x104    [fallback]
                    socket cgroupv2 level 2 "netweaver/wlan0"
        │
        ├─ ip rule:  fwmark 0x104 lookup 260   (priority 1000)
        ├─ table 260: default via 10.5.50.1 dev wlan0
        ├─ ip -6 rule: fwmark 0x104 lookup 260
        ├─ nft postrouting/srcnat: oifname "wlan0" mark 0x104 masquerade
        └─ egress on wlan0
```

The strict-policy path short-circuits at step (A/B): the first rule in the output chain
is `socket cgroupv2 level 2 "netweaver/blocked" drop`, and the eBPF program returns `0`
for that cgroup, so quarantined traffic never reaches the FIB.

## 3.3 Addressing scheme

| Object | Formula / value | Example |
|---|---|---|
| cgroup path | `/sys/fs/cgroup/netweaver/<iface>` | `/sys/fs/cgroup/netweaver/wlan0` |
| routing table | `0x100 + ifindex` | ifindex 4 → table 260 |
| fwmark | identical to table ID | `0x104` |
| FIB rule priority | `1000` (before `main` at 32766) | — |
| quarantine cgroup | `netweaver/blocked` | — |
| default metrics | Ethernet 50, Wi-Fi 100, USB 700 | — |
| daemon socket | `/run/netweaver/netweaver.sock` | mode `0666` |
| rules / settings | `/etc/netweaver/{rules,settings}.json` | — |

## 3.4 IPC surface

| Method | Request fields | Response | Backend call |
|---|---|---|---|
| `interfaces.list` | — | `interfaces[]` | `Monitor.DiscoverInterfaces` + telemetry |
| `processes.list` | — | `processes[]` | `Scanner.ScanProcesses` + subtree telemetry |
| `route.assign` | `pid`, `interface` | — | `AssignRoute` (tree walk + cgroup write) |
| `route.reset` | `pid` | — | `ResetRoute` |
| `rules.list` | — | `rules[]` | `rules.Store.List` |
| `rules.add` | `rule{match,interface,policy}` | — | `rules.Store.Add` |
| `rules.remove` | `match` | — | `rules.Store.Remove` |
| `policy.get` | — | `policy` | `policy.Manager.Default` |
| `policy.set` | `policy` | `policy` | `policy.Manager.SetDefault` |

Transport: one JSON object per connection in each direction, then the connection closes
(`internal/api/server.go:handleConn`). No framing layer is needed because each request
fits in a single JSON document and `json.Decoder` streams until the object is complete.

## 3.5 Annotated file tree

```
netweaver/
├── cmd/
│   ├── netweaverd/
│   │   ├── main.go              daemon wiring: cgroup init, discovery, watchers,
│   │   │                        eBPF load + fallback, API server, signal shutdown
│   │   └── failover.go          interface diffing, failover/strict reaction,
│   │                            quarantine release, classifier resync, nftables fallback
│   └── netweaver/
│       ├── main.go              subcommand dispatch (list/interfaces/assign/reset/
│       │                        rules/policy/web/run), NETWEAVER_SOCK resolution
│       ├── rules.go             `rules list|add|remove|clear` via API
│       ├── policy.go            `policy [set]` via API
│       ├── run.go               `run -i <iface> cmd…`: spawn, attach PID, wait
│       └── web.go               `web [-addr] [-open]`, signal lifecycle
├── internal/
│   ├── api/                     UDS JSON protocol; Backend interface, server, client
│   ├── autoroute/               /proc watcher: match → assign once per PID, retry,
│   │                            version-triggered re-apply, dead-PID pruning
│   ├── cgroups/                 hierarchy init/migrate, EnsureInterfaceCgroup,
│   │                            AssignPID, ResetPID, PIDs(iface), Block/BlockedCgroup
│   ├── classifier/              eBPF loader (embed), per-cgroup attach/detach,
│   │   ├── classifier.go        mark map sync, kernfs-inode cgroup IDs
│   │   ├── netweaver_bpfel.o    compiled object (committed; `make bpf` regenerates)
│   │   └── bpf/netweaver.c      cgroup_skb/egress program source
│   ├── failover/                pure policy engine: best survivor, block vs move
│   ├── interfaces/              discovery, carrier check, v4/v6 gateways,
│   │                            priority ordering, default-metric enforcement
│   ├── policy/                  precedence resolution, settings.json persistence
│   ├── process/                 user-app scanner: dedup, terminal task naming,
│   │                            session-leader detection, cgroup attribution
│   ├── routing/                 PBR tables, v4/v6 FIB rules, nftables ruleset
│   │                            rendering and cgroup-path filtering
│   ├── rules/                   rules.json store, glob matching, atomic writes,
│   │                            mutation version
│   ├── telemetry/               ss parser, sampling engine, rate math, formatting
│   ├── tui/                     Bubbletea model/update/view, sparklines, paging
│   ├── types/                   shared domain models and policy constants
│   └── web/                     HTTP server + embedded single-page dashboard
├── scripts/
│   ├── netweaver.service        systemd unit (KillMode=process)
│   ├── setup-veth-test.sh       two synthetic uplinks for demos
│   ├── teardown-veth-test.sh    removes them
│   └── verify-ebpf.sh           root-only kernel verification of the classifier
├── docs/superpowers/            original design specification and build plan
├── Makefile                     build · test · bpf
└── README.md                    operator documentation
```


# 4. Step-by-Step Build Walkthrough

The build order below matches the repository history. Each phase produced a compilable,
tested increment; later phases did not rework earlier data models except where noted.

| # | Phase | Commit | Outcome |
|---|---|---|---|
| 0 | Design specification | `47fa08d` | threat model, API shape, decision log |
| 1 | Domain models | `fab4547` | `types.InterfaceInfo`, `ProcessInfo`, `Rule`, validation |
| 2 | cgroups v2 manager | `43d027a` | hierarchy, assignment, reset, teardown |
| 3 | PBR + nftables engine | `3399d69` | tables, fwmark rules, ruleset template |
| 4 | Interface discovery | `c329998` | carrier filtering, v4/v6 gateways, watcher |
| 5 | Process scanner | `af90ef0` | user-app list, tree collapse, terminal naming |
| 6 | IPC | `036620a` | UDS server/client, `Backend` interface |
| 7 | Daemon + systemd | `4315d9b` | wiring, signal shutdown, unit file |
| 8 | CLI + run wrapper | `44711ca` | list/interfaces/assign/reset/run |
| 9 | TUI | `4db0da9` | Bubbletea dashboard, paging |
| 10 | Netns harness | `c702813` | dual-veth verification scripts |
| 11 | Review fixes | `78c356c`…`363b122` | multi-gateway, socket mode, teardown, dedup |
| 12 | Priority + IPv6 | `f3194ac` | Ethernet > Wi-Fi > USB, `unreachable` v6 defaults |
| 13 | Telemetry | `4a1461f` | per-app/interface rates and totals |
| 14 | Rules | `ce93d8a` | persistence + auto-attach on launch |
| 15 | Policies | `30ff2e6` | failover, kill-switch, quarantine |
| 16 | nft path fix | `b3bd517` | cgroup existence filtering (see §5.1) |
| 17 | Dashboard | `535c7e5` | embedded web UI over UDS |
| 18 | eBPF classifier | `9013fe6` | cgroup_skb marking + fallback |
| 19 | Classifier tests | `5cbd6a3` | injectable attach/map paths, verify script |

## 4.1 Phase 1 — Domain models

`internal/types/models.go` is deliberately small: it is the contract shared by the daemon,
the clients and the tests. Validation lives next to the data so that no handler can forget
it.

```go
type InterfaceInfo struct {
    Name     string `json:"name"`
    Index    int    `json:"index"`
    IP       string `json:"ip"`
    Gateway  string `json:"gateway"`
    Gateway6 string `json:"gateway6,omitempty"`
    TableID  int    `json:"table_id"`
    Up       bool   `json:"up"`
    RxBytes  uint64 `json:"rx_bytes"`
    TxBytes  uint64 `json:"tx_bytes"`
    RxRate   float64 `json:"rx_rate"`
    TxRate   float64 `json:"tx_rate"`
}
```

`TableID` is **derived** (`0x100 + ifindex`) rather than configured: it survives daemon
restarts without persistence, and is collision-free per netns because `ifindex` is unique.

## 4.2 Phase 2 — cgroup manager

`internal/cgroups/manager.go` implements the only operation that actually changes
behaviour:

```go
func (m *Manager) AssignPID(iface string, pid int) error {
    if pid <= 100 {
        return fmt.Errorf("cannot assign system process PID %d", pid)
    }
    path, err := m.InterfaceCgroupPath(iface)      // regex-validated iface name
    if err != nil {
        return err
    }
    f, err := os.OpenFile(filepath.Join(path, "cgroup.procs"),
        os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
    if err != nil {
        return fmt.Errorf("failed to open cgroup.procs: %w", err)
    }
    defer f.Close()
    _, err = f.WriteString(strconv.Itoa(pid) + "\n")
    return err
}
```

Three details matter:

1. **Writing a PID moves the entire thread group**, so a multi-threaded browser is not
   half-routed. This is why assignment is a single integer write per process rather than a
   socket-level hook.
2. **`InitHierarchy` migrates everything back to the root cgroup at startup**
   (`MigrateAllToRoot`). A daemon crash leaves processes in `netweaver/*`; without this
   sweep, stale membership would silently keep routing them on the next boot.
3. **PID ≤ 100 is refused** at both the cgroup layer and `GetProcessTree`. This prevents a
   mistyped CLI argument from moving `systemd` or the kernel threads into a routing slice.

## 4.3 Phase 3 — policy routing and nftables

`internal/routing/engine.go` writes state, then renders a complete ruleset:

```bash
# 1. per-interface default route inside its own table
ip route replace default via <GW> dev <IFACE> table <TID>

# 2. IPv6 counterpart, or an explicit black hole when the link has no v6
ip -6 route replace default via <GW6> dev <IFACE> table <TID>
ip -6 route replace unreachable default table <TID>

# 3. FIB rules, deleted first so the operation is idempotent
ip rule    del fwmark 0x<TID> table <TID>
ip rule    add fwmark 0x<TID> table <TID> priority 1000
ip -6 rule del fwmark 0x<TID> table <TID>
ip -6 rule add fwmark 0x<TID> table <TID> priority 1000
```

The nftables template is the contract between marking and routing:

```nft
table inet netweaver {
    chain output {
        type route hook output priority mangle; policy accept;
        socket cgroupv2 level 2 "netweaver/blocked" drop          # kill-switch
        socket cgroupv2 level 2 "netweaver/wlan0" meta mark set 0x104
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "wlan0" meta mark 0x104 masquerade
    }
}
```

`priority mangle` runs before routing decisions; `type route` means the chain may alter
routing metadata (the mark) that the FIB consults immediately afterwards. The
`postrouting`/`srcnat` chain only rewrites source addresses for the mark that belongs to
that interface, so a packet can never be NATed with the wrong uplink's address.

**Why `inet` rather than `ip` + `ip6`?** One table covers both families; the same cgroup
rule marks v4 and v6 packets, which eliminates the class of IPv6 leaks described in §5.2.

## 4.4 Phase 4 — interface discovery and priority

`interfaces.Monitor.DiscoverInterfaces` filters aggressively, because a wrong entry here
would create a routing table with a dead gateway:

```go
if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 { continue }
if strings.HasPrefix(iface.Name, "br-") || strings.HasPrefix(iface.Name, "docker") { continue }
if !isCarrierUp(iface.Name) { continue }          // /sys/class/net/<n>/carrier
// require a global IPv4 address; record v4 and v6 gateways from `ip route show`
```

Two behaviours are enforced on every discovery pass:

```go
func Priority(name string) int {          // lower wins
    switch {
    case strings.HasPrefix(name, "eno"), strings.HasPrefix(name, "eth"): return 50
    case strings.HasPrefix(name, "wlan"), strings.HasPrefix(name, "wl"): return 100
    default: return 700                   // USB tethering and anything else
    }
}
// EnforceDefaultPriorities: ip route replace default via GW dev IF metric <Priority>
```

This is a direct fix for the bug class where NetworkManager gives a USB-tethered phone
metric 100 and Wi-Fi 600, silently making cellular data the system default. The daemon
rewrites the main-table metrics on every discovery pass, so plugging the phone in no longer
steals the default route.

## 4.5 Phase 5 — process scanner and tree deduplication

The scanner answers "what would a user recognise as an application?" rather than "what is
running". The rules, in order:

```go
if p.Pid <= 100 { continue }                       // init/systemd
if ppid == 2 { continue }                          // kernel workers
if uid < 1000 { continue }                         // system services
if isIgnored(name) { continue }                    // pipewire, xdg-*, gvfs…
if parentName == name { continue }                 // browser helper collapse
if shell && p.Pid != sessionID { continue }        // only the session leader shell
displayName = fmt.Sprintf("terminal (%s)", task)   // e.g. terminal (omp)
markDescendants(p, seenDescendants)                // children are not separate rows
```

`markDescendants` is what stops a single browser from occupying twenty rows; the tree is
rendered once, at its root, and later phases attribute child traffic back to that root with
`GetProcessTree`. Shell rows are named after their foreground child
(`getShellTask`), which is why the TUI can say `terminal (sudo ./bin/netweaverd)` instead of
three indistinguishable `zsh` lines.

## 4.6 Phase 6 — IPC and the `Backend` interface

The daemon satisfies `api.Backend`; the tests use a 30-line mock that satisfies the same
interface. That single seam is why the protocol, the CLI and the dashboard are testable
without root:

```go
type Backend interface {
    ListInterfaces() ([]types.InterfaceInfo, error)
    ListProcesses() ([]types.ProcessInfo, error)
    AssignRoute(pid int, iface string) error
    ResetRoute(pid int) error
    ListRules() []types.Rule
    AddRule(rule types.Rule) error
    RemoveRule(match string) error
    GetPolicy() string
    SetPolicy(policy string) error
}
```

Socket permissions are widened with `os.Chmod(sockPath, 0666)` after `Listen`, so an
unprivileged TUI can talk to a root daemon without `sudo`. The privileged operations
themselves still validate their inputs (interface regex, PID floor), so a local user cannot
route arbitrary system processes.

## 4.7 Phase 7–9 — daemon, CLI, TUI

The daemon is intentionally a flat composition root: it owns no business logic beyond
wiring and lifecycle ordering.

```go
// startup order that matters
cgMgr.InitHierarchy()                  // 1. reclaim any stale membership
monitor.DiscoverInterfaces()           // 2. learn interfaces
cgMgr.EnsureInterfaceCgroup(iface)     // 3. create cgroups BEFORE nftables
engine.SetupInterfaceRoute(iface)      // 4. routes + FIB rules + ruleset
telemetry.Start(ctx)                   // 5. sampling
router.Start(ctx)                     // 6. rule watcher
api.NewServer(sock, daemon).Start()    // 7. expose
```

Step 3 before step 4 is mandatory: nftables resolves cgroup paths at load time
(§5.1). Shutdown reverses the order and additionally waits for `classifier.Close()` before
`engine.Teardown()`, so a BPF program cannot outlive the netns state it was attached to.

The TUI is a pure function of a snapshot plus a cursor. No terminal state is mutated from
`Update`; `View` renders a window of 15 rows and a 16-sample sparkline per PID:

```go
line := fmt.Sprintf("%s %-7d %-24s %-12s %-8s %-11s %-11s %-10s %-12s",
    cursor, p.PID, truncate(p.Name, 24), truncate(iface, 12), truncate(policy, 8),
    telemetry.FormatRate(p.RxRate), telemetry.FormatRate(p.TxRate),
    telemetry.FormatBytes(p.RxBytes+p.TxBytes), sparkline(m.history[p.PID], 12))
```

## 4.8 Phase 13 — telemetry

Two independent sources are sampled and joined by PID.

`ParseSS` walks `ss -tinpH` output as records: a socket line starts a record, indented
continuation lines carry `-i` counters. Loopback-to-loopback sockets are skipped so the
numbers reflect uplink traffic; multiple PIDs on one socket (socket passing) all receive the
counter.

```go
// per socket: bytes_acked (delivered, excludes retransmits) and bytes_received
for _, m := range pidPattern.FindAllStringSubmatch(line, -1) { pids = append(pids, atoi(m[1])) }
if v := ackedPattern.FindStringSubmatch(line); v != nil && n > tx { tx = n }
```

Rate derivation is monotonic by construction, because sockets disappear between samples:

```go
var dRx, dTx uint64
if cur.Rx >= prev.Rx { dRx = cur.Rx - prev.Rx }   // negative delta → rebase, not negative rate
if cur.Tx >= prev.Tx { dTx = cur.Tx - prev.Tx }
e.procUsage[pid] = usage.Add(dRx, dTx)            // cumulative never decreases
e.procRate[pid]  = Rate{Rx: float64(dRx) / elapsed, Tx: float64(dTx) / elapsed}
```

A closed socket therefore under-reports by at most one interval's worth of bytes; it can
never fabricate or double-count traffic. Cumulative usage for a terminal row is the sum over
its process tree (`SubtreeUsage`), which is why `terminal (omp)` shows the sum of the agent
and its tool subprocesses rather than zero.

## 4.9 Phase 14 — persistent rules and the auto-router

Rules are matched on **`comm`** by default, which is the precise semantic for "the browser
process group": Firefox helpers share `argv[0]` but not `comm`, so a plain `firefox` rule
matches one PID and the tree walk covers the rest. Two prefixes widen the match when needed:

| Pattern | Matches | Use case |
|---|---|---|
| `firefox` | process name (`comm`) | the process group root |
| `bin:firefox` | `argv[0]` basename | helpers that must be caught explicitly |
| `cmd:*-silent` | whole command line (`*` spans spaces) | distinguishing invocations of one binary |

The watcher is idempotent per process lifetime:

```go
if _, done := handled[pid]; done { continue }
rule, ok := r.store.Match(name, cmdline)          // comm + optional cmdline
if r.assigner.Current(pid) == rule.Interface {    // already correct → mark, don't write
    r.markHandled(pid, rule.Interface); continue
}
if err := r.assigner.Assign(pid, rule.Interface); err != nil { continue } // retry next tick
r.markHandled(pid, rule.Interface)
```

`handled` is pruned against the live PID set, so PID reuse cannot suppress a future
assignment. Mutating the store bumps a version counter; the watcher clears `handled` when it
observes a new version, which is how an edited rule takes effect on an already-running
process without a daemon restart.

## 4.10 Phase 15 — failover and the kill-switch

The decision logic is a pure function over an interface that the daemon implements:

```go
func HandleLoss(lost, remaining []string, m Mover) []Action {
    target := BestInterface(remaining)             // sorts by Priority, then name
    for _, iface := range lost {
        for _, pid := range must(m.PIDs(iface)) {
            if m.Policy(pid) == types.PolicyStrict {
                m.Block(pid, iface)                // quarantine; nftables/eBPF drops
                continue
            }
            if target != "" { m.Assign(target, pid) }   // failover
        }
    }
}
```

`BestInterface` reuses the same priority function as default-route enforcement, so failover
and steady-state preference can never disagree. Strict processes are tracked in
`DaemonService.blocked` (`pid → original interface`) and restored by `restoreBlocked` as
soon as the interface reappears; entries for dead PIDs are dropped on every pass, so the map
cannot grow without bound.

## 4.11 Phase 18 — eBPF classifier

The kernel-side program is 20 lines and has one job:

```c
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, __u64); __type(value, struct nw_target); } nw_targets SEC(".maps");

SEC("cgroup_skb/egress")
int nw_mark(struct __sk_buff *skb)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    struct nw_target *t = bpf_map_lookup_elem(&nw_targets, &cgid);
    if (!t) return 1;          // not managed → let the kernel route normally
    if (t->drop) return 0;     // strict policy → drop
    skb->mark = t->mark;       // table ID for the FIB
    return 1;
}
```

The userspace side must map a **path** to the same identifier the helper returns. The
kernfs inode of the cgroup directory is exactly that identifier:

```go
func cgroupID(path string) (uint64, error) {
    info, err := os.Stat(path)                  // e.g. /sys/fs/cgroup/netweaver/wlan0
    st := info.Sys().(*syscall.Stat_t)
    return st.Ino, nil                          // == bpf_get_current_cgroup_id()
}
```

Reconciliation is a diff, which makes repeated calls safe and lets interface hotplug drive
it:

```go
for name, l := range c.links {
    if _, keep := desired[name]; !keep {
        l.close()
        delete(c.links, name)
    }
}
for name, t := range desired {
    id, err := c.cgroupIDFn(path); if err != nil { continue }   // cgroup not created yet
    c.putFn(id, t)
    if _, attached := c.links[name]; !attached { c.links[name] = c.attachFn(path) }
}
```

## 4.12 Phase 17 — dashboard

The dashboard is a proxy, not a second daemon: `internal/web/server.go` holds one
`api.Client` and exposes five endpoints. State is a single document so the page renders it
atomically:

```go
type stateResponse struct {
    Interfaces []types.InterfaceInfo `json:"interfaces"`
    Processes  []types.ProcessInfo   `json:"processes"`
    Rules      []types.Rule          `json:"rules"`
    Policy     string                `json:"policy"`
}
```

Mutations accept at most 4 KiB (`http.MaxBytesReader`), validate required fields, and map
daemon errors to `502` while client errors map to `400`. The page polls every 1.5 s but
**skips re-render while a form control has focus**, which prevents a select box from being
yanked out from under the cursor mid-interaction.


# 5. Engineering Challenges, Trade-offs & Optimizations

## 5.1 nftables rejects the entire ruleset when one cgroup path is missing

**Symptom.** Marking silently stopped working while `ip rule` still looked correct.

**Root cause.** `nft` resolves `socket cgroupv2 level N "path"` **at load time** and aborts
the whole transaction if any path does not exist:

```
Error: Could not parse cgroupsv2 path
        socket cgroupv2 level 2 "netweaver/blocked" drop
```

The daemon applied the ruleset for every interface it had ever seen, including ones whose
cgroup directory had not been created yet, and discarded the error (`_ = engine…`).

**Fix (commit `b3bd517`).** Render only rules whose cgroup exists, and surface skips:

```go
for _, iface := range list {
    if !e.CgroupPathExists(iface.Name) { skipped = append(skipped, iface.Name); continue }
    kept = append(kept, iface)
}
return renderRuleset(rulesetData{Ifaces: kept, Marking: e.marking,
    Blocked: e.CgroupPathExists(cgroups.BlockedCgroup)}), skipped
```

The apply error now names the skipped groups, and the daemon logs route-setup failures
instead of discarding them. Verified in a user netns with two veth uplinks: the ruleset
loads, `ip route get 8.8.8.8 mark 0x105` selects `veth1` table 261, unmarked traffic follows
`veth0`.

**Trade-off.** Filtering at render time means a rule can lag one discovery cycle behind
cgroup creation; the startup order (ensure cgroup → apply rules) plus the 2 s watcher makes
that window unobservable in practice.

## 5.2 IPv6 leaks through the only interface that has IPv6

**Symptom.** Two terminals assigned to different interfaces reported the *same* public IP.
The IPv6-only lookup (`curl -6`) always returned the phone's address.

**Root cause.** Two independent defects: policy routing was installed for IPv4 only, and
Wi-Fi had no global IPv6 default route, so any v6 socket fell through to the single v6-capable
uplink regardless of cgroup.

**Fix (commit `f3194ac`).** Mirror every v4 object for v6 and make absence explicit:

```go
if info.Gateway6 != "" {
    ip -6 route replace default via <GW6> dev <IFACE> table <TID>
} else {
    ip -6 route replace unreachable default table <TID>   // fail fast, do not leak
}
ip -6 rule add fwmark 0x<TID> table <TID> priority 1000
```

An `unreachable` default is the correct semantic: the application gets `ENETUNREACH` and
falls back to IPv4 on the *intended* link. Silently using another link is worse than failing,
and for VPN/torrent use it is a privacy bug.

## 5.3 Route metrics silently hijacked the system default

USB tethering arrived with metric 100, Wi-Fi with 600, so plugging in a phone redirected
all unmarked traffic to cellular. The fix is a deterministic precedence table
(`Priority`: 50/100/700) applied with `ip route replace … metric N` on every discovery
pass. Because the same function picks failover targets, preference and recovery cannot
diverge.

## 5.4 Terminal rows showed zero traffic

**Cause.** The scanner collapses a browser or shell tree into its root PID, but sockets
belong to children (`omp` under a `zsh`, renderers under `firefox`). Summing only the root
PID's counters produced zeros.

**Fix.** `ListProcesses` resolves the tree per row and aggregates:

```go
pids, _ := d.scanner.GetProcessTree(procs[i].PID)
usage, rate := d.telemetry.SubtreeUsage(pids)
```

Cost: one recursive `Children()` walk per displayed row per request (≈10 rows), which is
negligible next to the `ss` spawn itself.

## 5.5 Counter resets between samples

Sockets close, so the per-PID sum can *decrease* between ticks. A naive `cur - prev` would
emit a negative rate and a decreasing cumulative total. The engine clamps negative deltas to
zero and rebases the previous snapshot, so usage is monotonically non-decreasing and a closed
socket costs at most one interval of accuracy.

## 5.6 Per-application numbers are TCP-only

`ss` exposes byte counters for TCP sockets (`bytes_acked`, `bytes_received`) but not for UDP,
so QUIC/HTTP-3 traffic is invisible at the application level while still counted at the
interface level (sysfs). This is documented rather than papered over:

- interface cards show exact, protocol-agnostic totals;
- per-app columns are labelled internally as socket-derived and can be zero while the
  interface rate is non-zero;
- the accurate fix (per-cgroup byte counting in eBPF) is defined but not implemented.

An attempted alternative — deriving per-app shares from interface counters — was rejected as
fabrication.

## 5.7 Kill-switch correctness

A strict policy must **fail closed**. Two mechanisms guarantee it:

1. The quarantine cgroup is the *first* rule in the output chain, before any marking rule, so
   a marked packet cannot escape by matching a later rule.
2. The eBPF program returns `0` for `drop` targets, which drops in the send path before the
   FIB is consulted at all.

Processes are released only when their original interface is present **and** the write to the
target `cgroup.procs` succeeds; failed releases stay in the map and are retried on the next
discovery pass.

## 5.8 Security posture of a root daemon

| Risk | Mitigation |
|---|---|
| Arbitrary interface names reaching `exec.Command` | `validIfaceRegex = ^[a-zA-Z0-9_.-]{1,16}$` validated in `InterfaceCgroupPath` and `InterfaceInfo.Validate` |
| Shell injection | every command is `exec.Command(name, args…)`; no shell is spawned |
| Moving critical processes | PID ≤ 100 refused in `AssignPID` **and** `GetProcessTree` |
| Unprivileged socket abuse | operations are limited to process→interface binding, system PIDs are refused, and the socket is local-only |
| Dashboard exposed to the network | binds `127.0.0.1:8088` by default; non-loopback is opt-in via `-addr` |
| BPF map growth | hash map capped at 4096 entries; links are closed on interface removal and shutdown |
| Stale state after crash | `InitHierarchy` migrates every managed PID back to the root cgroup on start; `KillMode=process` prevents systemd from killing unrelated children |

## 5.9 Performance characteristics

| Hot path | Cost | Notes |
|---|---|---|
| Telemetry tick | 1 × `ss -tinpH` + sysfs reads | `ss` spawn dominates (single-digit ms); parsing is O(sockets) |
| Interface watch | 2 × `ip route show` + sysfs stat per NIC | skips nftables re-apply when gateway/IP/table are unchanged |
| Auto-router tick | O(PIDs) reads of `comm`/`status`/`cmdline` | `/proc` direct, no gopsutil allocation |
| TUI refresh | 1 API round trip/s | JSON snapshot ≈ 1–2 KiB |
| Dashboard refresh | 1 HTTP request/1.5 s | skipped while a control is focused |
| Assignment | 1 `cgroup.procs` write (+ tree walk) | no rule changes required |

Deliberate non-optimizations: no caching of `ip rule` output (kernel is authoritative), no
batching of cgroup writes (process counts are small), no incremental ruleset patching
(regeneration is a few hundred bytes over a local socket).

## 5.10 Observability gaps (known)

There is no metrics endpoint and no persistent audit log of assignments. The daemon logs
lifecycle events (`auto-routed`, `failover`, `kill-switch`, `released`) to stdout/journald
only. A structured event stream is the natural next addition, and the `api.Broadcast`-style
seam does not exist yet — clients poll.


# 6. Reproduction, Setup & Deployment Guide

## 6.1 Prerequisites

| Requirement | Check | Install (Arch) |
|---|---|---|
| Linux with cgroups v2 | `stat -fc %T /sys/fs/cgroup` → `cgroup2fs` | enabled by default |
| Go ≥ 1.22 | `go version` | `pacman -S go` |
| `nftables` | `nft --version` | `pacman -S nftables` |
| `iproute2` (incl. `ss`) | `ss -V` | `pacman -S iproute2` |
| `bpftool` (verification only) | `bpftool version` | `pacman -S bpf` |
| `clang` (only to regenerate BPF) | `clang --version` | `pacman -S clang` |

## 6.2 Environment variables

The daemon reads the environment directly (no `.env` loader). A systemd drop-in or shell
export is the supported mechanism:

```bash
# /etc/netweaver/netweaver.env  — consumed via EnvironmentFile= or `set -a; . file`
# Socket path shared by daemon and clients (client-side override is the useful one)
NETWEAVER_SOCK=/run/netweaver/netweaver.sock

# Persistent auto-routing rules (JSON, created on first write)
NETWEAVER_RULES=/etc/netweaver/rules.json

# Global default policy: failover | strict
NETWEAVER_SETTINGS=/etc/netweaver/settings.json
```

| Variable | Default | Applies to | Effect |
|---|---|---|---|
| `NETWEAVER_SOCK` | `/run/netweaver/netweaver.sock` | client | alternate daemon / test harness |
| `NETWEAVER_RULES` | `/etc/netweaver/rules.json` | daemon | rule store location |
| `NETWEAVER_SETTINGS` | `/etc/netweaver/settings.json` | daemon | default-policy file |

## 6.3 Build and test

```bash
git clone https://github.com/ronakgupta03/netweaver
cd netweaver
make build          # bin/netweaverd, bin/netweaver
make test           # 14 packages, 41 test functions
make bpf            # optional: regenerate internal/classifier/netweaver_bpfel.o
```

`make bpf` is the only step requiring `clang`; the compiled object is committed so a clean
checkout builds offline with Go alone.

## 6.4 Run (development, three terminals)

```bash
# Terminal 1 — root daemon (foreground by design; it is a server)
sudo ./bin/netweaverd

# Terminal 2 — interactive dashboard
./bin/netweaver

# Terminal 3 — web dashboard (optional)
./bin/netweaver web --open
```

Expected daemon startup:

```
[netweaverd] Discovered interface: wlan0 (table 260)
[netweaverd] Discovered interface: enp5s0f4u2 (table 265)
[netweaverd] eBPF classifier active (cgroup_skb/egress marking)
[netweaverd] Listening on /run/netweaver/netweaver.sock
```

If BPF is unavailable the line becomes
`eBPF classifier unavailable, using nftables marking: …` and operation continues.

## 6.5 Operational commands

```bash
./bin/netweaver interfaces                 # adapters, IPs, gateways, tables, rates
./bin/netweaver list                       # apps + interface + policy + rates + usage
./bin/netweaver assign 1725 wlan0          # bind a PID (and its children)
./bin/netweaver reset 1725                 # back to the default route
./bin/netweaver run -i wlan0 firefox       # spawn already routed

./bin/netweaver rules add firefox wlan0 strict
./bin/netweaver rules add 'steam*' eno1
./bin/netweaver rules list
./bin/netweaver rules remove firefox
./bin/netweaver rules clear

./bin/netweaver policy                     # show default policy
./bin/netweaver policy set strict
```

## 6.6 Deployment as a systemd service

```bash
sudo install -m 0755 bin/netweaverd /usr/local/bin/netweaverd
sudo install -m 0755 bin/netweaver  /usr/local/bin/netweaver
sudo install -d /etc/netweaver
sudo cp scripts/netweaver.service /etc/systemd/system/netweaver.service
sudo systemctl daemon-reload
sudo systemctl enable --now netweaver
journalctl -u netweaver -f
```

The unit uses `KillMode=process`, so stopping the service does not signal the applications
it manages; the daemon's own shutdown path returns every PID to the root cgroup and removes
its nftables table, routes and FIB rules.

## 6.7 Verification recipes

**Routing (no root beyond the daemon):**

```bash
ip rule show                       # fwmark 0x104 lookup 260, priority 1000
ip route show table all            # per-interface defaults
sudo nft list ruleset              # marking only when nftables mode is active
```

**Per-application egress:**

```bash
./bin/netweaver assign <pid-A> wlan0
./bin/netweaver assign <pid-B> enp5s0f4u2
# in A: curl -4 https://api.ipify.org   → Wi-Fi public IP
# in B: curl -4 https://api.ipify.org   → tethering public IP (different)
```

**Two uplinks without hardware:**

```bash
sudo scripts/setup-veth-test.sh
# create, assign, and verify two veth pairs; teardown with:
sudo scripts/teardown-veth-test.sh
```

**eBPF classifier on the kernel:**

```bash
sudo scripts/verify-ebpf.sh
# asserts: nw_mark attached per cgroup, nw_targets map contents,
#          routing state, and clean teardown (no leftover nftables table)
```

**Test suite:**

```bash
go test ./...                       # unit + integration (UDS, HTTP, reconciliation)
go test ./internal/routing/ -run Nft -v
```

## 6.8 Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `netweaverd must run as root` | daemon started unprivileged | `sudo` |
| `failed connecting to daemon at …sock` | daemon not running or crashed | start it; check journal |
| `nft apply failed …` | `nft` missing or no writable cgroup dirs | install nftables; check `/sys/fs/cgroup/netweaver` |
| app rates `0 B/s` while interface moves | UDP/QUIC only, or `ss` missing | install iproute2; read interface totals |
| `eBPF classifier unavailable` | no CAP_BPF / kernel support | expected: nftables marking is used |
| interface missing from list | no carrier (cable/AP down) or no IPv4 address | fix link; discovery filters carrier-less NICs |
| assignment appears to revert | rule matches the app and re-applies at its version change | remove/adjust the rule |
| dashboard unreachable | bound to loopback only | `netweaver web --addr 0.0.0.0:8088` (explicit opt-in) |

## 6.9 Uninstall / cleanup

```bash
sudo systemctl disable --now netweaver
sudo rm /etc/systemd/system/netweaver.service
sudo rm -rf /etc/netweaver
sudo rm -f /usr/local/bin/netweaverd /usr/local/bin/netweaver
# daemon shutdown already removed: nftables table, FIB rules, routing tables, cgroups
```


# Appendix A — Verification matrix

| Area | Evidence produced during development | Requires root |
|---|---|---|
| Telemetry parsing | fixture test (loopback skipped, multi-PID attribution) | no |
| Telemetry live | `ss` + sysfs probe: firefox 307 KiB/s, 4.1 MiB total; wlan0 322 KiB/s | no |
| TUI rendering | pty capture of live rates, totals, sparklines, policy column | no |
| Rules store | persistence, atomic write, glob/prefix matching, version bump | no |
| Auto-router | real `/proc` scan matched only PID 1725; spawned `sleep` attached in one cycle | no |
| Policy | settings round-trip, precedence (explicit > rule > default) | no |
| Failover engine | strict blocks, failover picks `eno1`, no-survivor leaves in place | no |
| PBR + ruleset | user netns, two veth uplinks, `ip route get … mark` selects correct table; removal cleans only the lost interface | netns root only |
| nftables path filtering | unit test: missing cgroup omitted, blocked rule gated | no |
| Dashboard | browser session: add/delete rule, assign app, policy toggle, state polling | no |
| eBPF object | parses as `CGroupSKB` / egress, 8-byte map value | no |
| eBPF attach/map | injectable attach/map tests; EPERM path triggers documented fallback | load requires root |
| eBPF on kernel | `scripts/verify-ebpf.sh` (attach, map dump, teardown) | yes |

# Appendix B — Commit chronology

| Commit | Scope |
|---|---|
| `47fa08d`, `53b484d` | design specification, implementation plan |
| `fab4547` … `4db0da9` | models, cgroups, routing, discovery, scanner, IPC, daemon, CLI, TUI |
| `c702813`, `78c356c`, `cf39d95`, `8b780fb`, `0edc636`, `363b122` | netns harness, review fixes, carrier filtering, app surfacing, terminal naming, dedup |
| `f3194ac` | priority hierarchy + IPv6 leak prevention |
| `4a1461f`, `ce93d8a`, `30ff2e6` | telemetry, rules, policies |
| `b3bd517` | nftables cgroup-path filtering fix |
| `535c7e5`, `9013fe6`, `5cbd6a3` | web dashboard, eBPF classifier, classifier tests + verify script |

# Appendix C — Glossary

| Term | Meaning |
|---|---|
| **PBR** | policy-based routing: route selection driven by `ip rule` (here, by fwmark) |
| **fwmark** | 32-bit mark on a packet/socket consulted by `ip rule` |
| **cgroup v2** | unified Linux control-group hierarchy (`/sys/fs/cgroup`) |
| **kernfs inode** | inode number of a cgroup directory; equals `bpf_get_current_cgroup_id()` |
| **mangle / srcnat** | netfilter hook priorities: mark before routing, NAT after |
| **failover / strict** | policy for a vanished interface: relocate traffic, or block it |
| **quarantine cgroup** | `netweaver/blocked`, whose packets are dropped |
