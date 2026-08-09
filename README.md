# dpdk-bras — High-Performance BRAS for fastrg-node Testing

A minimal DPDK-based BRAS implementing:
- **PPPoE** Discovery (PADI/PADO/PADR/PADS/PADT) — RFC 2516
- **LCP** negotiation (MRU, auth method, magic number)
- **CHAP** authentication (MD5 challenge/response — accept-all for lab)
- **IPCP** address assignment from a /30 pool per session
- **IPCP DNS push** — primary/secondary DNS via options 129/131 (RFC 1877)
- **IPv6CP** interface-identifier negotiation (RFC 5072)
- **DHCPv6-PD** deterministic /56 delegation with recursive DNS (RFC 8415)
- **IPv6 routing** PPP 0x0057 decapsulation/encapsulation with /56 anti-spoofing
- **NDP/ICMPv6** upstream next-hop discovery and local echo replies
- **VF reset recovery** parked-lcore port rebuild after PF reset events
- **SNAT/DNAT** forwarding: PPPoE sessions ↔ upstream server

---

## Test Topology

```
┌─────────────────────────────────────────────────────────┐
│  Test Host (Use two DPDK capable NICs)                  │
│                                                         │
│  ┌──────────────┐   IPoPPPoE     ┌──────────────────┐   │
│  │ fastrg-node  │◄──────────────►│  To downstream   │   │
│  │  PPPoE client│                │  192.168.200.128 │   │
│  │  multi-tenant│                │    dpdk-bras     │   │
│  └──────────────┘                │                  │   │
│                                  │                  │   │
│  ┌──────────────┐   IPoE         │  To upstream     │   │
│  │  Upstream    │◄──────────────►│  192.168.201.1   │   │
│  │  Server      │                └──────────────────┘   │
│  │192.168.201.11│                                       │
│  └──────────────┘                                       │
└─────────────────────────────────────────────────────────┘
```

### fastrg-node Configuration (point at this BRAS)

In your fastrg-node config, set the WAN interface to the veth or physical
NIC connected to dpdk-bras's WAN port. The BRAS will:

1. Respond to PADI with PADO (AC-Name: `dpdk-bras`)
2. Assign session ID in PADS
3. Negotiate LCP with CHAP (or PAP)
4. Assign client IP from `10.64.0.0/30` pool:
   - Session 1 → server `10.64.0.1`, client `10.64.0.2`
   - Session 2 → server `10.64.0.5`, client `10.64.0.6`
   - Session N → server `10.64.0.(N-1)*4+1`, client `+1`
5. Delegate a deterministic IPv6 /56 after IPv6CP opens
6. Route delegated IPv6 prefixes between PPPoE and the upstream LAN
7. Route client IPv4 data to upstream server via SNAT

---

## Quick start

```bash
# Install dependencies (Ubuntu/Debian)
apt install dpdk dpdk-dev libnuma-dev meson ninja-build python3-pyelftools

# build
make

# Example Run
./dpdk-bras -l 0-5 -n 4 -- --pri-dns 192.168.10.1 \
  --pd-pool 2001:db8:6400::/48 \
  --lan-ip6 2001:db8:201::1 --upstream-ip6 2001:db8:201::11 \
  --drop-pcap ./test.pcap --vlans 3,5
```

---

## Architecture

### Lcore Assignment

Two modes are selected automatically at startup based on available lcores and
TX queue count.

**Distributor mode** (default on real NICs; needs ≥ 4 lcores and ≥ 3 TX queues):

| lcore | role |
|-------|------|
| 0 | main — init, stats loop, signal handling |
| 1 | `rx_dist_lcore` — polls WAN+LAN queue 0, classifies, tags by 5-tuple, fans out via `rte_distributor` |
| 2 | `ctrl_plane_lcore` — drains `ctrl_ring`, runs PPPoE/PPP/IPCP/IPv6CP/DHCPv6 state machines |
| 3+ | `dist_worker_lcore` × N — NAT + forwarding, each with a dedicated TX queue |

**Legacy mode** (fallback: < 4 lcores or single-queue vdevs like af_packet):

| lcore | role |
|-------|------|
| 0 | main |
| 1~N-1 | `datapath_lcore` — RX/classify/NAT inline |
| N | `ctrl_plane_lcore` |

### Packet Classification (WAN RX)

```
WAN RX burst
  ├── ethertype 0x8863 (PPPoE Discovery) ──► ctrl_ring ──► pppoe_handle_discovery()
  └── ethertype 0x8864 (PPPoE Session)
        ├── session not UP ──────────────► ctrl_ring ──► ppp_handle_ctrl()
        ├── PPP control or local/multicast 0x0057 ─► ctrl_ring ─► ppp_handle_ctrl()
        └── PPP proto = 0x0021 or global-dst 0x0057 data
              ├── distributor mode ───────► flow-tag + rte_distributor ──► worker: route_outbound() ──► LAN TX
              └── legacy mode ────────────► route_outbound() inline ──► LAN TX
```

### NAT Flow

```
Outbound (PPPoE → upstream):
  Strip PPPoE+PPP → SNAT (client_ip:port → PUBLIC_IP:nat_port) → LAN TX

Inbound (upstream → PPPoE):
  DNAT (PUBLIC_IP:nat_port → client_ip:inner_port) → Wrap PPPoE → WAN TX
```

---

## Key Files

| file | description |
|------|-------------|
| `include/bras.h` | All structs, constants, function prototypes |
| `src/main.c` | EAL init, port setup, lcore launch, utility functions |
| `src/pppoe.c` | PPPoE Discovery state machine |
| `src/ppp.c` | LCP/IPCP/IPv6CP/CHAP/PAP control plane |
| `src/dhcpv6.c` | DHCPv6 prefix delegation and DNS replies |
| `src/ipv6.c` | IPv6 routing, NDP, and ICMPv6 responders |
| `src/nat.c` | SNAT/DNAT engine with rte_hash tables |
| `src/datapath.c` | Fast-path RX/TX worker + control-plane lcore |

---

## Known Simplifications (for testing)

- CHAP always succeeds (`chap_verify_response` returns 1) — replace with
  RADIUS or local credential lookup for real deployments.
- Per-worker TX queues are already implemented (distributor mode allocates
  one TX queue per worker plus queue 0 for the RX lcore and queue N+1 for
  the ctrl lcore). Legacy mode serializes `rte_eth_tx_burst()` only when
  its data and control lcores must share a device TX queue.
- IPv6 forwarding uses one configured upstream next-hop and does not perform
  NAT66, generate ICMPv6 forwarding errors, or fragment oversized packets.
- Autonomous ARP/NS transmission is gated by LAN link state. Unresolved IPv6
  neighbour discovery retries once per second for 30 sends, then every 10
  seconds. VF reset callbacks only signal the main-lcore supervisor, which
  waits up to 10 seconds for link readiness without pausing traffic, then parks
  datapath lcores, rebuilds affected ports, and restores VLAN filters. The
  control lcore sends one gratuitous ARP and unsolicited NA after recovery.
  No WAN warm-up is needed because PPPoE uses session IDs rather than neighbour
  discovery, and port rebuild already restores the VF's MAC filters.
- Runtime log lines use local-time `[YYYY-MM-DD HH:MM:SS.mmm] ` prefixes.
- NAT entries are reclaimed by `nat_expire()` after 300 s of idle time;
  the ctrl lcore calls it on a 10 s tick.

---

## DNS Configuration

By default the BRAS pushes `1.1.1.1` (primary) and `8.8.8.8` (secondary) to
every client via IPCP options 129/131. Override at startup:

```bash
./dpdk-bras -l 0-2 -n 4 -- \
  --ip-pool 10.64.0.0 \
  --pri-dns 9.9.9.9 \
  --sec-dns 149.112.112.112
```

The negotiation goes:

```
Client  →  CONF_REQ  [IP=0.0.0.0, DNS1=0.0.0.0, DNS2=0.0.0.0]
BRAS    →  CONF_NAK  [IP=10.64.0.2, DNS1=1.1.1.1, DNS2=8.8.8.8]
Client  →  CONF_REQ  [IP=10.64.0.2, DNS1=1.1.1.1, DNS2=8.8.8.8]
BRAS    →  CONF_ACK  [IP=10.64.0.2, DNS1=1.1.1.1, DNS2=8.8.8.8]
```

If the client doesn't include DNS options in its `CONF_REQ`, the BRAS won't
push them — only options the client asks for are negotiated.

## DHCPv6 Prefix Delegation

After IPv6CP opens, the BRAS answers DHCPv6 Solicit, Request, Renew, Rebind,
and Release messages over PPP. Each session receives a deterministic /56 from
the configured pool. The node uses the delegated /56's first /64 for its LAN.
The Reply also carries both configured IPv6 DNS servers.

| option | default | description |
|--------|---------|-------------|
| `--pd-pool <prefix>/<plen>` | `2001:db8:6400::/48` | Delegated-prefix pool; length must be 1 through 55 and host bits must be zero. |
| `--lan-ip6 <IPv6>` | `2001:db8:201::1` | BRAS global IPv6 address on the upstream LAN. |
| `--upstream-ip6 <IPv6>` | `2001:db8:201::11` | Single IPv6 next-hop used by delegated-prefix traffic. |
| `--pri-dns6 <IPv6>` | `2606:4700:4700::1111` | Primary DNS server in DHCPv6 option 23. |
| `--sec-dns6 <IPv6>` | `2001:4860:4860::8888` | Secondary DNS server in DHCPv6 option 23. |

Example:

```bash
./dpdk-bras -l 0-2 -n 4 -- \
  --pd-pool 2001:db8:64::/48 \
  --pri-dns6 2606:4700:4700::1111 \
  --sec-dns6 2001:4860:4860::8888
```
