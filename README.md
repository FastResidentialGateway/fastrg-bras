# dpdk-bras — High-Performance BRAS for fastrg-node Testing

A minimal DPDK-based BRAS implementing:
- **PPPoE** Discovery (PADI/PADO/PADR/PADS/PADT) — RFC 2516
- **LCP** negotiation (MRU, auth method, magic number)
- **CHAP** authentication (MD5 challenge/response — accept-all for lab)
- **IPCP** address assignment from a /30 pool per session
- **IPCP DNS push** — primary/secondary DNS via options 129/131 (RFC 1877)
- **SNAT/DNAT** forwarding: PPPoE sessions ↔ upstream server

---

## Test Topology

```
┌──────────────────────────────────────────────────────────┐
│  Test Host (one machine with veth pairs or two NICs)      │
│                                                          │
│  ┌──────────────┐   eth0/veth0   ┌──────────────────┐   │
│  │ fastrg-node  │◄──────────────►│  WAN port (DPDK) │   │
│  │ (PPPoE client│                │                  │   │
│  │  multi-tenant│                │    dpdk-bras     │   │
│  └──────────────┘                │                  │   │
│                                  │  LAN port (DPDK) │   │
│  ┌──────────────┐   eth1/veth1   │                  │   │
│  │  Upstream    │◄──────────────►│                  │   │
│  │  Server      │                └──────────────────┘   │
│  │ 192.168.100.1│                                        │
└──────────────────────────────────────────────────────────┘
```

### Using Virtual Interfaces (no hardware NIC needed)

```bash
# Create veth pairs for testing
ip link add veth-wan type veth peer name veth-wan-bras
ip link add veth-lan type veth peer name veth-lan-bras

ip link set veth-wan up
ip link set veth-lan up
ip link set veth-wan-bras up
ip link set veth-lan-bras up

# Bind veth pairs to DPDK (using net_af_packet driver — no vfio needed)
# Then run with:
sudo ./build/dpdk-bras \
  -l 0-2 -n 4 \
  --vdev "net_af_packet0,iface=veth-wan-bras" \
  --vdev "net_af_packet1,iface=veth-lan-bras" \
  -- --ip-pool 10.64.0.0
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
5. Route client data to upstream server via SNAT

### Upstream Server

```bash
# On the upstream server machine (192.168.100.1):
# Accept and reply to any IP traffic (e.g. simple echo):
nc -lu 9999           # UDP echo test
python3 -m http.server 8080   # HTTP test
```

---

## Build

```bash
# Install dependencies (Ubuntu/Debian)
apt install dpdk dpdk-dev libnuma-dev meson ninja-build python3-pyelftools

# Build
meson setup build
ninja -C build

# Run (with real NICs)
./scripts/setup.sh
```

---

## Architecture

### Lcore Assignment

| lcore | role |
|-------|------|
| 0 | main (init, stats, signal handling) |
| 1 | `datapath_lcore` — RX/TX fast path, BURST_SIZE=32 |
| 2 | `ctrl_plane_lcore` — PPPoE/LCP/IPCP state machines |

### Packet Classification (WAN RX)

```
WAN RX burst
  ├── ethertype 0x8863 (PPPoE Discovery) ──► ctrl_ring ──► pppoe_handle_discovery()
  └── ethertype 0x8864 (PPPoE Session)
        ├── session not UP ──────────────► ctrl_ring ──► ppp_handle_ctrl()
        ├── PPP proto ≠ 0x0021 (ctrl) ───► ctrl_ring ──► ppp_handle_ctrl()
        └── PPP proto = 0x0021 (IP data) ► nat_translate_outbound() ──► LAN TX
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
| `src/ppp.c` | LCP/IPCP/CHAP/PAP control plane |
| `src/nat.c` | SNAT/DNAT engine with rte_hash tables |
| `src/datapath.c` | Fast-path RX/TX worker + control-plane lcore |

---

## Known Simplifications (for testing)

- CHAP always succeeds (`chap_verify_response` returns 1) — replace with
  RADIUS or local credential lookup for real deployments.
- Single TX queue per port — for multi-core scaling add per-lcore TX queues
  and `rte_eth_tx_burst` with queue_id = lcore_id.
- No IPv6CP.
- NAT port allocation is round-robin without expiry scan — add a timer to
  reclaim idle entries for long-running scenarios.

---

## DNS Configuration

By default the BRAS pushes `1.1.1.1` (primary) and `8.8.8.8` (secondary) to
every client via IPCP options 129/131. Override at startup:

```bash
sudo ./build/dpdk-bras -l 0-2 -n 4 -- \
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
