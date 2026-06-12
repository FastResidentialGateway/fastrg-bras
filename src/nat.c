/* nat.c — hybrid forwarding engine (PPPoE ⇄ upstream)
 *
 * The lab bench routes the subscriber pool: the WAN host has
 * "192.168.200.128/25 via 192.168.201.1" pointing at our LAN-side IP, and
 * the e2e suite verifies the PPPoE address end-to-end on the backbone LAN
 * (the TCP-SPI phase sniffs for it, the DNAT phase injects to it).  So
 * traffic whose destination is *on the backbone LAN* (192.168.201.0/24) is
 * forwarded transparently — no address translation.
 *
 * Internet-bound traffic is different: the WAN host's firewall only
 * forwards/masquerades the LAN net to the internet, not the subscriber
 * pool.  Those flows are SNATed to nat_public_ip (our LAN-side IP) so they
 * leave the bench as 192.168.201.1 and survive the trip.
 *
 * Outbound (PPPoE → upstream):
 *   Strip Eth/VLAN/PPPoE/PPP → plain Eth + IP packet
 *   dst ∈ LAN /24  → forward as-is (transparent)
 *   dst elsewhere  → SNAT src to nat_public_ip (TCP/UDP ports, ICMP ident)
 *   Forward out LAN_PORT toward the upstream next-hop (resolved via ARP)
 *
 * Inbound (upstream → PPPoE):
 *   dst == nat_public_ip                  → DNAT back via the flow table
 *   dst ∈ [ip_pool_start, ip_pool_end]    → transparent, session by dst IP
 *   Wrap in (VLAN+)PPPoE session frame, forward out WAN_PORT
 */

#include <string.h>
#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_spinlock.h>
#include <rte_debug.h>

#include "bras.h"

#define RTE_LOGTYPE_NAT  RTE_LOGTYPE_USER3

/* NAT port pool: 1024–65000 */
#define NAT_PORT_MIN     1024
#define NAT_PORT_MAX     65000
#define NAT_PORT_RANGE   (NAT_PORT_MAX - NAT_PORT_MIN)

/* Timeout: 300 seconds idle */
#define NAT_IDLE_TIMEOUT_CYCLES (300ULL * rte_get_timer_hz())

/* The backbone LAN is a /24 (192.168.201.0/24 in the lab topology). */
#define LAN_NETMASK      0xFFFFFF00u

/* Outbound NAT lookup key */
struct nat_out_key {
    uint32_t inner_ip;
    uint16_t inner_port;
    uint8_t  proto;
    uint8_t  pad;
};

/* Inbound NAT lookup key */
struct nat_in_key {
    uint16_t outer_port;
    uint8_t  proto;
    uint8_t  pad;
};

static uint16_t next_nat_port = NAT_PORT_MIN;

/* Serialises new-entry creation across data lcores. */
static rte_spinlock_t nat_alloc_lock = RTE_SPINLOCK_INITIALIZER;

/*
 * Scan for a free NAT port starting from next_nat_port.
 * Must be called under nat_alloc_lock.
 * Returns 0 when the pool is exhausted.
 */
static uint16_t
alloc_nat_port(void)
{
    uint16_t start = next_nat_port;
    do {
        uint16_t idx = next_nat_port - NAT_PORT_MIN;
        uint16_t p   = next_nat_port++;
        if (next_nat_port >= NAT_PORT_MAX)
            next_nat_port = NAT_PORT_MIN;
        if (!g_bras.nat_entries[idx].in_use)
            return p;
    } while (next_nat_port != start);
    return 0;  /* pool exhausted */
}

void
nat_init(void)
{
    /* Outbound table: key=(inner_ip, inner_port, proto) */
    struct rte_hash_parameters out_params = {
        .name       = "nat_out",
        .entries    = MAX_NAT_ENTRIES,
        .key_len    = sizeof(struct nat_out_key),
        .hash_func  = rte_jhash,
        .socket_id  = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };
    g_bras.nat_out_tbl = rte_hash_create(&out_params);

    /* Inbound table: key=(outer_port, proto) */
    struct rte_hash_parameters in_params = {
        .name       = "nat_in",
        .entries    = MAX_NAT_ENTRIES,
        .key_len    = sizeof(struct nat_in_key),
        .hash_func  = rte_jhash,
        .socket_id  = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };
    g_bras.nat_in_tbl = rte_hash_create(&in_params);

    if (!g_bras.nat_out_tbl || !g_bras.nat_in_tbl)
        rte_exit(EXIT_FAILURE, "Cannot create NAT hash tables\n");

    RTE_LOG(INFO, NAT, "NAT tables initialised\n");
}

/* ── checksum helpers ─────────────────────────────────────────────────── */

static void
update_ip_csum(struct rte_ipv4_hdr *ip)
{
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
}

/* Recompute the TCP/UDP checksum (incl. pseudo-header) from scratch. */
static void
update_l4_csum(struct rte_ipv4_hdr *ip, void *l4)
{
    if (ip->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = l4;
        tcp->cksum = 0;
        tcp->cksum = rte_ipv4_udptcp_cksum(ip, l4);
    } else if (ip->next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = l4;
        if (udp->dgram_cksum == 0)
            return;  /* checksum disabled — keep it that way */
        udp->dgram_cksum = 0;
        udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, l4);
        if (udp->dgram_cksum == 0)
            udp->dgram_cksum = 0xFFFF;
    }
}

/* Recompute the ICMP checksum (no pseudo-header). */
static void
update_icmp_csum(struct rte_ipv4_hdr *ip, struct rte_icmp_hdr *icmp)
{
    uint16_t icmp_len = ntohs(ip->total_length) -
                        ((ip->version_ihl & 0xF) << 2);
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = (uint16_t)~rte_raw_cksum(icmp, icmp_len);
}

/* ── SNAT (internet-bound, client → upstream) ────────────────────────── */

/*
 * snat_outbound — rewrite src to nat_public_ip with a flow-table mapping.
 * Called only for internet-bound packets (dst outside the LAN /24).
 * Returns 0 on success (including pass-through protos), -1 to drop.
 */
static int
snat_outbound(struct rte_ipv4_hdr *ip, struct bras_session *sess)
{
    uint8_t   proto = ip->next_proto_id;
    uint8_t  *l4 = (uint8_t *)ip + ((ip->version_ihl & 0xF) << 2);
    uint16_t  inner_port;
    uint16_t *l4_src_port_ptr = NULL;
    struct rte_icmp_hdr *icmp = NULL;

    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
        inner_port = ntohs(tcp->src_port);
        l4_src_port_ptr = &tcp->src_port;
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
        inner_port = ntohs(udp->src_port);
        l4_src_port_ptr = &udp->src_port;
    } else if (proto == IPPROTO_ICMP) {
        icmp = (struct rte_icmp_hdr *)l4;
        if (icmp->icmp_type != RTE_ICMP_TYPE_ECHO_REQUEST)
            return 0;  /* non-echo ICMP: forward un-NATed */
        inner_port = ntohs(icmp->icmp_ident);
    } else {
        return 0;  /* other protocols: forward un-NATed */
    }

    /* Lookup or create NAT entry */
    struct nat_out_key out_key = {
        .inner_ip   = ntohl(ip->src_addr),
        .inner_port = inner_port,
        .proto      = proto,
        .pad        = 0,
    };

    int32_t pos = rte_hash_lookup(g_bras.nat_out_tbl, &out_key);
    uint16_t outer_port;

    if (pos < 0) {
        /* New flow — serialise allocation across data lcores */
        rte_spinlock_lock(&nat_alloc_lock);
        /* Double-check: another worker may have created it while we waited */
        pos = rte_hash_lookup(g_bras.nat_out_tbl, &out_key);
        if (pos < 0) {
            outer_port = alloc_nat_port();
            if (outer_port == 0) {
                rte_spinlock_unlock(&nat_alloc_lock);
                return -1;  /* NAT pool exhausted */
            }
            struct nat_entry *entry =
                &g_bras.nat_entries[outer_port - NAT_PORT_MIN];
            entry->in_use     = 1;
            entry->proto      = proto;
            entry->inner_ip   = out_key.inner_ip;
            entry->inner_port = inner_port;
            entry->outer_ip   = g_bras.nat_public_ip;
            entry->outer_port = outer_port;
            entry->session_id = sess->session_id;
            entry->last_seen  = rte_rdtsc();

            rte_hash_add_key_data(g_bras.nat_out_tbl, &out_key,
                                  (void *)(uintptr_t)outer_port);
            struct nat_in_key in_key = {
                .outer_port = outer_port,
                .proto      = proto,
                .pad        = 0,
            };
            rte_hash_add_key_data(g_bras.nat_in_tbl, &in_key, entry);
        } else {
            /* Race: another worker created the entry first */
            void *data;
            rte_hash_lookup_data(g_bras.nat_out_tbl, &out_key, &data);
            outer_port = (uint16_t)(uintptr_t)data;
            g_bras.nat_entries[outer_port - NAT_PORT_MIN].last_seen =
                rte_rdtsc();
        }
        rte_spinlock_unlock(&nat_alloc_lock);
    } else {
        void *data;
        rte_hash_lookup_data(g_bras.nat_out_tbl, &out_key, &data);
        outer_port = (uint16_t)(uintptr_t)data;
        g_bras.nat_entries[outer_port - NAT_PORT_MIN].last_seen = rte_rdtsc();
    }

    /* Rewrite src ip + src port/ident, recompute checksums */
    ip->src_addr = htonl(g_bras.nat_public_ip);
    if (l4_src_port_ptr) {
        *l4_src_port_ptr = htons(outer_port);
        update_l4_csum(ip, l4);
    } else if (icmp) {
        icmp->icmp_ident = htons(outer_port);
        update_icmp_csum(ip, icmp);
    }
    update_ip_csum(ip);

    return 0;
}

/* ── DNAT (internet replies, upstream → client) ──────────────────────── */

/*
 * dnat_inbound — reverse the SNAT mapping for a packet addressed to
 * nat_public_ip.  Rewrites dst ip + dst port/ident in place.
 * Returns the owning session, or NULL to drop.
 */
static struct bras_session *
dnat_inbound(struct rte_ipv4_hdr *ip)
{
    uint8_t   proto = ip->next_proto_id;
    uint8_t  *l4 = (uint8_t *)ip + ((ip->version_ihl & 0xF) << 2);
    uint16_t  outer_port;
    uint16_t *l4_dst_port_ptr = NULL;
    struct rte_icmp_hdr *icmp = NULL;

    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
        outer_port = ntohs(tcp->dst_port);
        l4_dst_port_ptr = &tcp->dst_port;
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
        outer_port = ntohs(udp->dst_port);
        l4_dst_port_ptr = &udp->dst_port;
    } else if (proto == IPPROTO_ICMP) {
        icmp = (struct rte_icmp_hdr *)l4;
        if (icmp->icmp_type != RTE_ICMP_TYPE_ECHO_REPLY)
            return NULL;
        outer_port = ntohs(icmp->icmp_ident);
    } else {
        return NULL;
    }

    struct nat_in_key in_key = {
        .outer_port = outer_port,
        .proto      = proto,
        .pad        = 0,
    };
    void *data = NULL;
    if (rte_hash_lookup_data(g_bras.nat_in_tbl, &in_key, &data) < 0)
        return NULL;  /* no mapping — drop */

    struct nat_entry *entry = (struct nat_entry *)data;
    entry->last_seen = rte_rdtsc();

    uint16_t session_id = entry->session_id;
    if (session_id == 0 || session_id > MAX_SESSIONS)
        return NULL;
    struct bras_session *sess = &g_bras.sessions[session_id];
    if (sess->state != SESS_UP)
        return NULL;

    /* Rewrite dst ip + dst port/ident back to inner, recompute checksums */
    ip->dst_addr = htonl(entry->inner_ip);
    if (l4_dst_port_ptr) {
        *l4_dst_port_ptr = htons(entry->inner_port);
        update_l4_csum(ip, l4);
    } else if (icmp) {
        icmp->icmp_ident = htons(entry->inner_port);
        update_icmp_csum(ip, icmp);
    }
    update_ip_csum(ip);

    return sess;
}

/* ── outbound (client → upstream) ────────────────────────────────────── */

/*
 * route_outbound
 *
 * The mbuf arrives with:
 *   Eth [/ VLAN] / PPPoE / PPP(0x0021) / IP / ...
 *
 * After this function:
 *   Eth / IP / ...   (PPPoE stripped; src SNATed iff internet-bound)
 *   Ready to send out LAN_PORT.
 *
 * Returns 0 on success, -1 to drop.
 */
int
route_outbound(struct rte_mbuf *mbuf, struct bras_session *sess)
{
    uint8_t *base = rte_pktmbuf_mtod(mbuf, uint8_t *);
    uint16_t l2_len, vlan_tci;
    bras_frame_ethertype(base, &l2_len, &vlan_tci);
    (void)vlan_tci;

    size_t pppoe_overhead =
        l2_len +
        sizeof(struct pppoe_hdr) +
        sizeof(struct ppp_hdr);

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(base + pppoe_overhead);

    /* Only handle IPv4 */
    if ((ip->version_ihl >> 4) != 4)
        return -1;

    /* Next-hop MAC must have been resolved via ARP first. */
    if (!g_bras.upstream_mac_valid)
        return -1;

    /* Backbone-local dst → transparent; internet-bound → SNAT */
    uint32_t dst = ntohl(ip->dst_addr);
    if ((dst & LAN_NETMASK) != (g_bras.nat_public_ip & LAN_NETMASK)) {
        if (snat_outbound(ip, sess) < 0)
            return -1;
    }

    sess->bytes_up += mbuf->data_len;

    /* Strip Ethernet/VLAN/PPPoE/PPP and prepend a plain LAN Ethernet header. */
    struct rte_ether_hdr lan_eth;

    /* Route everything to the upstream next-hop on the LAN side */
    rte_ether_addr_copy(&g_bras.upstream_mac, &lan_eth.dst_addr);
    rte_ether_addr_copy(&g_bras.lan_mac,      &lan_eth.src_addr);
    lan_eth.ether_type = htons(RTE_ETHER_TYPE_IPV4);

    /* Trim original L2 + PPPoE + PPP from the front. */
    rte_pktmbuf_adj(mbuf, (uint16_t)pppoe_overhead);

    /* Add a plain Ethernet header for the upstream side. */
    uint8_t *new_base =
        (uint8_t *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));
    if (!new_base)
        return -1;
    memcpy(new_base, &lan_eth, sizeof(lan_eth));

    return 0;
}

/* ── inbound (upstream → client) ─────────────────────────────────────── */

/*
 * route_inbound
 *
 * The mbuf arrives from LAN_PORT:
 *   Eth / IPv4 / ...
 *     dst = nat_public_ip            → internet reply, DNAT back
 *     dst ∈ subscriber pool          → transparent, session by dst IP
 *
 * After this function:
 *   Eth [/ VLAN] / PPPoE-session / PPP(0x0021) / IP / ...
 *   Ready to send out WAN_PORT.
 *
 * Note: the e2e bench injects frames whose Ethernet dst is the fastrg-node
 * WAN MAC rather than ours — we rely on the LAN alias MAC filter and route
 * purely on the destination IP.
 *
 * Returns 0 on success, -1 to drop.
 */
int
route_inbound(struct rte_mbuf *mbuf)
{
    uint8_t *base = rte_pktmbuf_mtod(mbuf, uint8_t *);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)base;

    if (ntohs(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
        return -1;

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(base + sizeof(struct rte_ether_hdr));

    uint32_t dst = ntohl(ip->dst_addr);
    struct bras_session *sess;

    if (dst == g_bras.nat_public_ip) {
        /* Internet reply to a SNATed flow — rewrites dst in place */
        sess = dnat_inbound(ip);
        if (!sess)
            return -1;
    } else if (dst >= g_bras.ip_pool_start && dst <= g_bras.ip_pool_end) {
        /* Session N owns ip_pool_start + (N-1) — see session_alloc_ip() */
        uint16_t session_id = (uint16_t)(dst - g_bras.ip_pool_start) + 1;
        if (session_id == 0 || session_id > MAX_SESSIONS)
            return -1;
        sess = &g_bras.sessions[session_id];
        if (sess->state != SESS_UP || sess->client_ip != dst)
            return -1;
    } else {
        return -1;
    }

    sess->bytes_down += mbuf->data_len;

    /* Prepend PPPoE session header:
     * We need to add optional VLAN plus PPPoE+PPP in front of the IP packet,
     * and fix up the Ethernet header.
     *
     * Before:  [ETH(14)] [IPv4...]
     * After:   [ETH(14)] [optional VLAN(4)] [PPPoE(6)] [PPP(2)] [IPv4...]
     */
    uint16_t ip_len = ntohs(ip->total_length);

    uint16_t extra = sizeof(struct pppoe_hdr) + sizeof(struct ppp_hdr) +
                     (sess->tx_vlan ? sizeof(struct rte_vlan_hdr) : 0);

    /* Prepend room after the existing Ethernet header. */
    uint8_t *new_start = (uint8_t *)rte_pktmbuf_prepend(
        mbuf, extra);
    if (!new_start)
        return -1;

    /* Re-lay ethernet header at new start */
    struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)new_start;
    rte_ether_addr_copy(&sess->client_mac, &new_eth->dst_addr);
    rte_ether_addr_copy(&g_bras.wan_mac,   &new_eth->src_addr);
    new_eth->ether_type = htons(sess->tx_vlan ? ETH_P_8021Q : ETH_P_PPPoE_SESS);

    uint8_t *pppoe_start = new_start + sizeof(*new_eth);
    if (sess->tx_vlan) {
        struct rte_vlan_hdr *vh = (struct rte_vlan_hdr *)pppoe_start;
        vh->vlan_tci = htons(sess->vlan_tci);
        vh->eth_proto = htons(ETH_P_PPPoE_SESS);
        pppoe_start += sizeof(*vh);
    }

    /* PPPoE header */
    struct pppoe_hdr *ph = (struct pppoe_hdr *)pppoe_start;
    ph->ver_type   = 0x11;
    ph->code       = PPPOE_CODE_DATA;
    ph->session_id = htons(sess->session_id);
    ph->length     = htons(sizeof(struct ppp_hdr) + ip_len);

    /* PPP protocol = IP */
    struct ppp_hdr *pph = (struct ppp_hdr *)(ph + 1);
    pph->protocol = htons(PPP_IP);

    return 0;
}

/* ── NAT entry expiry ─────────────────────────────────────────────────── */

/*
 * nat_expire — scan all entries and reclaim those idle for NAT_IDLE_TIMEOUT.
 * Called from the ctrl-plane lcore every 10 seconds; safe because only one
 * writer (ctrl) ever calls this.
 */
void
nat_expire(void)
{
    uint64_t now     = rte_rdtsc();
    uint64_t timeout = NAT_IDLE_TIMEOUT_CYCLES;
    uint32_t n_freed = 0;

    for (int i = 0; i < NAT_PORT_RANGE; i++) {
        struct nat_entry *e = &g_bras.nat_entries[i];
        if (!e->in_use) continue;
        if (now - e->last_seen < timeout) continue;

        struct nat_out_key out_key = {
            .inner_ip   = e->inner_ip,
            .inner_port = e->inner_port,
            .proto      = e->proto,
            .pad        = 0,
        };
        struct nat_in_key in_key = {
            .outer_port = e->outer_port,
            .proto      = e->proto,
            .pad        = 0,
        };
        rte_hash_del_key(g_bras.nat_out_tbl, &out_key);
        rte_hash_del_key(g_bras.nat_in_tbl,  &in_key);
        memset(e, 0, sizeof(*e));
        n_freed++;
    }

    if (n_freed > 0)
        RTE_LOG(INFO, NAT, "NAT expiry: reclaimed %u entries\n", n_freed);
}

/*
 * nat_flush_session — immediately remove all NAT entries belonging to a
 * session (called on session teardown so ports are available right away).
 */
void
nat_flush_session(uint16_t session_id)
{
    for (int i = 0; i < NAT_PORT_RANGE; i++) {
        struct nat_entry *e = &g_bras.nat_entries[i];
        if (!e->in_use || e->session_id != session_id) continue;

        struct nat_out_key out_key = {
            .inner_ip   = e->inner_ip,
            .inner_port = e->inner_port,
            .proto      = e->proto,
            .pad        = 0,
        };
        struct nat_in_key in_key = {
            .outer_port = e->outer_port,
            .proto      = e->proto,
            .pad        = 0,
        };
        rte_hash_del_key(g_bras.nat_out_tbl, &out_key);
        rte_hash_del_key(g_bras.nat_in_tbl,  &in_key);
        memset(e, 0, sizeof(*e));
    }
}
