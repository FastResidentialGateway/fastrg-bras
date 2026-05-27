/* nat.c — SNAT/DNAT engine
 *
 * Outbound (PPPoE → upstream):
 *   Strip PPPoE/PPP headers → IP packet
 *   SNAT: src_ip = client_ip → NAT_PUBLIC_IP, src_port → allocated port
 *   Forward out LAN_PORT toward upstream server
 *
 * Inbound (upstream → PPPoE):
 *   DNAT: dst_ip:dst_port → inner_ip:inner_port
 *   Wrap in PPPoE session frame
 *   Forward out WAN_PORT to correct fastrg-node
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

#include "bras.h"

#define RTE_LOGTYPE_NAT  RTE_LOGTYPE_USER3

/* NAT port pool: 1024–65000 */
#define NAT_PORT_MIN     1024
#define NAT_PORT_MAX     65000
#define NAT_PORT_RANGE   (NAT_PORT_MAX - NAT_PORT_MIN)

/* Timeout: 300 seconds idle */
#define NAT_IDLE_TIMEOUT_CYCLES (300ULL * rte_get_timer_hz())

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

    RTE_LOG(INFO, NAT, "NAT tables initialised\n");
}

/* ── checksum helpers ─────────────────────────────────────────────────── */

static void
update_ip_csum(struct rte_ipv4_hdr *ip)
{
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
}

/*
 * Incremental L4 checksum update after modifying IP/port fields.
 * Uses the "RFC 1624" method to avoid re-summing the full payload.
 */
static uint16_t
csum_update(uint16_t old_csum,
            uint32_t old_ip, uint32_t new_ip,
            uint16_t old_port, uint16_t new_port)
{
    /* One's complement arithmetic: csum -= old, csum += new */
    uint32_t csum = (~old_csum) & 0xFFFF;
    csum -= (old_ip >> 16) & 0xFFFF;
    csum -= (old_ip      ) & 0xFFFF;
    csum -= old_port;
    csum += (new_ip >> 16) & 0xFFFF;
    csum += (new_ip      ) & 0xFFFF;
    csum += new_port;
    while (csum >> 16) csum = (csum & 0xFFFF) + (csum >> 16);
    return (uint16_t)(~csum);
}

/* ── outbound (client → upstream) ────────────────────────────────────── */

/*
 * nat_translate_outbound
 *
 * The mbuf arrives with:
 *   Eth / PPPoE / PPP(0x0021) / IP / TCP-or-UDP
 *
 * After this function:
 *   Eth / IP / TCP-or-UDP   (PPPoE stripped, src IP/port SNATed)
 *   Ready to send out LAN_PORT.
 *
 * Returns 0 on success, -1 to drop.
 */
int
nat_translate_outbound(struct rte_mbuf *mbuf, struct bras_session *sess)
{
    uint8_t *base = rte_pktmbuf_mtod(mbuf, uint8_t *);

    size_t pppoe_overhead =
        sizeof(struct rte_ether_hdr) +
        sizeof(struct pppoe_hdr) +
        sizeof(struct ppp_hdr);

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(base + pppoe_overhead);

    /* Only handle IPv4 */
    if ((ip->version_ihl >> 4) != 4)
        return -1;

    uint8_t  proto    = ip->next_proto_id;
    uint32_t inner_ip = ntohl(ip->src_addr);
    uint16_t inner_port = 0;
    uint16_t *l4_csum_ptr = NULL;
    uint16_t *l4_src_port_ptr = NULL;

    uint8_t *l4 = (uint8_t *)ip + ((ip->version_ihl & 0xF) << 2);

    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
        inner_port = ntohs(tcp->src_port);
        l4_csum_ptr = &tcp->cksum;
        l4_src_port_ptr = &tcp->src_port;
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
        inner_port = ntohs(udp->src_port);
        l4_csum_ptr = &udp->dgram_cksum;
        l4_src_port_ptr = &udp->src_port;
    } else if (proto == IPPROTO_ICMP) {
        /* ICMP: use query ID as "port" for NAT mapping */
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)l4;
        if (icmp->icmp_type == 8 || icmp->icmp_type == 0) {
            inner_port = ntohs(icmp->icmp_seq_nb);
        }
    } else {
        /* Non-TCP/UDP/ICMP: forward as-is after stripping PPPoE */
        goto strip_and_forward;
    }

    /* Lookup or create NAT entry */
    struct nat_out_key out_key = {
        .inner_ip   = inner_ip,
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
            entry->inner_ip   = inner_ip;
            entry->inner_port = inner_port;
            entry->outer_ip   = NAT_PUBLIC_IP;
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
            g_bras.nat_entries[outer_port - NAT_PORT_MIN].last_seen = rte_rdtsc();
        }
        rte_spinlock_unlock(&nat_alloc_lock);
    } else {
        void *data;
        rte_hash_lookup_data(g_bras.nat_out_tbl, &out_key, &data);
        outer_port = (uint16_t)(uintptr_t)data;
        g_bras.nat_entries[outer_port - NAT_PORT_MIN].last_seen = rte_rdtsc();
    }

    /* Rewrite src_ip and src_port */
    uint32_t old_ip   = ntohl(ip->src_addr);
    uint16_t old_port = inner_port;

    ip->src_addr = htonl(NAT_PUBLIC_IP);
    if (l4_src_port_ptr)
        *l4_src_port_ptr = htons(outer_port);

    /* Update checksums */
    if (l4_csum_ptr && *l4_csum_ptr != 0)
        *l4_csum_ptr = csum_update(*l4_csum_ptr,
                                   old_ip, NAT_PUBLIC_IP,
                                   htons(old_port), htons(outer_port));
    update_ip_csum(ip);

    sess->bytes_up += mbuf->data_len;

strip_and_forward:;
    /* Strip PPPoE/PPP overhead from front:
     * move Ethernet header forward by pppoe_overhead - sizeof(eth)
     * new offsets: Eth src/dst stay, just ether_type changes to 0x0800
     */
    size_t strip = sizeof(struct pppoe_hdr) + sizeof(struct ppp_hdr);
    struct rte_ether_hdr *old_eth =
        rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

    /* Replace dst/src MAC for LAN side */
    struct rte_ether_addr gw_mac = { UPSTREAM_GW_MAC };
    rte_ether_addr_copy(&gw_mac,          &old_eth->dst_addr);
    rte_ether_addr_copy(&g_bras.lan_mac,  &old_eth->src_addr);

    /* Adjust ether_type to plain IPv4 */
    old_eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    /* Trim PPPoE from the front (adjust data_off and data_len) */
    rte_pktmbuf_adj(mbuf, (uint16_t)strip);

    /* Move Ethernet header back into the adjusted headroom */
    uint8_t *new_base = rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));
    memmove(new_base, (uint8_t *)old_eth, sizeof(struct rte_ether_hdr));
    /* Note: old_eth is now stale; new_base is the valid eth header */
    ((struct rte_ether_hdr *)new_base)->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    return 0;
}

/* ── inbound (upstream → client) ─────────────────────────────────────── */

/*
 * nat_translate_inbound
 *
 * The mbuf arrives from LAN_PORT:
 *   Eth / IPv4 / TCP-or-UDP   (dst_ip = NAT_PUBLIC_IP)
 *
 * After this function:
 *   Eth / PPPoE-session / PPP(0x0021) / IP / TCP-or-UDP
 *   dst_ip = client_ip, dst_port = inner_port
 *   Ready to send out WAN_PORT.
 *
 * Returns 0 on success, -1 to drop.
 */
int
nat_translate_inbound(struct rte_mbuf *mbuf)
{
    uint8_t *base = rte_pktmbuf_mtod(mbuf, uint8_t *);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)base;

    if (ntohs(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
        return -1;

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(base + sizeof(struct rte_ether_hdr));

    uint8_t   proto     = ip->next_proto_id;
    uint16_t  outer_port = 0;
    uint8_t  *l4 = (uint8_t *)ip + ((ip->version_ihl & 0xF) << 2);
    uint16_t *l4_csum_ptr = NULL;
    uint16_t *l4_dst_port_ptr = NULL;

    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
        outer_port = ntohs(tcp->dst_port);
        l4_csum_ptr = &tcp->cksum;
        l4_dst_port_ptr = &tcp->dst_port;
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
        outer_port = ntohs(udp->dst_port);
        l4_csum_ptr = &udp->dgram_cksum;
        l4_dst_port_ptr = &udp->dst_port;
    } else {
        return -1;
    }

    struct nat_in_key in_key = {
        .outer_port = outer_port,
        .proto      = proto,
        .pad        = 0,
    };
    void *data = NULL;
    if (rte_hash_lookup_data(g_bras.nat_in_tbl, &in_key, &data) < 0)
        return -1;  /* no mapping — drop */

    struct nat_entry *entry = (struct nat_entry *)data;
    entry->last_seen = rte_rdtsc();

    uint16_t session_id = entry->session_id;
    if (session_id == 0 || session_id > MAX_SESSIONS)
        return -1;
    struct bras_session *sess = &g_bras.sessions[session_id];
    if (sess->state != SESS_UP)
        return -1;

    /* Rewrite dst_ip and dst_port back to inner */
    uint32_t old_dip   = ntohl(ip->dst_addr);
    uint16_t old_dport = outer_port;

    ip->dst_addr = htonl(entry->inner_ip);
    if (l4_dst_port_ptr)
        *l4_dst_port_ptr = htons(entry->inner_port);

    if (l4_csum_ptr && *l4_csum_ptr != 0)
        *l4_csum_ptr = csum_update(*l4_csum_ptr,
                                   old_dip, entry->inner_ip,
                                   htons(old_dport), htons(entry->inner_port));
    update_ip_csum(ip);

    sess->bytes_down += mbuf->data_len;

    /* Prepend PPPoE session header:
     * We need to add:  sizeof(pppoe_hdr) + sizeof(ppp_hdr) = 8 bytes
     * in front of the IP packet, and fix up the Ethernet header.
     *
     * Before:  [ETH(14)] [IPv4...]
     * After:   [ETH(14)] [PPPoE(6)] [PPP(2)] [IPv4...]
     */
    uint16_t ip_len = ntohs(ip->total_length);

    /* Save Ethernet header */
    struct rte_ether_hdr saved_eth;
    memcpy(&saved_eth, eth, sizeof(saved_eth));

    /* Prepend 8 bytes for PPPoE+PPP */
    uint8_t *new_start = (uint8_t *)rte_pktmbuf_prepend(
        mbuf, sizeof(struct pppoe_hdr) + sizeof(struct ppp_hdr));
    if (!new_start)
        return -1;

    /* Re-lay ethernet header at new start */
    struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)new_start;
    rte_ether_addr_copy(&sess->client_mac, &new_eth->dst_addr);
    rte_ether_addr_copy(&g_bras.wan_mac,   &new_eth->src_addr);
    new_eth->ether_type = htons(ETH_P_PPPoE_SESS);

    /* PPPoE header */
    struct pppoe_hdr *ph = (struct pppoe_hdr *)(new_start + sizeof(*new_eth));
    ph->ver_type   = 0x11;
    ph->code       = PPPOE_CODE_DATA;
    ph->session_id = htons(session_id);
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
