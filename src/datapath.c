/* datapath.c — fast-path RX/TX worker and control-plane lcore
 *
 * Two datapath modes, selected at startup in main():
 *
 *  distributor (default on real NICs):
 *      rx_dist_lcore     poll WAN+LAN queue 0, classify, tag data packets
 *                        by flow 5-tuple, fan out via rte_distributor.
 *      dist_worker_lcore N workers: NAT + forward, each with own TX queue.
 *      The X520/82599 VF cannot RSS PPPoE frames (the inner IP hides behind
 *      the PPPoE header), so the fan-out must happen in software.  The
 *      distributor keeps every flow on one worker and in order.
 *
 *  legacy (single-queue vdevs, e.g. af_packet on veth):
 *      datapath_lcore    poll WAN+LAN, classify + NAT + forward inline.
 *
 *  LCORE_CTRL:    drain ctrl_ring, run PPPoE discovery + PPP state machines.
 */

#include <string.h>
#include <netinet/in.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_ring.h>
#include <rte_cycles.h>
#include <rte_distributor.h>
#include <rte_hash_crc.h>

#include "bras.h"

#define RTE_LOGTYPE_DP   RTE_LOGTYPE_USER4

/* ── fast-path helpers ────────────────────────────────────────────────── */

/* Count + (optionally) capture + free a dropped data packet.  RX-side
 * drops are recorded as ingress on the packet's origin port. */
static inline void
drop_pkt(struct rte_mbuf *m, const char *reason)
{
    g_bras.stat_pkts_dropped++;
    drop_capture(m, m->port, RTE_PCAPNG_DIRECTION_IN, reason);
    rte_pktmbuf_free(m);
}

/* Called only at lcore-specific safe points where no mbuf is owned and the
 * next operation would touch ethdev. Each lcore writes only its own slot. */
static inline void
park_current_lcore(void)
{
    if (!__atomic_load_n(&g_bras.dp_pause, __ATOMIC_ACQUIRE))
        return;

    unsigned int me = rte_lcore_id();
    __atomic_store_n(&g_bras.dp_ack[me], 1, __ATOMIC_RELEASE);
    while (g_running &&
           __atomic_load_n(&g_bras.dp_pause, __ATOMIC_ACQUIRE))
        rte_pause();
    __atomic_store_n(&g_bras.dp_ack[me], 0, __ATOMIC_RELEASE);
}

/*
 * Decide if a PPPoE session frame belongs on the control lcore.  IPv4 is
 * always data.  IPv6 is data unless its destination is multicast or the
 * BRAS WAN link-local address; short/malformed IPv6 is sent to ctrl so the
 * normal validation path can discard it safely.
 */
static inline int
is_ppp_ctrl(struct rte_mbuf *mbuf)
{
    uint8_t *p = rte_pktmbuf_mtod(mbuf, uint8_t *);
    uint16_t l2_len, vlan_tci;
    bras_frame_ethertype(p, &l2_len, &vlan_tci);
    (void)vlan_tci;
    uint16_t ppp_off = l2_len + sizeof(struct pppoe_hdr);
    if (rte_pktmbuf_pkt_len(mbuf) < ppp_off + sizeof(struct ppp_hdr))
        return 1;
    struct ppp_hdr *pph = (struct ppp_hdr *)(p + ppp_off);
    uint16_t proto = ntohs(pph->protocol);
    if (proto == PPP_IP)
        return 0;
    if (proto != PPP_IPV6)
        return 1;

    uint16_t ip_off = ppp_off + sizeof(*pph);
    if (rte_pktmbuf_pkt_len(mbuf) < ip_off + sizeof(struct rte_ipv6_hdr))
        return 1;
    const struct rte_ipv6_hdr *ip6 =
        (const struct rte_ipv6_hdr *)(p + ip_off);
    const uint8_t *dst = (const uint8_t *)&ip6->dst_addr;
    if (rte_ipv6_check_version(ip6) != 0)
        return 1;
    return dst[0] == 0xff || memcmp(dst, g_bras.wan_ll, 16) == 0;
}

static inline uint16_t
ppp_protocol(struct rte_mbuf *mbuf, uint16_t l2_len)
{
    uint8_t *p = rte_pktmbuf_mtod(mbuf, uint8_t *);
    const struct ppp_hdr *pph = (const struct ppp_hdr *)
        (p + l2_len + sizeof(struct pppoe_hdr));
    return ntohs(pph->protocol);
}

static inline int
ipv6_in_pd_pool(const struct rte_ipv6_hdr *ip6)
{
    const uint8_t *dst = (const uint8_t *)&ip6->dst_addr;
    uint8_t plen = g_bras.pd_pool_plen;
    unsigned int bytes = plen / 8;
    unsigned int bits = plen % 8;

    if (plen == 0 || plen > 64 ||
        (bytes > 0 && memcmp(dst, g_bras.pd_pool_prefix, bytes) != 0))
        return 0;
    if (bits != 0) {
        uint8_t mask = (uint8_t)(0xffu << (8 - bits));
        if ((dst[bytes] & mask) !=
            (g_bras.pd_pool_prefix[bytes] & mask))
            return 0;
    }
    return 1;
}

/*
 * Send a ctrl_msg to the control-plane lcore.
 * Takes ownership of mbuf on success; caller must free on failure.
 */
static void
enqueue_ctrl(struct rte_mbuf *mbuf, ctrl_msg_type_t type, uint16_t session_id)
{
    struct ctrl_msg msg = {
        .type       = type,
        .mbuf       = mbuf,
        .session_id = session_id,
    };
    if (rte_ring_enqueue(g_bras.ctrl_ring, (void *)mbuf) != 0) {
        /* Ring full — drop (should not happen in testing) */
        RTE_LOG(WARNING, DP, "ctrl_ring full — dropping ctrl packet\n");
        rte_pktmbuf_free(mbuf);
    }
    (void)msg; /* msg.type/session_id carried via ring element tagging below */
}

/* ── WAN RX handler ───────────────────────────────────────────────────── */

static void
process_wan_burst(struct rte_mbuf **pkts, uint16_t nb)
{
    for (uint16_t i = 0; i < nb; i++) {
        struct rte_mbuf *m = pkts[i];
        g_bras.stat_pkts_rx++;

        uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);
        uint16_t l2_len, vlan_tci;
        uint16_t etype = bras_frame_ethertype(p, &l2_len, &vlan_tci);

        /* --vlans filter: reject PPPoE outside the allowed VLAN set */
        if ((etype == ETH_P_PPPoE_DISC || etype == ETH_P_PPPoE_SESS) &&
            !bras_vlan_accepted(l2_len, vlan_tci)) {
            g_bras.stat_drop_vlan++;
            drop_pkt(m, "drop:vlan");
            continue;
        }

        if (etype == ETH_P_PPPoE_DISC) {
            /* Discovery frames → control plane */
            enqueue_ctrl(m, CTRL_MSG_PPPOE_DISC, 0);
            continue;
        }

        if (etype == ETH_P_PPPoE_SESS) {
            struct pppoe_hdr *ph =
                (struct pppoe_hdr *)(p + l2_len);
            uint16_t sid = ntohs(ph->session_id);

            if (sid == 0 || sid > MAX_SESSIONS ||
                g_bras.sessions[sid].state != SESS_UP) {
                /* Unknown / not-yet-UP session — send to ctrl for handling */
                enqueue_ctrl(m, CTRL_MSG_PPP_CTRL, sid);
                continue;
            }

            if (is_ppp_ctrl(m)) {
                /* LCP keepalive / IPCP renegotiation on an UP session */
                enqueue_ctrl(m, CTRL_MSG_PPP_CTRL, sid);
                continue;
            }

            /* ── Data packet on established session ── */
            struct bras_session *sess = &g_bras.sessions[sid];
            uint16_t proto = ppp_protocol(m, l2_len);
            int routed = proto == PPP_IPV6 ?
                ipv6_route_outbound(m, sess) : route_outbound(m, sess);
            if (routed == 0) {
                send_pkt(LAN_PORT, m);
                g_bras.stat_pkts_tx++;
            } else {
                g_bras.stat_drop_route++;
                drop_pkt(m, "drop:route");
            }
            continue;
        }

        /* Unknown ethertype — drop */
        g_bras.stat_drop_other++;
        drop_pkt(m, "drop:other");
    }
}

/* ── LAN RX handler ───────────────────────────────────────────────────── */

static void
process_lan_burst(struct rte_mbuf **pkts, uint16_t nb)
{
    for (uint16_t i = 0; i < nb; i++) {
        struct rte_mbuf *m = pkts[i];
        g_bras.stat_pkts_rx++;

        struct rte_ether_hdr *eth =
            rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

        /* ARP: answer requests for our SNAT IP / learn next-hop MAC */
        if (eth->ether_type == htons(RTE_ETHER_TYPE_ARP)) {
            arp_input(m);
            continue;
        }

        if (eth->ether_type == htons(RTE_ETHER_TYPE_IPV6)) {
            if (ipv6_lan_input(m) == 0)
                continue;
            struct rte_ipv6_hdr *ip6 =
                (struct rte_ipv6_hdr *)(eth + 1);
            if (ipv6_in_pd_pool(ip6) && ipv6_route_inbound(m) == 0) {
                send_pkt(WAN_PORT, m);
                g_bras.stat_pkts_tx++;
            } else if (ipv6_in_pd_pool(ip6)) {
                g_bras.stat_drop_route++;
                drop_pkt(m, "drop:route");
            } else {
                g_bras.stat_drop_other++;
                drop_pkt(m, "drop:other");
            }
            continue;
        }

        /* Pings to our SNAT IP are answered locally */
        if (lan_icmp_echo_input(m) == 0) {
            g_bras.stat_pkts_tx++;
            continue;
        }

        if (route_inbound(m) == 0) {
            send_pkt(WAN_PORT, m);
            g_bras.stat_pkts_tx++;
        } else {
            g_bras.stat_drop_route++;
            drop_pkt(m, "drop:route");
        }
    }
}

/* ── distributor datapath ─────────────────────────────────────────────── */

/*
 * flow_tag — per-direction 5-tuple hash used as the distributor tag.
 * The distributor keeps every packet sharing a tag on a single worker and
 * in order, so same-flow packets never race while distinct flows (even
 * within one PPPoE session) spread across workers.  Fragments fall back to
 * the IP pair so all pieces of a datagram share a tag.
 */
static inline uint32_t
flow_tag(const uint8_t *ip_start)
{
    const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)ip_start;
    uint32_t tag = rte_hash_crc_4byte(ip->src_addr, 0);
    tag = rte_hash_crc_4byte(ip->dst_addr, tag);

    uint32_t l4_ports = 0;
    uint8_t  proto    = ip->next_proto_id;
    uint16_t frag     = rte_be_to_cpu_16(ip->fragment_offset);
    if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) &&
        (frag & (RTE_IPV4_HDR_OFFSET_MASK | RTE_IPV4_HDR_MF_FLAG)) == 0)
        memcpy(&l4_ports,
               ip_start + ((ip->version_ihl & 0xF) << 2), sizeof(l4_ports));

    tag = rte_hash_crc_4byte(l4_ports, tag);
    return rte_hash_crc_4byte(proto, tag);
}

/* IPv6 fixed-header flow hash.  Extension headers deliberately fall back
 * to the address pair because this datapath does not parse their chain. */
static inline uint32_t
flow_tag6(const uint8_t *ip_start, uint16_t available)
{
    const struct rte_ipv6_hdr *ip6 =
        (const struct rte_ipv6_hdr *)ip_start;
    const uint8_t *addresses = (const uint8_t *)&ip6->src_addr;
    uint32_t tag = 0;

    for (unsigned int i = 0; i < 8; i++) {
        uint32_t word;
        memcpy(&word, addresses + i * sizeof(word), sizeof(word));
        tag = rte_hash_crc_4byte(word, tag);
    }

    uint32_t ports = 0;
    if ((ip6->proto == IPPROTO_TCP || ip6->proto == IPPROTO_UDP) &&
        available >= sizeof(*ip6) + sizeof(ports))
        memcpy(&ports, ip_start + sizeof(*ip6), sizeof(ports));
    tag = rte_hash_crc_4byte(ports, tag);
    return rte_hash_crc_4byte(ip6->proto, tag);
}

/*
 * Classify one WAN burst: control traffic to the ctrl ring (as in legacy
 * mode), session data tagged and appended to the distributor batch.
 * Returns the new batch length.
 */
static uint16_t
classify_wan_dist(struct rte_mbuf **pkts, uint16_t nb,
                  struct rte_mbuf **batch, uint16_t n_batch)
{
    for (uint16_t i = 0; i < nb; i++) {
        struct rte_mbuf *m = pkts[i];
        g_bras.stat_pkts_rx++;

        uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);
        uint16_t l2_len, vlan_tci;
        uint16_t etype = bras_frame_ethertype(p, &l2_len, &vlan_tci);

        /* --vlans filter: reject PPPoE outside the allowed VLAN set */
        if ((etype == ETH_P_PPPoE_DISC || etype == ETH_P_PPPoE_SESS) &&
            !bras_vlan_accepted(l2_len, vlan_tci)) {
            g_bras.stat_drop_vlan++;
            drop_pkt(m, "drop:vlan");
            continue;
        }

        if (etype == ETH_P_PPPoE_DISC) {
            enqueue_ctrl(m, CTRL_MSG_PPPOE_DISC, 0);
            continue;
        }

        if (etype == ETH_P_PPPoE_SESS) {
            struct pppoe_hdr *ph = (struct pppoe_hdr *)(p + l2_len);
            uint16_t sid = ntohs(ph->session_id);

            if (sid == 0 || sid > MAX_SESSIONS ||
                g_bras.sessions[sid].state != SESS_UP ||
                is_ppp_ctrl(m)) {
                enqueue_ctrl(m, CTRL_MSG_PPP_CTRL, sid);
                continue;
            }

            /* Data on an UP session → tag by the inner 5-tuple */
            uint16_t ip_off = l2_len + sizeof(struct pppoe_hdr) +
                              sizeof(struct ppp_hdr);
            uint16_t proto = ppp_protocol(m, l2_len);
            m->hash.usr = proto == PPP_IPV6 ?
                flow_tag6(p + ip_off,
                          (uint16_t)(rte_pktmbuf_pkt_len(m) - ip_off)) :
                flow_tag(p + ip_off);
            batch[n_batch++] = m;
            continue;
        }

        g_bras.stat_drop_other++;
        drop_pkt(m, "drop:other");
    }
    return n_batch;
}

/*
 * Classify one LAN burst: ARP and pings to our SNAT IP handled inline
 * (low volume), IPv4 data tagged by its outer 5-tuple for the workers.
 * Returns the new batch length.
 */
static uint16_t
classify_lan_dist(struct rte_mbuf **pkts, uint16_t nb,
                  struct rte_mbuf **batch, uint16_t n_batch)
{
    for (uint16_t i = 0; i < nb; i++) {
        struct rte_mbuf *m = pkts[i];
        g_bras.stat_pkts_rx++;

        struct rte_ether_hdr *eth =
            rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

        if (eth->ether_type == htons(RTE_ETHER_TYPE_ARP)) {
            arp_input(m);
            continue;
        }

        if (eth->ether_type == htons(RTE_ETHER_TYPE_IPV6)) {
            if (ipv6_lan_input(m) == 0)
                continue;
            if (rte_pktmbuf_pkt_len(m) < sizeof(*eth) +
                                             sizeof(struct rte_ipv6_hdr)) {
                g_bras.stat_drop_other++;
                drop_pkt(m, "drop:other");
                continue;
            }
            struct rte_ipv6_hdr *ip6 =
                (struct rte_ipv6_hdr *)(eth + 1);
            if (!ipv6_in_pd_pool(ip6)) {
                g_bras.stat_drop_other++;
                drop_pkt(m, "drop:other");
                continue;
            }
            m->hash.usr = flow_tag6((uint8_t *)ip6,
                (uint16_t)(rte_pktmbuf_pkt_len(m) - sizeof(*eth)));
            batch[n_batch++] = m;
            continue;
        }

        if (lan_icmp_echo_input(m) == 0) {
            g_bras.stat_pkts_tx++;
            continue;
        }

        if (eth->ether_type == htons(RTE_ETHER_TYPE_IPV4)) {
            m->hash.usr =
                flow_tag((uint8_t *)eth + sizeof(struct rte_ether_hdr));
            batch[n_batch++] = m;
            continue;
        }

        g_bras.stat_drop_other++;
        drop_pkt(m, "drop:other");
    }
    return n_batch;
}

/*
 * rx_dist_lcore — distributor-mode RX/classify lcore.
 * Polls both ports' queue 0 and fans data packets out to the workers.
 */
int
rx_dist_lcore(void *arg __rte_unused)
{
    struct rte_distributor *dist = g_bras.dist;
    struct rte_mbuf *pkts[BURST_SIZE];
    struct rte_mbuf *batch[2 * BURST_SIZE];
    struct rte_mbuf *ret[2 * BURST_SIZE];
    uint16_t nb, n_batch;

    RTE_LOG(INFO, DP, "RX/classify lcore %u started (distributor, %u workers)\n",
            rte_lcore_id(), g_bras.n_workers);

    while (g_running) {
        if (__atomic_load_n(&g_bras.dp_pause, __ATOMIC_ACQUIRE)) {
            rte_distributor_process(dist, NULL, 0);
            rte_distributor_returned_pkts(dist, ret, RTE_DIM(ret));
            park_current_lcore();
            continue;
        }

        n_batch = 0;
        nb = rte_eth_rx_burst(WAN_PORT, 0, pkts, BURST_SIZE);
        if (nb > 0)
            n_batch = classify_wan_dist(pkts, nb, batch, n_batch);

        nb = rte_eth_rx_burst(LAN_PORT, 0, pkts, BURST_SIZE);
        if (nb > 0)
            n_batch = classify_lan_dist(pkts, nb, batch, n_batch);

        /* An empty call still flushes the internal backlog toward
         * idle workers, so call unconditionally. */
        int nd = rte_distributor_process(dist, n_batch ? batch : NULL,
                                         n_batch);
        for (int k = nd < 0 ? 0 : nd; k < n_batch; k++) {
            g_bras.stat_drop_dist++;
            drop_pkt(batch[k], "drop:dist");
        }

        /* Workers hand each batch back after TX purely for the
         * distributor's in-flight bookkeeping — drain and ignore. */
        rte_distributor_returned_pkts(dist, ret, RTE_DIM(ret));
    }

    rte_distributor_flush(dist);
    rte_distributor_clear_returns(dist);
    RTE_LOG(INFO, DP, "RX/classify lcore %u stopping\n", rte_lcore_id());
    return 0;
}

/*
 * dist_worker_lcore — NAT + forwarding worker (arg = worker id).
 * Uses the non-blocking request/poll API so g_running stays honoured even
 * when no traffic is in flight.
 */
int
dist_worker_lcore(void *arg)
{
    unsigned int wid = (unsigned int)(uintptr_t)arg;
    struct rte_distributor *dist = g_bras.dist;
    struct rte_mbuf *bufs[BURST_SIZE];
    int n;

    RTE_LOG(INFO, DP, "distributor worker %u started (lcore %u, TX queue %u)\n",
            wid, rte_lcore_id(), g_bras.lcore_queue[rte_lcore_id()]);

    rte_distributor_request_pkt(dist, wid, NULL, 0);
    while (g_running) {
        n = rte_distributor_poll_pkt(dist, wid, bufs);
        if (n < 0) {
            if (__atomic_load_n(&g_bras.dp_pause, __ATOMIC_ACQUIRE))
                park_current_lcore();
            rte_pause();
            continue;
        }

        g_bras.stat_worker_pkts[wid] += n;
        for (int i = 0; i < n; i++) {
            struct rte_mbuf *m = bufs[i];

            if (m->port == WAN_PORT) {
                uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);
                uint16_t l2_len, vlan_tci;
                bras_frame_ethertype(p, &l2_len, &vlan_tci);
                struct pppoe_hdr *ph = (struct pppoe_hdr *)(p + l2_len);
                uint16_t sid = ntohs(ph->session_id);
                struct bras_session *sess = &g_bras.sessions[sid];
                uint16_t proto = ppp_protocol(m, l2_len);

                /* Session may have been torn down while queued */
                int routed = -1;
                if (sess->state == SESS_UP)
                    routed = proto == PPP_IPV6 ?
                        ipv6_route_outbound(m, sess) :
                        route_outbound(m, sess);
                if (routed == 0) {
                    send_pkt(LAN_PORT, m);
                    g_bras.stat_pkts_tx++;
                } else {
                    g_bras.stat_drop_route++;
                    drop_pkt(m, "drop:route");
                }
            } else {
                struct rte_ether_hdr *eth =
                    rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                int routed = eth->ether_type == htons(RTE_ETHER_TYPE_IPV6) ?
                    ipv6_route_inbound(m) : route_inbound(m);
                if (routed == 0) {
                    send_pkt(WAN_PORT, m);
                    g_bras.stat_pkts_tx++;
                } else {
                    g_bras.stat_drop_route++;
                    drop_pkt(m, "drop:route");
                }
            }
        }

        /* Return the (already transmitted) batch and request the next */
        rte_distributor_request_pkt(dist, wid, bufs, n);
    }
    RTE_LOG(INFO, DP, "distributor worker %u stopping\n", wid);
    return 0;
}

/* ── lcore workers ────────────────────────────────────────────────────── */

/*
 * datapath_lcore — runs on LCORE_RX_TX
 * Tight poll loop: drain WAN + LAN in round-robin.
 */
int
datapath_lcore(void *arg)
{
    uint16_t queue_id = (uint16_t)(uintptr_t)arg;
    struct rte_mbuf *wan_pkts[BURST_SIZE];
    struct rte_mbuf *lan_pkts[BURST_SIZE];
    uint16_t nb;

    RTE_LOG(INFO, DP, "data-path lcore %u started (queue %u)\n",
            rte_lcore_id(), queue_id);

    while (g_running) {
        park_current_lcore();
        if (!g_running)
            break;

        /* WAN (client side) */
        nb = rte_eth_rx_burst(WAN_PORT, queue_id, wan_pkts, BURST_SIZE);
        if (nb > 0)
            process_wan_burst(wan_pkts, nb);

        /* LAN (upstream side) */
        nb = rte_eth_rx_burst(LAN_PORT, queue_id, lan_pkts, BURST_SIZE);
        if (nb > 0)
            process_lan_burst(lan_pkts, nb);
    }
    RTE_LOG(INFO, DP, "data-path lcore %u stopping\n", rte_lcore_id());
    return 0;
}

/*
 * ctrl_plane_lcore — runs on LCORE_CTRL
 * Drains ctrl_ring and dispatches to PPPoE / PPP state machines.
 * Also runs periodic timers (session timeout, LCP echo).
 */
int
ctrl_plane_lcore(void *arg __rte_unused)
{
    void *obj;
    uint64_t last_timer = rte_rdtsc();
    uint64_t last_neighbor_tick = 0;
    uint64_t last_nd6   = 0;
    uint32_t nd6_attempts = 0;
    const uint64_t timer_interval = rte_get_timer_hz() * 10; /* 10 sec */
    const uint64_t arp_interval   = rte_get_timer_hz();      /*  1 sec */

    RTE_LOG(INFO, DP, "control-plane lcore started (lcore %u)\n",
            rte_lcore_id());

    while (g_running) {
        park_current_lcore();
        if (!g_running)
            break;

        if (__atomic_exchange_n(&g_bras.nd6_backoff_reset, 0,
                                __ATOMIC_ACQ_REL)) {
            nd6_attempts = 0;
            last_nd6 = 0;
        }

        if (g_terminate_sessions) {
            g_terminate_sessions = 0;
            for (int i = 1; i <= MAX_SESSIONS; i++) {
                struct bras_session *s = &g_bras.sessions[i];
                if (s->state == SESS_UP)
                    lcp_send_term_req(s);
            }
        }

        if (g_padt_sessions) {
            g_padt_sessions = 0;
            for (int i = 1; i <= MAX_SESSIONS; i++) {
                struct bras_session *s = &g_bras.sessions[i];
                if (s->state == SESS_UP)
                    pppoe_send_padt(s);
            }
        }

        /* Gate autonomous neighbour discovery on the cached LAN link state.
         * ARP remains at 1 Hz; unresolved IPv6 backs off after 30 sends. */
        uint64_t neighbour_now = rte_rdtsc();
        if ((!g_bras.upstream_mac_valid || !g_bras.upstream_mac6_valid) &&
            neighbour_now - last_neighbor_tick >= arp_interval) {
            last_neighbor_tick = neighbour_now;
            struct rte_eth_link link;
            memset(&link, 0, sizeof(link));
            if (rte_eth_link_get_nowait(LAN_PORT, &link) == 0 &&
                link.link_status == RTE_ETH_LINK_UP) {
                if (!g_bras.upstream_mac_valid)
                    arp_request_upstream();

                uint64_t nd6_interval = nd6_attempts <
                    ND6_REQ_FAST_ATTEMPTS ? arp_interval :
                    rte_get_timer_hz() * ND6_REQ_SLOW_INTERVAL_SEC;
                if (!g_bras.upstream_mac6_valid &&
                    (last_nd6 == 0 ||
                     neighbour_now - last_nd6 >= nd6_interval)) {
                    last_nd6 = neighbour_now;
                    nd6_request_upstream();
                    nd6_attempts++;
                }
            }
        }

        /* Drain control ring */
        while (rte_ring_dequeue(g_bras.ctrl_ring, &obj) == 0) {
            struct rte_mbuf *m = (struct rte_mbuf *)obj;

            /* Re-classify: peek at ethertype to decide handler */
            uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);
            uint16_t l2_len, vlan_tci;
            uint16_t etype = bras_frame_ethertype(p, &l2_len, &vlan_tci);
            (void)vlan_tci;

            if (etype == ETH_P_PPPoE_DISC) {
                pppoe_handle_discovery(m);
            } else if (etype == ETH_P_PPPoE_SESS) {
                struct pppoe_hdr *ph =
                    (struct pppoe_hdr *)(p + l2_len);
                uint16_t sid = ntohs(ph->session_id);
                ppp_handle_ctrl(m, sid);
            } else {
                rte_pktmbuf_free(m);
            }
        }

        /* Periodic tasks */
        uint64_t now = rte_rdtsc();
        chap_retry_pending(now);
        if (now - last_timer >= timer_interval) {
            last_timer = now;

            nat_expire();

            for (int i = 1; i <= MAX_SESSIONS; i++) {
                struct bras_session *s = &g_bras.sessions[i];
                if (s->state == SESS_FREE) continue;

                /* Session idle timeout: 600 seconds */
                if ((now - s->last_activity) > rte_get_timer_hz() * 600) {
                    RTE_LOG(INFO, DP,
                            "session %u idle timeout — tearing down\n", i);
                    pppoe_send_padt(s);
                    continue;
                }

                /* LCP echo-request every 30 seconds for UP sessions */
                if (!g_no_lcp_echo && s->state == SESS_UP &&
                    (now - s->last_activity) > rte_get_timer_hz() * 30) {
                    /* Build LCP Echo-Request */
                    uint16_t pl = sizeof(struct lcp_hdr) + 4;
                    uint16_t l2_len = sizeof(struct rte_ether_hdr) +
                        (s->tx_vlan ? sizeof(struct rte_vlan_hdr) : 0);
                    struct rte_mbuf *em = alloc_pkt(
                        l2_len +
                        sizeof(struct pppoe_hdr) +
                        sizeof(struct ppp_hdr) + pl);
                    if (em) {
                        uint8_t *ep = rte_pktmbuf_mtod(em, uint8_t *);
                        /* Ethernet */
                        struct rte_ether_hdr *eeth =
                            (struct rte_ether_hdr *)ep;
                        rte_ether_addr_copy(&s->client_mac, &eeth->dst_addr);
                        rte_ether_addr_copy(&g_bras.wan_mac, &eeth->src_addr);
                        eeth->ether_type =
                            htons(s->tx_vlan ? ETH_P_8021Q : ETH_P_PPPoE_SESS);
                        ep += sizeof(*eeth);
                        if (s->tx_vlan) {
                            struct rte_vlan_hdr *vh =
                                (struct rte_vlan_hdr *)ep;
                            vh->vlan_tci = htons(s->vlan_tci);
                            vh->eth_proto = htons(ETH_P_PPPoE_SESS);
                            ep += sizeof(*vh);
                        }
                        /* PPPoE */
                        struct pppoe_hdr *eph = (struct pppoe_hdr *)ep;
                        eph->ver_type = 0x11; eph->code = 0;
                        eph->session_id = htons(s->session_id);
                        eph->length = htons(sizeof(struct ppp_hdr) + pl);
                        ep += sizeof(*eph);
                        /* PPP */
                        struct ppp_hdr *epph = (struct ppp_hdr *)ep;
                        epph->protocol = htons(PPP_LCP);
                        ep += sizeof(*epph);
                        /* LCP Echo-Req */
                        struct lcp_hdr *elcp = (struct lcp_hdr *)ep;
                        elcp->code = LCP_ECHO_REQ;
                        elcp->identifier = ++s->lcp_id;
                        elcp->length = htons(pl);
                        uint32_t magic_be = htonl(s->magic_number);
                        memcpy(ep + sizeof(*elcp), &magic_be, 4);
                        em->data_len = em->pkt_len =
                            l2_len +
                            sizeof(struct pppoe_hdr) +
                            sizeof(struct ppp_hdr) + pl;
                        send_pkt(WAN_PORT, em);
                    }
                }
            }

            /* Stats log */
            RTE_LOG(INFO, DP,
                    "stats: sessions_up=%lu rx=%lu tx=%lu drop=%lu "
                    "(txfull=%lu dist=%lu route=%lu vlan=%lu) w0=%lu w1=%lu\n",
                    g_bras.stat_sessions_up,
                    g_bras.stat_pkts_rx,
                    g_bras.stat_pkts_tx,
                    g_bras.stat_pkts_dropped,
                    g_bras.stat_drop_txfull,
                    g_bras.stat_drop_dist,
                    g_bras.stat_drop_route,
                    g_bras.stat_drop_vlan,
                    g_bras.stat_worker_pkts[0],
                    g_bras.stat_worker_pkts[1]);
        }
    }
    RTE_LOG(INFO, DP, "control-plane lcore stopping\n");
    return 0;
}
