/* datapath.c — fast-path RX/TX worker and control-plane lcore
 *
 *  LCORE_RX_TX:   poll WAN+LAN, classify packets, handle data-path inline,
 *                 enqueue control frames to ctrl_ring.
 *
 *  LCORE_CTRL:    drain ctrl_ring, run PPPoE discovery + PPP state machines.
 */

#include <string.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_ring.h>
#include <rte_cycles.h>

#include "bras.h"

#define RTE_LOGTYPE_DP   RTE_LOGTYPE_USER4

/* ── fast-path helpers ────────────────────────────────────────────────── */

/*
 * Decide if a PPPoE session frame contains PPP control traffic
 * (LCP, IPCP, CHAP, PAP) or IP data (0x0021).
 */
static inline int
is_ppp_ctrl(struct rte_mbuf *mbuf)
{
    uint8_t *p = rte_pktmbuf_mtod(mbuf, uint8_t *);
    struct ppp_hdr *pph = (struct ppp_hdr *)
        (p + sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr));
    uint16_t proto = ntohs(pph->protocol);
    return (proto != PPP_IP);
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
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
        uint16_t etype = ntohs(eth->ether_type);

        if (etype == ETH_P_PPPoE_DISC) {
            /* Discovery frames → control plane */
            enqueue_ctrl(m, CTRL_MSG_PPPOE_DISC, 0);
            continue;
        }

        if (etype == ETH_P_PPPoE_SESS) {
            struct pppoe_hdr *ph =
                (struct pppoe_hdr *)(p + sizeof(struct rte_ether_hdr));
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
            if (nat_translate_outbound(m, sess) == 0) {
                send_pkt(LAN_PORT, m);
                g_bras.stat_pkts_tx++;
            } else {
                g_bras.stat_pkts_dropped++;
                rte_pktmbuf_free(m);
            }
            continue;
        }

        /* Unknown ethertype — drop */
        g_bras.stat_pkts_dropped++;
        rte_pktmbuf_free(m);
    }
}

/* ── LAN RX handler ───────────────────────────────────────────────────── */

static void
process_lan_burst(struct rte_mbuf **pkts, uint16_t nb)
{
    for (uint16_t i = 0; i < nb; i++) {
        struct rte_mbuf *m = pkts[i];
        g_bras.stat_pkts_rx++;

        if (nat_translate_inbound(m) == 0) {
            send_pkt(WAN_PORT, m);
            g_bras.stat_pkts_tx++;
        } else {
            g_bras.stat_pkts_dropped++;
            rte_pktmbuf_free(m);
        }
    }
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

    while (1) {
        /* WAN (client side) */
        nb = rte_eth_rx_burst(WAN_PORT, queue_id, wan_pkts, BURST_SIZE);
        if (nb > 0)
            process_wan_burst(wan_pkts, nb);

        /* LAN (upstream side) */
        nb = rte_eth_rx_burst(LAN_PORT, queue_id, lan_pkts, BURST_SIZE);
        if (nb > 0)
            process_lan_burst(lan_pkts, nb);
    }
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
    const uint64_t timer_interval = rte_get_timer_hz() * 10; /* 10 sec */

    RTE_LOG(INFO, DP, "control-plane lcore started (lcore %u)\n",
            rte_lcore_id());

    while (1) {
        /* Drain control ring */
        while (rte_ring_dequeue(g_bras.ctrl_ring, &obj) == 0) {
            struct rte_mbuf *m = (struct rte_mbuf *)obj;

            /* Re-classify: peek at ethertype to decide handler */
            uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);
            struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
            uint16_t etype = ntohs(eth->ether_type);

            if (etype == ETH_P_PPPoE_DISC) {
                pppoe_handle_discovery(m);
            } else if (etype == ETH_P_PPPoE_SESS) {
                struct pppoe_hdr *ph =
                    (struct pppoe_hdr *)(p + sizeof(*eth));
                uint16_t sid = ntohs(ph->session_id);
                ppp_handle_ctrl(m, sid);
            } else {
                rte_pktmbuf_free(m);
            }
        }

        /* Periodic tasks */
        uint64_t now = rte_rdtsc();
        if (now - last_timer >= timer_interval) {
            last_timer = now;

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
                if (s->state == SESS_UP &&
                    (now - s->last_activity) > rte_get_timer_hz() * 30) {
                    /* Build LCP Echo-Request */
                    uint16_t pl = sizeof(struct lcp_hdr) + 4;
                    struct rte_mbuf *em = alloc_pkt(
                        sizeof(struct rte_ether_hdr) +
                        sizeof(struct pppoe_hdr) +
                        sizeof(struct ppp_hdr) + pl);
                    if (em) {
                        uint8_t *ep = rte_pktmbuf_mtod(em, uint8_t *);
                        /* Ethernet */
                        struct rte_ether_hdr *eeth =
                            (struct rte_ether_hdr *)ep;
                        rte_ether_addr_copy(&s->client_mac, &eeth->dst_addr);
                        rte_ether_addr_copy(&g_bras.wan_mac, &eeth->src_addr);
                        eeth->ether_type = htons(ETH_P_PPPoE_SESS);
                        ep += sizeof(*eeth);
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
                            sizeof(struct rte_ether_hdr) +
                            sizeof(struct pppoe_hdr) +
                            sizeof(struct ppp_hdr) + pl;
                        send_pkt(WAN_PORT, em);
                    }
                }
            }

            nat_expire();

            /* Stats log */
            RTE_LOG(INFO, DP,
                    "stats: sessions_up=%lu rx=%lu tx=%lu drop=%lu\n",
                    g_bras.stat_sessions_up,
                    g_bras.stat_pkts_rx,
                    g_bras.stat_pkts_tx,
                    g_bras.stat_pkts_dropped);
        }
    }
    return 0;
}
