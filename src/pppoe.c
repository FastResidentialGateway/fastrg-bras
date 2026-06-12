/* pppoe.c — PPPoE Discovery state machine (PADI/PADO/PADR/PADS/PADT)
 *
 * Flow:
 *   fastrg-node                     BRAS (this file)
 *   ──────────                      ────────────────
 *   PADI (broadcast)   ──────────>  pppoe_handle_discovery()
 *                      <──────────  pppoe_send_pado()
 *   PADR               ──────────>  pppoe_handle_discovery()
 *                      <──────────  pppoe_send_pads()  → triggers LCP
 *   PADT               ──────────>  session teardown
 */

#include <string.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <rte_cycles.h>

#include "bras.h"

#define RTE_LOGTYPE_PPPOE RTE_LOGTYPE_USER1

/* ── internal helpers ─────────────────────────────────────────────────── */

/* Find the most-recent session from this MAC/VLAN in the given state.
 * All fastrg users share the NIC port MAC, so a stale session in another
 * state (e.g. SESS_UP left over from an ungraceful client restart) must
 * not shadow the fresh PADO_SENT entry created by the latest PADI. */
static struct bras_session *
find_sess_by_mac_vlan(const struct rte_ether_addr *mac,
                      uint8_t has_vlan, uint16_t vlan_tci,
                      sess_state_t state)
{
    struct bras_session *best = NULL;
    for (int i = 1; i <= MAX_SESSIONS; i++) {
        struct bras_session *s = &g_bras.sessions[i];
        if (s->state == state &&
            rte_is_same_ether_addr(&s->client_mac, mac) &&
            s->has_vlan == has_vlan &&
            (!has_vlan || s->vlan_tci == vlan_tci) &&
            (!best || s->last_activity > best->last_activity))
            best = s;
    }
    return best;
}

/* Append a PPPoE tag to a buffer; returns new write pointer */
static uint8_t *
append_tag(uint8_t *p, uint16_t type, const void *val, uint16_t vlen)
{
    struct pppoe_tag *tag = (struct pppoe_tag *)p;
    tag->type   = htons(type);
    tag->length = htons(vlen);
    if (vlen && val)
        memcpy(tag->value, val, vlen);
    return p + sizeof(struct pppoe_tag) + vlen;
}

/* Build a complete Ethernet + PPPoE discovery frame into a fresh mbuf */
static struct rte_mbuf *
build_disc_frame(struct bras_session *sess,
                 const struct rte_ether_addr *dst,
                 uint8_t code, uint16_t session_id,
                 const uint8_t *payload, uint16_t payload_len)
{
    uint16_t l2_len = sizeof(struct rte_ether_hdr) +
                      (sess->tx_vlan ? sizeof(struct rte_vlan_hdr) : 0);
    struct rte_mbuf *m = alloc_pkt(l2_len +
                                   sizeof(struct pppoe_hdr) + payload_len);
    if (!m) return NULL;

    uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);

    /* Ethernet header */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    rte_ether_addr_copy(dst, &eth->dst_addr);
    rte_ether_addr_copy(&g_bras.wan_mac, &eth->src_addr);
    eth->ether_type = htons(sess->tx_vlan ? ETH_P_8021Q : ETH_P_PPPoE_DISC);
    p += sizeof(struct rte_ether_hdr);
    if (sess->tx_vlan) {
        struct rte_vlan_hdr *vh = (struct rte_vlan_hdr *)p;
        vh->vlan_tci = htons(sess->vlan_tci);
        vh->eth_proto = htons(ETH_P_PPPoE_DISC);
        p += sizeof(*vh);
    }

    /* PPPoE header */
    struct pppoe_hdr *ph = (struct pppoe_hdr *)p;
    ph->ver_type   = 0x11;
    ph->code       = code;
    ph->session_id = htons(session_id);
    ph->length     = htons(payload_len);
    p += sizeof(struct pppoe_hdr);

    if (payload_len && payload)
        memcpy(p, payload, payload_len);

    m->data_len = m->pkt_len =
        l2_len + sizeof(struct pppoe_hdr) + payload_len;

    return m;
}

/* ── public API ───────────────────────────────────────────────────────── */

/*
 * pppoe_handle_discovery  —  called by control-plane lcore for every
 * PPPoE 0x8863 frame.
 */
void
pppoe_handle_discovery(struct rte_mbuf *mbuf)
{
    uint8_t *p = rte_pktmbuf_mtod(mbuf, uint8_t *);

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    uint16_t l2_len, vlan_tci;
    bras_frame_ethertype(p, &l2_len, &vlan_tci);
    struct pppoe_hdr *ph = (struct pppoe_hdr *)(p + l2_len);
    uint16_t sess_id = ntohs(ph->session_id);

    switch (ph->code) {
    /* ── PADI  ──────────────────────────────────────────────────────── */
    case PPPOE_CODE_PADI: {
        RTE_LOG(DEBUG, PPPOE,
                "PADI from "RTE_ETHER_ADDR_PRT_FMT" (l2_len=%u vlan_tci=0x%x)\n",
                RTE_ETHER_ADDR_BYTES(&eth->src_addr), l2_len, vlan_tci);

        /* Allocate a fresh session slot */
        uint16_t sid = alloc_session_id();
        if (sid == 0) {
            RTE_LOG(WARNING, PPPOE, "no free sessions — dropping PADI\n");
            rte_pktmbuf_free(mbuf);
            return;
        }
        struct bras_session *s = &g_bras.sessions[sid];
        s->state      = SESS_PADI_RECV;
        s->session_id = sid;
        rte_ether_addr_copy(&eth->src_addr, &s->client_mac);
        rte_ether_addr_copy(&g_bras.wan_mac, &s->server_mac);
        s->has_vlan = (l2_len > sizeof(struct rte_ether_hdr));
        s->tx_vlan  = s->has_vlan;
        s->vlan_tci = vlan_tci;
        s->last_activity = rte_rdtsc();

        /* 82599 VF: software-tagged TX is silently dropped by the PF's TX
         * switch unless the VLAN is registered in the VLVF.  Try to register
         * it via the PF mailbox.  If the PF NACKs, it has administratively
         * assigned a port VLAN (VMVIR) to this VF: RX still shows the tag
         * (no strip in our VF), but TX must go out untagged — the PF inserts
         * the tag in hardware. */
        if (s->has_vlan) {
            uint16_t vid = s->vlan_tci & 0x0FFF;
            if (!g_bras.vlan_registered[vid]) {
                int vret = rte_eth_dev_vlan_filter(WAN_PORT, vid, 1);
                g_bras.vlan_registered[vid] = (vret == 0) ? 1 : 2;
                if (vret == 0)
                    RTE_LOG(INFO, PPPOE, "registered VLAN %u on WAN port\n",
                            vid);
                else
                    RTE_LOG(INFO, PPPOE,
                            "PF refused VLAN %u filter (%d) — assuming port "
                            "VLAN, sending untagged TX\n", vid, vret);
            }
            if (g_bras.vlan_registered[vid] == 2)
                s->tx_vlan = 0;
        }

        /* Extract Host-Uniq tag if present */
        uint8_t *tp = (uint8_t *)(ph + 1);
        uint8_t *end = tp + ntohs(ph->length);
        while (tp + 4 <= end) {
            struct pppoe_tag *tag = (struct pppoe_tag *)tp;
            uint16_t ttype = ntohs(tag->type);
            uint16_t tlen  = ntohs(tag->length);
            if (ttype == PPPOE_TAG_HOST_UNIQ && tlen <= 16) {
                memcpy(s->host_uniq, tag->value, tlen);
                s->host_uniq_len = (uint8_t)tlen;
            }
            if (ttype == PPPOE_TAG_EOL) break;
            tp += sizeof(struct pppoe_tag) + tlen;
        }

        pppoe_send_pado(s, mbuf);
        rte_pktmbuf_free(mbuf);
        break;
    }

    /* ── PADR  ──────────────────────────────────────────────────────── */
    case PPPOE_CODE_PADR: {
        RTE_LOG(DEBUG, PPPOE, "PADR from "RTE_ETHER_ADDR_PRT_FMT"\n",
                RTE_ETHER_ADDR_BYTES(&eth->src_addr));

        struct bras_session *s = find_sess_by_mac_vlan(
            &eth->src_addr,
            l2_len > sizeof(struct rte_ether_hdr),
            vlan_tci,
            SESS_PADO_SENT);
        if (!s) {
            RTE_LOG(WARNING, PPPOE, "PADR: no matching session in PADO_SENT\n");
            rte_pktmbuf_free(mbuf);
            return;
        }
        s->state = SESS_PADR_RECV;
        pppoe_send_pads(s, mbuf);
        rte_pktmbuf_free(mbuf);
        break;
    }

    /* ── PADT  ──────────────────────────────────────────────────────── */
    case PPPOE_CODE_PADT: {
        RTE_LOG(INFO, PPPOE, "PADT for session %u\n", sess_id);
        if (sess_id > 0 && sess_id <= MAX_SESSIONS &&
            g_bras.sessions[sess_id].state != SESS_FREE) {
            free_session(sess_id);
        }
        rte_pktmbuf_free(mbuf);
        break;
    }

    default:
        RTE_LOG(DEBUG, PPPOE, "unknown discovery code 0x%02x\n", ph->code);
        rte_pktmbuf_free(mbuf);
        break;
    }
}

/*
 * pppoe_send_pado  —  send a PADO (Active Discovery Offer) unicast back
 * to the client that sent the PADI.
 */
void
pppoe_send_pado(struct bras_session *sess, struct rte_mbuf *padi_mbuf)
{
    (void)padi_mbuf;
    uint8_t tags[128];
    uint8_t *tp = tags;

    if (sess->has_vlan) {
        /* fastrg-node stores only the first tag's length bytes from PADO.
         * A minimal EOL tag keeps its PADR builder deterministic. */
        uint32_t zero = 0;
        tp = append_tag(tp, PPPOE_TAG_EOL, &zero, sizeof(zero));
    } else {
        static const char ac_name[] = "dpdk-bras";
        tp = append_tag(tp, PPPOE_TAG_AC_NAME,
                        ac_name, (uint16_t)strlen(ac_name));
        if (sess->host_uniq_len)
            tp = append_tag(tp, PPPOE_TAG_HOST_UNIQ,
                            sess->host_uniq, sess->host_uniq_len);
        uint16_t cookie = htons(sess->session_id);
        tp = append_tag(tp, PPPOE_TAG_AC_COOKIE, &cookie, sizeof(cookie));
        tp = append_tag(tp, PPPOE_TAG_EOL, NULL, 0);
    }

    uint16_t payload_len = (uint16_t)(tp - tags);
    struct rte_mbuf *m = build_disc_frame(sess, &sess->client_mac,
                                          PPPOE_CODE_PADO,
                                          0,            /* session_id=0 for PADO */
                                          tags, payload_len);
    if (!m) return;

    sess->state = SESS_PADO_SENT;
    send_pkt(WAN_PORT, m);
    RTE_LOG(DEBUG, PPPOE, "PADO sent to "RTE_ETHER_ADDR_PRT_FMT"\n",
            RTE_ETHER_ADDR_BYTES(&sess->client_mac));
}

/*
 * pppoe_send_pads  —  send a PADS (Active Discovery Session-Confirmation)
 * and kick off LCP negotiation.
 */
void
pppoe_send_pads(struct bras_session *sess, struct rte_mbuf *padr_mbuf __rte_unused)
{
    uint8_t tags[64];
    uint8_t *tp = tags;

    if (sess->host_uniq_len)
        tp = append_tag(tp, PPPOE_TAG_HOST_UNIQ,
                        sess->host_uniq, sess->host_uniq_len);
    tp = append_tag(tp, PPPOE_TAG_EOL, NULL, 0);

    uint16_t payload_len = (uint16_t)(tp - tags);
    struct rte_mbuf *m = build_disc_frame(sess, &sess->client_mac,
                                          PPPOE_CODE_PADS,
                                          sess->session_id,
                                          tags, payload_len);
    if (!m) return;

    sess->state = SESS_PADS_SENT;
    send_pkt(WAN_PORT, m);

    RTE_LOG(INFO, PPPOE, "PADS sent — session %u assigned to "
            RTE_ETHER_ADDR_PRT_FMT"\n",
            sess->session_id,
            RTE_ETHER_ADDR_BYTES(&sess->client_mac));

    /* Immediately start LCP */
    lcp_send_conf_req(sess);
}

/*
 * pppoe_send_padt  —  terminate a session from the server side.
 */
void
pppoe_send_padt(struct bras_session *sess)
{
    uint8_t tags[8];
    uint8_t *tp = tags;
    tp = append_tag(tp, PPPOE_TAG_EOL, NULL, 0);

    struct rte_mbuf *m = build_disc_frame(sess, &sess->client_mac,
                                          PPPOE_CODE_PADT,
                                          sess->session_id,
                                          tags, (uint16_t)(tp - tags));
    if (m) send_pkt(WAN_PORT, m);

    RTE_LOG(INFO, PPPOE, "PADT sent for session %u\n", sess->session_id);
    free_session(sess->session_id);
}
