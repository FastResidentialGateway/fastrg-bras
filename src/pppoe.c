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
#include <rte_mbuf.h>
#include <rte_log.h>
#include <rte_cycles.h>

#include "bras.h"

#define RTE_LOGTYPE_PPPOE RTE_LOGTYPE_USER1

/* ── internal helpers ─────────────────────────────────────────────────── */

/* Find a session by client MAC (for matching PADR to existing PADI record) */
static struct bras_session *
find_sess_by_mac(const struct rte_ether_addr *mac)
{
    for (int i = 1; i <= MAX_SESSIONS; i++) {
        struct bras_session *s = &g_bras.sessions[i];
        if (s->state != SESS_FREE &&
            rte_is_same_ether_addr(&s->client_mac, mac))
            return s;
    }
    return NULL;
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
build_disc_frame(const struct rte_ether_addr *dst,
                 uint8_t code, uint16_t session_id,
                 const uint8_t *payload, uint16_t payload_len)
{
    struct rte_mbuf *m = alloc_pkt(sizeof(struct rte_ether_hdr) +
                                   sizeof(struct pppoe_hdr) + payload_len);
    if (!m) return NULL;

    uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);

    /* Ethernet header */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    rte_ether_addr_copy(dst, &eth->dst_addr);
    rte_ether_addr_copy(&g_bras.wan_mac, &eth->src_addr);
    eth->ether_type = htons(ETH_P_PPPoE_DISC);
    p += sizeof(struct rte_ether_hdr);

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
        sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr) + payload_len;

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
    struct pppoe_hdr *ph = (struct pppoe_hdr *)(p + sizeof(struct rte_ether_hdr));
    uint16_t sess_id = ntohs(ph->session_id);

    switch (ph->code) {
    /* ── PADI  ──────────────────────────────────────────────────────── */
    case PPPOE_CODE_PADI: {
        RTE_LOG(DEBUG, PPPOE, "PADI from "RTE_ETHER_ADDR_PRT_FMT"\n",
                RTE_ETHER_ADDR_BYTES(&eth->src_addr));

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
        s->last_activity = rte_rdtsc();

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

        struct bras_session *s = find_sess_by_mac(&eth->src_addr);
        if (!s || s->state != SESS_PADO_SENT) {
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
    static const char ac_name[] = "dpdk-bras";
    uint8_t tags[128];
    uint8_t *tp = tags;

    /* AC-Name tag */
    tp = append_tag(tp, PPPOE_TAG_AC_NAME,
                    ac_name, (uint16_t)strlen(ac_name));

    /* Echo back Host-Uniq if present */
    if (sess->host_uniq_len)
        tp = append_tag(tp, PPPOE_TAG_HOST_UNIQ,
                        sess->host_uniq, sess->host_uniq_len);

    /* AC-Cookie: use session_id as a trivial cookie (expand for security) */
    uint16_t cookie = htons(sess->session_id);
    tp = append_tag(tp, PPPOE_TAG_AC_COOKIE, &cookie, sizeof(cookie));

    tp = append_tag(tp, PPPOE_TAG_EOL, NULL, 0);

    uint16_t payload_len = (uint16_t)(tp - tags);
    struct rte_mbuf *m = build_disc_frame(&sess->client_mac,
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
    struct rte_mbuf *m = build_disc_frame(&sess->client_mac,
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

    struct rte_mbuf *m = build_disc_frame(&sess->client_mac,
                                          PPPOE_CODE_PADT,
                                          sess->session_id,
                                          tags, (uint16_t)(tp - tags));
    if (m) send_pkt(WAN_PORT, m);

    RTE_LOG(INFO, PPPOE, "PADT sent for session %u\n", sess->session_id);
    free_session(sess->session_id);
}
