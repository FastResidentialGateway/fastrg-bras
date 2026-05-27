/* ppp.c — LCP / IPCP / CHAP / PAP control-plane handler
 *
 * All control-protocol PDUs arrive via the ctrl_ring from the fast-path.
 * This runs entirely on LCORE_CTRL to avoid locking session state.
 *
 * LCP state machine (simplified):
 *
 *   PADS_SENT
 *     │  lcp_send_conf_req() → CONF_REQ sent
 *     ▼
 *   LCP_REQ_SENT
 *     │  recv CONF_ACK from client
 *     ▼
 *   LCP_UP  → send CHAP challenge (or PAP ack)
 *     │  auth success
 *     ▼
 *   AUTH_PENDING → IPCP negotiation
 *     │  IPCP CONF_ACK exchanged
 *     ▼
 *   SESS_UP  (data packets flow through fast-path)
 */

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_random.h>
#include <rte_byteorder.h>

#include "bras.h"

#define RTE_LOGTYPE_PPP RTE_LOGTYPE_USER2

/* ── frame building helpers ───────────────────────────────────────────── */

/*
 * Build: Ethernet / PPPoE-session / PPP-protocol / <payload>
 * Caller fills payload after calling this; returns pointer to payload area.
 */
static uint8_t *
begin_ppp_frame(struct rte_mbuf **out_mbuf,
                struct bras_session *sess,
                uint16_t ppp_proto,
                uint16_t payload_room)
{
    uint16_t total =
        sizeof(struct rte_ether_hdr) +
        sizeof(struct pppoe_hdr) +
        sizeof(struct ppp_hdr) +
        payload_room;

    struct rte_mbuf *m = alloc_pkt(total);
    if (!m) { *out_mbuf = NULL; return NULL; }

    uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);

    /* Ethernet */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    rte_ether_addr_copy(&sess->client_mac, &eth->dst_addr);
    rte_ether_addr_copy(&g_bras.wan_mac,   &eth->src_addr);
    eth->ether_type = htons(ETH_P_PPPoE_SESS);
    p += sizeof(*eth);

    /* PPPoE */
    struct pppoe_hdr *ph = (struct pppoe_hdr *)p;
    ph->ver_type   = 0x11;
    ph->code       = PPPOE_CODE_DATA;
    ph->session_id = htons(sess->session_id);
    ph->length     = htons(sizeof(struct ppp_hdr) + payload_room);
    p += sizeof(*ph);

    /* PPP protocol */
    struct ppp_hdr *pph = (struct ppp_hdr *)p;
    pph->protocol = htons(ppp_proto);
    p += sizeof(*pph);

    m->data_len = m->pkt_len = total;
    *out_mbuf = m;
    return p;  /* points at start of LCP/IPCP/etc payload */
}

static void
finish_and_send(struct rte_mbuf *m)
{
    send_pkt(WAN_PORT, m);
}

/* ── LCP ──────────────────────────────────────────────────────────────── */

/*
 * lcp_send_conf_req — server initiates LCP: MRU=1492, auth=CHAP, magic.
 */
void
lcp_send_conf_req(struct bras_session *sess)
{
    /* Options: MRU(4 bytes) + Auth(5 bytes) + Magic(6 bytes) = 15 bytes */
    uint16_t opts_len = 15;
    uint16_t payload_len = sizeof(struct lcp_hdr) + opts_len;

    struct rte_mbuf *m;
    uint8_t *p = begin_ppp_frame(&m, sess, PPP_LCP, payload_len);
    if (!p) return;

    struct lcp_hdr *lcp = (struct lcp_hdr *)p;
    lcp->code       = LCP_CONF_REQ;
    lcp->identifier = ++sess->lcp_id;
    lcp->length     = htons(sizeof(struct lcp_hdr) + opts_len);
    uint8_t *opt = p + sizeof(struct lcp_hdr);

    /* MRU = 1492 */
    opt[0] = LCP_OPT_MRU;  opt[1] = 4;
    uint16_t mru = htons(1492);
    memcpy(&opt[2], &mru, 2);
    opt += 4;

    /* Auth = CHAP MD5: type=0xC2, alg=0x05 */
    opt[0] = LCP_OPT_AUTH; opt[1] = 5;
    uint16_t chap_proto = htons(PPP_CHAP);
    memcpy(&opt[2], &chap_proto, 2);
    opt[4] = 0x05;  /* MD5 */
    opt += 5;

    /* Magic number */
    sess->magic_number = (uint32_t)rte_rand();
    opt[0] = LCP_OPT_MAGIC; opt[1] = 6;
    uint32_t magic = htonl(sess->magic_number);
    memcpy(&opt[2], &magic, 4);

    sess->state = SESS_LCP_REQ_SENT;
    finish_and_send(m);
    RTE_LOG(DEBUG, PPP, "[%u] LCP CONF_REQ sent\n", sess->session_id);
}

/*
 * lcp_send_conf_ack — echo back the client's CONF_REQ options verbatim.
 */
void
lcp_send_conf_ack(struct bras_session *sess, struct lcp_hdr *req, uint16_t len)
{
    uint16_t opts_len = len - sizeof(struct lcp_hdr);
    uint16_t payload_len = len;
    struct rte_mbuf *m;
    uint8_t *p = begin_ppp_frame(&m, sess, PPP_LCP, payload_len);
    if (!p) return;

    struct lcp_hdr *ack = (struct lcp_hdr *)p;
    ack->code       = LCP_CONF_ACK;
    ack->identifier = req->identifier;
    ack->length     = htons(payload_len);
    memcpy(p + sizeof(struct lcp_hdr),
           (uint8_t *)req + sizeof(struct lcp_hdr),
           opts_len);

    finish_and_send(m);
    RTE_LOG(DEBUG, PPP, "[%u] LCP CONF_ACK sent\n", sess->session_id);
}

void
lcp_send_term_ack(struct bras_session *sess, uint8_t id)
{
    uint16_t payload_len = sizeof(struct lcp_hdr);
    struct rte_mbuf *m;
    uint8_t *p = begin_ppp_frame(&m, sess, PPP_LCP, payload_len);
    if (!p) return;

    struct lcp_hdr *lcp = (struct lcp_hdr *)p;
    lcp->code       = LCP_TERM_ACK;
    lcp->identifier = id;
    lcp->length     = htons(payload_len);

    finish_and_send(m);
    free_session(sess->session_id);
}

/* ── CHAP ─────────────────────────────────────────────────────────────── */

void
chap_send_challenge(struct bras_session *sess)
{
    /* Challenge: 16 random bytes */
    static const char name[] = "dpdk-bras";
    uint8_t name_len = strlen(name);
    uint8_t challen_len = 16;

    /* CHAP payload: code(1) id(1) length(2) value_size(1) value(16) name */
    uint16_t payload_len = 1 + 1 + 2 + 1 + challen_len + name_len;

    struct rte_mbuf *m;
    uint8_t *p = begin_ppp_frame(&m, sess, PPP_CHAP, payload_len);
    if (!p) return;

    /* Generate challenge */
    for (int i = 0; i < 16; i += 8) {
        uint64_t r = rte_rand();
        memcpy(&sess->chap_challenge[i], &r, 8);
    }
    sess->chap_id = ++sess->lcp_id;

    p[0] = CHAP_CHALLENGE;
    p[1] = sess->chap_id;
    uint16_t len16 = htons(payload_len);
    memcpy(&p[2], &len16, 2);
    p[4] = challen_len;
    memcpy(&p[5], sess->chap_challenge, challen_len);
    memcpy(&p[5 + challen_len], name, name_len);

    sess->state = SESS_AUTH_PENDING;
    finish_and_send(m);
    RTE_LOG(DEBUG, PPP, "[%u] CHAP Challenge sent\n", sess->session_id);
}

/*
 * chap_verify_response — In a real BRAS this would query a RADIUS server.
 * For testing we accept any response (always returns 1 = success).
 * Replace with rte_hash lookup into a credentials table as needed.
 */
int
chap_verify_response(struct bras_session *sess,
                     uint8_t *payload, uint16_t len)
{
    (void)payload; (void)len;
    /* TODO: RADIUS or local user DB lookup */
    RTE_LOG(INFO, PPP, "[%u] CHAP Response received — accepting (test mode)\n",
            sess->session_id);
    return 1; /* always success for lab testing */
}

static void
chap_send_result(struct bras_session *sess, int success)
{
    const char *msg   = success ? "Welcome" : "Auth failed";
    uint8_t     msg_l = strlen(msg);
    uint16_t payload_len = 1 + 1 + 2 + msg_l;

    struct rte_mbuf *m;
    uint8_t *p = begin_ppp_frame(&m, sess, PPP_CHAP, payload_len);
    if (!p) return;

    p[0] = success ? CHAP_SUCCESS : CHAP_FAILURE;
    p[1] = sess->chap_id;
    uint16_t l = htons(payload_len);
    memcpy(&p[2], &l, 2);
    memcpy(&p[4], msg, msg_l);
    finish_and_send(m);
}

/* ── IPCP ─────────────────────────────────────────────────────────────── */

void
ipcp_send_conf_req(struct bras_session *sess)
{
    /* Offer our PPP endpoint IP */
    sess->server_ip = session_alloc_ip(sess->session_id);
    /* Client will be .session_id+1 in the pool */
    sess->client_ip = sess->server_ip + 1;

    uint16_t opts_len    = 6;   /* type(1)+len(1)+ip(4) */
    uint16_t payload_len = sizeof(struct lcp_hdr) + opts_len;

    struct rte_mbuf *m;
    uint8_t *p = begin_ppp_frame(&m, sess, PPP_IPCP, payload_len);
    if (!p) return;

    struct lcp_hdr *ipcp = (struct lcp_hdr *)p;
    ipcp->code       = IPCP_CONF_REQ;
    ipcp->identifier = ++sess->ipcp_id;
    ipcp->length     = htons(payload_len);

    uint8_t *opt = p + sizeof(struct lcp_hdr);
    opt[0] = IPCP_OPT_ADDR; opt[1] = 6;
    uint32_t sip = htonl(sess->server_ip);
    memcpy(&opt[2], &sip, 4);

    sess->state = SESS_IPCP_NEGOTIATING;
    finish_and_send(m);
    RTE_LOG(DEBUG, PPP, "[%u] IPCP CONF_REQ sent (server-side IP %u)\n",
            sess->session_id, sess->server_ip);
}

void
ipcp_send_conf_ack(struct bras_session *sess, uint8_t id, uint32_t client_ip)
{
    uint16_t opts_len    = 6;
    uint16_t payload_len = sizeof(struct lcp_hdr) + opts_len;

    struct rte_mbuf *m;
    uint8_t *p = begin_ppp_frame(&m, sess, PPP_IPCP, payload_len);
    if (!p) return;

    struct lcp_hdr *ipcp = (struct lcp_hdr *)p;
    ipcp->code       = IPCP_CONF_ACK;
    ipcp->identifier = id;
    ipcp->length     = htons(payload_len);

    uint8_t *opt = p + sizeof(struct lcp_hdr);
    opt[0] = IPCP_OPT_ADDR; opt[1] = 6;
    uint32_t cip = htonl(client_ip);
    memcpy(&opt[2], &cip, 4);

    sess->client_ip = client_ip;
    finish_and_send(m);
}

/* ── ppp_handle_ctrl — dispatcher ─────────────────────────────────────── */

/*
 * ppp_handle_ctrl — entry point for all PPP control packets (LCP/IPCP/auth).
 * Called from ctrl_plane_lcore() for every PPPoE session frame whose PPP
 * protocol is NOT 0x0021 (IP data).
 */
void
ppp_handle_ctrl(struct rte_mbuf *mbuf, uint16_t session_id)
{
    if (session_id == 0 || session_id > MAX_SESSIONS) {
        rte_pktmbuf_free(mbuf);
        return;
    }
    struct bras_session *sess = &g_bras.sessions[session_id];
    if (sess->state == SESS_FREE) {
        rte_pktmbuf_free(mbuf);
        return;
    }
    sess->last_activity = rte_rdtsc();

    uint8_t *base = rte_pktmbuf_mtod(mbuf, uint8_t *);
    size_t off = sizeof(struct rte_ether_hdr) +
                 sizeof(struct pppoe_hdr) +
                 sizeof(struct ppp_hdr);
    struct ppp_hdr *pph = (struct ppp_hdr *)
        (base + sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr));
    uint16_t proto = ntohs(pph->protocol);

    struct lcp_hdr *lcp = (struct lcp_hdr *)(base + off);
    uint16_t lcp_len = ntohs(lcp->length);

    switch (proto) {
    /* ── LCP ──────────────────────────────────────────────────────── */
    case PPP_LCP:
        switch (lcp->code) {
        case LCP_CONF_REQ:
            RTE_LOG(DEBUG, PPP, "[%u] LCP CONF_REQ from client\n", session_id);
            /* ACK client's options (simplified — accept everything) */
            lcp_send_conf_ack(sess, lcp, lcp_len);
            /* If we also got ACK for our own CONF_REQ, move to LCP_UP */
            if (sess->state == SESS_LCP_REQ_SENT)
                ; /* wait for our ACK first */
            break;

        case LCP_CONF_ACK:
            RTE_LOG(DEBUG, PPP, "[%u] LCP CONF_ACK from client\n", session_id);
            sess->state = SESS_LCP_UP;
            /* Start auth */
            chap_send_challenge(sess);
            break;

        case LCP_CONF_NAK:
            /* Re-send with adjusted options (simplified: resend same) */
            RTE_LOG(DEBUG, PPP, "[%u] LCP CONF_NAK — resending CONF_REQ\n",
                    session_id);
            lcp_send_conf_req(sess);
            break;

        case LCP_TERM_REQ:
            RTE_LOG(INFO, PPP, "[%u] LCP TERM_REQ from client\n", session_id);
            lcp_send_term_ack(sess, lcp->identifier);
            break;

        case LCP_ECHO_REQ: {
            /* Reflect as ECHO_REP */
            struct rte_mbuf *m;
            uint8_t *p = begin_ppp_frame(&m, sess, PPP_LCP, lcp_len);
            if (p) {
                memcpy(p, lcp, lcp_len);
                ((struct lcp_hdr *)p)->code = LCP_ECHO_REP;
                finish_and_send(m);
            }
            break;
        }
        default:
            break;
        }
        break;

    /* ── CHAP ─────────────────────────────────────────────────────── */
    case PPP_CHAP:
        if (lcp->code == CHAP_RESPONSE) {
            int ok = chap_verify_response(sess,
                         (uint8_t *)lcp + sizeof(struct lcp_hdr),
                         lcp_len - sizeof(struct lcp_hdr));
            chap_send_result(sess, ok);
            if (ok) {
                RTE_LOG(INFO, PPP, "[%u] auth OK — starting IPCP\n", session_id);
                ipcp_send_conf_req(sess);
            } else {
                RTE_LOG(INFO, PPP, "[%u] auth FAILED — tearing down\n", session_id);
                pppoe_send_padt(sess);
            }
        }
        break;

    /* ── PAP ──────────────────────────────────────────────────────── */
    case PPP_PAP:
        if (lcp->code == PAP_AUTH_REQ) {
            RTE_LOG(INFO, PPP, "[%u] PAP AUTH_REQ — accepting\n", session_id);
            /* Send ACK */
            const char *msg = "OK";
            uint16_t pl = 1+1+2+1+(uint16_t)strlen(msg);
            struct rte_mbuf *m;
            uint8_t *p = begin_ppp_frame(&m, sess, PPP_PAP, pl);
            if (p) {
                p[0] = PAP_AUTH_ACK; p[1] = lcp->identifier;
                uint16_t l = htons(pl); memcpy(&p[2],&l,2);
                p[4] = strlen(msg); memcpy(&p[5],msg,strlen(msg));
                finish_and_send(m);
            }
            ipcp_send_conf_req(sess);
        }
        break;

    /* ── IPCP ─────────────────────────────────────────────────────── */
    case PPP_IPCP:
        switch (lcp->code) {
        case IPCP_CONF_REQ: {
            /*
             * Walk client's options. For each one:
             *   - IP-Address (3):   we want sess->client_ip
             *   - Primary DNS (129): we want g_bras.pri_dns
             *   - Secondary DNS (131): we want g_bras.sec_dns
             *
             * If client's value matches what we want → keep in ACK list.
             * If client's value differs (commonly 0.0.0.0) → put in NAK
             *   list with our value, so client re-requests with correct one.
             * Unknown options → REJ.
             *
             * RFC 1877: client typically sends DNS options with value
             * 0.0.0.0 to ask server to supply them.
             */
            uint8_t  nak_buf[64], rej_buf[64];
            uint16_t nak_len = 0, rej_len = 0;
            int      all_ok = 1;

            uint8_t *opt = (uint8_t *)lcp + sizeof(struct lcp_hdr);
            uint8_t *end = (uint8_t *)lcp + lcp_len;

            while (opt + 2 <= end && opt + opt[1] <= end && opt[1] >= 2) {
                uint8_t  otype = opt[0];
                uint8_t  olen  = opt[1];
                uint32_t oval  = 0;
                uint32_t want  = 0;
                int      known = 0;

                if (olen == 6)
                    memcpy(&oval, &opt[2], 4);
                oval = ntohl(oval);

                switch (otype) {
                case IPCP_OPT_ADDR:    want = sess->client_ip; known = 1; break;
                case IPCP_OPT_PRI_DNS: want = g_bras.pri_dns;  known = 1; break;
                case IPCP_OPT_SEC_DNS: want = g_bras.sec_dns;  known = 1; break;
                default: known = 0; break;
                }

                if (!known) {
                    /* REJ: copy option verbatim */
                    if (rej_len + olen <= sizeof(rej_buf)) {
                        memcpy(&rej_buf[rej_len], opt, olen);
                        rej_len += olen;
                    }
                    all_ok = 0;
                } else if (oval != want) {
                    /* NAK: insert our value */
                    if (nak_len + 6 <= sizeof(nak_buf)) {
                        nak_buf[nak_len + 0] = otype;
                        nak_buf[nak_len + 1] = 6;
                        uint32_t be = htonl(want);
                        memcpy(&nak_buf[nak_len + 2], &be, 4);
                        nak_len += 6;
                    }
                    all_ok = 0;
                }
                /* else: matches — silently accepted in ACK below */

                opt += olen;
            }

            /* REJ takes priority over NAK (RFC 1661 §5.3). Send one only. */
            if (rej_len > 0) {
                uint16_t pl = sizeof(struct lcp_hdr) + rej_len;
                struct rte_mbuf *m;
                uint8_t *p = begin_ppp_frame(&m, sess, PPP_IPCP, pl);
                if (p) {
                    struct lcp_hdr *rej = (struct lcp_hdr *)p;
                    rej->code = IPCP_CONF_REJ;
                    rej->identifier = lcp->identifier;
                    rej->length = htons(pl);
                    memcpy(p + sizeof(struct lcp_hdr), rej_buf, rej_len);
                    finish_and_send(m);
                }
                RTE_LOG(DEBUG, PPP, "[%u] IPCP CONF_REJ sent (%u bytes)\n",
                        session_id, rej_len);
            } else if (nak_len > 0) {
                uint16_t pl = sizeof(struct lcp_hdr) + nak_len;
                struct rte_mbuf *m;
                uint8_t *p = begin_ppp_frame(&m, sess, PPP_IPCP, pl);
                if (p) {
                    struct lcp_hdr *nak = (struct lcp_hdr *)p;
                    nak->code = IPCP_CONF_NAK;
                    nak->identifier = lcp->identifier;
                    nak->length = htons(pl);
                    memcpy(p + sizeof(struct lcp_hdr), nak_buf, nak_len);
                    finish_and_send(m);
                }
                RTE_LOG(DEBUG, PPP, "[%u] IPCP CONF_NAK sent (%u bytes)\n",
                        session_id, nak_len);
            } else if (all_ok) {
                /* Echo all the client's options back in an ACK */
                uint16_t opts_total = lcp_len - sizeof(struct lcp_hdr);
                uint16_t pl = sizeof(struct lcp_hdr) + opts_total;
                struct rte_mbuf *m;
                uint8_t *p = begin_ppp_frame(&m, sess, PPP_IPCP, pl);
                if (p) {
                    struct lcp_hdr *ack = (struct lcp_hdr *)p;
                    ack->code = IPCP_CONF_ACK;
                    ack->identifier = lcp->identifier;
                    ack->length = htons(pl);
                    memcpy(p + sizeof(struct lcp_hdr),
                           (uint8_t *)lcp + sizeof(struct lcp_hdr),
                           opts_total);
                    finish_and_send(m);
                }
                RTE_LOG(DEBUG, PPP,
                        "[%u] IPCP CONF_ACK sent — all options match\n",
                        session_id);
            }
            break;
        }
        case IPCP_CONF_ACK:
            RTE_LOG(INFO, PPP,
                    "[%u] IPCP CONF_ACK — session UP! client_ip=%u.%u.%u.%u\n",
                    session_id,
                    (sess->client_ip >> 24) & 0xFF,
                    (sess->client_ip >> 16) & 0xFF,
                    (sess->client_ip >>  8) & 0xFF,
                    (sess->client_ip      ) & 0xFF);
            sess->state = SESS_UP;
            g_bras.stat_sessions_up++;
            break;
        default:
            break;
        }
        break;

    default:
        RTE_LOG(DEBUG, PPP, "[%u] unknown PPP ctrl proto 0x%04x\n",
                session_id, proto);
        break;
    }

    rte_pktmbuf_free(mbuf);
}
