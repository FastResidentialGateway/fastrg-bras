#ifndef BRAS_H
#define BRAS_H

#include <stdint.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>

/* =====================================================================
 * BRAS Configuration
 * ===================================================================== */
#define MAX_SESSIONS        4094        /* PPPoE max session IDs */
#define MAX_NAT_ENTRIES     65536
#define NAT_PUBLIC_IP       RTE_IPV4(203, 0, 113, 1)   /* change to your IP */
#define UPSTREAM_SERVER_IP  RTE_IPV4(192, 168, 100, 1)
#define UPSTREAM_GW_MAC     { 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF } /* upstream GW MAC */

#define WAN_PORT            0           /* DPDK port facing fastrg-node */
#define LAN_PORT            1           /* DPDK port facing upstream server */
#define BURST_SIZE          32
#define MBUF_POOL_SIZE      8191
#define MBUF_CACHE_SIZE     256
#define CTRL_RING_SIZE      1024
#define MAX_RX_QUEUES       8           /* max data-path lcores / queues per port */

/* LCore assignment */
#define LCORE_CTRL          2           /* control plane: PPPoE/LCP/IPCP */

/* =====================================================================
 * PPPoE Protocol Constants  (RFC 2516)
 * ===================================================================== */
#define ETH_P_PPPoE_DISC    0x8863
#define ETH_P_PPPoE_SESS    0x8864

#define PPPOE_CODE_PADI     0x09
#define PPPOE_CODE_PADO     0x07
#define PPPOE_CODE_PADR     0x19
#define PPPOE_CODE_PADS     0x65
#define PPPOE_CODE_PADT     0xa7
#define PPPOE_CODE_DATA     0x00

/* PPPoE Tag types */
#define PPPOE_TAG_EOL       0x0000
#define PPPOE_TAG_SVC_NAME  0x0101
#define PPPOE_TAG_AC_NAME   0x0102
#define PPPOE_TAG_HOST_UNIQ 0x0103
#define PPPOE_TAG_AC_COOKIE 0x0104

/* PPP Protocol numbers */
#define PPP_LCP             0xC021
#define PPP_PAP             0xC023
#define PPP_CHAP            0xC223
#define PPP_IPCP            0x8021
#define PPP_IP              0x0021

/* LCP codes */
#define LCP_CONF_REQ        1
#define LCP_CONF_ACK        2
#define LCP_CONF_NAK        3
#define LCP_CONF_REJ        4
#define LCP_TERM_REQ        5
#define LCP_TERM_ACK        6
#define LCP_ECHO_REQ        9
#define LCP_ECHO_REP        10

/* LCP option types */
#define LCP_OPT_MRU         1
#define LCP_OPT_AUTH        3
#define LCP_OPT_MAGIC       5

/* IPCP codes / options (RFC 1877 §1.1, §1.3) */
#define IPCP_CONF_REQ       1
#define IPCP_CONF_ACK       2
#define IPCP_CONF_NAK       3
#define IPCP_CONF_REJ       4
#define IPCP_OPT_ADDR       3
#define IPCP_OPT_PRI_DNS    129   /* Primary DNS server address  */
#define IPCP_OPT_SEC_DNS    131   /* Secondary DNS server address */

/* DNS servers we push to clients (defaults — Cloudflare 1.1.1.1 / Google 8.8.8.8).
 * Override at runtime via --pri-dns / --sec-dns command-line flags. */
#define DEFAULT_PRI_DNS     RTE_IPV4(1, 1, 1, 1)
#define DEFAULT_SEC_DNS     RTE_IPV4(8, 8, 8, 8)

/* CHAP codes */
#define CHAP_CHALLENGE      1
#define CHAP_RESPONSE       2
#define CHAP_SUCCESS        3
#define CHAP_FAILURE        4

/* PAP codes */
#define PAP_AUTH_REQ        1
#define PAP_AUTH_ACK        2
#define PAP_AUTH_NAK        3

/* =====================================================================
 * Wire-format structs (packed)
 * ===================================================================== */
#pragma pack(push, 1)

struct pppoe_hdr {
    uint8_t  ver_type;   /* 0x11 = ver 1, type 1 */
    uint8_t  code;
    uint16_t session_id;
    uint16_t length;     /* payload length */
};

struct pppoe_tag {
    uint16_t type;
    uint16_t length;
    uint8_t  value[0];
};

struct ppp_hdr {
    uint16_t protocol;
};

struct lcp_hdr {
    uint8_t  code;
    uint8_t  identifier;
    uint16_t length;
};

struct lcp_opt {
    uint8_t  type;
    uint8_t  length;
    uint8_t  data[0];
};

#pragma pack(pop)

/* =====================================================================
 * Session State Machine
 * ===================================================================== */
typedef enum {
    SESS_FREE = 0,
    SESS_PADI_RECV,
    SESS_PADO_SENT,
    SESS_PADR_RECV,
    SESS_PADS_SENT,       /* PPPoE established, LCP starting */
    SESS_LCP_REQ_SENT,
    SESS_LCP_UP,
    SESS_AUTH_PENDING,
    SESS_IPCP_NEGOTIATING,
    SESS_UP,              /* fully established, data flowing */
    SESS_TERMINATING,
} sess_state_t;

typedef enum {
    AUTH_NONE = 0,
    AUTH_PAP,
    AUTH_CHAP,
} auth_method_t;

struct bras_session {
    sess_state_t        state;
    uint16_t            session_id;
    struct rte_ether_addr client_mac;
    struct rte_ether_addr server_mac;  /* our WAN port MAC */

    /* PPP negotiation state */
    auth_method_t       auth_method;
    uint8_t             lcp_id;
    uint8_t             ipcp_id;
    uint32_t            magic_number;

    /* Assigned addressing */
    uint32_t            client_ip;     /* IP we assign to client */
    uint32_t            server_ip;     /* our PPP endpoint IP   */

    /* NAT: per-session port range for SNAT */
    uint16_t            nat_port_base;
    uint16_t            nat_port_count;

    /* Host-unique tag for matching PADR to PADI */
    uint8_t             host_uniq[16];
    uint8_t             host_uniq_len;

    /* CHAP challenge stored for response validation */
    uint8_t             chap_challenge[16];
    uint8_t             chap_id;

    uint64_t            last_activity; /* rte_rdtsc() timestamp */
    uint64_t            bytes_up;
    uint64_t            bytes_down;
};

/* =====================================================================
 * NAT table entry
 * ===================================================================== */
struct nat_entry {
    uint8_t     in_use;
    uint8_t     proto;
    uint16_t    session_id;  /* back-reference */
    uint32_t    inner_ip;
    uint16_t    inner_port;
    uint32_t    outer_ip;    /* NAT_PUBLIC_IP */
    uint16_t    outer_port;
    uint64_t    last_seen;
};

/* =====================================================================
 * Control message passed from fast-path to control-plane lcore
 * ===================================================================== */
typedef enum {
    CTRL_MSG_PPPOE_DISC,    /* discovery packet (PADI/PADR/PADT) */
    CTRL_MSG_PPP_CTRL,      /* LCP / IPCP / auth packet */
} ctrl_msg_type_t;

struct ctrl_msg {
    ctrl_msg_type_t     type;
    struct rte_mbuf    *mbuf;   /* caller hands ownership */
    uint16_t            session_id;
};

/* =====================================================================
 * Global BRAS context
 * ===================================================================== */
struct bras_ctx {
    /* Session table — index == session_id */
    struct bras_session sessions[MAX_SESSIONS + 1];

    /* Packet pools */
    struct rte_mempool *pktmbuf_pool;

    /* NAT hash: key=(inner_ip, inner_port, proto), val=nat_entry* */
    struct rte_hash    *nat_out_tbl;   /* outbound lookup */
    struct rte_hash    *nat_in_tbl;    /* inbound lookup (outer port) */
    struct nat_entry    nat_entries[MAX_NAT_ENTRIES];

    /* Ring from fast-path to control plane */
    struct rte_ring    *ctrl_ring;

    /* Our MAC addresses */
    struct rte_ether_addr wan_mac;
    struct rte_ether_addr lan_mac;

    /* IP pool for clients: base + offset per session */
    uint32_t            ip_pool_base;  /* e.g. 10.0.0.0 */

    /* DNS servers pushed to clients via IPCP options 129/131 (RFC 1877) */
    uint32_t            pri_dns;
    uint32_t            sec_dns;

    /* Multi-queue: per-port queue count and lcore→TX-queue mapping */
    uint16_t            n_queues;
    uint16_t            lcore_queue[RTE_MAX_LCORE];

    /* Statistics */
    uint64_t            stat_sessions_up;
    uint64_t            stat_pkts_rx;
    uint64_t            stat_pkts_tx;
    uint64_t            stat_pkts_dropped;
};

/* Singleton — defined in main.c */
extern struct bras_ctx g_bras;

/* =====================================================================
 * Function prototypes
 * ===================================================================== */

/* pppoe.c */
void pppoe_handle_discovery(struct rte_mbuf *mbuf);
void pppoe_send_pado(struct bras_session *sess, struct rte_mbuf *padi_mbuf);
void pppoe_send_pads(struct bras_session *sess, struct rte_mbuf *padr_mbuf);
void pppoe_send_padt(struct bras_session *sess);

/* ppp.c */
void ppp_handle_ctrl(struct rte_mbuf *mbuf, uint16_t session_id);
void lcp_send_conf_req(struct bras_session *sess);
void lcp_send_conf_ack(struct bras_session *sess, struct lcp_hdr *req, uint16_t len);
void lcp_send_term_ack(struct bras_session *sess, uint8_t id);
void chap_send_challenge(struct bras_session *sess);
int  chap_verify_response(struct bras_session *sess, uint8_t *payload, uint16_t len);
void ipcp_send_conf_req(struct bras_session *sess);
void ipcp_send_conf_ack(struct bras_session *sess, uint8_t id, uint32_t client_ip);

/* nat.c */
int  nat_translate_outbound(struct rte_mbuf *mbuf, struct bras_session *sess);
int  nat_translate_inbound(struct rte_mbuf *mbuf);
void nat_init(void);
void nat_expire(void);
void nat_flush_session(uint16_t session_id);

/* datapath.c */
int  datapath_lcore(void *arg);
int  ctrl_plane_lcore(void *arg);

/* utils.c */
struct rte_mbuf *alloc_pkt(uint16_t data_room);
void             send_pkt(uint16_t port, struct rte_mbuf *mbuf);
uint16_t         alloc_session_id(void);
void             free_session(uint16_t session_id);
uint32_t         session_alloc_ip(uint16_t session_id);

#endif /* BRAS_H */
