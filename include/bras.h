#ifndef BRAS_H
#define BRAS_H

#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <rte_ether.h>
#include <rte_pcapng.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_byteorder.h>

/* =====================================================================
 * BRAS Configuration
 * ===================================================================== */
#define MAX_SESSIONS        4094        /* PPPoE max session IDs */

/* Lab topology defaults — all overridable via CLI options after the EAL "--".
 *
 *   WAN_PORT (07:00.0): PPPoE terminal. Our PPP endpoint = 192.168.200.128,
 *     clients get 192.168.200.130 … 192.168.200.254 (within /25).
 *   LAN_PORT (08:00.0): mock backbone. We own 192.168.201.1/24 (SNAT exit IP),
 *     all NATed traffic is routed to the peer 192.168.201.11.
 */
#define DEFAULT_PPP_LOCAL_IP   RTE_IPV4(192, 168, 200, 128)
#define DEFAULT_IP_POOL_START  RTE_IPV4(192, 168, 200, 130)
#define DEFAULT_IP_POOL_END    RTE_IPV4(192, 168, 200, 254)
#define DEFAULT_NAT_PUBLIC_IP  RTE_IPV4(192, 168, 201, 1)
#define DEFAULT_UPSTREAM_IP    RTE_IPV4(192, 168, 201, 11)

#define WAN_PORT            0           /* DPDK port facing fastrg-node (07:00.0) */
#define LAN_PORT            1           /* DPDK port facing upstream backbone (08:00.0) */
#define BURST_SIZE          32
#define MBUF_POOL_SIZE      8191
#define MBUF_CACHE_SIZE     256
#define CTRL_RING_SIZE      1024
#define MAX_RX_QUEUES       8           /* max data-path lcores / queues per port */

/* LCore assignment */
#define LCORE_CTRL          2           /* control plane: PPPoE/PPP/DHCPv6 */
#define MAX_DIST_WORKERS    8           /* max distributor worker lcores */
#define ND6_REQ_FAST_ATTEMPTS       30
#define ND6_REQ_SLOW_INTERVAL_SEC   10
#define PORT_READY_POLL_MS          100
#define PORT_READY_WAIT_MS          10000
#define PORT_REINIT_ATTEMPTS        5
#define PORT_REINIT_DELAY_US        200000

/* =====================================================================
 * PPPoE Protocol Constants  (RFC 2516)
 * ===================================================================== */
#define ETH_P_PPPoE_DISC    0x8863
#define ETH_P_PPPoE_SESS    0x8864
#define ETH_P_8021Q         0x8100

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
#define PPP_IPV6CP          0x8057
#define PPP_IP              0x0021
#define PPP_IPV6            0x0057

/* ICMPv6 message and neighbour-discovery option types. */
#define ICMPV6_ECHO_REQ      128
#define ICMPV6_ECHO_REP      129
#define ICMPV6_RS            133
#define ICMPV6_RA            134
#define ICMPV6_NS            135
#define ICMPV6_NA            136
#define ND6_OPT_SLL          1
#define ND6_OPT_TLL          2

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

/* IPv6CP options (RFC 5072) */
#define IPV6CP_OPT_IFID     1

/* DNS servers we push to clients (defaults — Cloudflare 1.1.1.1 / Google 8.8.8.8).
 * Override at runtime via --pri-dns / --sec-dns command-line flags. */
#define DEFAULT_PRI_DNS     RTE_IPV4(1, 1, 1, 1)
#define DEFAULT_SEC_DNS     RTE_IPV4(8, 8, 8, 8)

/* DHCPv6 message types, options, ports, and lease timers (RFC 8415). */
#define DHCPV6_SOLICIT              1
#define DHCPV6_ADVERTISE            2
#define DHCPV6_REQUEST              3
#define DHCPV6_RENEW                5
#define DHCPV6_REBIND               6
#define DHCPV6_REPLY                7
#define DHCPV6_RELEASE              8

#define DHCPV6_OPT_CLIENTID         1
#define DHCPV6_OPT_SERVERID         2
#define DHCPV6_OPT_ORO              6
#define DHCPV6_OPT_STATUS           13
#define DHCPV6_OPT_DNS_SERVERS      23
#define DHCPV6_OPT_IA_PD            25
#define DHCPV6_OPT_IAPREFIX         26

#define DHCPV6_CLIENT_PORT          546
#define DHCPV6_SERVER_PORT          547
#define DHCPV6_STATUS_SUCCESS       0
#define DHCPV6_STATUS_NO_PREFIX     6
#define DHCPV6_PREFERRED_LIFETIME   43200
#define DHCPV6_VALID_LIFETIME       86400
#define DHCPV6_T1                   21600
#define DHCPV6_T2                   34560
#define DHCPV6_PD_PLEN              56

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

/* IPv6CP is optional and does not affect the IPv4 session state machine. */
typedef enum {
    IPV6CP_IDLE = 0,
    IPV6CP_NEGOTIATING,
    IPV6CP_OPENED,
    IPV6CP_FAILED,
} ipv6cp_state_t;

struct bras_session {
    sess_state_t        state;
    uint16_t            session_id;
    struct rte_ether_addr client_mac;
    struct rte_ether_addr server_mac;  /* our WAN port MAC */
    uint8_t             has_vlan;      /* fastrg-node uses 802.1Q PPPoE */
    uint8_t             tx_vlan;       /* insert 802.1Q tag on TX; 0 when the
                                        * PF enforces a port VLAN (VMVIR) and
                                        * inserts the tag in hardware itself */
    uint16_t            vlan_tci;      /* host order, includes PCP/DEI/VID */

    /* PPP negotiation state */
    auth_method_t       auth_method;
    uint8_t             lcp_id;
    uint8_t             ipcp_id;
    uint32_t            magic_number;

    /* IPv6CP negotiation state (RFC 5072) */
    ipv6cp_state_t      ipv6cp_state;
    uint8_t             ipv6cp_id;
    uint8_t             ipv6cp_local_acked;
    uint8_t             ipv6cp_peer_acked;
    uint8_t             local_ifid[8];
    uint8_t             peer_ifid[8];
    uint8_t             ipv6cp_attempts;
    uint64_t            ipv6cp_sent_at;

    /* DHCPv6-PD lease: high 64 bits of the delegated /56.  Bits 56..63
     * remain zero so the client can subnet the prefix into /64 LANs. */
    uint8_t             pd_prefix[8];
    uint8_t             pd_active;
    uint32_t            pd_iaid;

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
 * Control message passed from fast-path to control-plane lcore
 * ===================================================================== */
typedef enum {
    CTRL_MSG_PPPOE_DISC,    /* discovery packet (PADI/PADR/PADT) */
    CTRL_MSG_PPP_CTRL,      /* PPP control or control-plane IPv6 packet */
} ctrl_msg_type_t;

struct ctrl_msg {
    ctrl_msg_type_t     type;
    struct rte_mbuf    *mbuf;   /* caller hands ownership */
    uint16_t            session_id;
};

/* =====================================================================
 * NAT table entry — internet-bound flows only.
 * Backbone-local traffic (dst within the LAN /24) is routed transparently;
 * everything else is SNATed to nat_public_ip because the WAN host's
 * firewall only forwards/masquerades the LAN net to the internet, not the
 * subscriber pool.
 * ===================================================================== */
#define MAX_NAT_ENTRIES     65536

struct nat_entry {
    uint8_t     in_use;
    uint8_t     proto;
    uint32_t    inner_ip;    /* host order */
    uint16_t    inner_port;  /* host order; ICMP echo: ident */
    uint32_t    outer_ip;    /* host order */
    uint16_t    outer_port;  /* host order */
    uint16_t    session_id;
    uint64_t    last_seen;   /* rte_rdtsc() */
};

/* =====================================================================
 * Global BRAS context
 * ===================================================================== */
struct bras_ctx {
    /* Session table — index == session_id */
    struct bras_session sessions[MAX_SESSIONS + 1];

    /* Packet pools */
    struct rte_mempool *pktmbuf_pool;

    /* Ring from fast-path to control plane */
    struct rte_ring    *ctrl_ring;

    /* Our MAC addresses */
    struct rte_ether_addr wan_mac;
    struct rte_ether_addr lan_mac;

    /* PPP addressing: fixed server endpoint + linear client pool (inclusive) */
    uint32_t            ppp_local_ip;  /* our PPP endpoint, e.g. 192.168.200.128 */
    uint32_t            ip_pool_start; /* first client IP, e.g. 192.168.200.130 */
    uint32_t            ip_pool_end;   /* last  client IP, e.g. 192.168.200.254 */

    /* LAN-side addressing: our LAN IP (ARP/ICMP responder) + next-hop */
    uint32_t            nat_public_ip; /* our IP on the LAN net (gateway for
                                        * the subscriber pool route)         */
    uint32_t            upstream_ip;   /* next-hop for all outbound traffic   */
    struct rte_ether_addr upstream_mac;      /* learned via ARP */
    volatile uint8_t      upstream_mac_valid;

    /* IPv6 upstream-side addressing and resolved next-hop. */
    uint8_t             lan_ip6[16];       /* our LAN-side global address */
    uint8_t             lan_ip6_ll[16];    /* fe80:: EUI-64(lan_mac)      */
    uint8_t             upstream_ip6[16];  /* next-hop for v6 outbound    */
    struct rte_ether_addr upstream_mac6;    /* learned via NDP             */
    volatile uint8_t      upstream_mac6_valid;
    uint8_t             wan_ll[16];        /* fe80:: EUI-64(wan_mac)      */

    /* Extra unicast MAC accepted on LAN RX (e2e bench injects frames
     * addressed to the fastrg-node WAN MAC; VF promiscuous is unavailable
     * without PF trust, so we add it as a second MAC filter). */
    struct rte_ether_addr lan_alias_mac;
    uint8_t               lan_alias_mac_set;

    /* NAT tables (internet-bound flows only — see struct nat_entry) */
    struct rte_hash    *nat_out_tbl;   /* (inner_ip, inner_port, proto) → outer_port */
    struct rte_hash    *nat_in_tbl;    /* (outer_port, proto) → entry */
    struct nat_entry    nat_entries[MAX_NAT_ENTRIES];

    /* DNS servers pushed to clients via IPCP options 129/131 (RFC 1877) */
    uint32_t            pri_dns;
    uint32_t            sec_dns;

    /* DHCPv6 delegated-prefix pool and DNS servers. */
    uint8_t             pd_pool_prefix[8];
    uint8_t             pd_pool_plen;
    uint8_t             dns6_pri[16];
    uint8_t             dns6_sec[16];

    /* Multi-queue: per-port queue count and lcore→TX-queue mapping */
    uint16_t            n_queues;
    uint16_t            lcore_queue[RTE_MAX_LCORE];
    uint8_t             tx_queue_shared; /* serialize TX only when legacy
                                          * lcores share a hardware queue */

    /* Port-reset park protocol. Main writes dp_pause, claims reset pending,
     * and requeues degraded ports; the interrupt thread only sets pending.
     * Each datapath lcore writes only its own dp_ack slot. */
    volatile uint8_t    dp_pause;
    volatile uint8_t    dp_ack[RTE_MAX_LCORE];
    volatile uint8_t    port_reset_pending[2];
    volatile uint8_t    nd6_backoff_reset; /* main sets, ctrl consumes */
    volatile uint8_t    warmup_pending;    /* main sets, ctrl consumes */
    uint8_t             n_dp_lcores;
    uint16_t            cfg_n_rxq;
    uint16_t            cfg_n_txq;

    /* Software distributor datapath (X520/82599 VF cannot RSS PPPoE: the
     * inner IP is hidden behind the PPPoE header, so hardware always lands
     * every session frame on queue 0).  One RX lcore classifies and tags
     * data packets by flow 5-tuple; N worker lcores do NAT + forwarding,
     * each on its own TX queue.  NULL = legacy single-lcore datapath. */
    struct rte_distributor *dist;
    uint16_t            n_workers;

    /* VLANs registered with the WAN port (82599 VF needs PF-side VLVF
     * membership via mailbox before it may TX tagged frames). */
    uint8_t             vlan_registered[4096];

    /* Accepted PPPoE VLAN set (--vlans).  When vlan_filter_enabled, a PPPoE
     * frame is accepted only if it is tagged and its VID has vlan_allowed[]
     * set; otherwise it is dropped (drop:vlan).  Disabled = accept any. */
    uint8_t             vlan_allowed[4096];
    uint8_t             vlan_filter_enabled;

    /* Statistics */
    uint64_t            stat_sessions_up;
    uint64_t            stat_pkts_rx;
    uint64_t            stat_pkts_tx;
    uint64_t            stat_pkts_dropped;
    uint64_t            stat_worker_pkts[MAX_DIST_WORKERS];

    /* Drop forensics: every dropped data packet is copied to this pcapng
     * file (with a per-packet "drop:<reason>" comment) before being freed
     * (--drop-pcap <file>[,<max>]; NULL = disabled).  Full-traffic capture
     * is separate — attach dpdk-dumpcap at runtime (rte_pdump_init). */
    rte_pcapng_t       *drop_pcap;
    struct rte_mempool *drop_pcap_pool;  /* pcapng copy buffers */
    uint64_t            drop_pcap_max;   /* byte cap (<= 2 GiB), 0 = until cap */
    uint64_t            drop_pcap_bytes; /* bytes written so far */

    /* Drop reason breakdown (sum == stat_pkts_dropped for data drops) */
    uint64_t            stat_drop_txfull;  /* rte_eth_tx_burst returned 0  */
    uint64_t            stat_drop_dist;    /* distributor backlog refused  */
    uint64_t            stat_drop_route;   /* route_outbound/inbound == -1 */
    uint64_t            stat_drop_other;   /* unknown ethertype etc.       */
    uint64_t            stat_drop_vlan;    /* PPPoE VLAN not in --vlans set */
};

/* Singleton — defined in main.c */
extern struct bras_ctx g_bras;

/* Set by the signal handler; worker lcores poll this to exit cleanly. */
extern volatile int g_running;
extern volatile sig_atomic_t g_terminate_sessions;
extern volatile sig_atomic_t g_padt_sessions;
extern int g_no_lcp_echo;

/* Return the real ethertype after an optional single 802.1Q VLAN header. */
static inline uint16_t
bras_frame_ethertype(const uint8_t *p, uint16_t *l2_len, uint16_t *vlan_tci)
{
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)p;
    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);

    *l2_len = sizeof(struct rte_ether_hdr);
    *vlan_tci = 0;
    if (etype == ETH_P_8021Q) {
        const struct rte_vlan_hdr *vh =
            (const struct rte_vlan_hdr *)(p + sizeof(struct rte_ether_hdr));
        *l2_len += sizeof(struct rte_vlan_hdr);
        *vlan_tci = rte_be_to_cpu_16(vh->vlan_tci);
        etype = rte_be_to_cpu_16(vh->eth_proto);
    }
    return etype;
}

/* Return 1 if a PPPoE frame with this L2 framing passes the --vlans filter.
 * Always 1 when the filter is disabled; when enabled, only tagged frames
 * whose VID is in the allowed set are accepted (untagged → 0). */
static inline int
bras_vlan_accepted(uint16_t l2_len, uint16_t vlan_tci)
{
    if (!g_bras.vlan_filter_enabled)
        return 1;
    if (l2_len <= sizeof(struct rte_ether_hdr))
        return 0;  /* untagged PPPoE rejected when the filter is on */
    return g_bras.vlan_allowed[vlan_tci & 0x0FFF];
}

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
void lcp_send_term_req(struct bras_session *sess);
void lcp_send_term_ack(struct bras_session *sess, uint8_t id);
void chap_send_challenge(struct bras_session *sess);
void chap_retry_pending(uint64_t now);
int  chap_verify_response(struct bras_session *sess, uint8_t *payload, uint16_t len);
void ipcp_send_conf_req(struct bras_session *sess);
void ipcp_send_conf_ack(struct bras_session *sess, uint8_t id, uint32_t client_ip);
void ipv6cp_start(struct bras_session *sess);
uint8_t *ppp_begin_frame(struct rte_mbuf **out_mbuf,
                         struct bras_session *sess, uint16_t ppp_proto,
                         uint16_t payload_room);

/* dhcpv6.c */
void dhcpv6_input(struct bras_session *sess, const uint8_t *ip6, uint16_t len);

/* nat.c — hybrid forwarding: backbone-local routed, internet-bound SNATed */
int  route_outbound(struct rte_mbuf *mbuf, struct bras_session *sess);
int  route_inbound(struct rte_mbuf *mbuf);
void nat_init(void);
void nat_expire(void);
void nat_flush_session(uint16_t session_id);

/* datapath.c */
int  datapath_lcore(void *arg);
int  rx_dist_lcore(void *arg);
int  dist_worker_lcore(void *arg);
int  ctrl_plane_lcore(void *arg);

/* arp.c — LAN-side ARP + local ICMP echo responder */
void arp_input(struct rte_mbuf *mbuf);          /* consumes mbuf */
void arp_request_upstream(void);
void arp_announce_local(void);                  /* ctrl lcore */
int  lan_icmp_echo_input(struct rte_mbuf *mbuf); /* 0 = consumed */

/* ipv6.c — callers/lcores are documented at each implementation. */
void ipv6_mac_to_ifid(const struct rte_ether_addr *mac, uint8_t ifid[8]);
void ipv6_addr_init(void);                         /* main lcore, after ports */
int  ipv6_lan_input(struct rte_mbuf *mbuf);        /* RX lcore; 0 = consumed */
int  ipv6_route_outbound(struct rte_mbuf *mbuf,
                         struct bras_session *sess); /* data worker */
int  ipv6_route_inbound(struct rte_mbuf *mbuf);    /* data worker */
void ipv6_ctrl_input(struct bras_session *sess,
                     const uint8_t *ip6, uint16_t len); /* ctrl lcore */
void nd6_request_upstream(void);                   /* ctrl lcore */
void nd6_announce_local(void);                     /* ctrl lcore */

/* utils.c */
struct rte_mbuf *alloc_pkt(uint16_t data_room);
void             send_pkt(uint16_t port, struct rte_mbuf *mbuf);
void             drop_capture(struct rte_mbuf *mbuf, uint16_t port,
                              enum rte_pcapng_direction dir,
                              const char *reason);
uint16_t         alloc_session_id(void);
void             free_session(uint16_t session_id);
uint32_t         session_alloc_ip(uint16_t session_id);

#endif /* BRAS_H */
