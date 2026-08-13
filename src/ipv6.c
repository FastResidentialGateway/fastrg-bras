/* ipv6.c — IPv6 forwarding, NDP, and local ICMPv6 handling
 *
 * Lcore ownership:
 *   main:          ipv6_addr_init()
 *   RX/classify:   ipv6_lan_input() (LAN NDP and local echo, inline)
 *   data workers:  ipv6_route_outbound(), ipv6_route_inbound()
 *   LCORE_CTRL:    nd6_request_upstream(), nd6_announce_local(),
 *                  ipv6_ctrl_input()
 *
 * The upstream side uses one configured IPv6 next-hop.  Its MAC is learned
 * with NDP and then published to the forwarding workers through a valid flag.
 */

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_log.h>

#include "bras.h"

#define RTE_LOGTYPE_IPV6 RTE_LOGTYPE_USER6

#pragma pack(push, 1)
struct icmp6_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t data;
};

struct nd6_message {
    struct icmp6_hdr icmp;
    uint8_t target[16];
};

struct nd6_ll_option {
    uint8_t type;
    uint8_t length;
    uint8_t mac[RTE_ETHER_ADDR_LEN];
};
#pragma pack(pop)

#define ND6_MESSAGE_LEN (sizeof(struct nd6_message) + \
                         sizeof(struct nd6_ll_option))

static int
ipv6_equal(const void *a, const void *b)
{
    return memcmp(a, b, 16) == 0;
}

static int
ipv6_unspecified(const uint8_t address[16])
{
    static const uint8_t zero[16];

    return ipv6_equal(address, zero);
}

static int
prefix_matches(const uint8_t address[16], const uint8_t prefix[16],
               uint8_t plen)
{
    unsigned int bytes = plen / 8;
    unsigned int bits = plen % 8;

    if (bytes > 0 && memcmp(address, prefix, bytes) != 0)
        return 0;
    if (bits != 0) {
        uint8_t mask = (uint8_t)(0xffu << (8 - bits));
        if ((address[bytes] & mask) != (prefix[bytes] & mask))
            return 0;
    }
    return 1;
}

static uint64_t
read_be64(const uint8_t address[8])
{
    uint64_t value = 0;

    for (unsigned int i = 0; i < 8; i++)
        value = (value << 8) | address[i];
    return value;
}

void
ipv6_mac_to_ifid(const struct rte_ether_addr *mac, uint8_t ifid[8])
{
    const uint8_t *m = mac->addr_bytes;

    ifid[0] = m[0] ^ 0x02;
    ifid[1] = m[1];
    ifid[2] = m[2];
    ifid[3] = 0xff;
    ifid[4] = 0xfe;
    ifid[5] = m[3];
    ifid[6] = m[4];
    ifid[7] = m[5];
}

/* Ethernet mapping of an address' solicited-node multicast group: 33:33:ff
 * followed by the last three bytes of the address (RFC 2464). */
static void
solicited_node_mac(const uint8_t address[16], struct rte_ether_addr *mac)
{
    mac->addr_bytes[0] = 0x33;
    mac->addr_bytes[1] = 0x33;
    mac->addr_bytes[2] = 0xff;
    mac->addr_bytes[3] = address[13];
    mac->addr_bytes[4] = address[14];
    mac->addr_bytes[5] = address[15];
}

/* Called by the main lcore after both port MAC addresses are known: derives
 * the link-local addresses plus the multicast MACs the LAN port has to
 * subscribe to. */
void
ipv6_addr_init(void)
{
    uint8_t ifid[8];

    memset(g_bras.lan_ip6_ll, 0, sizeof(g_bras.lan_ip6_ll));
    g_bras.lan_ip6_ll[0] = 0xfe;
    g_bras.lan_ip6_ll[1] = 0x80;
    ipv6_mac_to_ifid(&g_bras.lan_mac, ifid);
    memcpy(g_bras.lan_ip6_ll + 8, ifid, sizeof(ifid));

    memset(g_bras.wan_ll, 0, sizeof(g_bras.wan_ll));
    g_bras.wan_ll[0] = 0xfe;
    g_bras.wan_ll[1] = 0x80;
    ipv6_mac_to_ifid(&g_bras.wan_mac, ifid);
    memcpy(g_bras.wan_ll + 8, ifid, sizeof(ifid));

    /* The two addresses upstream neighbours solicit us on.  Both map to the
     * same multicast MAC when lan_ip6 ends in the same three bytes as lan_mac,
     * so drop the duplicate. */
    solicited_node_mac(g_bras.lan_ip6, &g_bras.lan_mc_addrs[0]);
    solicited_node_mac(g_bras.lan_ip6_ll, &g_bras.lan_mc_addrs[1]);
    g_bras.lan_mc_count = rte_is_same_ether_addr(&g_bras.lan_mc_addrs[0],
                                                 &g_bras.lan_mc_addrs[1])
                          ? 1 : 2;
}

static void
learn_upstream_mac6(const struct rte_ether_addr *mac)
{
    if (g_bras.upstream_mac6_valid &&
        rte_is_same_ether_addr(&g_bras.upstream_mac6, mac))
        return;

    rte_ether_addr_copy(mac, &g_bras.upstream_mac6);
    rte_smp_wmb();
    g_bras.upstream_mac6_valid = 1;

    char address[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, g_bras.upstream_ip6, address, sizeof(address)))
        strcpy(address, "<invalid>");
    RTE_LOG(INFO, IPV6, "upstream %s is at " RTE_ETHER_ADDR_PRT_FMT "\n",
            address, RTE_ETHER_ADDR_BYTES(&g_bras.upstream_mac6));
}

static const struct nd6_ll_option *
find_ll_option(const struct nd6_message *nd, uint16_t icmp_len, uint8_t type)
{
    if (icmp_len < sizeof(*nd))
        return NULL;

    const uint8_t *cursor = (const uint8_t *)nd + sizeof(*nd);
    const uint8_t *end = (const uint8_t *)nd + icmp_len;
    while (cursor + 2 <= end) {
        uint16_t option_len = (uint16_t)cursor[1] * 8;
        if (option_len == 0 || cursor + option_len > end)
            return NULL;
        if (cursor[0] == type && option_len >= sizeof(struct nd6_ll_option))
            return (const struct nd6_ll_option *)cursor;
        cursor += option_len;
    }
    return NULL;
}

static void
icmp6_checksum(struct rte_ipv6_hdr *ip6, struct icmp6_hdr *icmp)
{
    icmp->checksum = 0;
    icmp->checksum = rte_ipv6_udptcp_cksum(ip6, icmp);
}

static int
is_our_lan_address(const uint8_t address[16])
{
    return ipv6_equal(address, g_bras.lan_ip6) ||
           ipv6_equal(address, g_bras.lan_ip6_ll);
}

/* RX/classify lcore.  Returns 0 if the mbuf was sent or freed. */
int
ipv6_lan_input(struct rte_mbuf *mbuf)
{
    uint32_t frame_len = rte_pktmbuf_pkt_len(mbuf);
    uint8_t *base = rte_pktmbuf_mtod(mbuf, uint8_t *);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)base;

    if (frame_len < sizeof(*eth) ||
        eth->ether_type != htons(RTE_ETHER_TYPE_IPV6))
        return 1;
    if (frame_len < sizeof(*eth) + sizeof(struct rte_ipv6_hdr)) {
        rte_pktmbuf_free(mbuf);
        return 0;
    }

    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
    uint16_t payload_len = ntohs(ip6->payload_len);
    if (rte_ipv6_check_version(ip6) != 0 ||
        payload_len > frame_len - sizeof(*eth) - sizeof(*ip6)) {
        rte_pktmbuf_free(mbuf);
        return 0;
    }
    if (ip6->proto != IPPROTO_ICMPV6)
        return 1;
    if (payload_len < sizeof(struct icmp6_hdr)) {
        rte_pktmbuf_free(mbuf);
        return 0;
    }

    uint8_t *src = (uint8_t *)&ip6->src_addr;
    uint8_t *dst = (uint8_t *)&ip6->dst_addr;
    struct icmp6_hdr *icmp = (struct icmp6_hdr *)(ip6 + 1);

    if (icmp->type == ICMPV6_NS &&
        payload_len >= sizeof(struct nd6_message)) {
        struct nd6_message *ns = (struct nd6_message *)icmp;

        if (ipv6_equal(src, g_bras.upstream_ip6)) {
            const struct nd6_ll_option *sll =
                find_ll_option(ns, payload_len, ND6_OPT_SLL);
            if (sll)
                learn_upstream_mac6((const struct rte_ether_addr *)sll->mac);
        }

        if (!is_our_lan_address(ns->target)) {
            rte_pktmbuf_free(mbuf);
            return 0;
        }

        /* DAD uses an unspecified source; this lab responder stays silent. */
        if (ipv6_unspecified(src)) {
            rte_pktmbuf_free(mbuf);
            return 0;
        }

        uint8_t requester[16];
        struct rte_ether_addr requester_mac = eth->src_addr;
        memcpy(requester, src, sizeof(requester));

        uint32_t wanted = sizeof(*eth) + sizeof(*ip6) + ND6_MESSAGE_LEN;
        if (frame_len < wanted) {
            if (!rte_pktmbuf_append(mbuf, (uint16_t)(wanted - frame_len))) {
                rte_pktmbuf_free(mbuf);
                return 0;
            }
        } else if (frame_len > wanted) {
            rte_pktmbuf_trim(mbuf, (uint16_t)(frame_len - wanted));
        }

        rte_ether_addr_copy(&requester_mac, &eth->dst_addr);
        rte_ether_addr_copy(&g_bras.lan_mac, &eth->src_addr);
        memcpy(dst, requester, sizeof(requester));
        memcpy(src, ns->target, sizeof(ns->target));
        ip6->payload_len = htons(ND6_MESSAGE_LEN);
        ip6->proto = IPPROTO_ICMPV6;
        ip6->hop_limits = 255;

        struct nd6_message *na = (struct nd6_message *)icmp;
        na->icmp.type = ICMPV6_NA;
        na->icmp.code = 0;
        na->icmp.data = htonl(0xe0000000u); /* router, solicited, override */
        struct nd6_ll_option *tll =
            (struct nd6_ll_option *)((uint8_t *)na + sizeof(*na));
        tll->type = ND6_OPT_TLL;
        tll->length = 1;
        memcpy(tll->mac, g_bras.lan_mac.addr_bytes, sizeof(tll->mac));
        icmp6_checksum(ip6, &na->icmp);

        send_pkt(LAN_PORT, mbuf);
        g_bras.stat_pkts_tx++;
        return 0;
    }

    if (icmp->type == ICMPV6_NA &&
        payload_len >= sizeof(struct nd6_message)) {
        struct nd6_message *na = (struct nd6_message *)icmp;
        if (ipv6_equal(src, g_bras.upstream_ip6)) {
            const struct nd6_ll_option *tll =
                find_ll_option(na, payload_len, ND6_OPT_TLL);
            if (tll)
                learn_upstream_mac6((const struct rte_ether_addr *)tll->mac);
            else
                learn_upstream_mac6(&eth->src_addr);
        }
        rte_pktmbuf_free(mbuf);
        return 0;
    }

    if (icmp->type == ICMPV6_ECHO_REQ && is_our_lan_address(dst)) {
        struct rte_ether_addr peer_mac = eth->src_addr;
        uint8_t peer[16];
        memcpy(peer, src, sizeof(peer));

        rte_ether_addr_copy(&peer_mac, &eth->dst_addr);
        rte_ether_addr_copy(&g_bras.lan_mac, &eth->src_addr);
        memcpy(src, dst, 16);
        memcpy(dst, peer, 16);
        ip6->hop_limits = 64;
        icmp->type = ICMPV6_ECHO_REP;
        icmp6_checksum(ip6, icmp);
        send_pkt(LAN_PORT, mbuf);
        g_bras.stat_pkts_tx++;
        return 0;
    }

    /* NDP/router/MLD control traffic is link-local and is not forwarded. */
    if (icmp->type == ICMPV6_NS || icmp->type == ICMPV6_NA ||
        icmp->type == ICMPV6_RS || icmp->type == ICMPV6_RA ||
        dst[0] == 0xff) {
        rte_pktmbuf_free(mbuf);
        return 0;
    }

    /* Echo and ICMPv6 errors for delegated prefixes are data traffic. */
    return 1;
}

/* Data worker: decapsulate PPP 0x0057 and route toward the IPv6 next-hop. */
int
ipv6_route_outbound(struct rte_mbuf *mbuf, struct bras_session *sess)
{
    uint8_t *base = rte_pktmbuf_mtod(mbuf, uint8_t *);
    uint16_t l2_len, vlan_tci;
    bras_frame_ethertype(base, &l2_len, &vlan_tci);
    (void)vlan_tci;

    uint16_t overhead = l2_len + sizeof(struct pppoe_hdr) +
                        sizeof(struct ppp_hdr);
    if (rte_pktmbuf_pkt_len(mbuf) < overhead + sizeof(struct rte_ipv6_hdr))
        return -1;

    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(base + overhead);
    uint8_t *src = (uint8_t *)&ip6->src_addr;
    if (rte_ipv6_check_version(ip6) != 0 || !g_bras.upstream_mac6_valid ||
        !sess->pd_active || memcmp(src, sess->pd_prefix, 7) != 0 ||
        ip6->hop_limits <= 1)
        return -1;

    ip6->hop_limits--;
    sess->bytes_up += mbuf->data_len;

    struct rte_ether_hdr lan_eth;
    rte_ether_addr_copy(&g_bras.upstream_mac6, &lan_eth.dst_addr);
    rte_ether_addr_copy(&g_bras.lan_mac, &lan_eth.src_addr);
    lan_eth.ether_type = htons(RTE_ETHER_TYPE_IPV6);

    if (!rte_pktmbuf_adj(mbuf, overhead))
        return -1;
    uint8_t *new_base = (uint8_t *)rte_pktmbuf_prepend(mbuf,
                                                       sizeof(lan_eth));
    if (!new_base)
        return -1;
    memcpy(new_base, &lan_eth, sizeof(lan_eth));
    return 0;
}

/* Data worker: map a delegated /56 destination directly back to a session. */
int
ipv6_route_inbound(struct rte_mbuf *mbuf)
{
    uint8_t *base = rte_pktmbuf_mtod(mbuf, uint8_t *);
    if (rte_pktmbuf_pkt_len(mbuf) < sizeof(struct rte_ether_hdr) +
                                     sizeof(struct rte_ipv6_hdr))
        return -1;

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)base;
    if (eth->ether_type != htons(RTE_ETHER_TYPE_IPV6))
        return -1;
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
    uint8_t *dst = (uint8_t *)&ip6->dst_addr;
    uint8_t pool[16] = {0};
    memcpy(pool, g_bras.pd_pool_prefix, sizeof(g_bras.pd_pool_prefix));
    if (rte_ipv6_check_version(ip6) != 0 ||
        !prefix_matches(dst, pool, g_bras.pd_pool_plen))
        return -1;

    uint64_t dst_high = read_be64(dst);
    uint64_t pool_high = read_be64(g_bras.pd_pool_prefix);
    if (dst_high < pool_high)
        return -1;
    uint64_t sid64 = (dst_high - pool_high) >> 8;
    if (sid64 == 0 || sid64 > MAX_SESSIONS)
        return -1;

    struct bras_session *sess = &g_bras.sessions[sid64];
    if (sess->state != SESS_UP || !sess->pd_active ||
        memcmp(dst, sess->pd_prefix, 7) != 0 || ip6->hop_limits <= 1)
        return -1;

    uint16_t ip_len = sizeof(*ip6) + ntohs(ip6->payload_len);
    if (rte_pktmbuf_pkt_len(mbuf) < sizeof(*eth) + ip_len)
        return -1;
    ip6->hop_limits--;
    sess->bytes_down += mbuf->data_len;

    uint16_t extra = sizeof(struct pppoe_hdr) + sizeof(struct ppp_hdr) +
                     (sess->tx_vlan ? sizeof(struct rte_vlan_hdr) : 0);
    uint8_t *new_start = (uint8_t *)rte_pktmbuf_prepend(mbuf, extra);
    if (!new_start)
        return -1;

    struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)new_start;
    rte_ether_addr_copy(&sess->client_mac, &new_eth->dst_addr);
    rte_ether_addr_copy(&g_bras.wan_mac, &new_eth->src_addr);
    new_eth->ether_type = htons(sess->tx_vlan ? ETH_P_8021Q :
                                                ETH_P_PPPoE_SESS);

    uint8_t *pppoe_start = new_start + sizeof(*new_eth);
    if (sess->tx_vlan) {
        struct rte_vlan_hdr *vh = (struct rte_vlan_hdr *)pppoe_start;
        vh->vlan_tci = htons(sess->vlan_tci);
        vh->eth_proto = htons(ETH_P_PPPoE_SESS);
        pppoe_start += sizeof(*vh);
    }

    struct pppoe_hdr *ph = (struct pppoe_hdr *)pppoe_start;
    ph->ver_type = 0x11;
    ph->code = PPPOE_CODE_DATA;
    ph->session_id = htons(sess->session_id);
    ph->length = htons(sizeof(struct ppp_hdr) + ip_len);
    struct ppp_hdr *pph = (struct ppp_hdr *)(ph + 1);
    pph->protocol = htons(PPP_IPV6);
    return 0;
}

/* LCORE_CTRL: send one NS for the configured upstream IPv6 next-hop. */
void
nd6_request_upstream(void)
{
    uint16_t total = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv6_hdr) + ND6_MESSAGE_LEN;
    struct rte_mbuf *m = alloc_pkt(total);
    if (!m)
        return;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    const uint8_t *target = g_bras.upstream_ip6;
    uint8_t multicast_ip[16] = {0xff, 0x02};
    multicast_ip[11] = 0x01;
    multicast_ip[12] = 0xff;
    memcpy(multicast_ip + 13, target + 13, 3);

    eth->dst_addr = (struct rte_ether_addr)
        { .addr_bytes = {0x33, 0x33, 0xff, target[13], target[14], target[15]} };
    rte_ether_addr_copy(&g_bras.lan_mac, &eth->src_addr);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV6);

    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
    memset(ip6, 0, sizeof(*ip6));
    ip6->vtc_flow = rte_cpu_to_be_32(UINT32_C(6) << 28);
    ip6->payload_len = htons(ND6_MESSAGE_LEN);
    ip6->proto = IPPROTO_ICMPV6;
    ip6->hop_limits = 255;
    memcpy(&ip6->src_addr, g_bras.lan_ip6, 16);
    memcpy(&ip6->dst_addr, multicast_ip, 16);

    struct nd6_message *ns = (struct nd6_message *)(ip6 + 1);
    memset(ns, 0, ND6_MESSAGE_LEN);
    ns->icmp.type = ICMPV6_NS;
    memcpy(ns->target, target, 16);
    struct nd6_ll_option *sll =
        (struct nd6_ll_option *)((uint8_t *)ns + sizeof(*ns));
    sll->type = ND6_OPT_SLL;
    sll->length = 1;
    memcpy(sll->mac, g_bras.lan_mac.addr_bytes, sizeof(sll->mac));
    icmp6_checksum(ip6, &ns->icmp);
    send_pkt(LAN_PORT, m);
}

/* LCORE_CTRL: announce the LAN IPv6 address after a port rebuild. */
void
nd6_announce_local(void)
{
    uint16_t total = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv6_hdr) + ND6_MESSAGE_LEN;
    struct rte_mbuf *m = alloc_pkt(total);
    if (!m)
        return;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    eth->dst_addr = (struct rte_ether_addr)
        { .addr_bytes = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01} };
    rte_ether_addr_copy(&g_bras.lan_mac, &eth->src_addr);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV6);

    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(eth + 1);
    memset(ip6, 0, sizeof(*ip6));
    ip6->vtc_flow = rte_cpu_to_be_32(UINT32_C(6) << 28);
    ip6->payload_len = htons(ND6_MESSAGE_LEN);
    ip6->proto = IPPROTO_ICMPV6;
    ip6->hop_limits = 255;
    memcpy(&ip6->src_addr, g_bras.lan_ip6, 16);
    uint8_t all_nodes[16] = {0xff, 0x02};
    all_nodes[15] = 0x01;
    memcpy(&ip6->dst_addr, all_nodes, sizeof(all_nodes));

    struct nd6_message *na = (struct nd6_message *)(ip6 + 1);
    memset(na, 0, ND6_MESSAGE_LEN);
    na->icmp.type = ICMPV6_NA;
    na->icmp.data = htonl(0xa0000000u); /* router + override, unsolicited */
    memcpy(na->target, g_bras.lan_ip6, sizeof(na->target));
    struct nd6_ll_option *tll =
        (struct nd6_ll_option *)((uint8_t *)na + sizeof(*na));
    tll->type = ND6_OPT_TLL;
    tll->length = 1;
    memcpy(tll->mac, g_bras.lan_mac.addr_bytes, sizeof(tll->mac));
    icmp6_checksum(ip6, &na->icmp);

    send_pkt(LAN_PORT, m);

    char address[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, g_bras.lan_ip6, address, sizeof(address)))
        strcpy(address, "<invalid>");
    RTE_LOG(INFO, IPV6, "unsolicited NA sent for %s on LAN port\n", address);
}

static void
ppp_send_na(struct bras_session *sess, const struct rte_ipv6_hdr *request,
            const struct nd6_message *ns)
{
    uint16_t packet_len = sizeof(struct rte_ipv6_hdr) + ND6_MESSAGE_LEN;
    struct rte_mbuf *m;
    uint8_t *payload = ppp_begin_frame(&m, sess, PPP_IPV6, packet_len);
    if (!payload)
        return;

    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)payload;
    memset(ip6, 0, sizeof(*ip6));
    ip6->vtc_flow = rte_cpu_to_be_32(UINT32_C(6) << 28);
    ip6->payload_len = htons(ND6_MESSAGE_LEN);
    ip6->proto = IPPROTO_ICMPV6;
    ip6->hop_limits = 255;
    memcpy(&ip6->src_addr, ns->target, 16);
    memcpy(&ip6->dst_addr, &request->src_addr, 16);

    struct nd6_message *na = (struct nd6_message *)(ip6 + 1);
    memset(na, 0, ND6_MESSAGE_LEN);
    na->icmp.type = ICMPV6_NA;
    na->icmp.data = htonl(0xe0000000u);
    memcpy(na->target, ns->target, 16);
    struct nd6_ll_option *tll =
        (struct nd6_ll_option *)((uint8_t *)na + sizeof(*na));
    tll->type = ND6_OPT_TLL;
    tll->length = 1;
    memcpy(tll->mac, g_bras.wan_mac.addr_bytes, sizeof(tll->mac));
    icmp6_checksum(ip6, &na->icmp);
    send_pkt(WAN_PORT, m);
}

/* LCORE_CTRL: dispatch PPP IPv6 between DHCPv6 and local ICMPv6. */
void
ipv6_ctrl_input(struct bras_session *sess, const uint8_t *packet, uint16_t len)
{
    if (len < sizeof(struct rte_ipv6_hdr))
        return;

    const struct rte_ipv6_hdr *request =
        (const struct rte_ipv6_hdr *)packet;
    uint16_t payload_len = ntohs(request->payload_len);
    if (rte_ipv6_check_version(request) != 0 ||
        payload_len > len - sizeof(*request))
        return;

    if (request->proto == IPPROTO_UDP) {
        dhcpv6_input(sess, packet, len);
        return;
    }
    if (request->proto != IPPROTO_ICMPV6 ||
        sess->ipv6cp_state != IPV6CP_OPENED ||
        payload_len < sizeof(struct icmp6_hdr))
        return;

    const struct icmp6_hdr *icmp =
        (const struct icmp6_hdr *)(packet + sizeof(*request));
    if (icmp->type == ICMPV6_NS &&
        payload_len >= sizeof(struct nd6_message)) {
        const struct nd6_message *ns = (const struct nd6_message *)icmp;
        if (ipv6_equal(ns->target, g_bras.wan_ll) &&
            !ipv6_unspecified((const uint8_t *)&request->src_addr))
            ppp_send_na(sess, request, ns);
        return;
    }

    if (icmp->type == ICMPV6_ECHO_REQ &&
        ipv6_equal(&request->dst_addr, g_bras.wan_ll)) {
        uint16_t packet_len = sizeof(*request) + payload_len;
        struct rte_mbuf *m;
        uint8_t *payload = ppp_begin_frame(&m, sess, PPP_IPV6, packet_len);
        if (!payload)
            return;
        memcpy(payload, packet, packet_len);
        struct rte_ipv6_hdr *reply = (struct rte_ipv6_hdr *)payload;
        uint8_t peer[16];
        memcpy(peer, &reply->src_addr, 16);
        memcpy(&reply->src_addr, g_bras.wan_ll, 16);
        memcpy(&reply->dst_addr, peer, 16);
        reply->hop_limits = 64;
        struct icmp6_hdr *reply_icmp =
            (struct icmp6_hdr *)(payload + sizeof(*reply));
        reply_icmp->type = ICMPV6_ECHO_REP;
        icmp6_checksum(reply, reply_icmp);
        send_pkt(WAN_PORT, m);
    }
}
