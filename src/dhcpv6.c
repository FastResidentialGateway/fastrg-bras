/* dhcpv6.c — DHCPv6 prefix-delegation server over PPP IPv6
 *
 * Packets are handled on LCORE_CTRL after IPv6CP opens.  The server keeps no
 * persistent lease database: each session ID maps deterministically to one
 * /56 in the configured pool.
 */

#include <string.h>
#include <arpa/inet.h>

#include <rte_ip6.h>
#include <rte_udp.h>
#include <rte_log.h>

#include "bras.h"

#define RTE_LOGTYPE_DHCPV6 RTE_LOGTYPE_USER3
#define DHCPV6_HEADER_LEN   4
#define DHCPV6_DUID_LL_LEN  10
#define DHCPV6_CLIENTID_MAX 130

struct dhcpv6_request {
    uint8_t msg_type;
    uint8_t xid[3];
    const uint8_t *client_id;
    uint16_t client_id_len;
    const uint8_t *server_id;
    uint16_t server_id_len;
    uint32_t iaid;
    uint8_t has_client_id;
    uint8_t has_server_id;
    uint8_t has_ia_pd;
};

static uint16_t
read_be16(const uint8_t *p)
{
    uint16_t value;

    memcpy(&value, p, sizeof(value));
    return ntohs(value);
}

static uint32_t
read_be32(const uint8_t *p)
{
    uint32_t value;

    memcpy(&value, p, sizeof(value));
    return ntohl(value);
}

static void
write_be16(uint8_t *p, uint16_t value)
{
    value = htons(value);
    memcpy(p, &value, sizeof(value));
}

static void
write_be32(uint8_t *p, uint32_t value)
{
    value = htonl(value);
    memcpy(p, &value, sizeof(value));
}

static int
options_well_formed(const uint8_t *opts, uint16_t len)
{
    while (len > 0) {
        if (len < 4)
            return 0;
        uint16_t opt_len = read_be16(opts + 2);
        if (opt_len > len - 4)
            return 0;
        opts += 4 + opt_len;
        len -= 4 + opt_len;
    }
    return 1;
}

static int
parse_request(const uint8_t *dhcp, uint16_t len,
              struct dhcpv6_request *request)
{
    if (len < DHCPV6_HEADER_LEN)
        return -1;

    memset(request, 0, sizeof(*request));
    request->msg_type = dhcp[0];
    memcpy(request->xid, &dhcp[1], sizeof(request->xid));

    const uint8_t *opt = dhcp + DHCPV6_HEADER_LEN;
    uint16_t remaining = len - DHCPV6_HEADER_LEN;
    while (remaining > 0) {
        if (remaining < 4)
            return -1;

        uint16_t code = read_be16(opt);
        uint16_t opt_len = read_be16(opt + 2);
        if (opt_len > remaining - 4)
            return -1;
        const uint8_t *data = opt + 4;

        switch (code) {
        case DHCPV6_OPT_CLIENTID:
            if (request->has_client_id || opt_len > DHCPV6_CLIENTID_MAX)
                return -1;
            request->client_id = data;
            request->client_id_len = opt_len;
            request->has_client_id = 1;
            break;
        case DHCPV6_OPT_SERVERID:
            if (request->has_server_id)
                return -1;
            request->server_id = data;
            request->server_id_len = opt_len;
            request->has_server_id = 1;
            break;
        case DHCPV6_OPT_IA_PD:
            if (request->has_ia_pd || opt_len < 12 ||
                !options_well_formed(data + 12, opt_len - 12))
                return -1;
            request->iaid = read_be32(data);
            request->has_ia_pd = 1;
            break;
        default:
            break;
        }

        opt += 4 + opt_len;
        remaining -= 4 + opt_len;
    }
    return 0;
}

static void
build_server_duid(uint8_t duid[DHCPV6_DUID_LL_LEN])
{
    write_be16(&duid[0], 3); /* DUID-LL */
    write_be16(&duid[2], 1); /* Ethernet */
    memcpy(&duid[4], g_bras.wan_mac.addr_bytes,
           RTE_ETHER_ADDR_LEN);
}

static int
server_id_matches(const struct dhcpv6_request *request,
                  const uint8_t duid[DHCPV6_DUID_LL_LEN])
{
    return request->has_server_id &&
           request->server_id_len == DHCPV6_DUID_LL_LEN &&
           memcmp(request->server_id, duid, DHCPV6_DUID_LL_LEN) == 0;
}

static int
append_option(uint8_t **cursor, const uint8_t *end, uint16_t code,
              const void *data, uint16_t len)
{
    if ((size_t)(end - *cursor) < (size_t)len + 4)
        return -1;

    write_be16(*cursor, code);
    write_be16(*cursor + 2, len);
    if (len > 0)
        memcpy(*cursor + 4, data, len);
    *cursor += 4 + len;
    return 0;
}

static int
delegated_prefix(struct bras_session *sess, uint8_t prefix[16])
{
    if (g_bras.pd_pool_plen == 0 || g_bras.pd_pool_plen > 55)
        return -1;

    uint64_t capacity = UINT64_C(1) <<
        (DHCPV6_PD_PLEN - g_bras.pd_pool_plen);
    if ((uint64_t)sess->session_id >= capacity)
        return -1;

    uint64_t high = 0;
    for (unsigned int i = 0; i < sizeof(g_bras.pd_pool_prefix); i++)
        high = (high << 8) | g_bras.pd_pool_prefix[i];
    high += (uint64_t)sess->session_id << 8;

    memset(prefix, 0, 16);
    for (int i = 7; i >= 0; i--) {
        prefix[i] = (uint8_t)high;
        high >>= 8;
    }
    return 0;
}

static int
append_ia_pd(uint8_t **cursor, const uint8_t *end, uint32_t iaid,
             const uint8_t prefix[16], int prefix_available)
{
    uint8_t ia_pd[64];
    uint8_t *ia_cursor = ia_pd;
    const uint8_t *ia_end = ia_pd + sizeof(ia_pd);

    write_be32(ia_cursor, iaid);
    write_be32(ia_cursor + 4, prefix_available ? DHCPV6_T1 : 0);
    write_be32(ia_cursor + 8, prefix_available ? DHCPV6_T2 : 0);
    ia_cursor += 12;

    if (prefix_available) {
        uint8_t ia_prefix[25];
        write_be32(&ia_prefix[0], DHCPV6_PREFERRED_LIFETIME);
        write_be32(&ia_prefix[4], DHCPV6_VALID_LIFETIME);
        ia_prefix[8] = DHCPV6_PD_PLEN;
        memcpy(&ia_prefix[9], prefix, 16);
        if (append_option(&ia_cursor, ia_end, DHCPV6_OPT_IAPREFIX,
                          ia_prefix, sizeof(ia_prefix)) != 0)
            return -1;
    } else {
        uint8_t status[2];
        write_be16(status, DHCPV6_STATUS_NO_PREFIX);
        if (append_option(&ia_cursor, ia_end, DHCPV6_OPT_STATUS,
                          status, sizeof(status)) != 0)
            return -1;
    }

    return append_option(cursor, end, DHCPV6_OPT_IA_PD, ia_pd,
                         (uint16_t)(ia_cursor - ia_pd));
}

static int
send_response(struct bras_session *sess, const struct rte_ipv6_hdr *request_ip,
              const struct dhcpv6_request *request, uint8_t response_type,
              const uint8_t duid[DHCPV6_DUID_LL_LEN],
              const uint8_t prefix[16], int prefix_available,
              int release)
{
    uint8_t dhcp[256];
    uint8_t *cursor = dhcp;
    const uint8_t *end = dhcp + sizeof(dhcp);

    *cursor++ = response_type;
    memcpy(cursor, request->xid, sizeof(request->xid));
    cursor += sizeof(request->xid);

    if (append_option(&cursor, end, DHCPV6_OPT_SERVERID,
                      duid, DHCPV6_DUID_LL_LEN) != 0 ||
        append_option(&cursor, end, DHCPV6_OPT_CLIENTID,
                      request->client_id, request->client_id_len) != 0)
        return -1;

    if (release) {
        uint8_t status[2];
        write_be16(status, DHCPV6_STATUS_SUCCESS);
        if (append_option(&cursor, end, DHCPV6_OPT_STATUS,
                          status, sizeof(status)) != 0)
            return -1;
    } else {
        if (append_ia_pd(&cursor, end, request->iaid, prefix,
                         prefix_available) != 0)
            return -1;
        uint8_t dns_servers[32];
        memcpy(dns_servers, g_bras.dns6_pri, 16);
        memcpy(dns_servers + 16, g_bras.dns6_sec, 16);
        if (append_option(&cursor, end, DHCPV6_OPT_DNS_SERVERS,
                          dns_servers, sizeof(dns_servers)) != 0)
            return -1;
    }

    uint16_t dhcp_len = (uint16_t)(cursor - dhcp);
    uint16_t udp_len = sizeof(struct rte_udp_hdr) + dhcp_len;
    uint16_t packet_len = sizeof(struct rte_ipv6_hdr) + udp_len;
    struct rte_mbuf *m;
    uint8_t *payload = ppp_begin_frame(&m, sess, PPP_IPV6, packet_len);
    if (!payload)
        return -1;

    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)payload;
    memset(ip6, 0, sizeof(*ip6));
    ip6->vtc_flow = rte_cpu_to_be_32(UINT32_C(6) << 28);
    ip6->payload_len = htons(udp_len);
    ip6->proto = IPPROTO_UDP;
    ip6->hop_limits = 64;
    uint8_t *src = (uint8_t *)&ip6->src_addr;
    src[0] = 0xfe;
    src[1] = 0x80;
    memcpy(src + 8, sess->local_ifid, sizeof(sess->local_ifid));
    memcpy(&ip6->dst_addr, &request_ip->src_addr,
           sizeof(ip6->dst_addr));

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(payload + sizeof(*ip6));
    udp->src_port = htons(DHCPV6_SERVER_PORT);
    udp->dst_port = htons(DHCPV6_CLIENT_PORT);
    udp->dgram_len = htons(udp_len);
    udp->dgram_cksum = 0;
    memcpy((uint8_t *)udp + sizeof(*udp), dhcp, dhcp_len);
    udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip6, udp);

    send_pkt(WAN_PORT, m);
    return 0;
}

void
dhcpv6_input(struct bras_session *sess, const uint8_t *packet, uint16_t len)
{
    if (sess->ipv6cp_state != IPV6CP_OPENED) {
        RTE_LOG(DEBUG, DHCPV6,
                "[%u] DHCPv6 ignored before IPv6CP OPENED\n",
                sess->session_id);
        return;
    }

    if (len < sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_udp_hdr) +
              DHCPV6_HEADER_LEN) {
        RTE_LOG(DEBUG, DHCPV6, "[%u] short DHCPv6 packet ignored\n",
                sess->session_id);
        return;
    }

    const struct rte_ipv6_hdr *ip6 = (const struct rte_ipv6_hdr *)packet;
    uint16_t ip_payload_len = ntohs(ip6->payload_len);
    if (rte_ipv6_check_version(ip6) != 0 || ip6->proto != IPPROTO_UDP ||
        ip_payload_len != len - sizeof(*ip6)) {
        RTE_LOG(DEBUG, DHCPV6, "[%u] invalid DHCPv6 IPv6 header ignored\n",
                sess->session_id);
        return;
    }

    const struct rte_udp_hdr *udp =
        (const struct rte_udp_hdr *)(packet + sizeof(*ip6));
    uint16_t udp_len = ntohs(udp->dgram_len);
    if (ntohs(udp->dst_port) != DHCPV6_SERVER_PORT ||
        udp_len != ip_payload_len ||
        udp_len < sizeof(*udp) + DHCPV6_HEADER_LEN) {
        RTE_LOG(DEBUG, DHCPV6, "[%u] invalid DHCPv6 UDP header ignored\n",
                sess->session_id);
        return;
    }

    /* RX checksum verification is intentionally omitted for the lab peer.
     * Every server response carries the mandatory IPv6 UDP checksum. */
    const uint8_t *dhcp = (const uint8_t *)udp + sizeof(*udp);
    uint16_t dhcp_len = udp_len - sizeof(*udp);
    struct dhcpv6_request request;
    if (parse_request(dhcp, dhcp_len, &request) != 0 ||
        !request.has_client_id) {
        RTE_LOG(DEBUG, DHCPV6, "[%u] malformed DHCPv6 request ignored\n",
                sess->session_id);
        return;
    }

    if (request.msg_type != DHCPV6_SOLICIT &&
        request.msg_type != DHCPV6_REQUEST &&
        request.msg_type != DHCPV6_RENEW &&
        request.msg_type != DHCPV6_REBIND &&
        request.msg_type != DHCPV6_RELEASE) {
        RTE_LOG(DEBUG, DHCPV6, "[%u] unsupported DHCPv6 message %u ignored\n",
                sess->session_id, request.msg_type);
        return;
    }

    uint8_t duid[DHCPV6_DUID_LL_LEN];
    build_server_duid(duid);
    if ((request.msg_type == DHCPV6_SOLICIT && request.has_server_id) ||
        ((request.msg_type == DHCPV6_REQUEST ||
          request.msg_type == DHCPV6_RENEW ||
          request.msg_type == DHCPV6_RELEASE) &&
         !server_id_matches(&request, duid))) {
        RTE_LOG(DEBUG, DHCPV6, "[%u] DHCPv6 Server ID mismatch ignored\n",
                sess->session_id);
        return;
    }

    if (request.msg_type == DHCPV6_RELEASE) {
        send_response(sess, ip6, &request, DHCPV6_REPLY, duid,
                      NULL, 0, 1);
        sess->pd_active = 0;
        memset(sess->pd_prefix, 0, sizeof(sess->pd_prefix));
        RTE_LOG(INFO, DHCPV6, "[%u] DHCPv6 IA_PD released\n",
                sess->session_id);
        return;
    }

    if (!request.has_ia_pd) {
        RTE_LOG(DEBUG, DHCPV6, "[%u] DHCPv6 request without IA_PD ignored\n",
                sess->session_id);
        return;
    }

    uint8_t prefix[16] = {0};
    int prefix_available = delegated_prefix(sess, prefix) == 0;
    uint8_t response_type = request.msg_type == DHCPV6_SOLICIT ?
        DHCPV6_ADVERTISE : DHCPV6_REPLY;
    if (send_response(sess, ip6, &request, response_type, duid,
                      prefix, prefix_available, 0) != 0)
        return;

    if (!prefix_available) {
        RTE_LOG(INFO, DHCPV6,
                "[%u] DHCPv6 IA_PD unavailable: prefix pool exhausted\n",
                sess->session_id);
        return;
    }

    if (request.msg_type != DHCPV6_SOLICIT) {
        memcpy(sess->pd_prefix, prefix, sizeof(sess->pd_prefix));
        sess->pd_iaid = request.iaid;
        sess->pd_active = 1;

        char prefix_text[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, prefix, prefix_text, sizeof(prefix_text)))
            strcpy(prefix_text, "<invalid>");
        RTE_LOG(INFO, DHCPV6, "[%u] DHCPv6 IA_PD delegated %s/56\n",
                sess->session_id, prefix_text);
    }
}
