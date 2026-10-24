/* arp.c — LAN-side ARP handling + local ICMP echo responder
 *
 * The LAN port owns g_bras.nat_public_ip (e.g. 192.168.201.1/24).
 * Responsibilities:
 *   - Answer ARP requests for nat_public_ip so the upstream peer can
 *     deliver return traffic to us.
 *   - Resolve the upstream next-hop (g_bras.upstream_ip) MAC; learned
 *     address is published to g_bras.upstream_mac for the fast path.
 *   - Answer ICMP echo requests addressed to nat_public_ip (handy for
 *     verifying L3 connectivity with a plain ping from the peer).
 */

#include <string.h>
#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_log.h>
#include <rte_branch_prediction.h>

#include "bras.h"

#define RTE_LOGTYPE_ARP  RTE_LOGTYPE_USER2

/* Publish the learned next-hop MAC for the data-path lcores. */
static void
learn_upstream_mac(const struct rte_ether_addr *mac)
{
    if (g_bras.upstream_mac_valid &&
        rte_is_same_ether_addr(&g_bras.upstream_mac, mac))
        return;

    rte_ether_addr_copy(mac, &g_bras.upstream_mac);
    rte_smp_wmb();
    g_bras.upstream_mac_valid = 1;
    RTE_LOG(INFO, ARP, "upstream %u.%u.%u.%u is at "RTE_ETHER_ADDR_PRT_FMT"\n",
            (g_bras.upstream_ip >> 24) & 0xFF,
            (g_bras.upstream_ip >> 16) & 0xFF,
            (g_bras.upstream_ip >>  8) & 0xFF,
            (g_bras.upstream_ip      ) & 0xFF,
            RTE_ETHER_ADDR_BYTES(&g_bras.upstream_mac));
}

/*
 * arp_input — handle an ARP frame received on LAN_PORT.
 * Consumes the mbuf (either re-used as the reply or freed).
 */
void
arp_input(struct rte_mbuf *mbuf)
{
    if (rte_pktmbuf_data_len(mbuf) <
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr)) {
        rte_pktmbuf_free(mbuf);
        return;
    }

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_arp_hdr   *arp = (struct rte_arp_hdr *)(eth + 1);

    if (arp->arp_hardware != htons(RTE_ARP_HRD_ETHER) ||
        arp->arp_protocol != htons(RTE_ETHER_TYPE_IPV4)) {
        rte_pktmbuf_free(mbuf);
        return;
    }

    uint32_t sip = ntohl(arp->arp_data.arp_sip);
    uint32_t tip = ntohl(arp->arp_data.arp_tip);

    /* Learn the next-hop MAC from any ARP we see from it */
    if (sip == g_bras.upstream_ip)
        learn_upstream_mac(&arp->arp_data.arp_sha);

    if (arp->arp_opcode == htons(RTE_ARP_OP_REQUEST) &&
        tip == g_bras.nat_public_ip) {
        /* Turn the request into a reply in place */
        arp->arp_opcode = htons(RTE_ARP_OP_REPLY);
        rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
        arp->arp_data.arp_tip = htonl(sip);
        rte_ether_addr_copy(&g_bras.lan_mac, &arp->arp_data.arp_sha);
        arp->arp_data.arp_sip = htonl(g_bras.nat_public_ip);

        rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
        rte_ether_addr_copy(&g_bras.lan_mac, &eth->src_addr);

        send_pkt(LAN_PORT, mbuf);
        return;
    }

    rte_pktmbuf_free(mbuf);
}

/*
 * arp_request_upstream — broadcast a who-has for the upstream next-hop.
 * Called from the ctrl-plane lcore until the MAC is resolved.
 */
void
arp_request_upstream(void)
{
    struct rte_mbuf *m = alloc_pkt(sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_arp_hdr));
    if (!m)
        return;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr   *arp = (struct rte_arp_hdr *)(eth + 1);

    memset(&eth->dst_addr, 0xFF, RTE_ETHER_ADDR_LEN);
    rte_ether_addr_copy(&g_bras.lan_mac, &eth->src_addr);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    arp->arp_hardware = htons(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen     = RTE_ETHER_ADDR_LEN;
    arp->arp_plen     = 4;
    arp->arp_opcode   = htons(RTE_ARP_OP_REQUEST);
    rte_ether_addr_copy(&g_bras.lan_mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = htonl(g_bras.nat_public_ip);
    memset(&arp->arp_data.arp_tha, 0, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_tip = htonl(g_bras.upstream_ip);

    send_pkt(LAN_PORT, m);
}

/* LCORE_CTRL: announce the LAN IPv4 address after a port rebuild. */
void
arp_announce_local(void)
{
    struct rte_mbuf *m = alloc_pkt(sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_arp_hdr));
    if (!m)
        return;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);

    memset(&eth->dst_addr, 0xff, RTE_ETHER_ADDR_LEN);
    rte_ether_addr_copy(&g_bras.lan_mac, &eth->src_addr);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    arp->arp_hardware = htons(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(RTE_ARP_OP_REQUEST);
    rte_ether_addr_copy(&g_bras.lan_mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = htonl(g_bras.nat_public_ip);
    memset(&arp->arp_data.arp_tha, 0, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_tip = htonl(g_bras.nat_public_ip);

    send_pkt(LAN_PORT, m);
    RTE_LOG(INFO, ARP, "gratuitous ARP sent for %u.%u.%u.%u on LAN port\n",
            (g_bras.nat_public_ip >> 24) & 0xFF,
            (g_bras.nat_public_ip >> 16) & 0xFF,
            (g_bras.nat_public_ip >>  8) & 0xFF,
            (g_bras.nat_public_ip      ) & 0xFF);
}

/*
 * lan_icmp_echo_input — answer pings addressed to nat_public_ip.
 * Returns 0 when the packet was consumed (replied), -1 otherwise.
 */
int
lan_icmp_echo_input(struct rte_mbuf *mbuf)
{
    uint8_t *base = rte_pktmbuf_mtod(mbuf, uint8_t *);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)base;

    if (eth->ether_type != htons(RTE_ETHER_TYPE_IPV4))
        return -1;

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(base + sizeof(struct rte_ether_hdr));
    if (ntohl(ip->dst_addr) != g_bras.nat_public_ip ||
        ip->next_proto_id != IPPROTO_ICMP)
        return -1;

    uint8_t  ihl = (ip->version_ihl & 0xF) << 2;
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)((uint8_t *)ip + ihl);
    if (icmp->icmp_type != RTE_ICMP_TYPE_ECHO_REQUEST)
        return -1;

    /* Learn the peer MAC opportunistically */
    if (ntohl(ip->src_addr) == g_bras.upstream_ip)
        learn_upstream_mac(&eth->src_addr);

    /* Swap L2/L3 and turn the request into a reply in place */
    rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
    rte_ether_addr_copy(&g_bras.lan_mac, &eth->src_addr);

    uint32_t tmp_ip = ip->src_addr;
    ip->src_addr = ip->dst_addr;
    ip->dst_addr = tmp_ip;
    ip->time_to_live = 64;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    icmp->icmp_type = RTE_ICMP_TYPE_ECHO_REPLY;
    uint16_t icmp_len = ntohs(ip->total_length) - ihl;
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = ~rte_raw_cksum(icmp, icmp_len);

    send_pkt(LAN_PORT, mbuf);
    return 0;
}
