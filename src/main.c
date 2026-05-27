/* main.c — DPDK BRAS entry point
 *
 * Usage:
 *   sudo ./dpdk-bras -l 0-2 -n 4 -- --wan <PCI> --lan <PCI> \
 *                                    --ip-pool 10.64.0.0      \
 *                                    --public-ip 203.0.113.1
 *
 * lcore mapping:
 *   0 = main (port init, stats)
 *   1 = datapath_lcore  (fast RX/TX)
 *   2 = ctrl_plane_lcore (PPPoE/PPP state machine)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_cycles.h>

#include "bras.h"

#define RTE_LOGTYPE_MAIN RTE_LOGTYPE_USER5

/* ── global BRAS context ──────────────────────────────────────────────── */
struct bras_ctx g_bras;

/* ── port configuration ───────────────────────────────────────────────── */

static int
port_init(uint16_t port, struct rte_mempool *pool, uint16_t n_queues)
{
    struct rte_eth_dev_info dev_info;
    int ret;

    if (!rte_eth_dev_is_valid_port(port)) {
        RTE_LOG(ERR, MAIN, "Invalid port %u\n", port);
        return -1;
    }

    ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        RTE_LOG(ERR, MAIN, "rte_eth_dev_info_get(%u): %d\n", port, ret);
        return ret;
    }

    /* Cap to device capability */
    n_queues = RTE_MIN(n_queues, dev_info.max_rx_queues);
    n_queues = RTE_MIN(n_queues, dev_info.max_tx_queues);
    if (n_queues == 0) n_queues = 1;

    struct rte_eth_conf conf = {
        .rxmode = { .mq_mode = RTE_ETH_MQ_RX_NONE },
        .txmode = { .mq_mode = RTE_ETH_MQ_TX_NONE },
    };

    /* Enable RSS when the device supports multiple queues */
    if (n_queues > 1) {
        uint64_t rss_hf = dev_info.flow_type_rss_offloads &
                          (RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP);
        if (rss_hf) {
            conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
            conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
        }
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;

    ret = rte_eth_dev_configure(port, n_queues, n_queues, &conf);
    if (ret < 0) {
        RTE_LOG(ERR, MAIN, "rte_eth_dev_configure(%u): %d\n", port, ret);
        return ret;
    }

    uint16_t nb_rx = 512, nb_tx = 512;
    rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx, &nb_tx);

    for (uint16_t q = 0; q < n_queues; q++) {
        ret = rte_eth_rx_queue_setup(port, q, nb_rx,
                                     rte_eth_dev_socket_id(port), NULL, pool);
        if (ret < 0) {
            RTE_LOG(ERR, MAIN, "rx_queue_setup(%u, q%u): %d\n", port, q, ret);
            return ret;
        }
        ret = rte_eth_tx_queue_setup(port, q, nb_tx,
                                     rte_eth_dev_socket_id(port), NULL);
        if (ret < 0) {
            RTE_LOG(ERR, MAIN, "tx_queue_setup(%u, q%u): %d\n", port, q, ret);
            return ret;
        }
    }

    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        RTE_LOG(ERR, MAIN, "rte_eth_dev_start(%u): %d\n", port, ret);
        return ret;
    }

    rte_eth_promiscuous_enable(port);

    if (port == WAN_PORT)
        rte_eth_macaddr_get(port, &g_bras.wan_mac);
    else
        rte_eth_macaddr_get(port, &g_bras.lan_mac);

    RTE_LOG(INFO, MAIN, "Port %u: %u queue(s), MAC: "RTE_ETHER_ADDR_PRT_FMT"\n",
            port, n_queues,
            RTE_ETHER_ADDR_BYTES(port == WAN_PORT ? &g_bras.wan_mac
                                                  : &g_bras.lan_mac));
    return 0;
}

/* ── utility implementations ─────────────────────────────────────────── */

struct rte_mbuf *
alloc_pkt(uint16_t data_room)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_bras.pktmbuf_pool);
    if (!m) return NULL;
    if (rte_pktmbuf_tailroom(m) < data_room) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    rte_pktmbuf_append(m, data_room);
    return m;
}

void
send_pkt(uint16_t port, struct rte_mbuf *mbuf)
{
    uint16_t queue = g_bras.lcore_queue[rte_lcore_id()];
    uint16_t sent  = rte_eth_tx_burst(port, queue, &mbuf, 1);
    if (sent == 0) {
        g_bras.stat_pkts_dropped++;
        rte_pktmbuf_free(mbuf);
    }
}

static uint16_t
next_session_id = 1;

uint16_t
alloc_session_id(void)
{
    /* Simple linear scan for a free slot */
    for (int tries = 0; tries < MAX_SESSIONS; tries++) {
        uint16_t sid = next_session_id++;
        if (next_session_id > MAX_SESSIONS)
            next_session_id = 1;
        if (g_bras.sessions[sid].state == SESS_FREE) {
            memset(&g_bras.sessions[sid], 0, sizeof(struct bras_session));
            g_bras.sessions[sid].session_id = sid;
            return sid;
        }
    }
    return 0; /* no free sessions */
}

void
free_session(uint16_t sid)
{
    if (sid == 0 || sid > MAX_SESSIONS) return;
    if (g_bras.stat_sessions_up > 0)
        g_bras.stat_sessions_up--;
    nat_flush_session(sid);
    memset(&g_bras.sessions[sid], 0, sizeof(struct bras_session));
}

/*
 * Allocate a /30 block from the IP pool for each session.
 * session 1 → 10.64.0.1 (server) / 10.64.0.2 (client)
 * session 2 → 10.64.0.5 / 10.64.0.6
 * etc.
 */
uint32_t
session_alloc_ip(uint16_t sid)
{
    /* /30 block: each uses 4 addresses, first usable = base + (sid-1)*4 + 1 */
    return g_bras.ip_pool_base + (uint32_t)(sid - 1) * 4 + 1;
}

/* ── signal handler ───────────────────────────────────────────────────── */

static volatile int g_running = 1;

static void
sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
    RTE_LOG(INFO, MAIN, "Shutting down...\n");
}

/* ── main ─────────────────────────────────────────────────────────────── */

static void
usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [EAL options] -- [opts]\n"
        "  EAL must specify exactly 2 ports (WAN=port0, LAN=port1)\n"
        "  --ip-pool <IP>   Base IP for PPP address pool (default 10.64.0.0)\n"
        "  --pri-dns <IP>   Primary DNS pushed via IPCP (default 1.1.1.1)\n"
        "  --sec-dns <IP>   Secondary DNS pushed via IPCP (default 8.8.8.8)\n",
        prog);
}

int
main(int argc, char *argv[])
{
    int ret;

    /* ── EAL init ────────────────────────────────────────────────────── */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "rte_eal_init failed\n");
        return 1;
    }
    argc -= ret;
    argv += ret;

    /* ── Application args ────────────────────────────────────────────── */
    memset(&g_bras, 0, sizeof(g_bras));
    g_bras.ip_pool_base = RTE_IPV4(10, 64, 0, 0);
    g_bras.pri_dns      = DEFAULT_PRI_DNS;
    g_bras.sec_dns      = DEFAULT_SEC_DNS;

    int opt;
    static struct option long_opts[] = {
        { "ip-pool", required_argument, NULL, 'p' },
        { "pri-dns", required_argument, NULL, '1' },
        { "sec-dns", required_argument, NULL, '2' },
        { NULL, 0, NULL, 0 }
    };
    while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': {
            struct in_addr addr;
            if (inet_aton(optarg, &addr) == 0) {
                fprintf(stderr, "Bad --ip-pool: %s\n", optarg);
                return 1;
            }
            g_bras.ip_pool_base = ntohl(addr.s_addr);
            break;
        }
        case '1': {
            struct in_addr addr;
            if (inet_aton(optarg, &addr) == 0) {
                fprintf(stderr, "Bad --pri-dns: %s\n", optarg);
                return 1;
            }
            g_bras.pri_dns = ntohl(addr.s_addr);
            break;
        }
        case '2': {
            struct in_addr addr;
            if (inet_aton(optarg, &addr) == 0) {
                fprintf(stderr, "Bad --sec-dns: %s\n", optarg);
                return 1;
            }
            g_bras.sec_dns = ntohl(addr.s_addr);
            break;
        }
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* ── Check port count ────────────────────────────────────────────── */
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2) {
        fprintf(stderr, "Need at least 2 DPDK ports (WAN + LAN). Got %u.\n",
                nb_ports);
        return 1;
    }

    /* ── Memory pool ─────────────────────────────────────────────────── */
    g_bras.pktmbuf_pool = rte_pktmbuf_pool_create(
        "BRAS_MBUF_POOL",
        MBUF_POOL_SIZE,
        MBUF_CACHE_SIZE,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (!g_bras.pktmbuf_pool) {
        RTE_LOG(CRIT, MAIN, "Cannot create mbuf pool\n");
        return 1;
    }

    /* ── Control ring ────────────────────────────────────────────────── */
    g_bras.ctrl_ring = rte_ring_create("CTRL_RING", CTRL_RING_SIZE,
                                       rte_socket_id(),
                                       RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!g_bras.ctrl_ring) {
        RTE_LOG(CRIT, MAIN, "Cannot create ctrl ring\n");
        return 1;
    }

    /* ── Enumerate data-path lcores, assign per-lcore TX queues ─────── */
    if (!rte_lcore_is_enabled(LCORE_CTRL)) {
        fprintf(stderr, "lcore %u (ctrl) not enabled — use -l 0-2 or wider\n",
                LCORE_CTRL);
        return 1;
    }

    uint16_t n_data = 0;
    uint16_t data_lcores[MAX_RX_QUEUES];
    unsigned lc;
    RTE_LCORE_FOREACH_WORKER(lc) {
        if (lc == LCORE_CTRL) continue;
        if (n_data >= MAX_RX_QUEUES) {
            RTE_LOG(WARNING, MAIN,
                    "lcore %u exceeds MAX_RX_QUEUES=%u — skipped\n",
                    lc, MAX_RX_QUEUES);
            continue;
        }
        g_bras.lcore_queue[lc] = n_data;
        data_lcores[n_data++]  = (uint16_t)lc;
    }
    if (n_data == 0) {
        fprintf(stderr, "No data-path lcores available "
                "(need at least one worker besides lcore %u)\n", LCORE_CTRL);
        return 1;
    }
    /* Ctrl lcore gets its own TX-only queue so it never races with data lcores */
    g_bras.lcore_queue[LCORE_CTRL] = n_data;
    g_bras.n_queues = n_data;
    uint16_t n_total_q = n_data + 1;

    /* ── Port init ───────────────────────────────────────────────────── */
    if (port_init(WAN_PORT, g_bras.pktmbuf_pool, n_total_q) != 0) return 1;
    if (port_init(LAN_PORT, g_bras.pktmbuf_pool, n_total_q) != 0) return 1;

    /* ── NAT tables ──────────────────────────────────────────────────── */
    nat_init();

    /* ── Signal handler ──────────────────────────────────────────────── */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ── Launch worker lcores ────────────────────────────────────────── */
    RTE_LOG(INFO, MAIN,
            "DPDK BRAS starting — WAN=port%u LAN=port%u "
            "data_lcores=%u ip_pool=%u.%u.%u.%u\n",
            WAN_PORT, LAN_PORT, n_data,
            (g_bras.ip_pool_base >> 24) & 0xFF,
            (g_bras.ip_pool_base >> 16) & 0xFF,
            (g_bras.ip_pool_base >>  8) & 0xFF,
            (g_bras.ip_pool_base      ) & 0xFF);
    RTE_LOG(INFO, MAIN,
            "DNS push: primary=%u.%u.%u.%u secondary=%u.%u.%u.%u\n",
            (g_bras.pri_dns >> 24) & 0xFF, (g_bras.pri_dns >> 16) & 0xFF,
            (g_bras.pri_dns >>  8) & 0xFF, (g_bras.pri_dns      ) & 0xFF,
            (g_bras.sec_dns >> 24) & 0xFF, (g_bras.sec_dns >> 16) & 0xFF,
            (g_bras.sec_dns >>  8) & 0xFF, (g_bras.sec_dns      ) & 0xFF);

    for (uint16_t i = 0; i < n_data; i++)
        rte_eal_remote_launch(datapath_lcore, (void *)(uintptr_t)i,
                              data_lcores[i]);
    rte_eal_remote_launch(ctrl_plane_lcore, NULL, LCORE_CTRL);

    /* ── Main loop: print stats, wait for SIGINT ─────────────────────── */
    while (g_running) {
        sleep(5);
        printf("[BRAS] sessions_up=%-4lu  rx=%-10lu  tx=%-10lu  drop=%-6lu\n",
               g_bras.stat_sessions_up,
               g_bras.stat_pkts_rx,
               g_bras.stat_pkts_tx,
               g_bras.stat_pkts_dropped);
    }

    /* Graceful shutdown: send PADT to all active sessions */
    for (int i = 1; i <= MAX_SESSIONS; i++) {
        if (g_bras.sessions[i].state != SESS_FREE)
            pppoe_send_padt(&g_bras.sessions[i]);
    }

    rte_eth_dev_stop(WAN_PORT);
    rte_eth_dev_stop(LAN_PORT);
    rte_eal_cleanup();
    return 0;
}
