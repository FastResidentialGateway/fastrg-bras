/* main.c — DPDK BRAS entry point
 *
 * Usage:
 *   sudo ./dpdk-bras -l 0-4 -n 4 -- --ip-pool 192.168.200.130 \
 *                                    --public-ip 192.168.201.1 \
 *                                    --upstream-ip 192.168.201.11
 *
 * lcore mapping:
 *   0 = main (port init, stats)
 *   1 = rx_dist_lcore    (RX + classify, feeds the distributor)
 *   2 = ctrl_plane_lcore (PPPoE/PPP state machine)
 *   3+ = dist_worker_lcore (NAT + forwarding workers)
 * With fewer lcores or single-queue vdevs (-l 0-2 / veth) the datapath
 * falls back to the legacy single-lcore inline mode.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <rte_spinlock.h>
#include <rte_pcapng.h>
#include <rte_pdump.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_distributor.h>

#include "bras.h"

#define RTE_LOGTYPE_MAIN RTE_LOGTYPE_USER5

/* ── global BRAS context ──────────────────────────────────────────────── */
struct bras_ctx g_bras;
auth_method_t g_default_auth_method = AUTH_PAP;

/* ── port configuration ───────────────────────────────────────────────── */

static int
port_init(uint16_t port, struct rte_mempool *pool,
          uint16_t n_rxq, uint16_t n_txq)
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
    n_rxq = RTE_MIN(n_rxq, dev_info.max_rx_queues);
    n_txq = RTE_MIN(n_txq, dev_info.max_tx_queues);
    if (n_rxq == 0) n_rxq = 1;
    if (n_txq == 0) n_txq = 1;

    struct rte_eth_conf conf = {
        .rxmode = { .mq_mode = RTE_ETH_MQ_RX_NONE },
        .txmode = { .mq_mode = RTE_ETH_MQ_TX_NONE },
    };

    /* Enable RSS when spreading RX over multiple queues (legacy mode only;
     * the distributor datapath uses a single RX queue per port). */
    if (n_rxq > 1) {
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

    /* WAN side carries 802.1Q PPPoE. On an 82599 VF a tagged TX frame is
     * silently dropped by the PF TX switch unless the VLAN was registered
     * via mailbox (rte_eth_dev_vlan_filter), which in turn requires the
     * VLAN_FILTER RX offload to be enabled at configure time. */
    if (port == WAN_PORT &&
        (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_FILTER))
        conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_VLAN_FILTER;

    ret = rte_eth_dev_configure(port, n_rxq, n_txq, &conf);
    if (ret < 0) {
        RTE_LOG(ERR, MAIN, "rte_eth_dev_configure(%u): %d\n", port, ret);
        return ret;
    }

    uint16_t nb_rx = 512, nb_tx = 512;
    rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx, &nb_tx);

    for (uint16_t q = 0; q < n_rxq; q++) {
        ret = rte_eth_rx_queue_setup(port, q, nb_rx,
                                     rte_eth_dev_socket_id(port), NULL, pool);
        if (ret < 0) {
            RTE_LOG(ERR, MAIN, "rx_queue_setup(%u, q%u): %d\n", port, q, ret);
            return ret;
        }
    }
    for (uint16_t q = 0; q < n_txq; q++) {
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

    /* Promiscuous RX is required on the LAN side: the e2e bench injects
     * frames addressed to the fastrg-node WAN MAC, not ours. */
    ret = rte_eth_promiscuous_enable(port);
    if (ret != 0)
        RTE_LOG(WARNING, MAIN,
                "rte_eth_promiscuous_enable(%u) failed: %s — "
                "foreign-MAC RX will not work\n", port, strerror(-ret));

    /* The 82599 VF silently ignores promiscuous without PF trust, so also
     * register the bench's foreign dst MAC as a real unicast filter. */
    if (port == LAN_PORT && g_bras.lan_alias_mac_set) {
        ret = rte_eth_dev_mac_addr_add(port, &g_bras.lan_alias_mac, 0);
        if (ret == 0)
            RTE_LOG(INFO, MAIN,
                    "LAN alias MAC " RTE_ETHER_ADDR_PRT_FMT " added\n",
                    RTE_ETHER_ADDR_BYTES(&g_bras.lan_alias_mac));
        else
            RTE_LOG(WARNING, MAIN,
                    "rte_eth_dev_mac_addr_add(LAN alias) failed: %s\n", strerror(-ret));
    }

    if (port == WAN_PORT)
        rte_eth_macaddr_get(port, &g_bras.wan_mac);
    else
        rte_eth_macaddr_get(port, &g_bras.lan_mac);

    RTE_LOG(INFO, MAIN,
            "Port %u: %u RX / %u TX queue(s), MAC: "RTE_ETHER_ADDR_PRT_FMT"\n",
            port, n_rxq, n_txq,
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
        g_bras.stat_drop_txfull++;
        drop_capture(mbuf, port, RTE_PCAPNG_DIRECTION_OUT, "drop:txfull");
        rte_pktmbuf_free(mbuf);
    }
}

/* ── drop forensics (--drop-pcap) ─────────────────────────────────────── *
 * The drop file is pcapng so each captured packet carries a per-packet
 * comment ("drop:txfull" / "drop:route" / "drop:dist" / "drop:other") and
 * a direction flag — open in Wireshark and filter on `frame.comment`.
 * Full-traffic capture is intentionally NOT done here (it would stall the
 * datapath at line rate); attach dpdk-dumpcap at runtime instead — see the
 * rte_pdump_init() call in main(). */

#define DROP_PCAP_SNAPLEN   256
#define DROP_PCAP_HARD_CAP  (2ULL * 1024 * 1024 * 1024)  /* 2 GiB */

static rte_spinlock_t drop_pcap_lock = RTE_SPINLOCK_INITIALIZER;

/*
 * Parse a byte size with an optional K/M/G suffix (e.g. "512M", "1G").
 * Returns 0 on parse error.
 */
static uint64_t
parse_size(const char *s)
{
    char *end = NULL;
    uint64_t v = strtoull(s, &end, 10);
    if (end == s) return 0;
    switch (*end) {
    case 'g': case 'G': v *= 1024ULL * 1024 * 1024; end++; break;
    case 'm': case 'M': v *= 1024ULL * 1024;        end++; break;
    case 'k': case 'K': v *= 1024ULL;               end++; break;
    case '\0': break;
    default: return 0;
    }
    return (*end == '\0') ? v : 0;
}

/*
 * Open the pcapng drop file.  spec is "<path>" or "<path>,<max-size>";
 * the size is clamped to DROP_PCAP_HARD_CAP (2 GiB).
 */
static int
drop_pcap_open(const char *spec)
{
    char path[256];
    uint64_t max = DROP_PCAP_HARD_CAP;

    const char *comma = strchr(spec, ',');
    if (comma) {
        size_t n = (size_t)(comma - spec);
        if (n >= sizeof(path)) return -1;
        memcpy(path, spec, n);
        path[n] = '\0';
        max = parse_size(comma + 1);
        if (max == 0) {
            fprintf(stderr, "Bad --drop-pcap size: %s\n", comma + 1);
            return -1;
        }
        if (max > DROP_PCAP_HARD_CAP) max = DROP_PCAP_HARD_CAP;
    } else {
        snprintf(path, sizeof(path), "%s", spec);
    }
    g_bras.drop_pcap_max = max;

    /* Dedicated pool for pcapng copies: each copy needs room for the
     * snapshot plus pcapng block overhead. */
    g_bras.drop_pcap_pool = rte_pktmbuf_pool_create(
        "DROP_PCAP_POOL", 1023, 64, 0,
        rte_pcapng_mbuf_size(DROP_PCAP_SNAPLEN) + RTE_PKTMBUF_HEADROOM,
        rte_socket_id());
    if (!g_bras.drop_pcap_pool) {
        fprintf(stderr, "Cannot create drop pcap pool\n");
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    g_bras.drop_pcap = rte_pcapng_fdopen(fd, NULL, NULL, "dpdk-bras",
                                         "dropped packets");
    if (!g_bras.drop_pcap) {
        close(fd);
        return -1;
    }
    rte_pcapng_add_interface(g_bras.drop_pcap, WAN_PORT, "WAN", NULL, NULL);
    rte_pcapng_add_interface(g_bras.drop_pcap, LAN_PORT, "LAN", NULL, NULL);
    RTE_LOG(INFO, MAIN, "drop pcap: %s (cap %lu MiB)\n",
            path, max / (1024 * 1024));
    return 0;
}

/*
 * drop_capture — copy a packet into the drop pcapng before it is freed.
 * Caller still owns (and must free) the mbuf.  Drops are rare, so a
 * spinlock around the copy+write is fine even across workers.
 */
void
drop_capture(struct rte_mbuf *mbuf, uint16_t port,
             enum rte_pcapng_direction dir, const char *reason)
{
    if (!g_bras.drop_pcap)
        return;

    rte_spinlock_lock(&drop_pcap_lock);
    if (g_bras.drop_pcap_bytes >= g_bras.drop_pcap_max) {
        rte_spinlock_unlock(&drop_pcap_lock);
        return;  /* size cap reached — stop writing */
    }

    struct rte_mbuf *cp = rte_pcapng_copy(port, 0, mbuf,
                                          g_bras.drop_pcap_pool,
                                          DROP_PCAP_SNAPLEN, dir, reason);
    if (cp) {
        ssize_t w = rte_pcapng_write_packets(g_bras.drop_pcap, &cp, 1);
        if (w > 0)
            g_bras.drop_pcap_bytes += (uint64_t)w;
        /* write_packets always frees cp */
    }
    rte_spinlock_unlock(&drop_pcap_lock);
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
 * Allocate one client IP from the linear pool [ip_pool_start, ip_pool_end].
 * session 1 → 192.168.200.130, session 2 → .131, …
 * Returns 0 when the session id exceeds the pool.
 */
uint32_t
session_alloc_ip(uint16_t sid)
{
    uint32_t ip = g_bras.ip_pool_start + (uint32_t)(sid - 1);
    if (ip > g_bras.ip_pool_end)
        return 0;
    return ip;
}

/* ── --vlans spec parser ──────────────────────────────────────────────── */

/*
 * Parse a VLAN spec into g_bras.vlan_allowed[].  Grammar: comma-separated
 * tokens, each a single VID or an inclusive range "a-b" (1..4094).
 *   "2-10"  → 2..10
 *   "2,5,3" → 2,3,5
 *   "2-5,8,10-12" → mixed
 * Returns 0 on success, -1 on any malformed token / out-of-range value.
 */
static int
parse_vlan_spec(const char *spec)
{
    char buf[512];
    if (snprintf(buf, sizeof(buf), "%s", spec) >= (int)sizeof(buf))
        return -1;

    for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
        char *dash = strchr(tok, '-');
        long lo, hi;
        char *end = NULL;

        if (dash) {
            *dash = '\0';
            lo = strtol(tok, &end, 10);
            if (end == tok || *end != '\0') return -1;
            char *r = dash + 1;
            hi = strtol(r, &end, 10);
            if (end == r || *end != '\0') return -1;
        } else {
            lo = hi = strtol(tok, &end, 10);
            if (end == tok || *end != '\0') return -1;
        }
        if (lo < 1 || hi > 4094 || lo > hi)
            return -1;
        for (long v = lo; v <= hi; v++)
            g_bras.vlan_allowed[v] = 1;
    }
    g_bras.vlan_filter_enabled = 1;
    return 0;
}

/* ── signal handler ───────────────────────────────────────────────────── */

volatile int g_running = 1;

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
        "  --local-ip <IP>     Our PPP endpoint IP   (default 192.168.200.128)\n"
        "  --ip-pool <IP>      First client pool IP  (default 192.168.200.130)\n"
        "  --ip-pool-end <IP>  Last client pool IP   (default 192.168.200.254)\n"
        "  --public-ip <IP>    SNAT exit IP on LAN   (default 192.168.201.1)\n"
        "  --upstream-ip <IP>  LAN next-hop          (default 192.168.201.11)\n"
        "  --pri-dns <IP>      Primary DNS via IPCP  (default 1.1.1.1)\n"
        "  --sec-dns <IP>      Secondary DNS via IPCP(default 8.8.8.8)\n"
        "  --auth <pap|chap>   PPP authentication    (default pap)\n"
        "  --lan-alias-mac <M> Extra unicast MAC accepted on LAN RX\n"
        "                      (default 74:4D:28:8D:00:2C — the e2e bench\n"
        "                       injects frames addressed to the fastrg-node\n"
        "                       WAN MAC; \"none\" disables)\n"
        "  --vlans <spec>      Accept PPPoE only on these VLANs (comma list\n"
        "                      of single VIDs or a-b ranges, 1..4094), e.g.\n"
        "                      \"2-10\", \"2,5,3\", \"2-5,8,10-12\".  Tagged\n"
        "                      frames outside the set (and untagged PPPoE)\n"
        "                      are dropped (drop:vlan).  Default: accept any.\n"
        "  --drop-pcap <file>[,<max>]\n"
        "                      Copy every dropped packet to a pcapng file,\n"
        "                      tagged with a per-packet comment\n"
        "                      (drop:txfull / drop:route / drop:dist /\n"
        "                       drop:other) and a direction flag — filter on\n"
        "                      frame.comment in Wireshark.  Optional <max>\n"
        "                      caps the file size (K/M/G suffix, e.g. 512M,\n"
        "                      1G); capped at 2G, the default.\n"
        "\n"
        "  Full-traffic capture is on-demand and has zero cost when idle:\n"
        "  attach the standard DPDK tool at runtime, e.g.\n"
        "      dpdk-dumpcap -i 0 -w /tmp/wan.pcapng   (port 0 = WAN)\n"
        "      dpdk-dumpcap -i 1 -w /tmp/lan.pcapng   (port 1 = LAN)\n",
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
    g_bras.ppp_local_ip  = DEFAULT_PPP_LOCAL_IP;
    g_bras.ip_pool_start = DEFAULT_IP_POOL_START;
    g_bras.ip_pool_end   = DEFAULT_IP_POOL_END;
    g_bras.nat_public_ip = DEFAULT_NAT_PUBLIC_IP;
    g_bras.upstream_ip   = DEFAULT_UPSTREAM_IP;
    g_bras.pri_dns       = DEFAULT_PRI_DNS;
    g_bras.sec_dns       = DEFAULT_SEC_DNS;
    /* e2e bench injects WAN-side frames addressed to the fastrg-node WAN
     * MAC; the LAN VF must explicitly filter-in that address (the 82599 VF
     * does not honour promiscuous mode without PF trust). */
    g_bras.lan_alias_mac = (struct rte_ether_addr)
        { .addr_bytes = { 0x74, 0x4D, 0x28, 0x8D, 0x00, 0x2C } };
    g_bras.lan_alias_mac_set = 1;

    int opt;
    static struct option long_opts[] = {
        { "local-ip",      required_argument, NULL, 'l' },
        { "ip-pool",       required_argument, NULL, 'p' },
        { "ip-pool-end",   required_argument, NULL, 'e' },
        { "public-ip",     required_argument, NULL, 'P' },
        { "upstream-ip",   required_argument, NULL, 'u' },
        { "pri-dns",       required_argument, NULL, '1' },
        { "sec-dns",       required_argument, NULL, '2' },
        { "auth",          required_argument, NULL, 'a' },
        { "lan-alias-mac", required_argument, NULL, 'm' },
        { "drop-pcap",     required_argument, NULL, 'D' },
        { "vlans",         required_argument, NULL, 'V' },
        { "help",          no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        if (opt == 'h') {
            usage(argv[0]);
            return 0;
        }
        if (opt == 'a') {
            if (strcmp(optarg, "pap") == 0)
                g_default_auth_method = AUTH_PAP;
            else if (strcmp(optarg, "chap") == 0)
                g_default_auth_method = AUTH_CHAP;
            else {
                fprintf(stderr, "Bad --auth mode: %s (expected pap or chap)\n",
                        optarg);
                return 1;
            }
            continue;
        }
        if (opt == 'V') {
            if (parse_vlan_spec(optarg) != 0) {
                fprintf(stderr, "Bad --vlans spec: %s\n", optarg);
                return 1;
            }
            continue;
        }
        if (opt == 'D') {
            if (drop_pcap_open(optarg) != 0) {
                fprintf(stderr, "Cannot open drop pcap: %s\n", optarg);
                return 1;
            }
            continue;
        }
        if (opt == 'm') {
            if (strcmp(optarg, "none") == 0) {
                g_bras.lan_alias_mac_set = 0;
            } else if (rte_ether_unformat_addr(optarg,
                                               &g_bras.lan_alias_mac) != 0) {
                fprintf(stderr, "Bad MAC argument: %s\n", optarg);
                return 1;
            } else {
                g_bras.lan_alias_mac_set = 1;
            }
            continue;
        }
        struct in_addr addr;
        if (opt != '?' && inet_aton(optarg, &addr) == 0) {
            fprintf(stderr, "Bad IP argument: %s\n", optarg);
            return 1;
        }
        uint32_t ip = ntohl(addr.s_addr);
        switch (opt) {
        case 'l': g_bras.ppp_local_ip  = ip; break;
        case 'p': g_bras.ip_pool_start = ip; break;
        case 'e': g_bras.ip_pool_end   = ip; break;
        case 'P': g_bras.nat_public_ip = ip; break;
        case 'u': g_bras.upstream_ip   = ip; break;
        case '1': g_bras.pri_dns       = ip; break;
        case '2': g_bras.sec_dns       = ip; break;
        default:
            usage(argv[0]);
            return 1;
        }
    }
    if (g_bras.ip_pool_end < g_bras.ip_pool_start) {
        fprintf(stderr, "--ip-pool-end must be >= --ip-pool\n");
        return 1;
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

    /* ── NAT tables (internet-bound flows) ───────────────────────────── */
    nat_init();

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
        data_lcores[n_data++] = (uint16_t)lc;
    }
    if (n_data == 0) {
        fprintf(stderr, "No data-path lcores available "
                "(need at least one worker besides lcore %u)\n", LCORE_CTRL);
        return 1;
    }

    /* ── Datapath mode selection ─────────────────────────────────────── *
     * The X520/82599 VF cannot RSS PPPoE frames, so RX parallelism needs a
     * software distributor: one RX/classify lcore + N workers, each worker
     * with a dedicated TX queue (queue 0 = RX lcore, 1..N = workers,
     * N+1 = ctrl).  Falls back to the legacy inline datapath when there
     * are not enough lcores or TX queues (e.g. af_packet vdevs on veth). */
    struct rte_eth_dev_info di_wan, di_lan;
    if (rte_eth_dev_info_get(WAN_PORT, &di_wan) != 0 ||
        rte_eth_dev_info_get(LAN_PORT, &di_lan) != 0) {
        fprintf(stderr, "Cannot query device info\n");
        return 1;
    }
    uint16_t max_txq = RTE_MIN(di_wan.max_tx_queues, di_lan.max_tx_queues);

    uint16_t n_workers = 0;
    if (n_data >= 2 && max_txq >= 3)
        n_workers = RTE_MIN(n_data - 1, max_txq - 2);
    n_workers = RTE_MIN(n_workers, MAX_DIST_WORKERS);

    uint16_t n_rxq, n_txq;
    if (n_workers >= 1) {
        /* Distributor mode */
        g_bras.n_workers = n_workers;
        g_bras.lcore_queue[data_lcores[0]] = 0;          /* RX lcore   */
        for (uint16_t i = 0; i < n_workers; i++)
            g_bras.lcore_queue[data_lcores[1 + i]] = 1 + i;
        g_bras.lcore_queue[LCORE_CTRL] = n_workers + 1;  /* ctrl lcore */
        g_bras.n_queues = 1;
        n_rxq = 1;
        n_txq = n_workers + 2;

        g_bras.dist = rte_distributor_create("bras_dist", rte_socket_id(),
                                             n_workers, RTE_DIST_ALG_BURST);
        if (!g_bras.dist) {
            RTE_LOG(CRIT, MAIN, "Cannot create distributor\n");
            return 1;
        }
        RTE_LOG(INFO, MAIN,
                "datapath: software distributor — RX lcore %u, %u worker(s)\n",
                data_lcores[0], n_workers);
    } else {
        /* Legacy: data lcores poll their own RSS queue pair inline */
        for (uint16_t i = 0; i < n_data; i++)
            g_bras.lcore_queue[data_lcores[i]] = i;
        g_bras.lcore_queue[LCORE_CTRL] = n_data;
        g_bras.n_queues = n_data;
        n_rxq = n_data;
        n_txq = n_data + 1;
        RTE_LOG(INFO, MAIN,
                "datapath: legacy inline (%u data lcore(s), max_txq=%u)\n",
                n_data, max_txq);
    }

    /* ── Port init ───────────────────────────────────────────────────── */
    if (port_init(WAN_PORT, g_bras.pktmbuf_pool, n_rxq, n_txq) != 0) return 1;
    if (port_init(LAN_PORT, g_bras.pktmbuf_pool, n_rxq, n_txq) != 0) return 1;

    /* Enable runtime full-traffic capture: with this, dpdk-dumpcap can be
     * attached on demand (e.g. `dpdk-dumpcap -i 0 -w /tmp/all.pcapng`)
     * with zero cost when not capturing.  Drop-only forensics is the
     * separate --drop-pcap path above. */
    if (rte_pdump_init() != 0)
        RTE_LOG(WARNING, MAIN,
                "rte_pdump_init failed — runtime dumpcap unavailable\n");

    /* --vlans: pre-register the allowed VLANs on the WAN port (best effort;
     * the PF may NACK on an 82599 VF — handled like the lazy PADI path) and
     * log the resulting set. */
    if (g_bras.vlan_filter_enabled) {
        char list[512];
        int n = 0;
        list[0] = '\0';
        for (int vid = 1; vid <= 4094; vid++) {
            if (!g_bras.vlan_allowed[vid]) continue;
            if (!g_bras.vlan_registered[vid]) {
                int vret = rte_eth_dev_vlan_filter(WAN_PORT, vid, 1);
                g_bras.vlan_registered[vid] = (vret == 0) ? 1 : 2;
            }
            n += snprintf(list + n, sizeof(list) - n, "%s%d",
                          n ? "," : "", vid);
            if (n >= (int)sizeof(list) - 8) break;
        }
        RTE_LOG(INFO, MAIN, "VLAN filter: allowed PPPoE VLANs = {%s}\n", list);
    } else {
        RTE_LOG(INFO, MAIN, "VLAN filter: disabled (accept any VLAN)\n");
    }

    /* ── Signal handler ──────────────────────────────────────────────── */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ── Launch worker lcores ────────────────────────────────────────── */
    RTE_LOG(INFO, MAIN,
            "DPDK BRAS starting — WAN=port%u LAN=port%u data_lcores=%u "
            "local_ip=%u.%u.%u.%u pool=%u.%u.%u.%u-%u.%u.%u.%u "
            "public_ip=%u.%u.%u.%u upstream=%u.%u.%u.%u\n",
            WAN_PORT, LAN_PORT, n_data,
            (g_bras.ppp_local_ip >> 24) & 0xFF,
            (g_bras.ppp_local_ip >> 16) & 0xFF,
            (g_bras.ppp_local_ip >>  8) & 0xFF,
            (g_bras.ppp_local_ip      ) & 0xFF,
            (g_bras.ip_pool_start >> 24) & 0xFF,
            (g_bras.ip_pool_start >> 16) & 0xFF,
            (g_bras.ip_pool_start >>  8) & 0xFF,
            (g_bras.ip_pool_start      ) & 0xFF,
            (g_bras.ip_pool_end >> 24) & 0xFF,
            (g_bras.ip_pool_end >> 16) & 0xFF,
            (g_bras.ip_pool_end >>  8) & 0xFF,
            (g_bras.ip_pool_end      ) & 0xFF,
            (g_bras.nat_public_ip >> 24) & 0xFF,
            (g_bras.nat_public_ip >> 16) & 0xFF,
            (g_bras.nat_public_ip >>  8) & 0xFF,
            (g_bras.nat_public_ip      ) & 0xFF,
            (g_bras.upstream_ip >> 24) & 0xFF,
            (g_bras.upstream_ip >> 16) & 0xFF,
            (g_bras.upstream_ip >>  8) & 0xFF,
            (g_bras.upstream_ip      ) & 0xFF);
    RTE_LOG(INFO, MAIN,
            "DNS push: primary=%u.%u.%u.%u secondary=%u.%u.%u.%u\n",
            (g_bras.pri_dns >> 24) & 0xFF, (g_bras.pri_dns >> 16) & 0xFF,
            (g_bras.pri_dns >>  8) & 0xFF, (g_bras.pri_dns      ) & 0xFF,
            (g_bras.sec_dns >> 24) & 0xFF, (g_bras.sec_dns >> 16) & 0xFF,
            (g_bras.sec_dns >>  8) & 0xFF, (g_bras.sec_dns      ) & 0xFF);

    if (g_bras.dist) {
        rte_eal_remote_launch(rx_dist_lcore, NULL, data_lcores[0]);
        for (uint16_t i = 0; i < n_workers; i++)
            rte_eal_remote_launch(dist_worker_lcore, (void *)(uintptr_t)i,
                                  data_lcores[1 + i]);
    } else {
        for (uint16_t i = 0; i < n_data; i++)
            rte_eal_remote_launch(datapath_lcore, (void *)(uintptr_t)i,
                                  data_lcores[i]);
    }
    rte_eal_remote_launch(ctrl_plane_lcore, NULL, LCORE_CTRL);

    /* ── Main loop: print stats, wait for SIGINT ─────────────────────── */
    while (g_running) {
        sleep(5);
        printf("[BRAS] sessions_up=%-4lu  rx=%-10lu  tx=%-10lu  drop=%-6lu",
               g_bras.stat_sessions_up,
               g_bras.stat_pkts_rx,
               g_bras.stat_pkts_tx,
               g_bras.stat_pkts_dropped);
        for (uint16_t i = 0; i < g_bras.n_workers; i++)
            printf("  w%u=%lu", i, g_bras.stat_worker_pkts[i]);
        printf("\n");
        fflush(stdout);
    }

    /* g_running is now 0 (set by sig_handler). Wait for worker lcores to
     * exit their poll loops so no one touches the ports concurrently. */
    RTE_LOG(INFO, MAIN, "waiting for worker lcores to stop...\n");
    rte_eal_mp_wait_lcore();

    /* Graceful shutdown: send PADT to all active sessions. Safe to TX from
     * the main lcore now that the data/ctrl lcores have stopped. */
    for (int i = 1; i <= MAX_SESSIONS; i++) {
        if (g_bras.sessions[i].state != SESS_FREE)
            pppoe_send_padt(&g_bras.sessions[i]);
    }

    rte_pdump_uninit();
    if (g_bras.drop_pcap)
        rte_pcapng_close(g_bras.drop_pcap);

    rte_eth_dev_stop(WAN_PORT);
    rte_eth_dev_stop(LAN_PORT);
    rte_eth_dev_close(WAN_PORT);
    rte_eth_dev_close(LAN_PORT);
    rte_eal_cleanup();
    return 0;
}
