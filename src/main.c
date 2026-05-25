#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>

#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf_dyn.h>
#include <rte_net.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ip.h>
#include <rte_malloc.h>

#if APP_LOG_LEVEL >= RTE_LOG_DEBUG
#define LOG_DP(fmt, ...) RTE_LOG(DEBUG, USER1, fmt, ##__VA_ARGS__)
#else
#define LOG_DP(fmt, ...) (void)0
#endif

#define MBUF_CACHE_SZ   256
#define NUM_MBUFS       8191
#define WORKER_RING_SZ  1024
#define MAX_BURST_SZ    32
#define RX_RING_SZ      (MAX_BURST_SZ * 32)
#define TX_RING_SZ      (MAX_BURST_SZ * 32)
#define MAX_FLOWS       65536

#define NUM_PORTS       2
#define MAX_NUM_WORKERS 100

struct flow_key
{
    uint32_t dst_ip;
    uint32_t src_ip;
    uint16_t dst_port;
    uint16_t src_port;
    uint8_t  proto;
} rte_packed;

struct flow_entry
{
    struct flow_key key;
    uint8_t         worker_id;
    uint64_t        last_seen;
};

struct flow_stats
{
    struct flow_key   key;
    uint64_t          rx_bytes;
    uint64_t          tx_bytes;
    uint64_t          rx_packets;
    uint64_t          tx_packets;
} __rte_cache_aligned;

struct worker_ctx
{
    int32_t           *owned_flow_idxs;
    rte_atomic32_t    flow_count;
    FILE              *stats_file;
    struct flow_stats *stats;
};

static struct rte_hash   *flow_hash;
static struct flow_entry *flow_table;
static struct worker_ctx *worker_ctxs;
static struct rte_ring   **worker_rings;

static int flow_key_offset = -1;
static unsigned num_workers;

static uint64_t stats_interval_cycles;
static uint64_t stats_interval_sec = 15;
static uint64_t flow_timeout_cycles;
static uint64_t flow_timeout_sec = 60;

static volatile int running = 1;

#define FLOW_KEY(m) \
    (*RTE_MBUF_DYNFIELD(m, flow_key_offset, struct flow_key *))

#define PRINT_IPV4(ip) \
    ((ip) & 0xFF), (((ip) >> 8) & 0xFF), \
    (((ip) >> 16) & 0xFF), (((ip) >> 24) & 0xFF)

#define DPDK_ERR(fmt, ...) \
    rte_exit(EXIT_FAILURE, fmt "\n", ##__VA_ARGS__)

#define DPDK_ERR_ERRNO(fmt, ...) \
    rte_exit(EXIT_FAILURE, fmt ": %s\n", ##__VA_ARGS__, rte_strerror(rte_errno))

static int init_port(uint8_t port, struct rte_mempool *mempool)
{
    struct rte_eth_conf port_conf = {0};
    int ret;

    if (!rte_eth_dev_is_valid_port(port))
    {
        return -ENODEV;
    }

    ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
    if (ret)
    {
        return ret;
    }

    ret = rte_eth_rx_queue_setup(port,
                                 0,
                                 RX_RING_SZ,
                                 rte_eth_dev_socket_id(port),
                                 NULL,
                                 mempool);
    if (ret)
    {
        return ret;
    }

    ret = rte_eth_tx_queue_setup(port,
                                 0,
                                 TX_RING_SZ,
                                 rte_eth_dev_socket_id(port),
                                 NULL);
    if (ret)
    {
        return ret;
    }

    ret = rte_eth_dev_start(port);
    if (ret)
    {
        return ret;
    }

    ret = rte_eth_promiscuous_enable(port);
    if (ret)
    {
        return ret;
    }

    return 0;
}

static uint8_t least_loaded_worker(void)
{
    uint8_t min_loaded_worker = 0;
    int32_t min_load = rte_atomic32_read(&worker_ctxs[0].flow_count);
    int32_t worker_load;

    for (uint8_t worker_id = 1; worker_id < num_workers; worker_id++)
    {
        worker_load = rte_atomic32_read(&worker_ctxs[worker_id].flow_count);
        if (worker_load < min_load)
        {
            min_loaded_worker = worker_id;
            min_load = worker_load;
        }
    }

    return min_loaded_worker;
}

static int parse_flow_key(struct rte_mbuf *mbuf, struct flow_key *key)
{
    struct rte_ipv4_hdr  *ipv4;
    struct rte_tcp_hdr   *tcp;
    struct rte_udp_hdr   *udp;
    struct rte_sctp_hdr  *sctp;

    struct rte_net_hdr_lens hdr_lens = {0};
    uint32_t ptype = rte_net_get_ptype(mbuf, &hdr_lens, RTE_PTYPE_ALL_MASK);

    if (((ptype & RTE_PTYPE_L3_MASK) != RTE_PTYPE_L3_IPV4))
    {
        return -1;
    }

    ipv4 = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, hdr_lens.l2_len);
    key->dst_ip = ipv4->dst_addr;
    key->src_ip = ipv4->src_addr;
    key->proto = ipv4->next_proto_id;

    if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)
    {
        tcp = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *,
                                      hdr_lens.l2_len + hdr_lens.l3_len);
        key->dst_port = tcp->dst_port;
        key->src_port = tcp->src_port;
    }
    else if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP)
    {
        udp = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *,
                                      hdr_lens.l2_len + hdr_lens.l3_len);
        key->dst_port = udp->dst_port;
        key->src_port = udp->src_port;
    }
    else if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_SCTP)
    {
        sctp = rte_pktmbuf_mtod_offset(mbuf, struct rte_sctp_hdr *,
                                       hdr_lens.l2_len + hdr_lens.l3_len);
        key->dst_port = sctp->dst_port;
        key->src_port = sctp->src_port;
    }
    else
    {
        key->dst_port = 0;
        key->src_port = 0;
    }

    return 0;
}

static const char *l4_proto_str(uint8_t proto)
{
    switch(proto)
    {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_SCTP:
            return "SCTP";
        default:
            return "UNKNOWN";
    }
}

static void log_flow_stats(unsigned worker_id)
{
    struct worker_ctx *ctx = &worker_ctxs[worker_id];
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_stamp[32];
    strftime(time_stamp, sizeof(time_stamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    int32_t flow_count = rte_atomic32_read(&ctx->flow_count);
    for (int32_t i = 0; i < flow_count; i++)
    {
        int32_t flow_tbl_idx = ctx->owned_flow_idxs[i];
        struct flow_stats *stats = &ctx->stats[flow_tbl_idx];

        if (rte_hash_lookup(flow_hash, &stats->key) < 0)
        {
            /* Flow no longer active, move last flow here to avoid gap */
            memset(stats, 0, sizeof(struct flow_stats));
            ctx->owned_flow_idxs[i] =
                ctx->owned_flow_idxs[rte_atomic32_read(&ctx->flow_count) - 1];
            rte_atomic32_dec(&ctx->flow_count);
            continue;
        }

        char dst_ip[INET_ADDRSTRLEN];
        char src_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &stats->key.dst_ip, dst_ip, sizeof(dst_ip));
        inet_ntop(AF_INET, &stats->key.src_ip, src_ip, sizeof(src_ip));

        fprintf(ctx->stats_file,
                "%s,%s,%s,%u,%u,%s,%lu,%lu,%lu,%lu\n",
                time_stamp, src_ip, dst_ip,
                rte_be_to_cpu_16(stats->key.src_port),
                rte_be_to_cpu_16(stats->key.dst_port),
                l4_proto_str(stats->key.proto),
                stats->rx_bytes, stats->tx_bytes,
                stats->rx_packets, stats->tx_packets);
    }

    fflush(ctx->stats_file);
}

static void remove_timed_out_flows(void)
{
    uint64_t now = rte_rdtsc();
    struct worker_ctx *ctx;

    for (unsigned worker_id = 0; worker_id < num_workers; worker_id++)
    {
        ctx = &worker_ctxs[worker_id];
        int32_t flow_count = rte_atomic32_read(&ctx->flow_count);
        for (int32_t i = 0; i < flow_count; i++)
        {
            int32_t flow_tbl_idx = ctx->owned_flow_idxs[i];
            if (now - flow_table[flow_tbl_idx].last_seen > flow_timeout_cycles)
            {
                rte_hash_del_key(flow_hash, &flow_table[flow_tbl_idx].key);
            }
        }
    }
}

static int worker_loop(void *arg)
{
    unsigned worker_id = (uintptr_t)arg;
    struct worker_ctx *ctx = &worker_ctxs[worker_id];
    struct rte_mbuf *rx_bufs[MAX_BURST_SZ];
    struct flow_key key;
    int32_t flow_tbl_idx;
    uint16_t nb_rx;
    uint64_t last_stats_flush = rte_rdtsc();

    struct tx_buf
    {
        struct rte_mbuf *pkts[MAX_BURST_SZ];
        int32_t         flow_tbl_index[MAX_BURST_SZ];
        uint16_t        count;
    };
    struct tx_buf tx_bufs[NUM_PORTS] = {0};
    struct tx_buf *tb;

    RTE_LOG(INFO, USER1,
            "Core %u running as worker %u\n", rte_lcore_id(), worker_id);

    fprintf(ctx->stats_file,
            "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,"
            "rx_bytes,tx_bytes,rx_pkts,tx_pkts\n");

    while(running)
    {
        nb_rx = rte_ring_dequeue_burst(worker_rings[worker_id],
                                       (void **)rx_bufs,
                                       MAX_BURST_SZ,
                                       NULL);

        for (uint16_t i = 0; i < nb_rx; i++)
        {
            if (i + 1 < nb_rx )
            {
                rte_prefetch0(rte_pktmbuf_mtod(rx_bufs[i + 1], void *));
            }
            key = FLOW_KEY(rx_bufs[i]);
            flow_tbl_idx = rte_hash_lookup(flow_hash, &key);
            if (flow_tbl_idx < 0)
            {
                LOG_DP("Worker %u flow not found in flow table, dropping: "
                       "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%s\n",
                       worker_id,
                       PRINT_IPV4(key.src_ip), rte_be_to_cpu_16(key.src_port),
                       PRINT_IPV4(key.dst_ip), rte_be_to_cpu_16(key.dst_port),
                       l4_proto_str(key.proto));
                rte_pktmbuf_free(rx_bufs[i]);
                continue;
            }

            struct flow_stats *stats = &ctx->stats[flow_tbl_idx];

            if (memcmp(&stats->key, &key, sizeof(struct flow_key)) != 0)
            {
                /* New flow, clear old stats */
                memset(stats, 0, sizeof(struct flow_stats));
                stats->key = key;
                ctx->owned_flow_idxs[rte_atomic32_read(&ctx->flow_count)] = flow_tbl_idx;
                rte_atomic32_inc(&ctx->flow_count);
            }

            stats->rx_packets++;
            stats->rx_bytes += rx_bufs[i]->pkt_len;

            tb = &tx_bufs[rx_bufs[i]->port ^ 1];
            tb->pkts[tb->count] = rx_bufs[i];
            tb->flow_tbl_index[tb->count] = flow_tbl_idx;
            tb->count++;
        }

        for (uint8_t port = 0; port < NUM_PORTS; port++)
        {
            if (tx_bufs[port].count == 0) continue;
            uint16_t nb_tx = rte_eth_tx_burst(port,
                                                 0, 
                                                 tx_bufs[port].pkts, 
                                                 tx_bufs[port].count);

            for (uint16_t i = 0; i < nb_tx; i++)
            {
                ctx->stats[tx_bufs[port].flow_tbl_index[i]].tx_packets++;
                ctx->stats[tx_bufs[port].flow_tbl_index[i]].tx_bytes +=
                    tx_bufs[port].pkts[i]->pkt_len;
            }
            for (uint16_t j = nb_tx; j < tx_bufs[port].count; j++)
            {
                key = FLOW_KEY(tx_bufs[port].pkts[j]);
                LOG_DP("Worker %u failed to send, dropping: "
                       "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%s\n",
                       worker_id,
                       PRINT_IPV4(key.src_ip), rte_be_to_cpu_16(key.src_port),
                       PRINT_IPV4(key.dst_ip), rte_be_to_cpu_16(key.dst_port),
                       l4_proto_str(key.proto));
                rte_pktmbuf_free(tx_bufs[port].pkts[j]);
            }
            tx_bufs[port].count = 0;
        }

        if (unlikely(rte_rdtsc() - last_stats_flush > stats_interval_cycles))
        {
            log_flow_stats(worker_id);
            last_stats_flush = rte_rdtsc();
        }
    }

    log_flow_stats(worker_id);
    return 0;
}

static int dispatcher_loop(__rte_unused void *arg)
{
    struct rte_mbuf *rx_bufs[MAX_BURST_SZ];
    struct rte_mbuf *worker_bufs[num_workers][MAX_BURST_SZ];
    uint16_t        enqs_per_worker[num_workers];
    struct flow_key key;
    uint8_t         worker_id;
    int32_t         flow_tbl_idx;
    uint16_t        nb_rx = 0;
    uint64_t        last_timeout_check = rte_rdtsc();

    memset(enqs_per_worker, 0, sizeof(enqs_per_worker));
    RTE_LOG(INFO, USER1, "Dispatcher running on core %u\n", rte_lcore_id());

    while(running)
    {
        if (unlikely(rte_rdtsc() - last_timeout_check > flow_timeout_cycles))
        {
            remove_timed_out_flows();
            last_timeout_check = rte_rdtsc();
        }
        for (uint8_t port = 0; port < NUM_PORTS; port++)
        {
            nb_rx = rte_eth_rx_burst(port, 0, rx_bufs, MAX_BURST_SZ);

            for (uint16_t i = 0; i < nb_rx; i++)
            {
                if (i + 1 < nb_rx )
                {
                    rte_prefetch0(rte_pktmbuf_mtod(rx_bufs[i + 1], void *));
                }

                rx_bufs[i]->port = port;

                if (parse_flow_key(rx_bufs[i], &key) < 0)
                {
                    LOG_DP("Dispacher received non IPv4 packet, dropping\n");
                    rte_pktmbuf_free(rx_bufs[i]); 
                    continue;
                }

                FLOW_KEY(rx_bufs[i]) = key;

                flow_tbl_idx = rte_hash_lookup(flow_hash, &key);

                if (flow_tbl_idx >= 0)
                {
                    worker_id = flow_table[flow_tbl_idx].worker_id;
                    flow_table[flow_tbl_idx].last_seen = rte_rdtsc();
                }
                else
                {
                    flow_tbl_idx = rte_hash_add_key(flow_hash, &key);
                    if (flow_tbl_idx < 0)
                    {
                        LOG_DP("Dispatcher failed to insert in flow table: "
                               "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%s\n",
                               PRINT_IPV4(key.src_ip), rte_be_to_cpu_16(key.src_port),
                               PRINT_IPV4(key.dst_ip), rte_be_to_cpu_16(key.dst_port),
                               l4_proto_str(key.proto));
                        rte_pktmbuf_free(rx_bufs[i]); 
                        continue;
                    }
                    worker_id = least_loaded_worker();
                    flow_table[flow_tbl_idx].key = key;
                    flow_table[flow_tbl_idx].worker_id = worker_id;
                    flow_table[flow_tbl_idx].last_seen = rte_rdtsc();
                }
                worker_bufs[worker_id][enqs_per_worker[worker_id]++] = rx_bufs[i];
            }

            for (worker_id = 0; worker_id < num_workers; worker_id++)
            {
                if (enqs_per_worker[worker_id] == 0) continue;

                uint16_t sent = 
                    rte_ring_enqueue_burst(worker_rings[worker_id],
                                           (void **)worker_bufs[worker_id],
                                           enqs_per_worker[worker_id],
                                           NULL);

                for (uint16_t n = sent; n < enqs_per_worker[worker_id]; n++)
                {
                    key = FLOW_KEY(worker_bufs[worker_id][n]);
                    LOG_DP("Failed to enqueue to worker %u ring: "
                           "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%s\n",
                           worker_id,
                           PRINT_IPV4(key.src_ip), rte_be_to_cpu_16(key.src_port),
                           PRINT_IPV4(key.dst_ip), rte_be_to_cpu_16(key.dst_port),
                           l4_proto_str(key.proto));
                    rte_pktmbuf_free(worker_bufs[worker_id][n]);
                }
            }
            memset(enqs_per_worker, 0, sizeof(enqs_per_worker));
        }
    }

    return 0;
}

static void parse_args(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "i:t:")) != -1)
    {
        switch(opt)
        {
            case 'i':
                stats_interval_sec = atoi(optarg);
                if (stats_interval_sec == 0)
                {
                    DPDK_ERR("Invalid stats interval");
                }
                break;
            case 't':
                flow_timeout_sec = atoi(optarg);
                if (flow_timeout_sec == 0)
                {
                    DPDK_ERR("Invalid flow timeout");
                }
                break;
            default:
                fprintf(stderr, "Usage: [EAL options] -- "
                                "-i <stats_interval_sec> -t <flow_timeout_sec>\n");
                DPDK_ERR("Invalid arguments");
        }
    }
}

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[])
{
    const struct rte_mbuf_dynfield flow_key_desc =
    {
        .name = "flow_key",
        .size = sizeof(struct flow_key),
        .align = __alignof__(struct flow_key),
        .flags = 0,
    };

    struct rte_mempool *mempools[NUM_PORTS];
    int ret;
    unsigned lcore_id;
    uint16_t port;
    uint8_t worker_id = 0;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        rte_panic("eal_init failed\n");
    }

    argc -= ret;
    argv += ret;

    rte_log_set_global_level(APP_LOG_LEVEL);
    rte_log_set_level(RTE_LOGTYPE_USER1, APP_LOG_LEVEL);

    parse_args(argc, argv);

    stats_interval_cycles = rte_get_tsc_hz() * stats_interval_sec;
    flow_timeout_cycles = rte_get_tsc_hz() * flow_timeout_sec;

    RTE_LOG(INFO, USER1,
            "Number of ethdevs available: %u\n", rte_eth_dev_count_avail());
    if (rte_eth_dev_count_avail() != NUM_PORTS)
    {
        DPDK_ERR("Need 2 ports, %u available", rte_eth_dev_count_avail());
    }

    num_workers = rte_lcore_count() - 1;
    RTE_LOG(INFO, USER1,
            "Number of lcores: %u. Number of workers %u\n",
            rte_lcore_count(), num_workers);

    flow_key_offset = rte_mbuf_dynfield_register(&flow_key_desc);

    if (flow_key_offset < 0)
    {
        DPDK_ERR_ERRNO("Cannot register dynfield");
    }

    struct rte_hash_parameters hash_params =
    {
        .name               = "flow_hash",
        .entries            = MAX_FLOWS,
        .key_len            = sizeof(struct flow_key),
        .hash_func          = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id          = rte_socket_id(),
        .extra_flag         = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    flow_hash = rte_hash_create(&hash_params);
    if (flow_hash == NULL)
    {
        DPDK_ERR_ERRNO("Failed to create flow hash");
    }

    flow_table = rte_zmalloc("flow_table",
                             sizeof(struct flow_entry) * MAX_FLOWS,
                             RTE_CACHE_LINE_SIZE);
    if (flow_table == NULL)
    {
        DPDK_ERR("Failed to allocate flow table");
    }

    worker_rings = rte_zmalloc("worker_rings",
                               sizeof(struct rte_ring *) * num_workers,
                               RTE_CACHE_LINE_SIZE);
    if (worker_rings == NULL)
    {
        DPDK_ERR("Failed to allocate worker rings");
    }

    worker_ctxs = rte_zmalloc("worker_ctxs",
                              sizeof(struct worker_ctx) * num_workers,
                              RTE_CACHE_LINE_SIZE);
    if (worker_ctxs == NULL)
    {
        DPDK_ERR("Failed to allocate worker contexts");
    }

    RTE_ETH_FOREACH_DEV(port)
    {
        char mempool_name[32];
        snprintf(mempool_name, sizeof(mempool_name), "mempool_%u", port);
        mempools[port] = rte_pktmbuf_pool_create(mempool_name,
                                                 NUM_MBUFS,
                                                 MBUF_CACHE_SZ,
                                                 0,
                                                 RTE_MBUF_DEFAULT_BUF_SIZE,
                                                 rte_eth_dev_socket_id(port));

        if (mempools[port] == NULL)
        {
            DPDK_ERR_ERRNO("Failed to create %s", mempool_name);
        }
        if (init_port(port, mempools[port]))
        {
            DPDK_ERR_ERRNO("Failed to init port %u", port);
        }
    }

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        struct worker_ctx *ctx = &worker_ctxs[worker_id];
        uint8_t socket = rte_lcore_to_socket_id(lcore_id);
        char name[30];
        snprintf(name, sizeof(name), "worker_ring_%u", worker_id);

        worker_rings[worker_id] = rte_ring_create(name,
                                                  WORKER_RING_SZ,
                                                  socket,
                                                  RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (worker_rings[worker_id] == NULL)
        {
            DPDK_ERR_ERRNO("Failed to create ring for worker %u", worker_id);
        }
    
        ctx->owned_flow_idxs = rte_zmalloc_socket("owned_flow_idxs",
                                                  sizeof(int32_t) * MAX_FLOWS,
                                                  RTE_CACHE_LINE_SIZE,
                                                  socket);
        if (ctx->owned_flow_idxs == NULL)
        {
            DPDK_ERR("Cannot allocate flow table position for worker context %u",
                     worker_id);
        }

        ctx->stats = rte_zmalloc_socket("flow_stats",
                                        sizeof(struct flow_stats) * MAX_FLOWS,
                                        RTE_CACHE_LINE_SIZE,
                                        socket);
        if (ctx->stats == NULL)
        {
            DPDK_ERR("Failed to allocate flow stats for worker %u", worker_id);
        }

        rte_atomic32_init(&worker_ctxs[worker_id].flow_count);

        char file_name[32];
        snprintf(file_name, sizeof(file_name), "flow_stats_core_%u.csv", worker_id);
        ctx->stats_file = fopen(file_name, "w");
        if (ctx->stats_file == NULL)
        {
            DPDK_ERR("Failed to open stats file %s", file_name);
        }

        rte_eal_remote_launch(worker_loop, (void *)(uintptr_t)worker_id, lcore_id);
        worker_id++;
    }

    dispatcher_loop(NULL);

    RTE_LOG(INFO, USER1, "All cores exited\n");

    return 0;
}
