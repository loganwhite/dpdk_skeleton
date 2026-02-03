/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright(c) 2024 Customized for DPDK 19.11 & MLX5
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_ip.h>

#define MAX_PKT_BURST 64
#define MEMPOOL_CACHE_SIZE 4096
#define NB_DESC 2048
#define NB_MBUF 8192
#define NUM_FLOWS 254

#ifdef XSTATS_ENABLE
/* * 统计结构体
 * 使用 __rte_cache_aligned 强制对齐到 Cache Line (通常 64字节)
 * 这样 Core A 写自己的计数器时，不会因为 Cache Coherency 协议影响 Core B
 */
struct lcore_stats {
    uint64_t rx_pkts;
    uint64_t rx_bytes;
    uint64_t tx_pkts;
	uint64_t tx_bytes;
} __rte_cache_aligned;
static struct lcore_stats lcore_statistics[RTE_MAX_LCORE];
#endif


static unsigned int lcore_queue_map[RTE_MAX_LCORE];

/* 强制停止标志 */
static volatile bool force_quit;

/* 手动定义 IPv4 宏，防止 implicit declaration 错误 */
#define IPv4(a,b,c,d) ((uint32_t)(((a) & 0xff) << 24) | \
					   (((b) & 0xff) << 16) | \
					   (((c) & 0xff) << 8)  | \
					   ((d) & 0xff))



static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}


static struct rte_flow *
generate_ipv4_flow(uint16_t port_id, uint16_t rx_q, uint32_t dst_ip, uint32_t mask)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PKT_BURST];
	struct rte_flow_action action[MAX_PKT_BURST];
	struct rte_flow *flow = NULL;
	struct rte_flow_error error;
	
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_action_queue queue;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	memset(pattern, 0, sizeof(pattern));

	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	memset(&ipv4_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ipv4_mask, 0, sizeof(struct rte_flow_item_ipv4));
	
	ipv4_spec.hdr.dst_addr = htonl(dst_ip);
	ipv4_mask.hdr.dst_addr = htonl(mask);

	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ipv4_spec;
	pattern[1].mask = &ipv4_mask;

	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	memset(action, 0, sizeof(action));
	
	queue.index = rx_q;
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;

	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	int res = rte_flow_validate(port_id, &attr, pattern, action, &error);
	if (!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, &error);

	if (!flow) {
		printf("Flow creation failed for Queue %d: %s\n", rx_q, error.message);
	} else {
		printf("Created flow: Dst IP 48.0.0.%d -> Queue %d\n", dst_ip & 0xFF, rx_q);
	}

	return flow;
}

#ifdef XSTATS_ENABLE

/* 打印统计信息的循环 (运行在 Master Core) */
static void
print_stats_loop(void)
{
    /* 定义数组保存上一秒的数据，用于计算差值（速率） */
    uint64_t prev_rx_pkts[RTE_MAX_LCORE] = {0};
    uint64_t prev_tx_pkts[RTE_MAX_LCORE] = {0};
    uint64_t prev_tx_bytes[RTE_MAX_LCORE] = {0};

    const char clr[] = { 27, '[', '2', 'J', '\0' };
    const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
    unsigned int lcore_id;

    printf("Stats loop started on Master Core.\n");

    while (!force_quit) {
        /* 睡眠 1 秒 */
        sleep(1);

        /* 清屏 */
        printf("%s%s", clr, topLeft);
        
        printf("\nData Plane Statistics (1 sec refresh)\n");
        printf("==================================================================================\n");
        /* 按要求调整列名 */
        printf(" %-10s | %-8s | %-12s | %-12s | %-15s\n", 
               "Lcore ID", "Queue ID", "RX PPS", "TX PPS", "TX Throughput");
        printf("----------------------------------------------------------------------------------\n");

        uint64_t total_rx_pps = 0;
        uint64_t total_tx_pps = 0;
        uint64_t total_tx_bps = 0;

        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            /* 1. 读取当前时刻的总计数值 */
            uint64_t cur_rx_pkts = lcore_statistics[lcore_id].rx_pkts;
            uint64_t cur_tx_pkts = lcore_statistics[lcore_id].tx_pkts;
            uint64_t cur_tx_bytes = lcore_statistics[lcore_id].tx_bytes;
            
            unsigned int q_id = lcore_queue_map[lcore_id];

            /* 2. 计算这一秒内的增量 (即速率) */
            uint64_t diff_rx_pkts = cur_rx_pkts - prev_rx_pkts[lcore_id];
            uint64_t diff_tx_pkts = cur_tx_pkts - prev_tx_pkts[lcore_id];
            uint64_t diff_tx_bytes = cur_tx_bytes - prev_tx_bytes[lcore_id];
            uint64_t diff_tx_bits = diff_tx_bytes * 8; /* 字节转比特 */

            /* 3. 更新旧值，供下一秒使用 */
            prev_rx_pkts[lcore_id] = cur_rx_pkts;
            prev_tx_pkts[lcore_id] = cur_tx_pkts;
            prev_tx_bytes[lcore_id] = cur_tx_bytes;

            /* 4. 累加全局总数 */
            total_rx_pps += diff_rx_pkts;
            total_tx_pps += diff_tx_pkts;
            total_tx_bps += diff_tx_bits;

            /* 5. 格式化输出 (Mpps, Mbps) */
            double rx_mpps = (double)diff_rx_pkts / 1000000.0;
            double tx_mpps = (double)diff_tx_pkts / 1000000.0;
            double tx_mbps = (double)diff_tx_bits / 1000000.0;

            if (lcore_queue_map[lcore_id] < RTE_MAX_LCORE) {
                printf(" %-10u | %-8u | %10.4f M | %10.4f M | %10.4f Mbps\n", 
                    lcore_id, q_id, rx_mpps, tx_mpps, tx_mbps);
            }
        }
        
        printf("==================================================================================\n");
        printf(" TOTAL      | ALL      | %10.4f M | %10.4f M | %10.4f Mbps\n", 
               (double)total_rx_pps / 1000000.0, 
               (double)total_tx_pps / 1000000.0,
               (double)total_tx_bps / 1000000.0);
        printf("==================================================================================\n");
    }
}
#endif /* XSTATS_ENABLE */

static int
l2fwd_main_loop(void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned lcore_id;
	unsigned j, portid, nb_rx;
	
	(void)dummy;

	lcore_id = rte_lcore_id();
	unsigned int q_id = lcore_queue_map[lcore_id];
	portid = 0; 

	if (q_id >= RTE_MAX_LCORE) {
		printf("Lcore %u has no queue assigned! Bye.\n", lcore_id);
		return -1;
	}

	printf("Lcore %u: Entering main loop on Port %u Queue %u\n", lcore_id, portid, q_id);

	while (!force_quit) {
		nb_rx = rte_eth_rx_burst(portid, q_id, pkts_burst, MAX_PKT_BURST);

		if (nb_rx == 0)
			continue;

#ifdef XSTATS_ENABLE
		lcore_statistics[lcore_id].rx_pkts += nb_rx;
		uint64_t bytes_batch = 0;
#endif

		/* --- 优化点 1: 预取逻辑 --- */
		/* 提前把前两个包的 Header 拉入 Cache，防止流水线停顿 */
		if (nb_rx > 1) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[0], void *));
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[1], void *));
		}

		for (j = 0; j < nb_rx; j++) {
			m = pkts_burst[j];

			/* --- 优化点 1 (继续): 循环内预取 --- */
			/* 处理第 j 个包时，预取第 j+2 个包 */
			/* 为什么是 +2？因为 +1 已经在上一轮循环或开头预取过了，保持流水线充盈 */
			if (j + 2 < nb_rx) {
				rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + 2], void *));
			}

#ifdef XSTATS_ENABLE
			bytes_batch += m->pkt_len;
#endif
			
			struct rte_ether_hdr *eth;
			eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			
			/* --- 优化点 2: 简化的 MAC 交换 --- */
			/* 标准的 3次 copy 比较慢。为了压测 100G，
			 * 我们可以简单地交换源/目的的最后 2 个字节，或者使用 64位赋值优化。
			 * 下面保留你的逻辑，但在高压下这可能是瓶颈。
			 */
			struct rte_ether_addr tmp;
			rte_ether_addr_copy(&eth->d_addr, &tmp);
			rte_ether_addr_copy(&eth->s_addr, &eth->d_addr);
			rte_ether_addr_copy(&tmp, &eth->s_addr);
		}

#ifdef XSTATS_ENABLE
		lcore_statistics[lcore_id].rx_bytes += bytes_batch;
#endif

		/* 批量发送 */
		uint16_t nb_tx = rte_eth_tx_burst(portid, q_id, pkts_burst, nb_rx);

		if (unlikely(nb_tx < nb_rx)) {
			for (j = nb_tx; j < nb_rx; j++)
				rte_pktmbuf_free(pkts_burst[j]);
		}

#ifdef XSTATS_ENABLE
		lcore_statistics[lcore_id].tx_pkts += nb_tx;
		/* 补全 TX Bytes 统计：简单起见，假设发出去的字节数 = 收到的平均值 * nb_tx 
		 * 或者你可以再遍历一次算精确值，但为了性能，通常只统计包数，或者假设 TX=RX Bytes
		 */
		if (nb_rx > 0) {
			lcore_statistics[lcore_id].tx_bytes += (bytes_batch / nb_rx) * nb_tx;
		}
#endif
	}
	return 0;
}

int
main(int argc, char **argv)
{
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports;
	uint16_t portid = 0;
	struct rte_eth_conf port_conf = {0};
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_dev_info dev_info;
	uint16_t nb_rxd = NB_DESC;
	uint16_t nb_txd = NB_DESC;
	int ret;
	unsigned int nb_lcores;

	force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* 初始化映射表为无效值 */
    for (int i = 0; i < RTE_MAX_LCORE; i++) {
		lcore_queue_map[i] = RTE_MAX_LCORE;

#ifdef XSTATS_ENABLE
		lcore_statistics[i].rx_pkts = 0;
        lcore_statistics[i].rx_bytes = 0;
		lcore_statistics[i].tx_pkts = 0;
        lcore_statistics[i].tx_bytes = 0;
#endif
	}

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	nb_lcores = rte_lcore_count();
	/* 我们将 Master Core 用于显示统计，不用于转发，所以工作核数量 -1 */
    unsigned int nb_forwarding_cores = nb_lcores - 1;
    
    printf("Total lcores: %u, Forwarding cores: %u, Stats core: 1\n", nb_lcores, nb_forwarding_cores);

    if (nb_forwarding_cores == 0) {
        rte_exit(EXIT_FAILURE, "Need at least 2 cores (1 for stats, 1+ for forwarding)\n");
    }

    unsigned int rx_idx = 0;
	unsigned int master_lcore = rte_get_master_lcore();
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_id == master_lcore)
            continue; /* Master 不处理队列 */
        lcore_queue_map[lcore_id] = rx_idx;
        printf("Mapping: Lcore %u -> Queue %u\n", lcore_id, rx_idx);
        rx_idx++;
    }

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NB_MBUF * nb_lcores,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	rte_eth_dev_info_get(portid, &dev_info);


	port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP;

	port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_SCATTER;
    port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_TCP_LRO;
	port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_VLAN_STRIP;

	ret = rte_eth_dev_configure(portid, nb_forwarding_cores, nb_forwarding_cores, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret, portid);

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	for (unsigned int q = 0; q < nb_forwarding_cores; q++) {
		ret = rte_eth_rx_queue_setup(portid, q, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, mbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, portid);
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;
	for (unsigned int q = 0; q < nb_forwarding_cores; q++) {
		ret = rte_eth_tx_queue_setup(portid, q, nb_txd, rte_eth_dev_socket_id(portid), &txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, portid);
	}

	ret = rte_eth_dev_start(portid);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, portid);

	rte_eth_promiscuous_enable(portid);

	printf("\n--- Configuring Flow Director Rules ---\n");
	for (unsigned int i = 0; i < NUM_FLOWS; i++) {
		uint32_t target_ip = IPv4(48, 0, 0, 1 + i);
		uint32_t full_mask = 0xFFFFFFFF;
		
		generate_ipv4_flow(portid, i % nb_forwarding_cores, target_ip, full_mask);
	}
	printf("--- Flow Rules Configured ---\n\n");


	rte_eal_mp_remote_launch(l2fwd_main_loop, NULL, CALL_MASTER);

#ifdef XSTATS_ENABLE
	/* Master Core 运行统计循环 */
    print_stats_loop();
#endif

	/* 等待退出 */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}