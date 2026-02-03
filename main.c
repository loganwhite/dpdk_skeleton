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

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define NB_MBUF 8192
#define NUM_FLOWS 254

static unsigned int lcore_queue_map[RTE_MAX_LCORE];

/* 手动定义 IPv4 宏，防止 implicit declaration 错误 */
#define IPv4(a,b,c,d) ((uint32_t)(((a) & 0xff) << 24) | \
					   (((b) & 0xff) << 16) | \
					   (((c) & 0xff) << 8)  | \
					   ((d) & 0xff))

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

static int
l2fwd_main_loop(void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned lcore_id;
	unsigned j, portid, nb_rx;
	
	/* 消除 unused warning */
	(void)dummy;

	lcore_id = rte_lcore_id();
	unsigned int q_id = lcore_queue_map[lcore_id];
	portid = 0; 

    /* 安全检查：如果映射错误，直接退出避免 Crash */
    if (q_id >= RTE_MAX_LCORE) {
        printf("Lcore %u has no queue assigned! Bye.\n", lcore_id);
        return -1;
    }

	printf("Lcore %u: Entering main loop on Port %u Queue %u\n", lcore_id, portid, q_id);

	while (1) {
		nb_rx = rte_eth_rx_burst(portid, q_id, pkts_burst, MAX_PKT_BURST);

		if (nb_rx == 0)
			continue;

		for (j = 0; j < nb_rx; j++) {
			m = pkts_burst[j];
			
			struct rte_ether_hdr *eth;
			eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			
			/* DPDK 19.11 修正: 使用 d_addr 和 s_addr */
			struct rte_ether_addr tmp;
			rte_ether_addr_copy(&eth->d_addr, &tmp);
			rte_ether_addr_copy(&eth->s_addr, &eth->d_addr);
			rte_ether_addr_copy(&tmp, &eth->s_addr);

			rte_eth_tx_burst(portid, q_id, &m, 1);
		}
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
	uint16_t nb_rxd = 1024;
	uint16_t nb_txd = 1024;
	int ret;
	unsigned int nb_lcores;

    /* 初始化映射表为无效值 */
    for (int i = 0; i < RTE_MAX_LCORE; i++)
        lcore_queue_map[i] = RTE_MAX_LCORE;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	nb_lcores = rte_lcore_count();
	printf("Number of lcores enabled: %u\n", nb_lcores);

    unsigned int rx_idx = 0;
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
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

	ret = rte_eth_dev_configure(portid, nb_lcores, nb_lcores, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret, portid);

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	for (unsigned int q = 0; q < nb_lcores; q++) {
		ret = rte_eth_rx_queue_setup(portid, q, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, mbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, portid);
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;
	for (unsigned int q = 0; q < nb_lcores; q++) {
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
		
		generate_ipv4_flow(portid, i % nb_lcores, target_ip, full_mask);
	}
	printf("--- Flow Rules Configured ---\n\n");


	rte_eal_mp_remote_launch(l2fwd_main_loop, NULL, CALL_MASTER);

	
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}