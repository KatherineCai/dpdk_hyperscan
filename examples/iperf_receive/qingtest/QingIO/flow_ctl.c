/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "./include/flow_ctl.h"

#define APP_NAME_SIZE	32

#define APP_RETA_SIZE_MAX     (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)


/* Core Mask String in Hex Representation */
#define APP_CORE_MASK_STRING_SIZE ((64 * APP_CORE_MASK_SIZE) / 8 * 2 + 1)

static inline int
app_link_filter_arp_add(struct rte_eth_ethertype_filter filter,int port_id)
{
		assert(filter.ether_type == ETHER_TYPE_ARP);
		assert(filter.flags == 0);
		assert(filter.queue != -1);

	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_ETHERTYPE,
		RTE_ETH_FILTER_ADD,
		&filter);
}

static inline int
app_link_filter_tcp_syn_add(struct rte_eth_syn_filter filter,int port_id)
{
    assert(filter.hig_pri == 1);
    assert(filter.queue != -1);

	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_SYN,
		RTE_ETH_FILTER_ADD,
		&filter);
}

static inline int
app_link_filter_ip_add(struct rte_eth_ntuple_filter filter,int port_id)
{
#if 0
	struct rte_eth_ntuple_filter filter = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = rte_bswap32(l2->ip),
		.dst_ip_mask = UINT32_MAX, /* Enable */
		.src_ip = 0,
		.src_ip_mask = 0, /* Disable */
		.dst_port = 0,
		.dst_port_mask = 0, /* Disable */
		.src_port = 0,
		.src_port_mask = 0, /* Disable */
		.proto = 0,
		.proto_mask = 0, /* Disable */
		.tcp_flags = 0,
		.priority = 1, /* Lowest */
		.queue = l1->ip_local_q,
	};
#endif
	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_ADD,
		&filter);
}

static inline int
app_link_filter_ip_del(struct rte_eth_ntuple_filter filter, int port_id)
{
#if 0
	struct rte_eth_ntuple_filter filter = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = rte_bswap32(l2->ip),
		.dst_ip_mask = UINT32_MAX, /* Enable */
		.src_ip = 0,
		.src_ip_mask = 0, /* Disable */
		.dst_port = 0,
		.dst_port_mask = 0, /* Disable */
		.src_port = 0,
		.src_port_mask = 0, /* Disable */
		.proto = 0,
		.proto_mask = 0, /* Disable */
		.tcp_flags = 0,
		.priority = 1, /* Lowest */
		.queue = l1->ip_local_q,
	};
#endif
	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_DELETE,
		&filter);
}

static inline int
app_link_filter_tcp_add(struct rte_eth_ntuple_filter filter, int port_id)
{
#if 0
	struct rte_eth_ntuple_filter filter = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = rte_bswap32(l2->ip),
		.dst_ip_mask = UINT32_MAX, /* Enable */
		.src_ip = 0,
		.src_ip_mask = 0, /* Disable */
		.dst_port = 0,
		.dst_port_mask = 0, /* Disable */
		.src_port = 0,
		.src_port_mask = 0, /* Disable */
		.proto = IPPROTO_TCP,
		.proto_mask = UINT8_MAX, /* Enable */
		.tcp_flags = 0,
		.priority = 2, /* Higher priority than IP */
		.queue = l1->tcp_local_q,
	};
#endif
	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_ADD,
		&filter);
}

static inline int
app_link_filter_tcp_del(struct rte_eth_ntuple_filter filter, int port_id)
{
#if 0
	struct rte_eth_ntuple_filter filter = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = rte_bswap32(l2->ip),
		.dst_ip_mask = UINT32_MAX, /* Enable */
		.src_ip = 0,
		.src_ip_mask = 0, /* Disable */
		.dst_port = 0,
		.dst_port_mask = 0, /* Disable */
		.src_port = 0,
		.src_port_mask = 0, /* Disable */
		.proto = IPPROTO_TCP,
		.proto_mask = UINT8_MAX, /* Enable */
		.tcp_flags = 0,
		.priority = 2, /* Higher priority than IP */
		.queue = l1->tcp_local_q,
	};
#endif
	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_DELETE,
		&filter);
}

static inline int
app_link_filter_udp_add(struct rte_eth_ntuple_filter filter, int port_id)
{
#if 0
	struct rte_eth_ntuple_filter filter = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = rte_bswap32(l2->ip),
		.dst_ip_mask = UINT32_MAX, /* Enable */
		.src_ip = 0,
		.src_ip_mask = 0, /* Disable */
		.dst_port = 0,
		.dst_port_mask = 0, /* Disable */
		.src_port = 0,
		.src_port_mask = 0, /* Disable */
		.proto = IPPROTO_UDP,
		.proto_mask = UINT8_MAX, /* Enable */
		.tcp_flags = 0,
		.priority = 2, /* Higher priority than IP */
		.queue = l1->udp_local_q,
	};
#endif
	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_ADD,
		&filter);
}

static inline int
app_link_filter_udp_del(struct rte_eth_ntuple_filter filter, int port_id)
{
#if 0
	struct rte_eth_ntuple_filter filter = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = rte_bswap32(l2->ip),
		.dst_ip_mask = UINT32_MAX, /* Enable */
		.src_ip = 0,
		.src_ip_mask = 0, /* Disable */
		.dst_port = 0,
		.dst_port_mask = 0, /* Disable */
		.src_port = 0,
		.src_port_mask = 0, /* Disable */
		.proto = IPPROTO_UDP,
		.proto_mask = UINT8_MAX, /* Enable */
		.tcp_flags = 0,
		.priority = 2, /* Higher priority than IP */
		.queue = l1->udp_local_q,
	};
#endif
	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_DELETE,
		&filter);
}

static inline int
app_link_filter_sctp_add(struct rte_eth_ntuple_filter filter, int port_id)
{
#if 0
	struct rte_eth_ntuple_filter filter = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = rte_bswap32(l2->ip),
		.dst_ip_mask = UINT32_MAX, /* Enable */
		.src_ip = 0,
		.src_ip_mask = 0, /* Disable */
		.dst_port = 0,
		.dst_port_mask = 0, /* Disable */
		.src_port = 0,
		.src_port_mask = 0, /* Disable */
		.proto = IPPROTO_SCTP,
		.proto_mask = UINT8_MAX, /* Enable */
		.tcp_flags = 0,
		.priority = 2, /* Higher priority than IP */
		.queue = l1->sctp_local_q,
	};
#endif
	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_ADD,
		&filter);
}

static inline int
app_link_filter_sctp_del(struct rte_eth_ntuple_filter filter, int port_id)
{
#if 0
	struct rte_eth_ntuple_filter filter = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = rte_bswap32(l2->ip),
		.dst_ip_mask = UINT32_MAX, /* Enable */
		.src_ip = 0,
		.src_ip_mask = 0, /* Disable */
		.dst_port = 0,
		.dst_port_mask = 0, /* Disable */
		.src_port = 0,
		.src_port_mask = 0, /* Disable */
		.proto = IPPROTO_SCTP,
		.proto_mask = UINT8_MAX, /* Enable */
		.tcp_flags = 0,
		.priority = 2, /* Higher priority than IP */
		.queue = l1->sctp_local_q,
	};
#endif
	return rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_DELETE,
		&filter);
}
#if 0
static void
app_link_set_arp_filter(struct app_params *app, struct app_link_params *cp)
{
	if (cp->arp_q != 0) {
		int status = app_link_filter_arp_add(cp);

		APP_LOG(app, LOW, "%s (%" PRIu32 "): "
			"Adding ARP filter (queue = %" PRIu32 ")",
			cp->name, cp->pmd_id, cp->arp_q);

		if (status)
			rte_panic("%s (%" PRIu32 "): "
				"Error adding ARP filter "
				"(queue = %" PRIu32 ") (%" PRId32 ")\n",
				cp->name, cp->pmd_id, cp->arp_q, status);
	}
}

static void
app_link_set_tcp_syn_filter(struct app_params *app, struct app_link_params *cp)
{
	if (cp->tcp_syn_q != 0) {
		int status = app_link_filter_tcp_syn_add(cp);

		APP_LOG(app, LOW, "%s (%" PRIu32 "): "
			"Adding TCP SYN filter (queue = %" PRIu32 ")",
			cp->name, cp->pmd_id, cp->tcp_syn_q);

		if (status)
			rte_panic("%s (%" PRIu32 "): "
				"Error adding TCP SYN filter "
				"(queue = %" PRIu32 ") (%" PRId32 ")\n",
				cp->name, cp->pmd_id, cp->tcp_syn_q,
				status);
	}
}
#endif
#if 0
void
app_link_up_internal(struct app_params *app, struct app_link_params *cp)
{
	uint32_t i;
	int status;

	/* For each link, add filters for IP of current link */
	if (cp->ip != 0) {
		for (i = 0; i < app->n_links; i++) {
			struct app_link_params *p = &app->link_params[i];

			/* IP */
			if (p->ip_local_q != 0) {
				int status = app_link_filter_ip_add(p, cp);

				APP_LOG(app, LOW, "%s (%" PRIu32 "): "
					"Adding IP filter (queue= %" PRIu32
					", IP = 0x%08" PRIx32 ")",
					p->name, p->pmd_id, p->ip_local_q,
					cp->ip);

				if (status)
					rte_panic("%s (%" PRIu32 "): "
						"Error adding IP "
						"filter (queue= %" PRIu32 ", "
						"IP = 0x%08" PRIx32
						") (%" PRId32 ")\n",
						p->name, p->pmd_id,
						p->ip_local_q, cp->ip, status);
			}

			/* TCP */
			if (p->tcp_local_q != 0) {
				int status = app_link_filter_tcp_add(p, cp);

				APP_LOG(app, LOW, "%s (%" PRIu32 "): "
					"Adding TCP filter "
					"(queue = %" PRIu32
					", IP = 0x%08" PRIx32 ")",
					p->name, p->pmd_id, p->tcp_local_q,
					cp->ip);

				if (status)
					rte_panic("%s (%" PRIu32 "): "
						"Error adding TCP "
						"filter (queue = %" PRIu32 ", "
						"IP = 0x%08" PRIx32
						") (%" PRId32 ")\n",
						p->name, p->pmd_id,
						p->tcp_local_q, cp->ip, status);
			}

			/* UDP */
			if (p->udp_local_q != 0) {
				int status = app_link_filter_udp_add(p, cp);

				APP_LOG(app, LOW, "%s (%" PRIu32 "): "
					"Adding UDP filter "
					"(queue = %" PRIu32
					", IP = 0x%08" PRIx32 ")",
					p->name, p->pmd_id, p->udp_local_q,
					cp->ip);

				if (status)
					rte_panic("%s (%" PRIu32 "): "
						"Error adding UDP "
						"filter (queue = %" PRIu32 ", "
						"IP = 0x%08" PRIx32
						") (%" PRId32 ")\n",
						p->name, p->pmd_id,
						p->udp_local_q, cp->ip, status);
			}

			/* SCTP */
			if (p->sctp_local_q != 0) {
				int status = app_link_filter_sctp_add(p, cp);

				APP_LOG(app, LOW, "%s (%" PRIu32
					"): Adding SCTP filter "
					"(queue = %" PRIu32
					", IP = 0x%08" PRIx32 ")",
					p->name, p->pmd_id, p->sctp_local_q,
					cp->ip);

				if (status)
					rte_panic("%s (%" PRIu32 "): "
						"Error adding SCTP "
						"filter (queue = %" PRIu32 ", "
						"IP = 0x%08" PRIx32
						") (%" PRId32 ")\n",
						p->name, p->pmd_id,
						p->sctp_local_q, cp->ip,
						status);
			}
		}
	}

	/* PMD link up */
	status = rte_eth_dev_set_link_up(cp->pmd_id);
	/* Do not panic if PMD does not provide link up functionality */
	if (status < 0 && status != -ENOTSUP)
		rte_panic("%s (%" PRIu32 "): PMD set link up error %"
			PRId32 "\n", cp->name, cp->pmd_id, status);

	/* Mark link as UP */
	cp->state = 1;
}

void
app_link_down_internal(struct app_params *app, struct app_link_params *cp)
{
	uint32_t i;
	int status;

	/* PMD link down */
	status = rte_eth_dev_set_link_down(cp->pmd_id);
	/* Do not panic if PMD does not provide link down functionality */
	if (status < 0 && status != -ENOTSUP)
		rte_panic("%s (%" PRIu32 "): PMD set link down error %"
			PRId32 "\n", cp->name, cp->pmd_id, status);

	/* Mark link as DOWN */
	cp->state = 0;

	/* Return if current link IP is not valid */
	if (cp->ip == 0)
		return;

	/* For each link, remove filters for IP of current link */
	for (i = 0; i < app->n_links; i++) {
		struct app_link_params *p = &app->link_params[i];

		/* IP */
		if (p->ip_local_q != 0) {
			int status = app_link_filter_ip_del(p, cp);

			APP_LOG(app, LOW, "%s (%" PRIu32
				"): Deleting IP filter "
				"(queue = %" PRIu32 ", IP = 0x%" PRIx32 ")",
				p->name, p->pmd_id, p->ip_local_q, cp->ip);

			if (status)
				rte_panic("%s (%" PRIu32
					"): Error deleting IP filter "
					"(queue = %" PRIu32
					", IP = 0x%" PRIx32
					") (%" PRId32 ")\n",
					p->name, p->pmd_id, p->ip_local_q,
					cp->ip, status);
		}

		/* TCP */
		if (p->tcp_local_q != 0) {
			int status = app_link_filter_tcp_del(p, cp);

			APP_LOG(app, LOW, "%s (%" PRIu32
				"): Deleting TCP filter "
				"(queue = %" PRIu32
				", IP = 0x%" PRIx32 ")",
				p->name, p->pmd_id, p->tcp_local_q, cp->ip);

			if (status)
				rte_panic("%s (%" PRIu32
					"): Error deleting TCP filter "
					"(queue = %" PRIu32
					", IP = 0x%" PRIx32
					") (%" PRId32 ")\n",
					p->name, p->pmd_id, p->tcp_local_q,
					cp->ip, status);
		}

		/* UDP */
		if (p->udp_local_q != 0) {
			int status = app_link_filter_udp_del(p, cp);

			APP_LOG(app, LOW, "%s (%" PRIu32
				"): Deleting UDP filter "
				"(queue = %" PRIu32 ", IP = 0x%" PRIx32 ")",
				p->name, p->pmd_id, p->udp_local_q, cp->ip);

			if (status)
				rte_panic("%s (%" PRIu32
					"): Error deleting UDP filter "
					"(queue = %" PRIu32
					", IP = 0x%" PRIx32
					") (%" PRId32 ")\n",
					p->name, p->pmd_id, p->udp_local_q,
					cp->ip, status);
		}

		/* SCTP */
		if (p->sctp_local_q != 0) {
			int status = app_link_filter_sctp_del(p, cp);

			APP_LOG(app, LOW, "%s (%" PRIu32
				"): Deleting SCTP filter "
				"(queue = %" PRIu32
				", IP = 0x%" PRIx32 ")",
				p->name, p->pmd_id, p->sctp_local_q, cp->ip);

			if (status)
				rte_panic("%s (%" PRIu32
					"): Error deleting SCTP filter "
					"(queue = %" PRIu32
					", IP = 0x%" PRIx32
					") (%" PRId32 ")\n",
					p->name, p->pmd_id, p->sctp_local_q,
					cp->ip, status);
		}
	}
}

static void
app_check_link(struct app_params *app)
{
	uint32_t all_links_up, i;

	all_links_up = 1;

	for (i = 0; i < app->n_links; i++) {
		struct app_link_params *p = &app->link_params[i];
		struct rte_eth_link link_params;

		memset(&link_params, 0, sizeof(link_params));
		rte_eth_link_get(p->pmd_id, &link_params);

		APP_LOG(app, HIGH, "%s (%" PRIu32 ") (%" PRIu32 " Gbps) %s",
			p->name,
			p->pmd_id,
			link_params.link_speed / 1000,
			link_params.link_status ? "UP" : "DOWN");

		if (link_params.link_status == ETH_LINK_DOWN)
			all_links_up = 0;
	}

	if (all_links_up == 0)
		rte_panic("Some links are DOWN\n");
}

static uint32_t
is_any_swq_frag_or_ras(struct app_params *app)
{
	uint32_t i;

	for (i = 0; i < app->n_pktq_swq; i++) {
		struct app_pktq_swq_params *p = &app->swq_params[i];

		if ((p->ipv4_frag == 1) || (p->ipv6_frag == 1) ||
			(p->ipv4_ras == 1) || (p->ipv6_ras == 1))
			return 1;
	}

	return 0;
}

static void
app_init_link_frag_ras(struct app_params *app)
{
	uint32_t i;

	if (is_any_swq_frag_or_ras(app)) {
		for (i = 0; i < app->n_pktq_hwq_out; i++) {
			struct app_pktq_hwq_out_params *p_txq = &app->hwq_out_params[i];

			p_txq->conf.txq_flags &= ~ETH_TXQ_FLAGS_NOMULTSEGS;
		}
	}
}
#endif
static inline int
app_get_cpu_socket_id(uint32_t pmd_id)
{
	int status = rte_eth_dev_socket_id(pmd_id);

	return (status != SOCKET_ID_ANY) ? status : 0;
}

static inline int
app_link_rss_enabled(int port_id)
{

	struct rte_eth_dev_info dev_info;
	uint32_t i;
	int status;

    /* Get RETA size */
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);
}

static void
app_link_rss_setup(int port_id)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rss_reta_entry64 reta_conf[APP_RETA_SIZE_MAX];
	uint32_t i;
	int status;

    /* Get RETA size */
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);

	assert(dev_info.reta_size != 0);

	assert(dev_info.reta_size <= ETH_RSS_RETA_SIZE_512);

	/* Setup RETA contents */
	memset(reta_conf, 0, sizeof(reta_conf));

	for (i = 0; i < dev_info.reta_size; i++)
		reta_conf[i / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;

	for (i = 0; i < dev_info.reta_size; i++) {
		uint32_t reta_id = i / RTE_RETA_GROUP_SIZE;
		uint32_t reta_pos = i % RTE_RETA_GROUP_SIZE;
//		uint32_t rss_qs_pos = i % cp->n_rss_qs;
        uint16_t rss_qs = 123;
//need change here
		reta_conf[reta_id].reta[reta_pos] = rss_qs;
//			(uint16_t) cp->rss_qs[rss_qs_pos];
	}

	/* RETA update */
	status = rte_eth_dev_rss_reta_update(port_id,
		reta_conf,
		dev_info.reta_size);
	assert (status == 0);
}
