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
#ifndef FLOW_C
#define FLOW_C
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#if 0
#ifdef RTE_EXEC_ENV_LINUXAPP
#include <linux/if.h>
#include <linux/if_tun.h>
#endif
#endif
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_eal.h>
#include <rte_malloc.h>


#define APP_NAME_SIZE	32

#define APP_RETA_SIZE_MAX     (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)


/* Core Mask String in Hex Representation */
#define APP_CORE_MASK_STRING_SIZE ((64 * APP_CORE_MASK_SIZE) / 8 * 2 + 1)

static inline int
app_link_filter_arp_add(struct rte_eth_ethertype_filter filter,int port_id);

static inline int
app_link_filter_tcp_syn_add(struct rte_eth_syn_filter filter,int port_id);

static inline int
app_link_filter_ip_add(struct rte_eth_ntuple_filter filter,int port_id);

static inline int
app_link_filter_ip_del(struct rte_eth_ntuple_filter filter, int port_id);

static inline int
app_link_filter_tcp_add(struct rte_eth_ntuple_filter filter, int port_id);

static inline int
app_link_filter_tcp_del(struct rte_eth_ntuple_filter filter, int port_id);

static inline int
app_link_filter_udp_add(struct rte_eth_ntuple_filter filter, int port_id);

static inline int
app_link_filter_udp_del(struct rte_eth_ntuple_filter filter, int port_id);

static inline int
app_link_filter_sctp_add(struct rte_eth_ntuple_filter filter, int port_id);

static inline int
app_link_filter_sctp_del(struct rte_eth_ntuple_filter filter, int port_id);
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
app_get_cpu_socket_id(uint32_t pmd_id);

static inline int
app_link_rss_enabled(int port_id);

static void
app_link_rss_setup(int port_id);
#endif
