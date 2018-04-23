/*-
 *   BSD LICENSE
 *
 *   Copyright 2017 Mellanox.
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
 *     * Neither the name of Mellanox. nor the names of its
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

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
//#include <rte_flow.h>
#include <rte_time.h>
#include <rte_cycles.h>

#include "cipher.h"
static volatile bool force_quit;

static uint8_t port_id;
static uint16_t nr_queues = 5;
static uint8_t selected_queue = 4;
struct rte_mempool *mbuf_pool;
//struct rte_flow *flow_1;

struct rte_flow *flow_2;
#define SRC_IP ((2<<24) + (2<<16) + (2<<8) + 3) /* src ip = 0.0.0.0 */
#define DEST_IP ((2<<24) + (2<<16) + (2<<8) + 5) /* dest ip = 192.168.1.1 */
#define FULL_MASK 0xffffffff /* full mask */
#define EMPTY_MASK 0x0 /* empty mask */

//#include "flow_blocks.c"
#if 0
struct rte_eth_fdir_filter  farg =
{
    .soft_id = 1,
    .input = {
        .flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP,
        .flow = {
        }
       
    },
    .action = {
        .rx_queue = 3,
        .behavior = RTE_ETH_FDIR_ACCEPT,
        .report_status = RTE_ETH_FDIR_REPORT_ID,
    }
} 
#endif
static inline void
print_ether_addr(const char *what, struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", what, buf);
}

static void
main_loop(void)
{
	struct rte_mbuf *mbufs[32];
	struct ether_hdr *eth_hdr;
        struct ipv4_hdr *ip_head;

	//struct rte_flow_error error;
	uint16_t nb_rx;
	uint16_t i;
	uint16_t j;
        uint32_t time = 0;
        int32_t sum = 0;
      //  struct rte_timer stats_timer;
       // rte_timer_subsystem_init();
       // rte_timer_init(&stats_timer);
        int lcore_id = rte_lcore_id();
        const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
            1000; //means 1000us
        uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;


	while (!force_quit) {
		for (i = 0; i < nr_queues; i++) {
			nb_rx = 0;
			nb_rx = rte_eth_rx_burst(port_id, i, mbufs, 32);
                        if( i == 3 && nb_rx > 0){

		                //    fprintf(stderr,"receive wrong packets in wrong queue i is %d and nb_rx is %d!!!!!\n",i,nb_rx);
		                //    rte_exit(EXIT_FAILURE,"receive wrong packets in wrong queue i is %d and nb_rx is %d!!!!!\n",i,nb_rx);
						}else if(nb_rx > 0){

		                //     fprintf(stderr,"receive good packets in wrong queue i is %d and nb_rx is %d!!!!!\n",i,nb_rx);
						}
                        if(nb_rx > 0 && time == 0){
                              cur_tsc = rte_rdtsc();
                              time = 1;
                        }
                        if(nb_rx > 0){
                        sum = sum + nb_rx;  
                        }     
                        if(sum >= 100000000){
                           force_quit = true;
                           prev_tsc = rte_rdtsc();
                           diff_tsc = prev_tsc - cur_tsc;
                           diff_tsc =diff_tsc *1000 / drain_tsc;
                           printf("receive sum packets %d need %ld us \n",sum,diff_tsc);
                          
                        }
			if (nb_rx) {
				for (j = 0; j < nb_rx; j++) {
					struct rte_mbuf *m = mbufs[j];
#if 0
					eth_hdr = rte_pktmbuf_mtod(m,
							struct ether_hdr *);
                                        ip_head = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr * , sizeof(struct ether_hdr));//+ sizeof(struct ipv4_hdr));
	//				print_ether_addr("src=",
	//						&eth_hdr->s_addr);
	//				print_ether_addr(" - dst=",
	//						&eth_hdr->d_addr);
	//
        //                               struct rte_eth_stats eth_stats;
        //                                rte_eth_stats_get(0, &eth_stats);
                                        time++;
                                        if(time >= 100){                
                                        printf("=====================begin ===================\n");
#if 0
                                        if(ip_head->next_proto_id == 17){
                                        printf("this is udp packets \n");
                                        }else{
                                        printf("this is tcp packets \n");
                                        }
					printf("src_ip = %x  = %d.%d.%d.%d \n",(ip_head->src_addr),(ip_head->src_addr & 0x000000ff)  , \
                                                                      (ip_head->src_addr &0x0000ff00 ) >>8,  \
                                                                      (ip_head->src_addr & 0x00ff0000 )>>16 ,  \
                                                                      (ip_head->src_addr & 0xff000000)>>24);
                                        printf("set src_ip is %x \n",htonl(SRC_IP));

					printf("dst_ip = %x = %d.%d.%d.%d \n",(ip_head->dst_addr ),(ip_head->dst_addr & 0x000000ff)  , \
                                                                      (ip_head->dst_addr &0x0000ff00 ) >>8,  \
                                                                      (ip_head->dst_addr & 0x00ff0000 )>>16 ,  \
                                                                      (ip_head->dst_addr & 0xff000000)>>24);
					
                                        printf("set dst_ip is %x \n",htonl(DEST_IP));
#endif
//                                        printf(" - queue=0x%x \n",i);
                                        unsigned char *ptr = m->buf_addr + m->data_off;
                                        ptr = m->buf_addr + m->data_off + 64;
//                                        printf("payload mark is %c%c%c \n",*(ptr),*(ptr+1),*(ptr+2));

                                        printf("=====================end ===================\n");
					printf("\n");
                                        }
#endif
					rte_pktmbuf_free(m);
				}
			}
		}
	}

	/* closing and releasing resources */
	//rte_flow_flush(port_id, &error);
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
}

static void
assert_link_status(void)
{
	struct rte_eth_link link;

	memset(&link, 0, sizeof(link));
	rte_eth_link_get(port_id, &link);
	if (link.link_status == ETH_LINK_DOWN)
		rte_exit(EXIT_FAILURE, ":: error: link is still down\n");
}

static void
init_port(void)
{
	int ret;
	uint16_t i;
	struct rte_eth_conf port_conf = {
	.rxmode = {
			.split_hdr_size = 0,
			/**< Header Split disabled */
			.header_split   = 0,
			/**< IP checksum offload disabled */
			.hw_ip_checksum = 0,
			/**< VLAN filtering disabled */
			.hw_vlan_filter = 0,
			/**< Jumbo Frame Support disabled */
			.jumbo_frame    = 0,
			/**< CRC stripped by hardware */
			.hw_strip_crc   = 1,
            .mq_mode = ETH_MQ_RX_RSS,
		},
#if 1
        .rx_adv_conf = {
               .rss_conf = {
                    .rss_key = NULL,
                    .rss_hf =  ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP | ETH_RSS_SCTP,
               },
        },
#endif
//#define FDIR_TEST 1
#if 1
#ifdef FDIR_TEST
        .fdir_conf = {

	    .mode = RTE_FDIR_MODE_PERFECT,
	    .pballoc = RTE_FDIR_PBALLOC_64K,
	    .status = RTE_FDIR_REPORT_STATUS,
	    .mask = {
		.vlan_tci_mask = 0x0,
		.ipv4_mask     = {
			.src_ip = 0xFFFFFFFF,
			.dst_ip = 0xFFFFFFFF,
		},
		.ipv6_mask     = {
			.src_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
			.dst_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
		},
		.src_port_mask = 0xFFFF,
		.dst_port_mask = 0xFFFF,
		.mac_addr_byte_mask = 0xFF,
		.tunnel_type_mask = 1,
		.tunnel_id_mask = 0xFFFFFFFF,
	    },
	    .drop_queue = 127,
        }
#endif
#endif
	};

	printf(":: initializing port: %d\n", port_id);
	ret = rte_eth_dev_configure(port_id,
				nr_queues, nr_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}
       
	/* only set Rx queues: something we care only so far */
	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 512,
				     rte_eth_dev_socket_id(port_id),
				     NULL,
				     mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	rte_eth_promiscuous_enable(port_id);

//	port_rss_reta_reset(0);

	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, port_id);
	}

	//port_rss_reta_reset(0);
	assert_link_status();

	printf(":: initializing port: %d done\n", port_id);
#if 0

        //for test this part can use and send UDP and TCP packets to DIFFERENT right queue
#if 1
        //for test this part can use and send UDP packets to right queue
        printf("::begin to initalizing udp flow filter \n");
        struct rte_eth_fdir_filter entry;
        memset(&entry, 0, sizeof(struct rte_eth_fdir_filter));
        entry.soft_id = 1;
        entry.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
        entry.input.flow.udp4_flow.ip.src_ip = 0x03020202;
        entry.input.flow.udp4_flow.ip.dst_ip = 0x05020202;

        entry.input.flow.udp4_flow.dst_port = rte_cpu_to_be_16(1024);
        entry.input.flow.udp4_flow.src_port = rte_cpu_to_be_16(1024);

        entry.action.rx_queue = 2;
        entry.action.behavior = RTE_ETH_FDIR_ACCEPT,
        entry.action.report_status = RTE_ETH_FDIR_REPORT_ID;
 

        ret = rte_eth_dev_filter_ctrl(0,RTE_ETH_FILTER_FDIR,RTE_ETH_FILTER_ADD,&entry);
        	if (ret < 0){
		printf("udp filter programming error: (%s)\n",
			strerror(-ret));
                }else{

		printf("udp filter programming success \n");
                }
#endif

#if 1

        //for test this part can use and send TCP packets to right queue
        struct rte_eth_fdir_filter tcp_entry;

        memset(&tcp_entry, 0, sizeof(struct rte_eth_fdir_filter));
        tcp_entry.soft_id = 2;
        tcp_entry.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_TCP;
        tcp_entry.input.flow.tcp4_flow.ip.src_ip = 0x03020202;
        tcp_entry.input.flow.tcp4_flow.ip.dst_ip = 0x05020202;

        tcp_entry.input.flow.tcp4_flow.dst_port = rte_cpu_to_be_16(1024);
        tcp_entry.input.flow.tcp4_flow.src_port = rte_cpu_to_be_16(1024);

        tcp_entry.action.rx_queue = 4;
        tcp_entry.action.behavior = RTE_ETH_FDIR_ACCEPT,
        tcp_entry.action.report_status = RTE_ETH_FDIR_REPORT_ID;


        ret = rte_eth_dev_filter_ctrl(0,RTE_ETH_FILTER_FDIR,RTE_ETH_FILTER_ADD,&tcp_entry);
        	if (ret < 0){
		printf("tcp filter programming error: (%s)\n",
			strerror(-ret));
                }else{

		printf("tcp filter programming success \n");
                }

#endif
#endif
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	int ret;
	uint8_t nr_ports;
//	struct rte_flow_error error;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nr_ports = rte_eth_dev_count();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");
	port_id = 0;
	if (nr_ports != 1) {
		printf(":: warn: %d ports detected, but we use only one: port %u\n",
			nr_ports, port_id);
	}
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 4096, 128, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	init_port();
        char string_1[3];
        string_1[0] = 'a';
        string_1[1] = 'b';
        string_1[2] = 'c';

        char string_2[3];
        string_2[0] = 'a';
        string_2[1] = 'b';
        string_2[2] = 'd';
#ifdef FDIR_TEST
    printf("this is  test \n");

    struct rte_flow *flow_1;
	/* create flow for send packet with */
	flow_1 = generate_tcp_flow_with_payload(port_id, 4,
				SRC_IP, FULL_MASK,
				DEST_IP, FULL_MASK, &error,string_1);
	if (!flow_1) {
		printf("Flow can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow_1");
	}
#endif

#if 0
	flow_2 = generate_tcp_flow_with_payload(port_id, 4,
				SRC_IP, FULL_MASK,
				DEST_IP, FULL_MASK, &error,string_2);
	if (!flow_1) {
		printf("Flow can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow_1");
	}

#endif
       main_loop();

}
