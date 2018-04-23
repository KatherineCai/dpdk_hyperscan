/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
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

#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
//for test
#include <unistd.h>
#include <time.h>


#include "pktgen.h"
//#include "datatype.h"



#include "./include/datatype.h"
#include "./include/qstack.h"
#include "./include/io_module.h"
#include "./include/flow_ctl.h"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define MAX_BURST_SIZE 32
#define BURST_QUEUE 10
#define MAX_SPEED 10
#define PACKET_SIZE 1500
struct rte_mbuf *bufs[BURST_QUEUE][MAX_BURST_SIZE];
static int MAX_PACKET_SEND = 0;
static int BURST_SIZE;
static unsigned long long SEND_CONT = 0;
static long long last_cont = 0;


/*
 *
 * build packet count and read pakcet count 
*/
static int producer;
static int consumer;
int seq_cnt = 0;
//static long long last_cont_mark = 0;
/* ethernet addresses of ports */
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

static const struct rte_eth_conf port_conf_default = {
         .rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static unsigned nb_ports;

static struct {
	uint64_t total_cycles;
	uint64_t total_pkts;
} latency_numbers;



static void show_data(struct rte_mbuf *mbuf){

    struct ether_hdr *eth;
    struct arp_data *arp;
    uint8_t *tmp;
    uint16_t *ops;
    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    arp = rte_pktmbuf_mtod(mbuf, struct arp_data *) + sizeof(struct ether_hdr);
    int i = 0;
    for(i = 0;i<6;i++){
        tmp = &(arp->s_addr.addr_bytes[i]);
        if(i == 0){
        printf("receive packet src MAC address: ");
        }
        if(i != 5){ 
        printf("%02X:",*tmp);
        }else{
        printf("%02X \n",*tmp);
        }

    }

    for(i = 0;i<6;i++){
        tmp = &(arp->d_addr.addr_bytes[i]);
        if(i == 0){
        printf("receive packet dst MAC address: ");
        }
        if(i != 5){ 
        printf("%02X:",*tmp);
        }else{
        printf("%02X \n",*tmp);
        }

    }
    ops = &eth->ether_type;
    printf("receive ether_type  is %04X \n", *ops);
   
    
}
static void change_ether_data(struct rte_mbuf *mbuf,uint8_t port){

    struct ether_hdr *eth;

    uint8_t *tmp;
    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    /*dst addr */
    eth->d_addr = eth->s_addr;
    int i = 0;
    for(i = 0;i<6;i++){
        tmp = &(eth->d_addr.addr_bytes[i]);
        if(i == 0){
        printf("after change packet dst MAC address: ");
        }
        if(i != 5){ 
        printf("%02X:",*tmp);
        }else{
        printf("%02X \n",*tmp);
        }

    }
    /* src addr */
    ether_addr_copy(&ports_eth_addr[port], &eth->s_addr);

    for(i = 0;i<6;i++){
        tmp = &(eth->s_addr.addr_bytes[i]);
        if(i == 0){
        printf("after change packet src MAC address: ");
        }
        if(i != 5){ 
        printf("%02X:",*tmp);
        }else{
        printf("%02X \n",*tmp);
        }

    }
}   

static void change_ip_head_data(struct rte_mbuf *mbuf,uint8_t port){
    struct ip_head_data *ip_head;

    if(port != 0){
        printf("port is not 0\n");
    }
    ip_head = rte_pktmbuf_mtod_offset(mbuf, struct ip_head_data * , sizeof(struct ether_hdr));
    uint32_t ip_src = ip_head->srcaddr;
    ip_head->srcaddr = ip_head->dstaddr;
    ip_head->dstaddr = ip_src;
    //need to change checksum
    //
    //
}
static void change_icmp_data(struct rte_mbuf *mbuf,uint8_t port){

   struct icmp_data *icmp;
   uint8_t *tmp8;
   uint8_t *tmp16;

    if(port != 0){
        printf("port is not 0\n");
    }
   icmp = rte_pktmbuf_mtod_offset(mbuf, struct icmp_data * ,(sizeof(struct ether_hdr) + sizeof(struct ip_head_data)));

   while(icmp->icmp_type == 0x08){
   //just deal with this type
   //change it in future
       icmp->icmp_type = 0x00;
       icmp->icmp_code =0x00;
   }
   //need to change checksum
   //
   //
   
}
static void change_arp_data(struct rte_mbuf *mbuf,uint8_t port){
   struct arp_data *arp;
   uint8_t *tmp8;
   uint8_t *tmp16;
   arp = rte_pktmbuf_mtod_offset(mbuf, struct arp_data *, sizeof(struct ether_hdr));
   
    if(port != 0){
        printf("port is not 0\n");
    }

   struct ether_hdr *eth;
   eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
   uint16_t op = arp->op;
   //change apr type
   if(op == 0x0100){ 
   op = 0x0200;
   arp->op = op;
   }else{
      printf("the op is 0x%02X \n",op);
   }
   //change ether src and dst
//   change_ether_data(mbuf);

   //change arp arc and dst

   arp->d_addr = eth->d_addr;

   ether_addr_copy(&ports_eth_addr[0], &arp->s_addr);
   
   uint32_t xip_addr;
   xip_addr = arp->ip_d_addr;
   arp->ip_d_addr = arp->ip_s_addr;
   arp->ip_s_addr = xip_addr;



}
 

static int change_data(struct rte_mbuf *mbuf ,uint8_t port){
    int ret = - 1;
    if(port != 0){
        printf("port is not 0\n");
    }
    struct ether_hdr *eth;
    uint8_t *tmp;
    uint16_t *ops;
    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

    ops = &eth->ether_type;
    switch (*ops){
    case 0x0008:
    //this for ip packet
    printf("this is 0800 packet \n");
    change_ether_data(mbuf,port);
    change_ip_head_data(mbuf,port);
    change_icmp_data(mbuf,port);
    ret = 1;
    break;
    case 0x0608:
    //this for arp packet
    printf("this is 0806 packet \n");
    change_ether_data(mbuf,port);
    change_arp_data(mbuf,port);
    ret = 1;
    break;
    case 0x3508:
    //this for rarp packet
    ret = -1;
    break;
    }

    return ret;
}
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;
        
        uint8_t portid = port;
        rte_eth_macaddr_get(portid,&ports_eth_addr[portid]);
        printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				(unsigned) portid,
				ports_eth_addr[portid].addr_bytes[0],
				ports_eth_addr[portid].addr_bytes[1],
				ports_eth_addr[portid].addr_bytes[2],
				ports_eth_addr[portid].addr_bytes[3],
				ports_eth_addr[portid].addr_bytes[4],
				ports_eth_addr[portid].addr_bytes[5]);
        return 0;
}

/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 */

static  __attribute__((noreturn)) void
lcore_main(int nb_ports,int queue_num)
{
	uint8_t port;

	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u receive packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
  //      int seq_cnt = 0;
  
        int core;
        core = rte_lcore_id();
        int queue_id = 0;

        static struct mtcp_thread_context *ctx;
        
        ctx = MTCPRunThread(core,queue_id);

        struct mtcp_manager *mtcp;
        mtcp = ctx->mtcp_manager;
        
        struct dpdk_private_context *dpc;
         
        dpc = (struct dpdk_private_context *) ctx->io_private_context;
        

        int i = 0;
        int k = 0;

	struct rte_mbuf *bufsq[BURST_SIZE];
 //       for(k = 0;k<BURST_QUEUE;k++){
    	    while(i < BURST_SIZE )
            {
                bufsq[i] = mtcp->iom->dev_alloc_mbuf(ctx,0);
                build_tcp_pkt(bufsq[i], PACKET_SIZE , seq_cnt);
                seq_cnt++;
                seq_cnt = seq_cnt % 0xFF;
                i++;
            }
            i = 0;
 //       }


	for (;;) {
		for (port = 0; port < nb_ports; port++) {
			
                        int i = 0;
                        int ret = 0;
                        uint16_t nb_tx = 0;
                        if(SEND_CONT < MAX_PACKET_SEND){
                       
                         nb_tx =  mtcp->iom->dev_tx_send(ctx,0,0,&bufsq,BURST_SIZE);

                         mtcp->iom->check_ringbuffer(ctx);

                        }

//                       nb_tx = rte_eth_tx_burst(port, 0,
//					bufs[consumer], BURST_SIZE);
//                        }
                       // printf("nb_tx is %d \n",nb_tx);
                        SEND_CONT = SEND_CONT + nb_tx;
                        if(SEND_CONT > last_cont * 1000){
                            
                            last_cont =  last_cont + 1;
                        }
#if 1
                        if (nb_tx < BURST_SIZE) {
				uint16_t buf;
				for (buf = nb_tx; buf < BURST_SIZE; buf++)
					rte_pktmbuf_free(bufs[consumer][buf]);
			}
#endif
                       consumer = consumer + 1;
                       consumer = consumer % BURST_QUEUE;

		}
	}
}
void build_packet(){
    int i = 0;
    int ret = 0;
    for (;;) {
        if(producer != consumer){
            for( i = 0;i<BURST_SIZE;i++){
                             
                //   ret = build_udp_pkt(bufs[i], PACKET_SIZE , seq_cnt);

                ret = build_tcp_pkt(bufs[producer][i], PACKET_SIZE , seq_cnt);
                seq_cnt++;
                seq_cnt = seq_cnt % 0xFF;

            }
        producer = producer + 1;
        producer = producer%BURST_QUEUE; 
        }
    }
}
void  set_speed(){

        printf("for test we run here for test\n");
        struct rte_timer hb_timer, stats_timer;
        uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	rte_timer_subsystem_init();
	rte_timer_init(&stats_timer);
        int lcore_id = rte_lcore_id();
        prev_tsc = 0;
        const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			1000; //means 1000us
        int times = 0;

        long long last_cont_mark = 0;

        long long send_each_time = 1000;
        float speed = 0;
        while(1){
           cur_tsc = rte_rdtsc();
           diff_tsc = cur_tsc - prev_tsc;
           if (unlikely(diff_tsc > drain_tsc)){

      //         timer0_cb();
           MAX_PACKET_SEND = MAX_PACKET_SEND + send_each_time;
           times++;
           unsigned long long send_cnt = 0;
           if(times == 1000){
          
	   printf("send_cnt %d,  SEND_CONT  is %d and last_cont is %d\n",  send_cnt-1, SEND_CONT,last_cont_mark);
           send_cnt = SEND_CONT - last_cont_mark;


           if(send_cnt <= 1){

               continue;
           }

      //     float max_speed = 10.0;
      //     int now_spped = (float)(send_cnt-1)*PACKET_SIZE*8/1024/1024/1024;

           if(speed *1.01 < (float)(send_cnt-1)*PACKET_SIZE*8/1024/1024/1024 || speed *0.99 > (float)(send_cnt-1)*PACKET_SIZE*8/1024/1024/1024){
         
               speed =  (float)(send_cnt-1)*PACKET_SIZE*8/1024/1024/1024;
               if(speed > MAX_SPEED *1.03){
              send_each_time = send_each_time * 0.8;
               }else if(speed < MAX_SPEED *0.97){
              send_each_time = send_each_time * 1.2;
               }
           }
           last_cont_mark = SEND_CONT;

           times = 0;
               
	       printf("send cnt is %d and  throughput is %f gbps\n",  last_cont_mark, (float)(send_cnt-1)*PACKET_SIZE*8/1024/1024/1024);
           }
           prev_tsc = cur_tsc;

           }
 
        }

//        rte_timer_reset(&stats_timer, (1 * rte_get_timer_hz()) / 1000
//                             , PERIODICAL, lcore_id, &timer0_cb, NULL);
} 
static int
lcore_loop(__attribute__((unused)) void *arg)
{
              
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
//        printf("hello from core %u\n", lcore_id);
        if(lcore_id == 3){
        //    build_packet();
        }
        if(lcore_id == 2){
            set_speed();
        }
        if(lcore_id == 1){
	    lcore_main(1,8);
        }
        if(lcore_id == 0){

        printf("hello from core %u\n", lcore_id);
        }
	return 0;
}
/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
#if 1
	struct rte_mempool *mbuf_pool;
	uint8_t portid;
        printf("for test \n");
        BURST_SIZE = 32;
        producer = 0;
        consumer = 0;
	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count();


        int queue_num = 1;
	current_iomodule_func->load_module(queue_num);

        printf("test 2\n");

        unsigned lcore_id;
        /* call lcore_hello() on every slave lcore */

        rte_eal_mp_remote_launch(lcore_loop, NULL, CALL_MASTER);
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
                if (rte_eal_wait_lcore(lcore_id) < 0)
                        return -1;
        }
        printf("test 1\n");
#else

	struct rte_mempool *mbuf_pool;
	uint8_t portid;
        printf("for test \n");
        BURST_SIZE = 32;
        producer = 0;
        consumer = -1;
	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count();
//	if (nb_ports != 1)
//		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
       // if(nb_ports != 0 ){
              
       //		rte_exit(EXIT_FAILURE, "ports number is not 0 \n");
       // }
	/* initialize all ports */

	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);



        int i = 0;
        int k = 0;
        for(k = 0;k<BURST_QUEUE;k++){
    	    while(i < MAX_BURST_SIZE )
            {
                bufs[k][i] = rte_mbuf_raw_alloc(mbuf_pool);

                ret = build_tcp_pkt(bufs[k][i], PACKET_SIZE , seq_cnt);
                seq_cnt++;
                seq_cnt = seq_cnt % 0xFF;
                i++;
            }
            i = 0;
        }
        unsigned lcore_id;
        /* call lcore_hello() on every slave lcore */

        rte_eal_mp_remote_launch(lcore_loop, NULL, CALL_MASTER);
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
                if (rte_eal_wait_lcore(lcore_id) < 0)
                        return -1;
        }
//        printf("Bye and SEND_CONT is %d \n",SEND_CONT);
//	lcore_main();
#endif
	return 0;
}
