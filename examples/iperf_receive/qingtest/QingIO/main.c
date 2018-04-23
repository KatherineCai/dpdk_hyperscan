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


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <sys/param.h>
#include <assert.h>
#include <unistd.h>

#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

#include <lthread_api.h>
#include "./include/datatype.h"
#include "./include/qstack.h"
#include "./include/io_module.h"
#include "./include/flow_ctl.h"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

/* ethernet addresses of ports */
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

struct mtcp_thread_context *ctxs[16];
int  ctxs_init[16];
int ctxs_queue_id;

cpu_set_t cpu_info[8];
#if 0
/** Descriptor for a single flow. */
struct port_flow {
	size_t size; /**< Allocated space including data[]. */
	struct port_flow *next; /**< Next flow in list. */
	struct port_flow *tmp; /**< Temporary linking. */
	uint32_t id; /**< Flow rule ID. */
	struct rte_flow *flow; /**< Opaque flow object returned by PMD. */
	struct rte_flow_attr attr; /**< Attributes. */
	struct rte_flow_item *pattern; /**< Pattern. */
	struct rte_flow_action *actions; /**< Actions. */
	uint8_t data[]; /**< Storage for pattern/actions. */
};
#endif

static const struct rte_eth_conf port_conf_default = {
         .rxmode = {
		.mq_mode = ETH_MQ_RX_NONE,
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
    arp = rte_pktmbuf_mtod(mbuf, struct arp_data *);
    int i = 0;
    for(i = 0;i<6;i++){
        tmp = &arp->eth.s_addr.addr_bytes[i];
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
        tmp = &arp->eth.d_addr.addr_bytes[i];
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
    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    /*dst addr */
    eth->d_addr = eth->s_addr;
    /* src addr */
    ether_addr_copy(&ports_eth_addr[port], &eth->s_addr);
}   
static void change_ip_head_data(struct rte_mbuf *mbuf,uint8_t port){
    struct ip_head_data *ip_head;
    ip_head = rte_pktmbuf_mtod(mbuf, struct ip_head_data *);
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
   icmp = rte_pktmbuf_mtod(mbuf, struct icmp_data *);
   while(icmp->icmp_type == 0x08){
   //just deal with this type
   //change it in future
       icmp->icmp_type = 0x00;
       icmp->icmp_code == 0x00;
   }
   //need to change checksum
   //
   //
   
}
static void change_arp_data(struct rte_mbuf *mbuf,uint8_t port){
   struct arp_data *arp;
   uint8_t *tmp8;
   uint8_t *tmp16;
   arp = rte_pktmbuf_mtod(mbuf, struct arp_data *);
   
   uint16_t op = arp->op;
   //change apr type
   if(op == 0x0100){ 
   op = 0x0200;
   arp->op = op;
   }
   //change ether src and dst
//   change_ether_data(mbuf);

   //change arp arc and dst
   arp->d_addr = arp->s_addr;

   ether_addr_copy(&ports_eth_addr[0], &arp->s_addr);
   
   uint32_t xip_addr;
   xip_addr = arp->ip_d_addr;
   arp->ip_d_addr = arp->ip_s_addr;
   arp->ip_s_addr = xip_addr;

}
 

static int change_data(struct rte_mbuf *mbuf ,uint8_t port){
    int ret = - 1;

    struct ether_hdr *eth;
    uint8_t *tmp;
    uint16_t *ops;
    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

    ops = &eth->ether_type;
    switch (*ops){
    case 0x0008:
    //this for ip packet
  //  printf("this is 0800 packet \n");
    change_ether_data(mbuf,port);
    change_ip_head_data(mbuf,port);
    change_icmp_data(mbuf,port);
    ret = 1;
    break;
    case 0x0608:
    //this for arp packet
  //  printf("this is 0806 packet \n");
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


	struct rte_eth_txconf *txconf;
	struct rte_eth_dev_info dev_info;
//	struct rte_eth_txconf *txconf;

	const uint16_t rx_queue = 8, tx_queue = 8;
	int retval;
	uint16_t q;



	if (port >= rte_eth_dev_count())
		return -1;

   

    rte_eth_dev_info_get(port,&dev_info);
	retval = rte_eth_dev_configure(port, rx_queue, tx_queue, &port_conf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_queue; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_queue; q++) {

        txconf = &dev_info.default_txconf;
        txconf->tx_free_thresh = 0;
        txconf->txq_flags = 0;
        

		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), txconf);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;
        
        uint8_t portid = port;
        rte_eth_macaddr_get(portid,&ports_eth_addr[portid]);

	return 0;
}

/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 * for this part test_main for new dpdk_io_api
 * and lcore_main for old dpdk_api
 */

 //    printf("begin to check device \n");

static  __attribute__((noreturn)) void
test_check(void *arg){
    int test_main_num = *(int *)arg;

	unsigned lcore_id;
	uint8_t portid;


	/*
 * 	 * Move this lthread to the selected lcore
 * 	 	 */
  //  printf("test_main_num is %d \n",test_main_num);
//	lthread_set_affinity(test_main_num+5);
    int i = 0;
    i = test_main_num;
    CPU_ZERO(&cpu_info[i]);
    CPU_SET(i + 5 , &cpu_info[i]);
//    if(pthread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&cpu_info[i]) !=0)

     // printf("pthread_setaffinity_np");

    int ret = pthread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&cpu_info[i]);
    if(ret != 0){

    printf("pthread_setaffinity_np");
    }
    i = 0; 
    int time[MAX_CPUS] = {0};
    printf("begin to check device and test_main num is %d\n",test_main_num);

    for(i=0;i<test_main_num;i++){
        printf("ctxs_init[%d] is %d\n",i,ctxs_init[i] );
    }
    struct mtcp_thread_context *ctx = NULL;
    for(;;){
        for(i=0;i<test_main_num;i++){

            ctx = ctxs[i];
            assert(ctx != NULL);
            struct mtcp_manager *mtcp;
            mtcp = ctx->mtcp_manager;
            mtcp->iom->check_ringbuffer(ctx);
            
        }    
    }

}


//for test 
struct arp_data {
    struct ether_hdr eth;
    uint16_t hard_type;
    uint16_t ops_type;
    uint8_t hard_len;
    uint8_t ops_len;
    uint16_t op;
    struct ether_addr s_addr; /**< Source address. */
    uint32_t ip_d_addr;
    struct ether_addr d_addr; /**< Destination address. */   
    uint32_t ip_s_addr;
}__attribute__((__packed__));


static  __attribute__((noreturn)) void
test_main(void *arg)
{
    int ret = 0;
    int i = 0;
    struct rte_mbuf *rbufs[BURST_SIZE];

    struct rte_mbuf *tbufs[BURST_SIZE];

    static struct mtcp_thread_context *ctx;
    int core;
    core = rte_lcore_id();
    int queue_id = *(int *)arg;

    int core;
    core = rte_lcore_id();
    int queue_id = *(int *)arg;
    i = queue_id;


    CPU_ZERO(&cpu_info[i]);
    CPU_SET(i + 8 , &cpu_info[i]);
//    if(pthread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&cpu_info[i]) !=0)

     // printf("pthread_setaffinity_np");

    ret = pthread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&cpu_info[i]);
    if(ret != 0){

    printf("pthread_setaffinity_np");
    }
    i = 0;
//	lthread_set_affinity(queue_id + 1);
    {

        ctx = MTCPRunThread(core,queue_id);

        ctxs[queue_id] = ctx;
        ctxs_init[queue_id] = 1;
            
        struct mtcp_manager *mtcp;
        mtcp = ctx->mtcp_manager;
        
        struct dpdk_private_context *dpc;
         
        dpc = (struct dpdk_private_context *) ctx->io_private_context;
        for(;;)
        {
            int ret = 0;

 //           mtcp->iom->check_ringbuffer(ctx);
			struct rte_mbuf *bufs[BURST_SIZE];
            ret = mtcp->iom->dev_rx_receive(ctx,0,0,&bufs);

        //    printf("for test ret = %d means receive packet in queue %d\n",ret,queue_id);
            if(ret != 0){
                int nb_tx = ret;
                int send_num = 0;
            //    printf("for test ret = %d means receive packet in queue %d\n",ret,queue_id);
                int k = 0;
                for(k = 0; k < ret;k++){
                   
                        //    show_data(bufs[k]);
                            change_data(bufs[k],0);
                        //    show_data(bufs[k]);
                }

                send_num =  mtcp->iom->dev_tx_send(ctx,0,0,&bufs,nb_tx);




                ret = 0;
            }
            
         //   mtcp->iom->check_ringbuffer(ctx);


        }
   
   
    }
   // lcore_main();

}


static  __attribute__((noreturn)) void
lcore_main(int nb_ports,int queue_num)
{
	uint8_t port;

//    if(pehread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&cpu_info[i]) !=0)

     // printf("pthread_setaffinity_np");

	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u receive packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	for (;;) {
		for (port = 0; port < nb_ports; port++) {
			struct rte_mbuf *bufs[BURST_SIZE];
            int queue_id;
            for(queue_id = 0; queue_id < queue_num;queue_id ++){
			const uint16_t nb_rx = rte_eth_rx_burst(port, queue_id,
					bufs, BURST_SIZE);

           			   if (unlikely(nb_rx == 0)){
		        		    continue;
                       }
                       int i = 0;
                       int ret = 0;
                        for( i = 0;i<nb_rx;i++){
                             printf("queue_id is %d \n",queue_id);
                            // show_data(bufs[i]);
                             ret = change_data(bufs[i],port);
                            // show_data(bufs[i]);
                        }
                       
                        const uint16_t nb_tx = rte_eth_tx_burst(port, queue_id, bufs, nb_rx);
                      //  printf("after we send nb_tx  %d packet \n",nb_tx);

                        for( i = 0;i<nb_rx;i++){
                        //     printf("after we send the buff\n");
                        //     show_data(bufs[i]);
                        }
//                        if (unlikely(nb_tx < nb_rx)) {
//				             uint16_t buf;
//			        	    for (buf = nb_tx; buf < nb_rx; buf++){
//				        	rte_pktmbuf_free(bufs[buf]);
//                            }
//			            }
            }
		}
	}
}

/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint8_t portid = 0;
    ctxs_queue_id = 0;//this is for test
	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

        rte_eth_macaddr_get(portid,&ports_eth_addr[portid]);
                printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                                (unsigned) portid,
                                ports_eth_addr[portid].addr_bytes[0],
                                ports_eth_addr[portid].addr_bytes[1],
                                ports_eth_addr[portid].addr_bytes[2],
                                ports_eth_addr[portid].addr_bytes[3],
                                ports_eth_addr[portid].addr_bytes[4],
                                ports_eth_addr[portid].addr_bytes[5]);

#if 0
#else
    int queue_num = 8;
	current_iomodule_func->load_module(queue_num);
#endif
#if 0
	lcore_main(1,queue_num);
#else
      static pthread_t app_thread[MAX_CPUS]; 
      int cores[MAX_CPUS];
      pthread_attr_t attr[8];

//      cpu_set_t cpu_info[8];
      int core_limit = queue_num;
       
      int i = 0;


      sleep(1);
      int need = 1;
      for( i = 0; i<(core_limit+need);i++) {
         pthread_attr_init(&attr[i]);
         printf("i is %d and core_limit is %d \n",i,core_limit);
         if(i > core_limit){
             printf("is over need to break\n");
             break;
         }
        


//         CPU_ZERO(&cpu_info[i]);
//         CPU_SET(i + 5 , &cpu_info[i]);
//         pthread_attr_setaffinity_np(&attr[i], sizeof(cpu_set_t), &cpu_info[i]);
         if(i < core_limit){

             cores[i] = i;
             int err = 0;
             err =  pthread_create(&app_thread[i], NULL, test_main, (void *)&cores[i]);
             
             if(err != 0)
             {
                        printf("Failed to create server thread.\n");
             }
             sleep(1);
         }
         if( i == core_limit){
             cores[i] = i;
             int err;
             err =  pthread_create(&app_thread[i], NULL, test_check, (void *)&cores[i]);
             if(err != 0)
             {  
                        printf("Failed to create server thread.\n");
             }

             sleep(1);
         }
     }
     
      

     for (i = 0; i < (core_limit + need); i++) {
            pthread_join(app_thread[i], NULL);

     }

  //  printf("begin to run lcore_main device \n");


//	lcore_main();

#endif

	return 0;
}
