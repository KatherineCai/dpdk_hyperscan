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
#include <assert.h>

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
//#include "node.h"
#include "config.h"
#include <hs.h>
#include "nids_interface.h"
//#include <fstream>
//#include <iomanip>

static volatile bool force_quit;
/////////////
int match = 0;
char test[1]={"a"};
hs_scratch_t *scratch = NULL;
hs_database_t *database = NULL;
// http.dns.FTP
const char * pattern[12] = {
             "http/(0\\.9|1\\.0|1\\.1)[1-5][0-9][0-9]|post[\\x09-\\x0d -~]*http/[01]\\.[019]",
             "^.?.?.?.?[\\x01\\x02].?.?.?.?.?.?[\\x01-?][a-z0-9][\\x01-?a-z]*[\\x02-\\x06][a-z][a-z][fglmoprstuvz]?[aeop]?(um)?[\\x01-\\x10\\x1c][\\x01\\x03\\x04\\xFF]",
             "^(.?.?\\x16\\x03.*\\x16\\x03|.?.?\\x01\\x03\\x01?.*\\x0b)",
            "http",
			"^220[\\x09-\x0d -~]* (e?smtp|simple mail)",
			"^(\\+ok|-err)",
			"^ssh-[12]\\.[0-9]",
			"^\\xff[\\xfb-\\xfe].\\xff[\\xfb-\\xfe].\\xff[\\xfb-\\xfe]",
			"^[()]...?.?.?(reg|get|query)",
			"^[\\x01\\x02][\\x01- ]\\x06.*c\x82sc",
			"^(get[\\x09-\\x0d -~]* Accept: application/x-rtsp-tunnelled|http/(0\\.9|1\\.0|1\\.1) [1-5][0-9][0-9] [\\x09-\\x0d -~]*a=control:rtsp://)",
			"^.?.?\\x02.+\\x03$"};
char * protocol[12]={"http","dns","ftp","http","smtp","pop3","ssh","telnet","xunlei","dhcp","http_rtsp","qq"};
//int match = 0;
unsigned int ids[12]={0,1,2,3,4,5,6,7,8,9,10,11};
struct ipv4_hdr *ipHdr = NULL;
struct ipv4_hdr *ip_head = NULL;
unsigned int flags[12]={HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL,HS_FLAG_DOTALL};
   // pattern="file";
unsigned char * ptr;
int k=0;
hs_error_t err;
struct ether_hdr *ethHdr = NULL;
pthread_mutex_t mutex_b;
struct buf * first;
struct buf * last;
long item_count = 0;

uint32_t size = 0; 
//struct ring_buffer *ring_buf = NULL;
unsigned char* read_buffer;
uint32_t stream_get_count = 0;
uint32_t hyperscan_get_count = 0;
////////

/* MAC updating enabled by default */
static int mac_updating = 1;
/////////

#define is_power_of_2(x) ((x) != 0 && (((x) & ((x) - 1)) == 0))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define BUFFER_SIZE (1 << 30)
#define READ_BUFFER_SIZE (1 << 27)
/////////
#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define NB_MBUF   8192

#define MAX_PKT_BURST 500
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/* 
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int l2fwd_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
		.mq_mode = ETH_MQ_RX_RSS,
	},
	 .rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP | ETH_RSS_SCTP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */



////////////////////////////////////////


void print(){
	     struct buf * p;
	     p = head;
	     //FILE * fp;
	    // fp = fopen("data_test.txt","w");
	     if(head != NULL){
		         do{
					 int len = strlen(p->buffer);
//			             fprintf(stdout,"///////////the data is %s \n",p->buffer);
			             printf("///////////the data is %d: %s \n", len,p->buffer);
			             p = p->next;
			         }while(p != NULL);
		     }
	 }


static inline void
print_ether_addr(const char *what, struct ether_addr *eth_addr)
{
        char buf[ETHER_ADDR_FMT_SIZE];
        ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
        printf("%s%s", what, buf);
}
static int eventHandler(unsigned int id,unsigned long long from,unsigned long long to,unsigned int flags,void * ctx){
    fprintf(stderr,"match for pattern \"%s\" \n", pattern[id]);
	fprintf(stderr,"the protol is %s \n",protocol[id]);
    // rte_mbuf * mm=(rte_mbuf *)ctx; 
    fprintf(stderr,"the id  is  %u\n\n",id); 
    //print_ether_addr("src=",&ethHdr->s_addr);
    //print_ether_addr(" - dst=",&ethHdr->d_addr);
    //printf("src_ip = %x  = %d.%d.%d.%d \n",(ip_head->src_addr),(ip_head->src_addr & 0x000000ff)  , \
                                                               (ip_head->src_addr &0x0000ff00 ) >>8,  \
                                                               (ip_head->src_addr & 0x00ff0000 )>>16 ,  \
                                                                (ip_head->src_addr & 0xff000000)>>24);

    //printf("dst_ip = %x = %d.%d.%d.%d \n",(ip_head->dst_addr ),(ip_head->dst_addr & 0x000000ff)  , \
                                                                (ip_head->dst_addr &0x0000ff00 ) >>8,  \
                                                                (ip_head->dst_addr & 0x00ff0000 )>>16 ,  \
                                                                (ip_head->dst_addr & 0xff000000)>>24);

   // printf("the packet id is :%d \n",ip_head->packet_id);
   // printf("the protocol type is :%d \n \n \n \n",ip_head->next_proto_id);
    match += 1;
    return 0;
}

///////////////////////////////////////
/* Print out statistics on packets dropped */  
static void print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

/*	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
		*/
        struct rte_eth_stats eth_stats;
        int i;
		for (i = 0; i < 1; i++) {
            rte_eth_stats_get(i, &eth_stats);
            if(!eth_stats.ipackets && !eth_stats.opackets && !eth_stats.ierrors
                    && !eth_stats.oerrors && !eth_stats.rx_nombuf) continue;
            printf("\nPort %u stats:\n", i);
            printf(" - Pkts in:   %"PRIu64"\n", eth_stats.ipackets);
            printf(" - Pkts out:  %"PRIu64"\n", eth_stats.opackets);
            printf(" - In Errs:   %"PRIu64"\n", eth_stats.ierrors);
            printf(" - Out Errs:  %"PRIu64"\n", eth_stats.oerrors);
            printf(" - Mbuf Errs: %"PRIu64"\n", eth_stats.rx_nombuf);
        	printf(" - miss pkt:  %"PRIu64"\n", eth_stats.imissed);
		}
	printf("\n====================================================\n");
}  
static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
 {
	struct ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);
}

static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned portid)
{
	unsigned dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;

	dst_port = l2fwd_dst_ports[portid];

	if (mac_updating)
		l2fwd_mac_updating(m, dst_port);

	buffer = tx_buffer[dst_port];
	sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
	if (sent)
		port_statistics[dst_port].tx += sent;
}

/////////////////

struct kfifo {
    unsigned char *buffer;     /* the buffer holding the data */
    unsigned int size;         /* the size of the allocated buffer */
    unsigned int in;           /* data is added at offset (in % size) */
    unsigned int out;          /* data is extracted from off. (out % size) */
//	unsigned int placed;
	// spinlock_t *lock;          /* protects concurrent modifications */
} * ring_buf, *len_buf;

struct kfifo *kfifo_init(unsigned char *buffer, unsigned int size)
{ 
    struct kfifo *fifo = NULL;
    /* size must be a power of 2 */
   // BUG_ON(!is_power_of_2(size));
    fifo = malloc(sizeof(struct kfifo));
    if (!fifo)
        return fifo;
    fifo->buffer = buffer;
    fifo->size = size;
    fifo->in = fifo->out = 0;
   // fifo->lock = lock;

    return fifo;
}
unsigned long roundup_pow_of_two(unsigned long val)
{
    if((val & (val-1)) == 0)
	    return val;
    unsigned long maxulong = (unsigned long)((unsigned long)~0);
    unsigned long andv = ~(maxulong&(maxulong>>1));
    while((andv & val) == 0)
		andv = andv>>1;
   
  	return andv<<1;
}

void  kfree (struct kfifo *ring_buf)
{
    if (ring_buf)
    {
   		 if (ring_buf->buffer)
    	{
        	free(ring_buf->buffer);
        	ring_buf->buffer = NULL;
   		}
    	free(ring_buf);
    	ring_buf = NULL;
    }
}


struct kfifo *kfifo_alloc(unsigned int size)
{
    unsigned char *buffer;
    struct kfifo *ret;
    if (!is_power_of_2(size)) {
        //BUG_ON(size > 0x80000000);
        size = roundup_pow_of_two(size);
    	assert("the size is not the pow of 2!\n");
	}
    buffer = (char *)malloc(size);//size is /byte
    if (!buffer)
        assert("malloc buffer fail\n");
    ret = kfifo_init(buffer, size);

    if (!ret)
        kfree(ret);
    return ret;
}

static unsigned int __kfifo_put(struct kfifo *fifo,
            const unsigned char *buffer, unsigned int len)
{ 
    unsigned int l;
	len = min(len, fifo->size - fifo->in + fifo->out);
	if(len == 0) return 0;
    /*
     * Ensure that we sample the fifo->out index -before- we
     * start putting bytes into the kfifo.
     */
    //smp_mb();
    /* first put the data starting from fifo->in to buffer end */
    l = min(len, fifo->size - (fifo->in & (fifo->size - 1)));
    memcpy(fifo->buffer + (fifo->in & (fifo->size - 1)), buffer, l);
    /* then put the rest (if any) at the beginning of the buffer */
    memcpy(fifo->buffer, buffer + l, len - l);
	//printf("[put l: %d]\n", l);

    /*
     * Ensure that we add the bytes to the kfifo -before-
     * we update the fifo->in index.
     */
    //smp_wmb();
    fifo->in += len; 
    return len;
}

static inline unsigned int kfifo_put(struct kfifo *fifo,
                const unsigned char *buffer, unsigned int len)
{
    unsigned long flags;
    unsigned int ret;
   // spin_lock_irqsave(fifo->lock, flags);
    ret = __kfifo_put(fifo, buffer, len);
    //spin_unlock_irqrestore(fifo->lock, flags);
    return ret;
} 


static unsigned int __kfifo_get(struct kfifo *fifo,
							unsigned char *buffer, unsigned int len)
{
    unsigned int l;
	len = min(len, fifo->in - fifo->out);
	if(len == 0) return 0;
    /*
    /*
     * Ensure that we sample the fifo->in index -before- we
     * start removing bytes from the kfifo.
	 */
    //smp_rmb();
    /* first get the data from fifo->out until the end of the buffer */
    l = min(len, fifo->size - (fifo->out & (fifo->size - 1)));
	memcpy(buffer, fifo->buffer + (fifo->out & (fifo->size - 1)), l);
    /* then get the rest (if any) from the beginning of the buffer */
    memcpy(buffer + l, fifo->buffer, len - l);
//	printf("[get l: %d]\n", l);
	/*
     * Ensure that we remove the bytes from the kfifo -before-
     * we update the fifo->out index.
     */
    //smp_mb();
    fifo->out += len;
    return len;
} 
static inline  unsigned int kfifo_get(struct kfifo *fifo,
                     unsigned char *buffer, unsigned int len)
{
    unsigned long flags;
    unsigned int ret;
    //spin_lock_irqsave(fifo->lock, flags);
    ret = __kfifo_get(fifo, buffer, len);
	if (fifo->in == fifo->out)
        fifo->in = fifo->out = 0;
    //spin_unlock_irqrestore(fifo->lock, flags);
    return ret;
}

static unsigned int __kfifo_len(const struct kfifo * fifo) {
	return fifo->in - fifo->out;
}

static unsigned int kfifo_len(const struct kfifo* fifo) {
	unsigned int len = __kfifo_len(fifo);
	return len;
}



/////////////////
/* main processing loop */
static void
l2fwd_main_loop(int queue_id)
{   
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}
	
  //	size = BUFFER_SIZE;
 //	ring_buf = kfifo_alloc(size);
    
//	process_init();
    while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = l2fwd_dst_ports[qconf->rx_port_list[i]];
				buffer = tx_buffer[portid];

				sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
				if (sent)
					port_statistics[portid].tx += sent;

			}

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on master core */
					if (lcore_id == rte_get_master_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}
		/*
		 * Read packet from RX queues
		 */
        const uint8_t nb_ports = rte_eth_dev_count();
        //////////////////////////////
       // for (i = 0; i < qconf->n_rx_port; i++) {
        for (i = 0; i < 1; i++) {
			portid = qconf->rx_port_list[i];
			portid = 0;
		//	int q_id;
		//	for(q_id = 0; q_id < 4 ;q_id ++){
				nb_rx = rte_eth_rx_burst(portid, queue_id,
						 pkts_burst, MAX_PKT_BURST);
			
            	if(nb_rx == 0) continue;
            //printf("nb_rx: [%d]\nportid: [%d]\n", nb_rx, portid);
				port_statistics[portid].rx += nb_rx;
				for (j = 0; j < nb_rx; j++) {
					m = pkts_burst[j];
					uint32_t pkt_len = rte_pktmbuf_data_len(pkts_burst[j]);
					kfifo_put(ring_buf, &pkt_len, sizeof(pkt_len));
					
					char *t_buf = (char *)&pkt_len;
					int remain = sizeof(uint32_t);
					while(remain > 0) {
						uint32_t ret = kfifo_put(len_buf, t_buf, remain);
						t_buf += ret;
						remain -= ret;
					}
					kfifo_put(ring_buf, rte_pktmbuf_mtod(pkts_burst[j], char *), pkt_len);
					
					t_buf = (char *)rte_pktmbuf_mtod(pkts_burst[j], char *);
					remain = pkt_len;
//					printf("[PPPUT ptk_len: %u]\n", pkt_len);
					while(remain > 0) {
						uint32_t ret = kfifo_put(ring_buf, t_buf, remain);
						t_buf += ret;
						remain -= ret;
//						if(ret != 0) printf("[PPPUT read bytes: %u]\n", ret);
					}
					//put_data(rte_pktmbuf_data_len(pkts_burst[j]),rte_pktmbuf_mtod(pkts_burst[j],char *));
             //   ethHdr = rte_pktmbuf_mtod(m,struct ether_hdr*);
          //     ip_head = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr * , sizeof(struct ether_hdr));//+ sizeof(struct ipv4_hdr));
            //  fprintf(stderr,"data size: %ld",ip_head->total_length);
			   // ipHdr  = (struct ipv4_hdr *)((char *)ethHdr + 1);
				//rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				//l2fwd_simple_forward(m, portid);
             //   printf("pktmbuf is freed!! \n");
				rte_pktmbuf_free(m);
			}
		}
    }
}

void  get_data(){ 
	//pthread_mutex_lock( &mutex_b );
    struct buf* q = last->prev;
    while(1){
		if(item_count > 10) 
      	{
        	free_item();
        	item_count--;
			break;
      	} 
	}
    //pthread_mutex_unlock( &mutex_b );
}   

void stream_ressembly(){
	//static unsigned char * buffer = (const unsigned char*)malloc(READ_BUFFER_SIZE);
	read_buffer = (const unsigned char*)malloc(READ_BUFFER_SIZE);
	uint32_t pkt_len, remain;
	process_init();
	while(!force_quit){
		/*
		struct buf * tmp = last->prev;
		while(tmp != first && tmp != NULL){
			process_pkt_callback(tmp->buffer,tmp->len);
			tmp = tmp->prev;	 	
			//get_data();
		}
		*/
		while(1) {
			//while(kfifo_len(ring_buf) < sizeof(uint32_t));
			remain = sizeof(uint32_t);
			char* t_buf = (char*)&pkt_len;
			while(remain > 0) {
				int ret = kfifo_get(len_buf, t_buf, remain);
				t_buf += ret;
				remain -= ret;
			}
			remain = pkt_len;
			t_buf = (char*)read_buffer;
//		    printf("[GGGET ptk_len: %u]\n", pkt_len);
			while(remain > 0) {
				uint32_t ret = kfifo_get(ring_buf, t_buf, remain);
				t_buf += ret;
				remain -= ret;
//				printf("[GGGET read bytes: %u]\n", ret);
			}
			stream_get_count += 1;
			process_pkt_callback(read_buffer, pkt_len);
		}
	}
	free(read_buffer);
}

void hyperscan( ){
	fprintf(stderr,"hyperscan is coming\n");
   	if(hs_alloc_scratch(database,&scratch) != HS_SUCCESS){
        printf("error:unable to allocate scratch space.exiting.\n");
        err=hs_alloc_scratch(database,&scratch);
        printf("%d",err);           
		hs_free_database(database);
        return;
    }
	while(!force_quit){
	if(tail != NULL){
	struct buf * tmp = tail->prev;
    if(tmp != head){
		hyperscan_get_count += 1;
        if(hs_scan(database,tmp->buffer,tmp->len,0,scratch,eventHandler, tmp) != HS_SUCCESS){
            printf("error:cannot scan the input data!\n");
            err=hs_scan(database,tmp->buffer,tmp->len,0,scratch,eventHandler,tmp);
            printf("%d`",err);
            //    hs_free_scratch(scratch);
            //   hs_free_database(database);
            return;
        }
		//	fprintf(stderr,"scanning successfully\n");
        	tmp->state = 1;
      }  	
	}
  }
}

void  free_item(){
 	int k;
	struct buf *p;
	//printf("  ///free this node!!////");
    p = last->prev;
    if(p->prev != first){
        last->prev = p->prev;
        p->prev->next = last;
    }else{
        first->next = last;
        last->prev = first;
    }   
    if ( p != first ){
       // free( p ); 
      	kfifo_get(ring_buf,p->buffer,p->len); 
		p = NULL;
        } 
}

void put_data(int size,char * data){
//	pthread_mutex_lock( &mutex_b );
	//printf("///i am puting data!!\n");
    create_item( size, data );
    item_count++;
  //  pthread_mutex_unlock( &mutex_b );
    //sleep( 1 );
}
void create_item( int size, char *data ){
	struct buf *con;
/*
    if ( !(con = (struct buf *) malloc( sizeof(struct buf) ) ) )
    {
        assert( "con malloc fail!" );
    }

    if ( !(con->buffer = (char *) malloc( size * sizeof(char) ) ) )
    {
        assert( "con buffer malloc fail!" );
    }
*/	
//	memset( con->buffer, 0, size * sizeof(char) );
//    memcpy( con->buffer, data, size * sizeof(char) );
 	kfifo_put(ring_buf,size, sizeof(size));
	kfifo_put(ring_buf,data,size); 
	con->len  = size;
    con->prev = NULL;
    con->state= 0;
    con->next = NULL;
	if ( first->next == last )
    {
        first->next = con;
		con->prev = first;
        con->next = last;
        last->prev = con;
    }else{
        con->prev = first;
        con->next = first->next;
     //   first->next = con;
        first->next->prev = con;
        first->next = con;

    }
}

void init_datalink(){
	if(!(first = (struct buf *)malloc(sizeof(struct buf)))){
		 assert("head maclloc fail!!");
	}
	if(!(last = (struct buf *)malloc(sizeof(struct buf)))){
         assert("tail malloc fail!!");
	}
	 
	first->len  = 0;
    first->prev = NULL;
    first->state= 0;
    first->next =last;

    last->len  = 0;
    last->prev = first;
    last->next = NULL;
    last->state = 0;
}


static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	//read_buffer = (const unsigned char*)malloc(READ_BUFFER_SIZE);
	unsigned lcore_id;
	init_datalink();
 	pthread_mutex_init(&mutex_b,NULL);
	
	size = BUFFER_SIZE;
	ring_buf = kfifo_alloc(size);
	len_buf = kfifo_alloc(size);
	lcore_id = rte_lcore_id();
	if(lcore_id  == 0 ){
		l2fwd_main_loop(0);
 	}
	else if(lcore_id  == 1){
		stream_ressembly();	
	}else if(lcore_id == 2){
		hyperscan();
	}
//	l2fwd_main_loop();
	//////////////////free(read_buffer);
	return 0;
} 

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
		   "  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
		   "      When enabled:\n"
		   "       - The source MAC address is replaced by the TX port MAC address\n"
		   "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n",
	       prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static const char short_options[] =
	"p:"  /* portmask */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
};

static const struct option lgopts[] = {
	{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
	{NULL, 0, 0, 0}
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* long options */
		case 0:
			break;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint16_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
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
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_info dev_info;
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available;
	uint16_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");

	printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	/* create the mbuf pool */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;
	last_port = 0;

	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			l2fwd_dst_ports[portid] = last_port;
			l2fwd_dst_ports[last_port] = portid;
		}
		else
			last_port = portid;

		nb_ports_in_mask++;

		rte_eth_dev_info_get(portid, &dev_info);
	}
	if (nb_ports_in_mask % 2) {
		printf("Notice: odd number of ports in portmask.\n");
		l2fwd_dst_ports[last_port] = last_port;
	}

	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id])
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
	}

	nb_ports_available = nb_ports;

	/* Initialise each port */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			nb_ports_available--;
			continue;
		}
		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);
		ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);
		rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);

		/* init one RX queue */
		fflush(stdout);
		int q;
	//	for(q = 0;q < 4;q ++){
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     NULL,
					     l2fwd_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, portid);
		//}
		/* init one TX queue on each port */
		fflush(stdout);
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);

		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");

		rte_eth_promiscuous_enable(0);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(nb_ports, l2fwd_enabled_port_mask);



//////////////////////////////////////
    ret = rte_eal_has_hugepages();
    if(unlikely(ret < 0)){
        rte_panic("\n Error:no huge page\n");
        exit(EXIT_FAILURE);
    }

    hs_compile_error_t *compile_err;
//    printf("pattern=%s \n HS_FLAG_DOTALL=%d \n HS_MODE_BLOCK=%d \n &database=%d \n &compile_err=%d \n", pattern,
 //           HS_FLAG_DOTALL, HS_MODE_BLOCK,(unsigned int)&database,(unsigned int)&compile_err);
    if(hs_compile_multi((const char * const *)pattern,flags,ids,4,HS_MODE_BLOCK,NULL,&database,&compile_err) != HS_SUCCESS){
        if (compile_err->expression < 0) {
            // The error does not refer to a particular expression.
            printf("error:%s \n",compile_err->message);  
            } else {
                printf("error:pattern %s \n",pattern[compile_err->expression]);                       		  printf( " failed compilation with error: %s" ,compile_err->message);
            }
        hs_free_compile_error(compile_err);
        return -1;
    }
    
  //      while(1)
            rte_delay_ms(1000);
      //  hs_free_database(database);
////////////////////////////////////////
	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);
	////////////////
  hs_free_scratch(scratch);
  hs_free_database(database);
  //////////////////
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	for (portid = 0; portid < nb_ports; portid++) {
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}
