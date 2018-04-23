/* for io_module_func def'ns */
#include "./include/io_module.h"

//#include "dpdk_module.h"
#ifndef DISABLE_DPDK
/* for mtcp related def'ns */
#include "./include/qstack.h"

#include "./include/datatype.h"
/* for errno */
#include <errno.h>
#include <assert.h>
/* for rte_max_eth_ports */
#include <rte_common.h>
/* for rte_eth_rxconf */
#include <rte_ethdev.h>
/* for delay funcs */
#include <rte_cycles.h>
#include <rte_errno.h>
#define ENABLE_STATS_IOCTL		1
#ifdef ENABLE_STATS_IOCTL
/* for close */
#include <unistd.h>
/* for open */
#include <fcntl.h>
/* for ioctl */
#include <sys/ioctl.h>
#endif /* !ENABLE_STATS_IOCTL */
/* for ip pseudo-chksum */
#include <rte_ip.h>

#include <rte_tcp.h>
//#define IP_DEFRAG			1
#ifdef IP_DEFRAG
/* for ip defragging */
#include <rte_ip_frag.h>
#endif
/*----------------------------------------------------------------------------*/
/* Essential macros */
#define MAX_RX_QUEUE_PER_LCORE		MAX_CPUS
#define MAX_TX_QUEUE_PER_PORT		MAX_CPUS

#ifdef ENABLELRO
#define BUF_SIZE			16384
#else
#define BUF_SIZE			2048
#endif /* !ENABLELRO */
#define MBUF_SIZE 			(BUF_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF				81920
#define MEMPOOL_CACHE_SIZE		256
//#define RX_IDLE_ENABLE			1
#define RX_IDLE_TIMEOUT			1	/* in micro-seconds */
#define RX_IDLE_THRESH			64

#define MBUF_CACHE_SIZE 250
/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 			8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 			8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 			4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 			36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH			0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH			0  /**< Default values of TX write-back threshold reg. */

#define MAX_PKT_BURST			64/*128*/

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT	512
#define RTE_TEST_TX_DESC_DEFAULT	512

/*
 * Ethernet frame overhead
 */

#define ETHER_IFG			12
#define	ETHER_PREAMBLE			8
#define ETHER_OVR			(ETHER_CRC_LEN + ETHER_PREAMBLE + ETHER_IFG)


#define swab16(x) ((x&0x00ff) << 8 | (x&0xff00) >> 8)
#define swab32(x) ((x&0x000000ff) << 24 | (x&0x0000ff00) << 8 | (x&0x00ff0000) >> 8 | (x&0xff000000) >> 24)


static uint16_t nb_rxd = 		RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = 		RTE_TEST_TX_DESC_DEFAULT;
/*----------------------------------------------------------------------------*/
/* packet memory pools for storing packet bufs */
static struct rte_mempool *pktmbuf_pool[128] = {NULL};

//#define DEBUG				1
#ifdef DEBUG
/* ethernet addresses of ports */
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
#endif

static struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];

static const struct rte_eth_conf port_conf_default = {
         .rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload enabled */
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
#if 0
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode	= 	ETH_MQ_RX_RSS,
		.max_rx_pkt_len = 	ETHER_MAX_LEN,
		.split_hdr_size = 	0,
		.header_split   = 	0, /**< Header Split disabled */
		.hw_ip_checksum = 	1, /**< IP checksum offload enabled */
		.hw_vlan_filter = 	0, /**< VLAN filtering disabled */
		.jumbo_frame    = 	0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 	1, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = 	NULL,
			.rss_hf = 	ETH_RSS_TCP | ETH_RSS_UDP |
					ETH_RSS_IP | ETH_RSS_L2_PAYLOAD
		},
	},
	.txmode = {
		.mq_mode = 		ETH_MQ_TX_NONE,
	},
};
#endif
static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = 		RX_PTHRESH, /* RX prefetch threshold reg */
		.hthresh = 		RX_HTHRESH, /* RX host threshold reg */
		.wthresh = 		RX_WTHRESH, /* RX write-back threshold reg */
	},
	.rx_free_thresh = 		32,
};

//        txconf = &dev_info.default_txconf;
//        txconf->tx_free_thresh = 0;
//        txconf->txq_flags = 0;
static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = 		TX_PTHRESH, /* TX prefetch threshold reg */
		.hthresh = 		TX_HTHRESH, /* TX host threshold reg */
		.wthresh = 		TX_WTHRESH, /* TX write-back threshold reg */
	},
	.tx_free_thresh = 		0, /* Use PMD default values */
	.tx_rs_thresh = 		0, /* Use PMD default values */
	/*
	 * As the example won't handle mult-segments and offload cases,
	 * set the flag by default.
	 */
	.txq_flags = 			0,
};
#define MAX_MTABLE 20000
struct mbuf_table_q {
       volatile int head;
       volatile int tail;
       struct rte_mbuf *m_table[MAX_MTABLE];
       volatile int len;
       int queue_id;
       int type;

};



struct mbuf_table {
	unsigned len; /* length of queued packets */
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct dpdk_private_context {
	struct mbuf_table rmbufs[RTE_MAX_ETHPORTS];
	struct mbuf_table wmbufs[RTE_MAX_ETHPORTS];
	struct rte_mempool *pktmbuf_pool;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];


	struct rte_mbuf *pkts_rxburst[MAX_PKT_BURST];
        int rx_num;
	struct rte_mbuf *pkts_txburst[MAX_PKT_BURST];
        int tx_num;

        struct mbuf_table_q rh_mbufs[RTE_MAX_ETHPORTS];
        struct mbuf_table_q rl_mbufs[RTE_MAX_ETHPORTS];

        struct mbuf_table_q tl_mbufs[RTE_MAX_ETHPORTS];
        struct mbuf_table_q th_mbufs[RTE_MAX_ETHPORTS];

} __rte_cache_aligned;

/* new struct add here







*/
#ifdef ENABLE_STATS_IOCTL
#define DEV_NAME				"/dev/dpdk-iface"
/**
 * stats struct passed on from user space to the driver
 */
struct stats_struct {
	uint64_t tx_bytes;
	uint64_t tx_pkts;
	uint64_t rx_bytes;
	uint64_t rx_pkts;
	uint64_t rmiss;
	uint64_t rerr;
	uint64_t terr;
	uint8_t qid;
	uint8_t dev;
};
#endif /* !ENABLE_STATS_IOCTL */

#ifdef IP_DEFRAG
/* Should be power of two. */
#define IP_FRAG_TBL_BUCKET_ENTRIES		16
#define RTE_LOGTYPE_IP_RSMBL 			RTE_LOGTYPE_USER1
#define MAX_FRAG_NUM				RTE_LIBRTE_IP_FRAG_MAX_FRAG
#endif /* !IP_DEFRAG */
/*----------------------------------------------------------------------------*/
void
dpdk_init_handle(struct mtcp_thread_context *ctxt)
{
	struct dpdk_private_context *dpc;
	int i, j;
	char mempool_name[RTE_MEMPOOL_NAMESIZE];

	/* create and initialize private I/O module context */
	ctxt->io_private_context = calloc(1, sizeof(struct dpdk_private_context));
	if (ctxt->io_private_context == NULL) {
		exit(EXIT_FAILURE);
	}

	sprintf(mempool_name, "mbuf_pool-%d", ctxt->cpu);
	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	dpc->pktmbuf_pool = pktmbuf_pool[ctxt->queue];
        
        printf("dpc->pktmbuf_pool addr  is 0x%x and ctx->cpu is %d \n",dpc->pktmbuf_pool,ctxt->queue);
         
/* need change here */
#if 0
	/* set wmbufs correctly */
	for (j = 0; j < num_devices_attached; j++) {
		/* Allocate wmbufs for each registered port */
		for (i = 0; i < MAX_PKT_BURST; i++) {
			dpc->wmbufs[j].m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool[ctxt->cpu]);
			if (dpc->wmbufs[j].m_table[i] == NULL) {
				TRACE_ERROR("Failed to allocate %d:wmbuf[%d] on device %d!\n",
					    ctxt->cpu, i, j);
				exit(EXIT_FAILURE);
			}
		}
		/* set mbufs queue length to 0 to begin with */
		dpc->wmbufs[j].len = 0;
	}
#endif
}
/*----------------------------------------------------------------------------*/
int
dpdk_link_devices(struct mtcp_thread_context *ctxt)
{
	/* linking takes place during mtcp_init() */

	return 0;
}
/*----------------------------------------------------------------------------*/
void
dpdk_release_pkt(struct mtcp_thread_context *ctxt, int ifidx, unsigned char *pkt_data, int len)
{
	/*
	 * do nothing over here - memory reclamation
	 * will take place in dpdk_recv_pkts
	 */
}
/*----------------------------------------------------------------------------*/
int
dpdk_send_pkts(struct mtcp_thread_context *ctxt, int ifidx)
{
	struct dpdk_private_context *dpc;
	mtcp_manager_t mtcp;
	int ret, i, portid = 0;//CONFIG.eths[ifidx].ifindex;

	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	mtcp = ctxt->mtcp_manager;
	ret = 0;

	/* if there are packets in the queue... flush them out to the wire */
	if (dpc->wmbufs[ifidx].len >/*= MAX_PKT_BURST*/ 0) {
		struct rte_mbuf **pkts;
		int cnt = dpc->wmbufs[ifidx].len;
		pkts = dpc->wmbufs[ifidx].m_table;
		do {
			/* tx cnt # of packets */
			ret = rte_eth_tx_burst(portid, ctxt->cpu,
					       pkts, cnt);
			pkts += ret;
			cnt -= ret;
			/* if not all pkts were sent... then repeat the cycle */
		} while (cnt > 0);

		/* time to allocate fresh mbufs for the queue */
		for (i = 0; i < dpc->wmbufs[ifidx].len; i++) {
			dpc->wmbufs[ifidx].m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool[ctxt->cpu]);
			/* error checking */
			if (unlikely(dpc->wmbufs[ifidx].m_table[i] == NULL)) {
				exit(EXIT_FAILURE);
			}
		}
		/* reset the len of mbufs var after flushing of packets */
		dpc->wmbufs[ifidx].len = 0;
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
uint8_t *
dpdk_get_wptr(struct mtcp_thread_context *ctxt, int ifidx, uint16_t pktsize)
{
	struct dpdk_private_context *dpc;
	mtcp_manager_t mtcp;
	struct rte_mbuf *m;
	uint8_t *ptr;
	int len_of_mbuf;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	mtcp = ctxt->mtcp_manager;

	/* sanity check */
	if (unlikely(dpc->wmbufs[ifidx].len == MAX_PKT_BURST))
		return NULL;

	len_of_mbuf = dpc->wmbufs[ifidx].len;
	m = dpc->wmbufs[ifidx].m_table[len_of_mbuf];

	/* retrieve the right write offset */
	ptr = (void *)rte_pktmbuf_mtod(m, struct ether_hdr *);
	m->pkt_len = m->data_len = pktsize;
	m->nb_segs = 1;
	m->next = NULL;

#ifdef NETSTAT
	mtcp->nstat.tx_bytes[ifidx] += pktsize + ETHER_OVR;
#endif

	/* increment the len_of_mbuf var */
	dpc->wmbufs[ifidx].len = len_of_mbuf + 1;

	return (uint8_t *)ptr;
}
/*----------------------------------------------------------------------------*/
static inline void
free_pkts(struct rte_mbuf **mtable, unsigned len)
{
	int i;

	/* free the freaking packets */
	for (i = 0; i < len; i++) {
		rte_pktmbuf_free(mtable[i]);
		RTE_MBUF_PREFETCH_TO_FREE(mtable[i+1]);
	}
}
/*----------------------------------------------------------------------------*/
int32_t
dpdk_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx)
{
	struct dpdk_private_context *dpc;
	int ret;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;

	if (dpc->rmbufs[ifidx].len != 0) {
//		free_pkts(dpc->rmbufs[ifidx].m_table, dpc->rmbufs[ifidx].len);
		dpc->rmbufs[ifidx].len = 0;
	}

	int portid = 0;//CONFIG.eths[ifidx].ifindex;
	ret = rte_eth_rx_burst((uint8_t)portid, ctxt->queue,
			       dpc->pkts_burst, MAX_PKT_BURST);
#ifdef RX_IDLE_ENABLE
	dpc->rx_idle = (likely(ret != 0)) ? 0 : dpc->rx_idle + 1;
#endif
	dpc->rmbufs[ifidx].len = ret;

	return ret;
}
/*----------------------------------------------------------------------------*/
#ifdef IP_DEFRAG
struct rte_mbuf *
ip_reassemble(struct dpdk_private_context *dpc, struct rte_mbuf *m)
{
	struct ether_hdr *eth_hdr;
	struct rte_ip_frag_tbl *tbl;
	struct rte_ip_frag_death_row *dr;

	/* if packet is IPv4 */
	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
		struct ipv4_hdr *ip_hdr;

		eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
		ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

		/* if it is a fragmented packet, then try to reassemble. */
		if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr)) {
			struct rte_mbuf *mo;

			tbl = dpc->frag_tbl;
			dr = &dpc->death_row;

			/* prepare mbuf: setup l2_len/l3_len. */
			m->l2_len = sizeof(*eth_hdr);
			m->l3_len = sizeof(*ip_hdr);

			/* process this fragment. */
			mo = rte_ipv4_frag_reassemble_packet(tbl, dr, m, rte_rdtsc(), ip_hdr);
			if (mo == NULL)
				/* no packet to send out. */
				return NULL;

			/* we have our packet reassembled. */
			if (mo != m)
				m = mo;
		}
	}

	/* if packet isn't IPv4, just accept it! */
	return m;
}
#endif
/*----------------------------------------------------------------------------*/
uint8_t *
dpdk_get_rptr(struct mtcp_thread_context *ctxt, int ifidx, int index, uint16_t *len)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	uint8_t *pktbuf;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;

	m = dpc->pkts_burst[index];
#ifdef IP_DEFRAG
	m = ip_reassemble(dpc, m);
#endif
	*len = m->pkt_len;
	pktbuf = rte_pktmbuf_mtod(m, uint8_t *);

	/* enqueue the pkt ptr in mbuf */
	dpc->rmbufs[ifidx].m_table[index] = m;

	/* verify checksum values from ol_flags */
	if ((m->ol_flags & (PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD)) != 0) {
		pktbuf = NULL;
	}
#ifdef ENABLELRO
	dpc->cur_rx_m = m;
#endif /* ENABLELRO */

	return pktbuf;
}
/*----------------------------------------------------------------------------*/
int32_t
dpdk_select(struct mtcp_thread_context *ctxt)
{
#ifdef RX_IDLE_ENABLE
	struct dpdk_private_context *dpc;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
	if (dpc->rx_idle > RX_IDLE_THRESH) {
		dpc->rx_idle = 0;
		usleep(RX_IDLE_TIMEOUT);
	}
#endif
	return 0;
}
/*----------------------------------------------------------------------------*/
void
dpdk_destroy_handle(struct mtcp_thread_context *ctxt)
{
	struct dpdk_private_context *dpc;
	int i;

	dpc = (struct dpdk_private_context *) ctxt->io_private_context;
/*need change*/
#if 0
	/* free wmbufs */
	for (i = 0; i < num_devices_attached; i++)
		free_pkts(dpc->wmbufs[i].m_table, MAX_PKT_BURST);

#endif

	/* free it all up */
	free(dpc);
}
/*----------------------------------------------------------------------------*/
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 			100 /* 100ms */
#define MAX_CHECK_TIME 			90 /* 9s (90 * 100ms) in total */

	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
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


int port_init(uint8_t port, struct rte_mempool *mbuf_pool)
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
		retval = rte_eth_rx_queue_setup(port, q, 128,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_queue; q++) {

        txconf = &dev_info.default_txconf;
        txconf->tx_free_thresh = 0;
        txconf->txq_flags = 0;
        

		retval = rte_eth_tx_queue_setup(port, q, 512,
				rte_eth_dev_socket_id(port), txconf);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0){
		return retval;
    }else{
        return 0;
    }
           
}
/*----------------------------------------------------------------------------*/
void
dpdk_load_module(int queue_num)
{

#if 0

	struct rte_mempool *mbuf_pool;
	uint8_t portid;

	/* init EAL */
//	int ret = rte_eal_init(argc, argv);



	int nb_ports = rte_eth_dev_count();
//	if (nb_ports != 1)
//		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	pktmbuf_pool[0] = rte_pktmbuf_pool_create("MBUF_POOL",
		8000 * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    mbuf_pool = pktmbuf_pool[0];
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);


	/* call lcore_main on master core only */
	return 0;
#else
	int portid, rxlcore_id, ret;
	/* for Ethernet flow control settings */
	struct rte_eth_fc_conf fc_conf;
        portid = 0;
        rte_eth_dev_stop(portid);

	/* setting the rss key */

//	if (!CONFIG.multi_process || (CONFIG.multi_process && CONFIG.multi_process_is_master)) 
      //  if (1)
        {
		for (rxlcore_id = 0; rxlcore_id < queue_num; rxlcore_id++) {
			char name[RTE_MEMPOOL_NAMESIZE];
			uint32_t nb_mbuf;
			sprintf(name, "mbuf_pool-%d", rxlcore_id);
			nb_mbuf = NB_MBUF;
			/* create the mbuf pools */

	        pktmbuf_pool[rxlcore_id] = rte_pktmbuf_pool_create(name,
		         nb_mbuf, MBUF_CACHE_SIZE, 0,
		         RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	        if (pktmbuf_pool[rxlcore_id] == NULL){
		        printf("Cannot create mbuf pool in rxlcore_id %d\n",rxlcore_id);
            }else{
                printf("mempool init over and pktmbuf_pool addr  is 0x%x and rxlcore_id is %d \n",pktmbuf_pool[rxlcore_id],rxlcore_id);
            }
		}

		/* Initialise each port */
		int i;
        int  num_devices_attached =  rte_eth_dev_count();
        printf("num_devices_attached is %d \n",num_devices_attached);
        for (i = 0; i < num_devices_attached; ++i)
        {
		        /* get portid form the index of attached devices */
		        portid = i;//devices_attached[i];
			/* init port */ 
		printf("Initializing port %u... \n", (unsigned) portid);
		fflush(stdout);

	    struct rte_eth_txconf *txconf;
        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(portid,&dev_info);

       	const uint16_t rx_queue = queue_num, tx_queue = queue_num;




   

  	    ret = rte_eth_dev_configure(portid, rx_queue, tx_queue, &port_conf_default);
//			ret = rte_eth_dev_configure(portid, 8, 8, &port_conf_default);
		if (ret < 0){
   		    rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
					 ret, (unsigned) portid);
        }else{
            printf("init port %d success \n",portid);
        }
			/* init one RX queue per CPU */
		fflush(stdout);
			/* check port capabilities */
        int port = portid;
        int q = 0;

        printf("begin to init rx_queue and tx_queue \n");
        for (q = 0; q < rx_queue; q++) {
                ret = 0;

                printf("pktmbuf_pool addr[%d]  is 0x%x \n",q,pktmbuf_pool[q]);
	  	        ret = rte_eth_rx_queue_setup(port, q, nb_rxd,rte_eth_dev_socket_id(port), NULL, pktmbuf_pool[q]);
      	        if (ret < 0){
                    printf("setup rx queue fail in rx_queue %d \n",q);
                }else{

                    printf("setup rx queue success in rx_queue %d \n",q);
                }
        }

       	for (q = 0; q < tx_queue; q++) {
            ret = 0;

            txconf = &dev_info.default_txconf;
            txconf->tx_free_thresh = 0;
            txconf->txq_flags = 0;
	        ret = rte_eth_tx_queue_setup(port, q, nb_txd,
			rte_eth_dev_socket_id(port), txconf);
	        if (ret < 0){
            printf("setup tx queue fail \n");
            }
        }

  	printf("done: \n");
#if 1
			rte_eth_promiscuous_enable(portid);

                        /* retrieve current flow control settings per port */
	memset(&fc_conf, 0, sizeof(fc_conf));
        ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
	if (ret != 0){
                      rte_exit(EXIT_FAILURE, "Failed to get flow control info!\n");
        }else{
                     RTE_LOG(CRIT, EAL, "get fd success \n");
        }
			/* and just disable the rx/tx flow control */\
                          
                        RTE_LOG(CRIT, EAL, "fc_conf->send_xon is %d \n",fc_conf.send_xon);
			fc_conf.mode = RTE_FC_TX_PAUSE;
			ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
                        if (ret != 0)
                                rte_exit(EXIT_FAILURE, "Failed to set flow control info!: errno: %d\n",
                                         ret);
#endif



		}
	}

        printf("begin to start device \n");
			/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0){
				rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
					 ret, (unsigned) portid);
                }
#endif
}
/*----------------------------------------------------------------------------*/
int
dpdk_dev_ioctl(struct mtcp_thread_context *ctx, int nif, int cmd, void *argp)
{
	return 0;
}
int dpdk_soft_filter(struct rte_mbuf * pkt_mbuf){
/*
     unsigned char *ptr = pkt_mbuf->buf_addr + pkt_mbuf->data_off;

     int i = (sizeof(struct ether_hdr)+sizeof(struct ip_head_data)+sizeof(struct tcphdr) + 5)

     if(*(ptr + i) ==  1){
         return 0;
     }else{
         return 1;
     }
*/
}

void  dpdk_check_tx_device(struct mtcp_thread_context *ctxt){

//second for send
#if 1

    int portid = 0;// port;//CONFIG.eths[ifidx].ifindex;
    int level = 0;
    int ret = 0;
    volatile int head = 0;
    volatile int tail = 0;
    volatile int lhead = 0;
    volatile int ltail = 0;
    int i =0;
    struct dpdk_private_context *dpc;
    dpc = (struct dpdk_private_context *) ctxt->io_private_context;
    struct mbuf_table_q *tx_low_mbufs = &dpc->tl_mbufs[portid];

    struct mbuf_table_q *tx_high_mbufs = &dpc->th_mbufs[portid];
    
    struct mbuf_table_q *tx_mbufs = NULL;
    int send_level = 0;
    while(send_level <= 1){

    if(send_level == 0){
        tx_mbufs = tx_high_mbufs;
        send_level = 1;
        }else{
        tx_mbufs = tx_low_mbufs;
        send_level = 2;
        }
    head = tx_mbufs->head;
    tail = tx_mbufs->tail;
    
    int be = tail - head;
    if(be < 0){
        be = be + MAX_MTABLE;
        }
    volatile int max_send = be;
    int count = 0;
    if(max_send != 0){
       //  printf("we will  do something here and max_send is %d and head is %d and tail is %d \n",max_send,head,tail);
        }
    if(send_level == 2){
        //for low level just send a burst;
        if(max_send > MAX_PKT_BURST){
            max_send = MAX_PKT_BURST;
            }
    }
    for(i = 0;i<max_send;){
        int send_num;
        if(max_send - i > MAX_PKT_BURST){
            send_num = MAX_PKT_BURST;
            }else{
            send_num = max_send - i;
            }
        int k = 0;
        for(k = 0;k<send_num;k++){
               dpc->pkts_burst[k%MAX_MTABLE] = tx_mbufs->m_table[(head + i + k)%MAX_MTABLE];
            }
        int tx_nm = 0;
        tx_nm = rte_eth_tx_burst((uint8_t)portid, ctxt->queue,dpc->pkts_burst, send_num);
        i = i + tx_nm;
    }
    tx_mbufs->head = (tx_mbufs->head + max_send)%MAX_MTABLE;
        

    }

#endif
}



void  dpdk_check_rx_device(struct mtcp_thread_context *ctxt){


    int ret = 0;
    volatile int head = 0;
    volatile int tail = 0;
    volatile int lhead = 0;
    volatile int ltail = 0;
    struct dpdk_private_context *dpc;
    dpc = (struct dpdk_private_context *) ctxt->io_private_context;
    
    int portid = 0;// port;//CONFIG.eths[ifidx].ifindex;
    int level = 0;

//first for read
    struct mbuf_table_q *rx_mbufs;

    struct mbuf_table_q *rx_low_mbufs;
    int i = 0;
    int isfull = 0;

    int test = 0;
    
    ret = rte_eth_rx_burst((uint8_t)portid, (ctxt->queue),
			       dpc->pkts_burst,MAX_PKT_BURST);

    for( i = 0	;i< ret ;i++){
         level = dpdk_soft_filter(dpc->pkts_burst[i]);
         if(level == 0){
             rx_mbufs = &dpc->rl_mbufs[portid];
         }else{
             rx_mbufs = &dpc->rh_mbufs[portid];
         }
               
         head = rx_mbufs->head;
         tail = rx_mbufs->tail;
         rx_mbufs->m_table[tail] = dpc->pkts_burst[i];
         if((tail + 1)%MAX_MTABLE == head ){
             break;
         }
         tail = (tail + 1)%MAX_MTABLE;
         rx_mbufs->tail = tail;
         
     }
}
void  dpdk_check_device(struct mtcp_thread_context *ctxt){


    int ret = 0;
    volatile int head = 0;
    volatile int tail = 0;
    volatile int lhead = 0;
    volatile int ltail = 0;
    struct dpdk_private_context *dpc;
    dpc = (struct dpdk_private_context *) ctxt->io_private_context;
    
    int portid = 0;// port;//CONFIG.eths[ifidx].ifindex;
    int level = 0;

//first for read
    struct mbuf_table_q *rx_mbufs;

    struct mbuf_table_q *rx_low_mbufs;
    int i = 0;
    int isfull = 0;

    int test = 0;
    
    ret = rte_eth_rx_burst((uint8_t)portid, (ctxt->queue),
			       dpc->pkts_burst,MAX_PKT_BURST);

    for( i = 0	;i< ret ;i++){
         level = dpdk_soft_filter(dpc->pkts_burst[i]);
         if(level == 0){
             rx_mbufs = &dpc->rl_mbufs[portid];
         }else{
             rx_mbufs = &dpc->rh_mbufs[portid];
         }
               
         head = rx_mbufs->head;
         tail = rx_mbufs->tail;
         rx_mbufs->m_table[tail] = dpc->pkts_burst[i];
         if((tail + 1)%MAX_MTABLE == head ){
             break;
         }
         tail = (tail + 1)%MAX_MTABLE;
         rx_mbufs->tail = tail;
         
     }
/*need change*/
//second for send
#if 1
    struct mbuf_table_q *tx_low_mbufs = &dpc->tl_mbufs[portid];

    struct mbuf_table_q *tx_high_mbufs = &dpc->th_mbufs[portid];
    
    struct mbuf_table_q *tx_mbufs = NULL;
    int send_level = 0;
    while(send_level <= 1){

    if(send_level == 0){
        tx_mbufs = tx_high_mbufs;
        send_level = 1;
        }else{
        tx_mbufs = tx_low_mbufs;
        send_level = 2;
        }
    head = tx_mbufs->head;
    tail = tx_mbufs->tail;
    
    int be = tail - head;
    if(be < 0){
        be = be + MAX_MTABLE;
        }
    volatile int max_send = be;
    int count = 0;
    if(send_level == 2){
        //for low level just send a burst;
        if(max_send > MAX_PKT_BURST){
            max_send = MAX_PKT_BURST;
            }
    }
    for(i = 0;i<max_send;){
        int send_num;
        if(max_send - i > MAX_PKT_BURST){
            send_num = MAX_PKT_BURST;
            }else{
            send_num = max_send - i;
            }
        int k = 0;
        for(k = 0;k<send_num;k++){
               dpc->pkts_burst[k%MAX_MTABLE] = tx_mbufs->m_table[(head + i + k)%MAX_MTABLE];
            }
        int tx_nm = 0;
        tx_nm = rte_eth_tx_burst((uint8_t)portid, ctxt->queue,dpc->pkts_burst, send_num);
        i = i + tx_nm;
    }
    tx_mbufs->head = (tx_mbufs->head + max_send)%MAX_MTABLE;
    }
#endif


}

int32_t  dpdk_rx_receive_one(struct mtcp_thread_context *ctxt,int level,int port,struct rte_mbuf *ptr){

    int ret = 0;
    int head = 0;
    int tail = 0;
    int i = 0;
    struct mbuf_table_q *rx_mbufs;

    struct dpdk_private_context *dpc;
    dpc = (struct dpdk_private_context *) ctxt->io_private_context;
    if(level == 0){
         rx_mbufs = &dpc->rl_mbufs[port];
    }else{
         rx_mbufs = &dpc->rh_mbufs[port];
    }

    head = rx_mbufs->head;
    tail = rx_mbufs->tail;

    int be = tail - head;
    if(be < 0 ){
    be = be + MAX_MTABLE;
    }
    int max_receive = be;
    if(max_receive < 0){
    max_receive = 0;
    return -1;
    }

    for( i = 0; i < 1; i++){
        ptr = rx_mbufs->m_table[(head + i)%MAX_MTABLE ];
    }

    rx_mbufs->head = (rx_mbufs->head + 1)%MAX_MTABLE;
    return 1;
}



int32_t  dpdk_rx_receive(struct mtcp_thread_context *ctxt,int level,int port,struct rte_mbuf **ptr){
    int ret = 0;
    int head = 0;
    int tail = 0;
    struct rte_mbuf **start = ptr;
    struct dpdk_private_context *dpc;
    dpc = (struct dpdk_private_context *) ctxt->io_private_context;
    int portid = port;//CONFIG.eths[ifidx].ifindex;
//    level = 0;
    struct mbuf_table_q *rx_mbufs;
    int i = 0;
    if(level == 0){
         rx_mbufs = &dpc->rl_mbufs[portid];
    }else{
         rx_mbufs = &dpc->rh_mbufs[portid];
    }
    
    head = rx_mbufs->head;
    tail = rx_mbufs->tail;

    int be = tail - head;
    if(be < 0 ){
    be = be + MAX_MTABLE;
    }
    int max_receive = be;
    if(max_receive < 0){
    max_receive = 0;
    return 0;
    }
    if(max_receive > MAX_PKT_BURST){
   
    max_receive =  MAX_PKT_BURST;
    }
       
    int rx_num = 0;
    dpc->rx_num = 0;
    for( i = 0; i < max_receive; i++){
        start[i] = rx_mbufs->m_table[(head + i)%MAX_MTABLE ];
        rx_num++;
    }

    rx_mbufs->head = (rx_mbufs->head + max_receive)%MAX_MTABLE;
    return rx_num;

}
int32_t   dpdk_tx_send(struct mtcp_thread_context *ctxt,int level,int port,struct rte_mbuf **ptr,int len){

    int ret = 0;
    int head = 0;
    int tail = 0;

    struct dpdk_private_context *dpc;
    dpc = (struct dpdk_private_context *) ctxt->io_private_context;
    
    int portid = port;//CONFIG.eths[ifidx].ifindex;

    struct mbuf_table_q *tx_mbufs;

    int i = 0;
    if(level == 0){
         tx_mbufs = &dpc->tl_mbufs[portid];
    }else{
         tx_mbufs = &dpc->th_mbufs[portid];
    }
    
    head = tx_mbufs->head;
    tail = tx_mbufs->tail;
    int be = tail - head;
    if(be < 0 ){
    be = be + MAX_MTABLE;
    }
    int max_send = MAX_MTABLE - be -1;
    if(max_send < 0){
    max_send = 0;
    return 0;
    }
    if(len < max_send){
       max_send = len;
       
    }
    struct rte_mbuf **start = ptr;

    int tx_num = 0;
    for( i = 0; i < max_send; i++){
        if(start[i] == NULL){
             continue;
        }
        tx_mbufs->m_table[(tail + tx_num)%MAX_MTABLE] = start[i];
        tx_num++;
    } 
 
    tx_mbufs->tail = (tail + tx_num)%MAX_MTABLE;
    ret = tx_num;
    dpc->tx_num = ret;

    return ret;
}

uint8_t dpdk_alloc_mbuf(struct mtcp_thread_context *ctx, int ifidx){
         
     struct rte_mbuf *ptr;
     int portid = 0;

     struct dpdk_private_context *dpc;
     dpc = (struct dpdk_private_context *) ctx->io_private_context;

     ptr = rte_mbuf_raw_alloc(dpc->pktmbuf_pool);
     //assert(portid == 0);
     //this is for our test v0.1,only one port

         
     return (uint8_t)ptr;
}

/*----------------------------------------------------------------------------*/
io_module_func dpdk_module_func = {
	.load_module		   = dpdk_load_module,
	.init_handle		   = dpdk_init_handle,
	.link_devices		   = dpdk_link_devices,
	.release_pkt		   = dpdk_release_pkt,
	.send_pkts		   = dpdk_send_pkts,
	.get_wptr   		   = dpdk_get_wptr,
	.recv_pkts		   = dpdk_recv_pkts,
	.get_rptr	   	   = dpdk_get_rptr,
	.select			   = dpdk_select,
	.destroy_handle		   = dpdk_destroy_handle,
	.dev_ioctl		   = dpdk_dev_ioctl,
        .check_ringbuffer          = dpdk_check_device,
        .dev_rx_receive            = dpdk_rx_receive,
        .dev_tx_send               = dpdk_tx_send,
        .dev_alloc_mbuf            = dpdk_alloc_mbuf
};
/*----------------------------------------------------------------------------*/
#else
/*----------------------------------------------------------------------------*/
#endif /* !DISABLE_DPDK */
