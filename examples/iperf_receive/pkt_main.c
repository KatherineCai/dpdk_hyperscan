#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "packet.h"

#define NB_MBUF 16384 
#define MAX_PKT_BURST_TX 32 
#define MAX_PKT_BURST_RX 32 


struct rte_mempool *pktmbuf_pool = NULL;
struct rte_mbuf *pkt_200 = NULL;
struct rte_mbuf *pkt_74 = NULL;
struct rte_mbuf *pkt_66 = NULL;
unsigned long long send_cnt = 0;
uint8_t portid;


static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_DCB_NONE,
	},
};

static int rte_id_search(void)
{
    int i = 0;
    struct rte_eth_dev *dev;
    int  nb_ports = rte_eth_dev_count();
#define MAX_PORTS 8
    if (nb_ports == 0)
                rte_exit(EXIT_FAILURE, "No physical ports!\n");
    if (nb_ports > MAX_PORTS)
                nb_ports = MAX_PORTS;
    printf("nb_ports is %d \n",nb_ports);
    for( i = 0; i < (int)nb_ports;i++){
        dev = &rte_eth_devices[i];

        if(dev->pci_dev->id.vendor_id == 0x8086){
             printf("find the port id and port id is %d \n",i);
             return i;
        }
    }
    return -1;
}



int init_dpdk(int argc, char **argv)
{
	int ret;

	printf("rte_eal_init!\n");
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL!\n");
	
	pktmbuf_pool = rte_pktmbuf_pool_create("pkt_pool", NB_MBUF, 32, 0, 
				RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool!\n");

	portid = (uint8_t)rte_id_search();

	printf("rte_eth_dev_configure!\n");
	ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
	if (ret != 0)
	rte_exit(EXIT_FAILURE, "port %u: configuration failed res = %d\n", 
					portid, ret);
	printf("rte_eth_rx_queue_setup!\n");
	ret = rte_eth_rx_queue_setup(portid, 0, 512, rte_eth_dev_socket_id(portid),
					NULL, pktmbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, portid); 

	printf("rte_eth_tx_queue_setup!\n");
	ret = rte_eth_tx_queue_setup(portid, 0, 512, rte_eth_dev_socket_id(portid), NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, portid); 

	ret = rte_eth_dev_start(portid);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, (unsigned)portid);

	return 0;	
}

unsigned char *fbuf = NULL;
unsigned int flen=0, pos=0,header_error=0;
int build_pkt_64(struct rte_mbuf *pkt_mbuf)
{
	unsigned int last32,ret=1,index=0;
	unsigned short high8,low8;
	static int count=1;
	unsigned long long * ptr_data, *ptr;
	if (pkt_mbuf == NULL)
	{
		printf("alloc mbuf error!\n");
		return -1;
	}
	pkt_mbuf->data_len = 1024;
	pkt_mbuf->pkt_len = 1024;
	
	ptr_data = pkt_mbuf->buf_addr + pkt_mbuf->data_off;
	ptr = &fbuf[pos];
#if 1 
	#if 1 
	if((pos+1024)<=flen){
		if((ptr[0]!=0x1a38ffffffffffff) || (ptr[1]!=0x03f2f20390e2ba16)){
			header_error++;
			printf("header error!! 0: %lx 1:%lx, error_cnt: %d\n",ptr_data[0],ptr_data[1], header_error);
		}
		do{
		ptr_data[index] = ptr[index];	
		ptr_data[index+1] = ptr[index+1];	
		ptr_data[index+2] = ptr[index+2];	
		ptr_data[index+3] = ptr[index+3];	
		ptr_data[index+4] = ptr[index+4];	
		ptr_data[index+5] = ptr[index+5];	
		ptr_data[index+6] = ptr[index+6];	
		ptr_data[index+7] = ptr[index+7];
		index+=8;	
		} while(index<128);
		pos+=1024;
	}
	else return 0;
	#else
	ptr_data[0]=0x1a38ffffffffffff;
	ptr_data[1]=0x03f2f20390e2ba16;
	#endif
#endif

	return 1;
}
#define FIFO_LENGTH 1024
unsigned int fifo_head=0,fifo_tail=0,fifo_num=0; 
static int pkt_main_loop(__attribute__((unused))void *arg)
{
	unsigned lcore_id;
	unsigned int cnt_74 = 0;
	struct rte_mbuf *pkts_burst_rx[MAX_PKT_BURST_RX];
	struct rte_mbuf *pkts_burst_tx[MAX_PKT_BURST_TX];
	struct rte_mbuf *fifo[FIFO_LENGTH];
	struct rte_mbuf *m;
	unsigned long long sum = 0,sum_to_send=0;
	unsigned int nb_rx = 0, nb_tx = 0;
	unsigned long long cnt = 0;
	unsigned int i = 0, j;
	int start_send = 0, not_eof = 1;
	struct timeval tv_pre,tv_after;

	FILE *fd;
	
#if 0 
	for (i = 0; i < MAX_PKT_BURST_TX; i++)
	{
		pkts_burst_tx[i] = __rte_mbuf_raw_alloc(pktmbuf_pool);
		//build_pkt_74(pkts_burst_tx[i]);
	}
#endif 

	lcore_id = rte_lcore_id();

#if 0
	pkt_66 = __rte_mbuf_raw_alloc(pktmbuf_pool);
	build_pkt_200(pkt_200, 0x2);
	build_pkt_74(pkt_74);
	build_pkt_66(pkt_66);
#endif
	
	gettimeofday(&tv_pre,NULL);	
        long time = 1;
#if 1	
	do
	{
#if 1 
		//RX
		//stop = 1;
		nb_rx = rte_eth_rx_burst((uint8_t) portid, 0, pkts_burst_rx, MAX_PKT_BURST_RX);
		sum += nb_rx;
		nb_tx=0;
	
#if 0  //add return back
		if(((cnt%20)==1) && (nb_rx>0)){
		for (i = 0; i < nb_rx; i++)
		{
			m = pkts_burst_rx[i];
			unsigned char dest_mac[6];
			unsigned char * ptr = m->buf_addr + m->data_off;
			dest_mac[0]=ptr[0];
			dest_mac[1]=ptr[1];
			dest_mac[2]=ptr[2];
			dest_mac[3]=ptr[3];
			dest_mac[4]=ptr[4];
			dest_mac[5]=ptr[5];
			ptr[0]=ptr[6];
			ptr[1]=ptr[7];
			ptr[2]=ptr[8];
			ptr[3]=ptr[9];
			ptr[4]=ptr[10];
			ptr[5]=ptr[11];
			
			ptr[6]=dest_mac[0];
			ptr[7]=dest_mac[1];
			ptr[8]=dest_mac[2];
			ptr[9]=dest_mac[3];
			ptr[10]=dest_mac[4];
			ptr[11]=dest_mac[5];
			ptr[72]=0x3; //direction
		}
		nb_tx = rte_eth_tx_burst(portid, 0, pkts_burst_rx, nb_rx);
		send_cnt += nb_tx;
		}
#endif
                nb_tx = 0;	
		for (i = nb_tx; i < nb_rx; i++)
		{
			m = pkts_burst_rx[i];
			__rte_mbuf_raw_free(m);
		}	
	
		if ((cnt % 10000000) == 0){
			printf("receive_cnt = %d, send_cnt is %d, start_send is %d\n", sum, send_cnt,start_send);
                        time++;
                }
		cnt++;
#endif 
	}while(not_eof && (send_cnt<10000000));
	
#endif
	gettimeofday(&tv_after,NULL);	
	printf("used time %.3f ms\n",(double)(tv_after.tv_sec-tv_pre.tv_sec)*1000.0+(double)(tv_after.tv_usec-tv_pre.tv_usec)/1000.0);
	free(fbuf);
	printf("lcore_id %u, send_cnt %d, receive_cnt %d, sum_to_send %d\n", lcore_id, send_cnt,sum,sum_to_send);
	return 0;
}


int main(int argc, char argv[])
{
	unsigned lcore_id;	

	//init rx/tx queue and start device
	init_dpdk(argc, argv);
	
	pkt_main_loop(NULL);
	

	return 0;
}
