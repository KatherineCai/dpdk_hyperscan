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

//#include <rte_eth_ctrl.h>
#include <rte_tcp.h>


#include "./include/datatype.h"
#include "./include/qstack.h"
#include "./include/io_module.h"
#include "./include/pktgen.h"
#include "./include/flow_ctl.h"

#define NB_MBUF 16384 
#define MAX_PKT_BURST_TX 32 
#define MAX_PKT_BURST_RX 32 
#define MAX_QUEUE_NUM 8
#define swab32(x) ((x&0x000000ff) << 24 | (x&0x0000ff00) << 8 | (x&0x00ff0000) >> 8 | (x&0xff000000) >> 24)
struct rte_mempool *pktmbuf_pool = NULL;
struct rte_mbuf *pkt_200[50000];
struct rte_mbuf *pkt_74 = NULL;
struct rte_mbuf *pkt_66 = NULL;
unsigned long long send_cnt = 0;
uint8_t portid;

volatile long long sum = 0;

static struct mtcp_thread_context *ctx[MAX_QUEUE_NUM] = {NULL};

struct mtcp_manager *mtcp[MAX_QUEUE_NUM] = {NULL};

struct dpdk_private_context *dpc[MAX_QUEUE_NUM] = {NULL};
static volatile long long sum_queue[MAX_QUEUE_NUM];
long long sum_to_send=0;

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
volatile int test_seq = 0;
volatile int test_time = 0;
static void show_data(struct rte_mbuf *mbuf){
    if(mbuf != NULL){

    struct ether_hdr *eth;
    struct tcp_hdr *tcp;
    
    uint8_t *tmp;
    uint16_t *ops;
    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

    tcp = rte_pktmbuf_mtod_offset(mbuf, struct tcp_hdr * , sizeof(struct ether_hdr)+sizeof(struct ip_head_data));
    int seq = 0;
    seq = (swab32(tcp->sent_seq)) ;
    if(test_time == 0){
      test_time = 1;
      test_seq = seq;
    }else{


      if(seq != (test_seq + 1)%0xfffffff){
          //  printf("seq wrong and seq is %d test_seq is %d \n",seq,test_seq);
           
      }
      test_seq = seq;
    }

  //  printf("seq is %d data and tcp->sent_seq is %d\n",seq,tcp->sent_seq);
    }else{
   
  //  printf("mbuf is NULL in show data\n");
    }


}


#define FIFO_LENGTH 1024
unsigned int fifo_head=0,fifo_tail=0,fifo_num=0; 

void show_speed(){
       long cnt1  = 0; 
       long cnt2 = 0;
       while(sum<10000000000){
                if((cnt1 %100) == 0){ 
		    cnt2++;
		}
		if ((cnt2 % 1000000) == 0){
                        int i = 0;
                        sum = 0;
                        for( i = 0;i <MAX_QUEUE_NUM;i++){   
			    printf("===receive_cnt = %ld, in this test and i is %ld \n===", sum_queue[i],i);
                            sum = sum + sum_queue[i];
                        }
                        printf("we receive sum is %d \n",sum);
                        struct rte_eth_stats eth_stats;
                        rte_eth_stats_get(0, &eth_stats);
//                        printf("there is a test here \n");
//                        printf("max receive packet num is %ld  \n",eth_stats.ipackets);
                       
//                        printf("max receive bety num is %ld  \n",eth_stats.ibytes);
//                        printf("Total number of erroneous received packets is %ld \n",eth_stats.ierrors);
//                        printf("Total number of RX mbuf allocation failures. is %ld \n",eth_stats.rx_nombuf);   
			cnt2++;
                       // time++;

                }
		cnt1++;
        }
}

void  pkt_main_check(int max_queue){

        struct mtcp_thread_context *ct = NULL;
        int i = 0;
        int loop = 0;
	sleep(5);
        printf("begin to check ring buff \n");
        while(loop == 0){
            for(i = 0; i<MAX_QUEUE_NUM;i++)
            {
                if(ctx[i] != NULL && mtcp[i] != NULL){
        //       ct = ctx[i];
                     mtcp[i]->iom->check_ringbuffer(ctx[i]);
                }      
            }
 

        }
}

void  pkt_main_loop(int in_queue)
{
	unsigned lcore_id;
	unsigned int cnt_74 = 0;
	struct rte_mbuf *pkts_burst_rx[MAX_PKT_BURST_RX];
	struct rte_mbuf *pkts_burst_tx[MAX_PKT_BURST_TX];
	struct rte_mbuf *fifo[FIFO_LENGTH];
	struct rte_mbuf *m;
//	long long sum = 0,sum_to_send=0;
	unsigned int nb_rx = 0, nb_tx = 0;
	long long cnt = 0;
	unsigned int i = 0;
	int start_send = 0, not_eof = 1;
	struct timeval tv_pre,tv_after;

	FILE *fd;
	

	lcore_id = rte_lcore_id();
 //       static struct mtcp_thread_context *ctx[MAX_QUEUE_NUM];

 //       struct mtcp_manager *mtcp[MAX_QUEUE_NUM];


 //       struct dpdk_private_context *dpc[MAX_QUEUE_NUM];
        int core;
        for(i = 0; i<MAX_QUEUE_NUM;i++){
           if(i == in_queue)
           {
          
            core = rte_lcore_id();
            ctx[i] = MTCPRunThread(core,i);


            mtcp[i] = ctx[i]->mtcp_manager;


            dpc[i] = (struct dpdk_private_context *) ctx[i]->io_private_context;
            }
        }
	sleep(5);
//	gettimeofday(&tv_pre,NULL);	
        int queue = in_queue;
        printf("in_queue is %d \n",queue);
        int time = 1;
	int cntz = 1;
        nb_rx = 0;
#if 1	
	do
	{
       		nb_rx =     mtcp[queue]->iom->dev_rx_receive(ctx[queue],0,0,&pkts_burst_rx);      
  
		if(time == 1 && nb_rx > 0){
                time = 2;
         	   gettimeofday(&tv_pre,NULL);	
		}
        //        mtcp[queue]->iom->check_ringbuffer(ctx[queue]);
        //		nb_rx = rte_eth_rx_burst((uint8_t) portid, queue, pkts_burst_rx, MAX_PKT_BURST_RX);
		sum_queue[queue] += nb_rx;
		nb_tx=0;
	#if 1
		for (i = nb_tx; i < nb_rx; i++)
		{
			m = pkts_burst_rx[i];

                        show_data(m);
                        if(m != NULL){

                            if(m->pkt_len != 200){         
                                  printf("rte_mbuf ->pke_len is %d \n  ",m->pkt_len);
                            }
			__rte_mbuf_raw_free(m);
                        }else{
                                  printf("rte_mbuf is NULL \n");
                        }
		}	
        #endif
        //        queue = (queue + 1)%MAX_QUEUE_NUM;
	}while((sum <= 1000000010));


	
#endif
	gettimeofday(&tv_after,NULL);	
	printf("used time %.3f ms\n",(double)(tv_after.tv_sec-tv_pre.tv_sec)*1000.0+(double)(tv_after.tv_usec-tv_pre.tv_usec)/1000.0);
	double btime = (double)(tv_after.tv_sec-tv_pre.tv_sec)*1000.0+(double)(tv_after.tv_usec-tv_pre.tv_usec)/1000.0;
	
        double speed;
        speed = sum_queue[queue]*200*8*1000/btime;

             
//	free(fbuf);
	printf("lcore_id %u and speed is %f mbps \n", lcore_id,speed/1024/1024);
	return;
}
static int 
lcore_loop(__attribute__((unused)) void *arg)
{
    
    unsigned lcore_id;
    lcore_id = rte_lcore_id();
        if(lcore_id == 1){ 
            show_speed();
        }   
        if(lcore_id > 1 && lcore_id  < MAX_QUEUE_NUM+2 ){ 
            pkt_main_loop(lcore_id - 2);
        }   
        if(lcore_id == 0){ 

            printf("hello from core %u\n", lcore_id);
        }
        if(lcore_id == MAX_QUEUE_NUM + 2){
            pkt_main_check(MAX_QUEUE_NUM);
        }   
    return 0;
}


int main(int argc, char argv[])
{
	unsigned lcore_id;	

	//init rx/tx queue and start device
//	init_dpdk(argc, argv);
       
	printf("rte_eal_init!\n");
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL!\n");
	int queue_num = MAX_QUEUE_NUM;;
        current_iomodule_func->load_module(queue_num);
//	pkt_main_loop(NULL);
          //     unsigned lcore_id;
        /* call lcore_hello() on every slave lcore */
        struct rte_eth_ntuple_filter filter1,filter2;
        memset(&filter1, 0, sizeof(struct rte_eth_ntuple_filter));
        memset(&filter2, 0, sizeof(struct rte_eth_ntuple_filter));
        app_link_filter_ip_init(&filter1,3);
    //    app_link_filter_ip_init(&filter2,5);

        link_filter_set_add(filter1,0,RTE_ETH_FILTER_NTUPLE);

        link_filter_set_add(filter2,0,RTE_ETH_FILTER_NTUPLE);
        

        rte_eal_mp_remote_launch(lcore_loop, NULL, CALL_MASTER);
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
                if (rte_eal_wait_lcore(lcore_id) < 0)
                        return -1;
        }
	

	return 0;
}
