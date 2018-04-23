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

#include <rte_tcp.h>

#include "./include/flow_ctl.h"
int
app_link_filter_arp_init(struct rte_eth_ethertype_filter *filter,int queue){

    if(filter == NULL){
        return -1;
    }

    filter->ether_type = ETHER_TYPE_ARP;
    filter->flags = 0;
    filter->queue = queue;

    return 0;

}

int
app_link_filter_tcp_syn_init(struct rte_eth_syn_filter *filter,int queue){
 

    if(filter == NULL){
        return -1;
    }

    filter->hig_pri = 1;
    filter->queue = queue;
    return 0;
}

int
app_link_filter_ip_init(struct rte_eth_ntuple_filter *filter,int queue){
    
    if(filter == NULL){
        return -1;
    }
    //this is for test
       
    filter->flags = RTE_5TUPLE_FLAGS;
   // filter->dst_ip = rte_bswap32(IPv4(192, 168, 75, 101));//rte_bswap32(l2->ip);
    filter->dst_ip_mask = UINT32_MAX; /* Enable */
    filter->src_ip = 0;
    filter->src_ip_mask = 0; /* Disable */
    filter->dst_port = 0;
    filter->dst_port_mask = 0; /* Disable */
    filter->src_port = 0;
    filter->src_port_mask = 0; /* Disable */
    filter->proto = 0;
    filter->proto_mask = 0; /* Disable */
    filter->tcp_flags = 0;
    filter->priority = 1; /* Lowest */
    if(queue == 3){
    filter->dst_ip = rte_bswap32(IPv4(192, 168, 75, 1));//rte_bswap32(l2->ip);
    filter->queue = queue;
    }else{

    filter->dst_ip = rte_bswap32(IPv4(192, 168, 75, 1));//rte_bswap32(l2->ip);
    filter->queue = queue;

    }



    return 0;
   
}

int link_filter_set_add(struct rte_eth_ntuple_filter filter,int port_id,int type){


        int ret = -1;
        switch(type){
        case RTE_ETH_FILTER_NONE:

        break;
	case RTE_ETH_FILTER_ETHERTYPE:

	ret = rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_ETHERTYPE,
		RTE_ETH_FILTER_ADD,
		&filter);
        break;
	case RTE_ETH_FILTER_SYN:

	ret = rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_SYN,
		RTE_ETH_FILTER_ADD,
		&filter);
        break;
	case RTE_ETH_FILTER_NTUPLE:

	ret = rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_ADD,
		&filter);
        break;
        default:
        break;


        }
        return ret;
}



