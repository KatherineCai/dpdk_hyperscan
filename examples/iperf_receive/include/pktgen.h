
#ifndef _RTE_PKT_
#define _RTE_PKT_
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
#include "pktgen.h"
#include "datatype.h"

#define NB_MBUF 16384 
#define MAX_PKT_BURST_TX 32 
#define MAX_PKT_BURST_RX 32 


short pakcet_cksum(char *sendbuf,int len);

void build_ether_head_data(struct rte_mbuf *mbuf);

void build_ip_head_data(struct rte_mbuf *mbuf,int size,int id,int ip_type);
void build_upd_head_data(struct rte_mbuf *mbuf,int size);
int build_udp_pkt(struct rte_mbuf *mbuf , int size ,int seq_cnt);

void build_tcp_head_data(struct rte_mbuf *mbuf,int size, int seq_cnt);
int build_tcp_pkt(struct rte_mbuf *mbuf , int size ,int seq_cnt);
#endif
