

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <linux/tcp.h>


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
#include <rte_ip.h>
#include <rte_tcp.h>
//#include "pktgen.h"

#include "./include/datatype.h"

#include "./include/pktgen.h"

#define swab16(x) ((x&0x00ff) << 8 | (x&0xff00) >> 8)
#define swab32(x) ((x&0x000000ff) << 24 | (x&0x0000ff00) << 8 | (x&0x00ff0000) >> 8 | (x&0xff000000) >> 24)
void build_icmp_head_data(struct rte_mbuf *mbuf){

   struct icmp_data *icmp;
   uint8_t *tmp8;
   uint8_t *tmp16;

   icmp = rte_pktmbuf_mtod_offset(mbuf, struct icmp_data * ,(sizeof(struct ether_hdr) + sizeof(struct ip_head_data)));

   if(icmp->icmp_type == 0x08){
   //just deal with this type
   //change it in future
       icmp->icmp_type = 0x00;
       icmp->icmp_code =0x00;
   }else{
       
       icmp->icmp_type = 0x08;


   }
}
void build_ether_head_data(struct rte_mbuf *mbuf){
 
    struct ether_hdr *eth;
    uint8_t *tmp;
    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
#if 0

		*(ptr + 0) = 0x68;
		*(ptr + 1) = 0x05;
		*(ptr + 2) = 0xca;
		*(ptr + 3) = 0x30;
		*(ptr + 4) = 0x04;
		*(ptr + 5) = 0x31;
	
		*(ptr + 6) = 0x68;
		*(ptr + 7) = 0x05;
		*(ptr + 8) = 0xca;
		*(ptr + 9) = 0x30;
		*(ptr + 10) = 0x00;
		*(ptr + 11) = 0x3a;
#endif
    /*dst addr */

    eth->d_addr.addr_bytes[0] =  0x68;
    eth->d_addr.addr_bytes[1] =  0x05;
    eth->d_addr.addr_bytes[2] =  0xca;
    eth->d_addr.addr_bytes[3] =  0x30;
    eth->d_addr.addr_bytes[4] =  0x04;
    eth->d_addr.addr_bytes[5] =  0x31;
    
    /*src addr */
    /*00:0c:29:7d:f9:b7*/
    eth->s_addr.addr_bytes[0] =  0x68;
    eth->s_addr.addr_bytes[1] =  0x05;
    eth->s_addr.addr_bytes[2] =  0xca;
    eth->s_addr.addr_bytes[3] =  0x30;
    eth->s_addr.addr_bytes[4] =  0x00;
    eth->s_addr.addr_bytes[5] =  0x3a;

    /*ether_type*/
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

}
void build_ip_head_data(struct rte_mbuf *mbuf,int size,int id,int ip_type){
    struct ipv4_hdr *ip_head;

    ip_head = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr * , sizeof(struct ether_hdr));

    ip_head->src_addr = swab32(IPv4(192, 168, 75, 101));
    ip_head->dst_addr = swab32(IPv4(192, 168, 75, 1));

    ip_head->version_ihl = 0x45;
    
    ip_head->type_of_service = 0;
    ip_head->fragment_offset = 0;
    ip_head->total_length = swab16( size - sizeof(struct ether_hdr));
    ip_head->packet_id = swab16(id);
    ip_head->time_to_live   = 64;
    
    ip_head->next_proto_id = ip_type;
    
    	/*
 * 	 * Compute IP header checksum.
 * 	 	 */
    uint16_t *ptr16;
    uint32_t ip_cksum;
    ptr16 = (unaligned_uint16_t*) ip_head;
    ip_cksum = 0;
    ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
    ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
    ip_cksum += ptr16[4];
    ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
    ip_cksum += ptr16[8]; ip_cksum += ptr16[9];
 /*
 * 	 * Reduce 32 bit checksum to 16 bits and complement it.
 * 	 	 */
    ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
		(ip_cksum & 0x0000FFFF);
    if (ip_cksum > 65535)
		ip_cksum -= 65535;
    ip_cksum = (~ip_cksum) & 0x0000FFFF;
    if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
    ip_head->hdr_checksum = (uint16_t) ip_cksum;
    
}

void build_upd_head_data(struct rte_mbuf *mbuf,int size){
#if 0
    struct udp_head_data *udp_head;

    udp_head = rte_pktmbuf_mtod_offset(mbuf, struct udp_head_data * , sizeof(struct ether_hdr)+sizeof(struct ip_head_data));

    udp_head->src_port = 0x1451;//0x1451 == 5201
    udp_head->dst_port = 0x1451;//0x1451 == 5201
    udp_head->len = swab16(size - sizeof(struct ether_hdr) - sizeof(struct ip_head_data));
   
    	/*
 * 	 * Compute UDP header checksum.
 * 	 	 */
    uint16_t *ptr16;
    uint32_t ip_cksum;
    ptr16 = (unaligned_uint16_t*) udp_head;
    ip_cksum = 0;
    ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
    ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
 /*
 * 	 * Reduce 32 bit checksum to 16 bits and complement it.
 * 	 	 */
    ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
		(ip_cksum & 0x0000FFFF);
    if (ip_cksum > 65535)
		ip_cksum -= 65535;
    ip_cksum = (~ip_cksum) & 0x0000FFFF;
    if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
    udp_head->chk_sum = (uint16_t) ip_cksum;
         
#endif    
}

int build_udp_pkt(struct rte_mbuf *pkt_mbuf, int size, int seq_cnt){
     //this is only for ip packet 
     //so the size must >= 64
     //and size mut <= 1500
     
     if(size < 64 || size >1500){
          return -1;
     }
     //pkt_mbuf  can not be a NULL
     if(pkt_mbuf == NULL){
          return -1;
     }
     unsigned char *ptr = pkt_mbuf->buf_addr + pkt_mbuf->data_off;
     unsigned char *ptr_proto = ptr + 23;
     unsigned long *ptr_seq;


     pkt_mbuf->data_len = size;     
     pkt_mbuf->pkt_len = size;
     
     int i = 0;
     for(i = 0; i<size;i++){
  //        *(ptr + i) = 0x11;
     }         
     
     build_ether_head_data(pkt_mbuf);
     #define UDP_PRO_ID 17
     build_ip_head_data(pkt_mbuf,size,seq_cnt,UDP_PRO_ID);
     build_upd_head_data(pkt_mbuf,size);
     
         
     return 1;

}


void build_tcp_head_data(struct rte_mbuf *mbuf,int size,int seq){

    struct tcp_hdr *tcp_head;

    tcp_head = rte_pktmbuf_mtod_offset(mbuf, struct tcp_hdr * , sizeof(struct ether_hdr)+sizeof(struct ip_head_data));

    #ifndef __LITTLE_ENDIAN_BITFIELD
    #define __LITTLE_ENDIAN_BITFIELD 1
    #endif
     /* Build TCP header and checksum it. */
    tcp_head->src_port= 0x0088;
    tcp_head->dst_port = 0x0081;
      
    tcp_head->sent_seq = swab32(seq);
    tcp_head->recv_ack = 0;
    tcp_head->data_off = (20/4)<<4;
  //  *(((__be16 *)tcp_head) + 6)    = htons(((sizeof(struct tcphdr) >> 2) << 12) |
  //                 0xff);
    
    memset((tcp_head+12),1,2);
    if(seq == 0){
    tcp_head->tcp_flags = 0x02;
    }else{
    tcp_head->tcp_flags = 0x0;
    }
    tcp_head->rx_win = htons( 4096U);


/* this is for linux struct tcphdr and now use dpdk structy tcp_hdr
    tcp_head->check        = 0;
    tcp_head->urg_ptr        = 0;
    tcp_head->window    = htons( 4096U);
    tcp_head->fin = 0;
    tcp_head->syn = seq;
    tcp_head->rst = 0;
    tcp_head->psh = 0;
    tcp_head->ack = 0;
    tcp_head->urg = 0;
    
*/

    	/*
 * 	 * Compute UDP header checksum.
 * 	 	 */
    uint16_t *ptr16;
    uint32_t tcp_cksum;
    ptr16 = (unaligned_uint16_t*) tcp_head;
    tcp_cksum = 0;
    int k = 0;
    while(k < 10){
    tcp_cksum += ptr16[k];
    k++;
    }
 /*
 * 	 * Reduce 32 bit checksum to 16 bits and complement it.
 * 	 	 */
    tcp_cksum = ((tcp_cksum & 0xFFFF0000) >> 16) +
		(tcp_cksum & 0x0000FFFF);
    if (tcp_cksum > 65535)
		tcp_cksum -= 65535;
    tcp_cksum = (~tcp_cksum) & 0x0000FFFF;
    if (tcp_cksum == 0)
		tcp_cksum = 0xFFFF;
    tcp_head->cksum = (uint16_t) tcp_cksum;
    
}


int build_tcp_pkt(struct rte_mbuf *pkt_mbuf, int size, int seq_cnt){
     //this is only for ip packet 
     //so the size must >= 64
     //and size mut <= 1500
     
     if(size < 64 || size >1500){
          return -2;
     }
     //pkt_mbuf  can not be a NULL
     if(pkt_mbuf == NULL){
          return -1;
     }
     unsigned char *ptr = pkt_mbuf->buf_addr + pkt_mbuf->data_off;
     unsigned char *ptr_proto = ptr + 23;
     unsigned long *ptr_seq;


     pkt_mbuf->data_len = size;     
     pkt_mbuf->pkt_len = size;
     
     int i = 0;
     for(i = 0; i<size;i++){
          *(ptr + i) = i;

          int time = 0;
          time = seq_cnt % 2;
          if(i == (sizeof(struct ether_hdr)+sizeof(struct ip_head_data)+sizeof(struct tcphdr) + 5)){

          *(ptr + i) = 1 + time*2;
          }
     }         
    
     build_ether_head_data(pkt_mbuf);

     #define TCP_PRO_ID 6
     build_ip_head_data(pkt_mbuf,size,seq_cnt,TCP_PRO_ID);
     build_tcp_head_data(pkt_mbuf,size,seq_cnt);
     
         
     return 1;

}

