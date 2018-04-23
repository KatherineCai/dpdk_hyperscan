#ifndef _RTE_PING_
#define _RTE_PING_

#include <poll.h>
#include <linux/ioctl.h>
#include <net/if.h>

#include <rte_ethdev.h>
#include <rte_mempool.h>

#define IPv4(a, b, c, d) ((uint32_t)(((a) & 0xff) << 24) |		\
	(((b) & 0xff) << 16) |						\
	(((c) & 0xff) << 8) |						\
	((d) & 0xff))

struct arp_data {
//    struct ether_hdr eth;
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

struct ip_head_data{
//   struct ether_hdr eth;
  

   uint8_t  version_hlen; 
    
   uint8_t  tos;  
   uint16_t tot_len;  
   uint16_t id;  
   uint16_t fra_off:13; 
   uint16_t  fra_ops:3; 
   uint8_t ttl;  
   uint8_t protocol;  
   uint16_t chk_sum;  
   uint32_t srcaddr;  
   uint32_t dstaddr;  
}__attribute__((__packed__));

struct icmp_data{
//   struct ether_hdr eth;
   struct ip_head_data ip;
   uint8_t icmp_type;
   uint8_t icmp_code;
   uint16_t icmp_cksum;
   uint16_t icmp_id;
   uint16_t icmp_seq;
}__attribute__((__packed__));

struct udp_head_data{

//   struct ether_hdr eth;
//   struct ip_head_data ip;
   uint16_t src_port;
   uint16_t dst_port;
   uint16_t len;
   uint16_t chk_sum;
}__attribute__((__packed__));

#endif
