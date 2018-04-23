/*-
 *   BSD LICENSE
 *
 *   Copyright 2017 Mellanox.
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
 *     * Neither the name of Mellanox nor the names of its
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

#define MAX_PATTERN_NUM		6

struct rte_flow *
generate_udp_flow(uint8_t port_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask,
		struct rte_flow_error *error, char *string);


struct rte_flow *
generate_tcp_flow(uint8_t port_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask,
		struct rte_flow_error *error, char *string);

struct rte_flow *
generate_tcp_flow_with_payload(uint8_t port_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask,
		struct rte_flow_error *error, char *string);
/**
 * create a flow rule that sends packets with matching src and dest ip
 * to selected queue.
 *
 * @param port_id
 *   The selected port.
 * @param rx_q
 *   The selected target queue.
 * @param src_ip
 *   The src ip value to match the input packet.
 * @param src_mask
 *   The mask to apply to the src ip.
 * @param dest_ip
 *   The dest ip value to match the input packet.
 * @param dest_mask
 *   The mask to apply to the dest ip.
 * @param[out] error
 *   Perform verbose error reporting if not NULL.
 *
 * @return
 *   A flow if the rule could be created else return NULL.
 */
struct rte_flow *
generate_udp_flow(uint8_t port_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask,
		struct rte_flow_error *error,
                char *string)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_PATTERN_NUM];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = rx_q };
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_vlan vlan_spec;
	struct rte_flow_item_vlan vlan_mask;
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;

    struct rte_flow_item_udp udp_spec; 
    struct rte_flow_item_udp udp_mask;


    struct rte_flow_item_raw raw_spec;
    struct rte_flow_item_raw raw_mask;



	int res;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (eth).
	 * since in this example we just want to get the
	 * ipv4 we set this level to allow all.
	 */
#if 1
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	eth_spec.type = 0;
	eth_mask.type = 0;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	/*
	 * setting the second level of the pattern (vlan).
	 * since in this example we just want to get the
	 * ipv4 we also set this level to allow all.
	 */
#endif
#if 0
	memset(&vlan_spec, 0, sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
	pattern[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
	pattern[1].spec = &vlan_spec;
	pattern[1].mask = &vlan_mask;
#endif
	/*
	 * setting the third level of the pattern (ip).
	 * in this example this is the level we care about
	 * so we set it according to the parameters.
	 */
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ip_spec.hdr.dst_addr = htonl(dest_ip);
        printf("dest_ip in flow_ctrl is %x \n",htonl(dest_ip));
	ip_mask.hdr.dst_addr = 0xffff0000;//dest_mask;
	ip_spec.hdr.src_addr = htonl(src_ip);
	ip_mask.hdr.src_addr = 0xffff0000;//src_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;

	/* the final level must be always type end */

	memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
	memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
        udp_spec.hdr.src_port = rte_cpu_to_be_16(1024);
        udp_spec.hdr.dst_port = rte_cpu_to_be_16(1024);

        udp_mask.hdr.src_port = rte_cpu_to_be_16(1024);
        udp_mask.hdr.dst_port = rte_cpu_to_be_16(1024);


	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[2].spec = &udp_spec;
	pattern[2].mask = &udp_mask;


	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;


	res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);

	return flow;
}

struct rte_flow *
generate_tcp_flow(uint8_t port_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask,
		struct rte_flow_error *error,
                char *string)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_PATTERN_NUM];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = rx_q };
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_vlan vlan_spec;
	struct rte_flow_item_vlan vlan_mask;
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;

        struct rte_flow_item_udp udp_spec; 
        struct rte_flow_item_udp udp_mask;


        struct rte_flow_item_tcp tcp_spec; 
        struct rte_flow_item_tcp tcp_mask;

        struct rte_flow_item_raw raw_spec;
        struct rte_flow_item_raw raw_mask;



	int res;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (eth).
	 * since in this example we just want to get the
	 * ipv4 we set this level to allow all.
	 */
#if 1
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	eth_spec.type = 0;
	eth_mask.type = 0;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	/*
	 * setting the second level of the pattern (vlan).
	 * since in this example we just want to get the
	 * ipv4 we also set this level to allow all.
	 */
#endif
#if 0
	memset(&vlan_spec, 0, sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
	pattern[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
	pattern[1].spec = &vlan_spec;
	pattern[1].mask = &vlan_mask;
#endif
	/*
	 * setting the third level of the pattern (ip).
	 * in this example this is the level we care about
	 * so we set it according to the parameters.
	 */
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ip_spec.hdr.dst_addr = htonl(dest_ip);
        printf("dest_ip in flow_ctrl is %x \n",htonl(dest_ip));
	ip_mask.hdr.dst_addr = 0xffff0000;//dest_mask;
	ip_spec.hdr.src_addr = htonl(src_ip);
	ip_mask.hdr.src_addr = 0xffff0000;//src_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;

	/* the final level must be always type end */

	memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
	memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
        tcp_spec.hdr.src_port = rte_cpu_to_be_16(1024);
        tcp_spec.hdr.dst_port = rte_cpu_to_be_16(1024);

        tcp_mask.hdr.src_port = rte_cpu_to_be_16(1024);
        tcp_mask.hdr.dst_port = rte_cpu_to_be_16(1024);


	pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[2].spec = &tcp_spec;
	pattern[2].mask = &tcp_mask;


	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;


	res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);

	return flow;
}



struct rte_flow *
generate_tcp_flow_with_payload(uint8_t port_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask,
		struct rte_flow_error *error,
                char *string)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_PATTERN_NUM];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = rx_q };
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_vlan vlan_spec;
	struct rte_flow_item_vlan vlan_mask;
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;

        struct rte_flow_item_udp udp_spec; 
        struct rte_flow_item_udp udp_mask;


        struct rte_flow_item_tcp tcp_spec; 
        struct rte_flow_item_tcp tcp_mask;

        struct rte_flow_item_raw *raw_spec;
        struct rte_flow_item_raw *raw_mask;



	int res;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (eth).
	 * since in this example we just want to get the
	 * ipv4 we set this level to allow all.
	 */
#if 1
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	eth_spec.type = 0;
	eth_mask.type = 0;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	/*
	 * setting the second level of the pattern (vlan).
	 * since in this example we just want to get the
	 * ipv4 we also set this level to allow all.
	 */
#endif
#if 0
	memset(&vlan_spec, 0, sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
	pattern[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
	pattern[1].spec = &vlan_spec;
	pattern[1].mask = &vlan_mask;
#endif
	/*
	 * setting the third level of the pattern (ip).
	 * in this example this is the level we care about
	 * so we set it according to the parameters.
	 */
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ip_spec.hdr.dst_addr = htonl(dest_ip);
       // printf("dest_ip in flow_ctrl is %x \n",htonl(dest_ip));
	ip_mask.hdr.dst_addr = 0;//0xffffffff;//dest_mask;
	ip_spec.hdr.src_addr = htonl(src_ip);
	ip_mask.hdr.src_addr = 0;//0xffffffff;//src_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;

	/* the final level must be always type end */

	memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
	memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
    //    tcp_spec.hdr.src_port = rte_cpu_to_be_16(1024);
    //    tcp_spec.hdr.dst_port = rte_cpu_to_be_16(1024);

    //    tcp_mask.hdr.src_port = rte_cpu_to_be_16(1024);
    //    tcp_mask.hdr.dst_port = rte_cpu_to_be_16(1024);


	pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[2].spec = &tcp_spec;
	pattern[2].mask = &tcp_mask;


        raw_spec = malloc((sizeof(struct rte_flow_item_raw)) + sizeof(char) * 10);
        if(raw_spec == NULL){
            return NULL;
        }
	memset(raw_spec, 0, sizeof(struct rte_flow_item_raw) + sizeof(char) * 10);
//	memset(raw_mask, 0, sizeof(struct rte_flow_item_raw) + sizeof(char) * 10) ;
        raw_spec->relative = 1;
        raw_spec->search = 0;
        raw_spec->reserved = 0;
        raw_spec->offset = 5;
        raw_spec->length = 8;
   //     raw_mask->pattern = (uint8_t)string;       
   //     raw_spec->pattern[0] = 'a';
   //     raw_spec->pattern[1] = 'b';
   //     if(rx_q == 3){ 
        raw_spec->pattern[0] = 0x1;
   //     }else{
   //     raw_spec->pattern[0] = 'b';
   //     }

	pattern[3].type = RTE_FLOW_ITEM_TYPE_RAW;
	pattern[3].spec = raw_spec;
	pattern[3].mask = raw_spec;

	pattern[4].type = RTE_FLOW_ITEM_TYPE_END;


	res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (!res){
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
        }else{
                printf("rte_flow_validate wrong with queue is %d \n",rx_q);
        }

	return flow;
}



void port_rss_reta_reset(int port){
    // for i40e reta_conf number is  512/64 = 8
    int num = 8;
    int status = -1;
    struct rte_eth_rss_reta_entry64 reta_conf[ETH_RSS_RETA_SIZE_512/RTE_RETA_GROUP_SIZE];

    struct rte_eth_rss_reta_entry64 reta_conf_get[ETH_RSS_RETA_SIZE_512/RTE_RETA_GROUP_SIZE];
    memset(reta_conf, 0, sizeof(struct rte_eth_rss_reta_entry64)*8);  


    struct rte_eth_dev_info dev_info;
    /* Get RETA size */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port, &dev_info);

   
    status = rte_eth_dev_rss_reta_query(port,reta_conf,dev_info.reta_size);
 //   if (status != 0){
 //      rte_panic("%s (%u): RSS setup error (RETA quary failed)\n");
 //   }
    status = -1;
    int i = 0;
    int j = 0;
    int idx = 0;
    for(idx = 0;idx < dev_info.reta_size; idx++){
		reta_conf[idx / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;
	}
	
    for(idx = 0;idx < dev_info.reta_size; idx++){
		uint32_t reta_id = idx / RTE_RETA_GROUP_SIZE;
		uint32_t reta_pos = idx % RTE_RETA_GROUP_SIZE;
		
        reta_conf[reta_id].reta[reta_pos] = idx%5;
		if(reta_conf[reta_id].reta[reta_pos] == 3){
        	reta_conf[reta_id].reta[reta_pos] = 0;
		}
    }
    int ret = 1;
	fprintf(stderr,"dev_info.reta_size is %d \n",dev_info.reta_size);
 //  rte_eth_dev_rss_reta_query(port,reta_conf,512);
   status  = rte_eth_dev_rss_reta_update(port,reta_conf,dev_info.reta_size);
//   ret = rte_eth_dev_rss_reta_query(port,reta_conf_get,512);

    if (status != 0){
       rte_panic("%s (%u): RSS setup error (RETA update failed)\n");
    }
#if 0
   if (ret != 0){
			fprintf(stderr,"Bad redirection table parameter, "
					"return code = %d \n", ret);
   }else{

            for(idx = 0;idx <num;idx++){
				j = 0;
                for(i = 0; i <RTE_RETA_GROUP_SIZE;i++){
		        j =  reta_conf_get[idx].reta[i];
               
			    fprintf(stderr,"good redirection table parameter get and i is %d and result is %d \n",i,j);
				}
            }   
			fprintf(stderr,"Good redirection table parameter, "
					"return code = %d \n", ret);
   }
#endif


}
