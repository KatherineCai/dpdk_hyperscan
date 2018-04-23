#include <rte_mbuf.h>




void build_pkt_74(struct rte_mbuf *pkt_mbuf)
{
	unsigned char *ptr_mac, *ptr_ip, *ptr_tcp, *ptr_payload;
	
	if (pkt_mbuf == NULL)
	{
		printf("alloc mbuf error!\n");
		return -1;
	}
	pkt_mbuf->data_len = 74;
	pkt_mbuf->pkt_len = 74;
	
	ptr_mac = pkt_mbuf->buf_addr + pkt_mbuf->data_off;
	ptr_ip = ptr_mac + 14;
	ptr_tcp = ptr_ip + 20;

#if 0	
	//dst mac addr
	*(ptr_mac + 0) = 0xaa;
	*(ptr_mac + 1) = 0xbb;
	*(ptr_mac + 2) = 0xcc;
	*(ptr_mac + 3) = 0xdd;
	*(ptr_mac + 4) = 0xee;
	*(ptr_mac + 5) = 0xff;
#endif

	//dst mac addr
	*(ptr_mac + 0) = 0xaa;
	*(ptr_mac + 1) = 0xbb;
	*(ptr_mac + 2) = 0xcc;
	*(ptr_mac + 3) = 0xdd;
	*(ptr_mac + 4) = 0xee;
	*(ptr_mac + 5) = 0x07;

#if 0
	//src_mac_addr
	*(ptr_mac + 6) = 0x90;
	*(ptr_mac + 7) = 0xe2;
	*(ptr_mac + 8 )= 0xba;
	*(ptr_mac + 9) = 0x16;
	*(ptr_mac + 10) = 0x1f;
	*(ptr_mac + 11) = 0xd0;
#endif
#if 1
	//src_mac_addr
	*(ptr_mac + 6) = 0xff;
	*(ptr_mac + 7) = 0xff;
	*(ptr_mac + 8 )= 0xff;
	*(ptr_mac + 9) = 0xff;
	*(ptr_mac + 10) = 0xff;
	*(ptr_mac + 11) = 0xff;
#endif


	//layer 2 type 
	*(ptr_mac + 12) = 0x08;
	*(ptr_mac + 13) = 0x00;


	//IP packet length
	//*ip_len = 0xBA;
	*(ptr_ip + 0) = 0x45;
	*(ptr_ip + 1) = 0x00;
	*(ptr_ip + 2) = 0x00;
	*(ptr_ip + 3) = 0x3c;	
	*(ptr_ip + 4) = 0x00;	
	*(ptr_ip + 5) = 0x00;	
	*(ptr_ip + 6) = 0x40;	
	*(ptr_ip + 7) = 0x00;		
	*(ptr_ip + 8) = 0x40;
	*(ptr_ip + 9) = 0x06;	
	*(ptr_ip + 10) = 0x26;	
	*(ptr_ip + 11) = 0xb9;	
	*(ptr_ip + 12) = 0x0a;	
	*(ptr_ip + 13) = 0x00;	
	*(ptr_ip + 14) = 0x00;	
	*(ptr_ip + 15) = 0x06;	
	*(ptr_ip + 16) = 0x0a;	
	*(ptr_ip + 17) = 0x00;	
	*(ptr_ip + 18) = 0x00;	
	*(ptr_ip + 19) = 0x05;	

	//tcp head length
	*(ptr_tcp + 0) = 0x04;	
	*(ptr_tcp + 1) = 0xd2;	
	*(ptr_tcp + 2) = 0x00;	
	*(ptr_tcp + 3) = 0x50;	
	*(ptr_tcp + 4) = 0x1d;	
	*(ptr_tcp + 5) = 0x26;	
	*(ptr_tcp + 6) = 0x15;	
	*(ptr_tcp + 7) = 0xa1;	
	*(ptr_tcp + 8) = 0x00;	
	*(ptr_tcp + 9) = 0x00;	
	*(ptr_tcp + 10) = 0x00;	
	*(ptr_tcp + 11) = 0x00;	
	*(ptr_tcp + 12) = 0xa0;	
	*(ptr_tcp + 13) = 0x02;	
	*(ptr_tcp + 14) = 0x39;	
	*(ptr_tcp + 15) = 0x08;	
	*(ptr_tcp + 16) = 0x77;	
	*(ptr_tcp + 17) = 0x2e;	
	*(ptr_tcp + 18) = 0x00;	
	*(ptr_tcp + 19) = 0x00;	
	*(ptr_tcp + 20) = 0x02;	
	*(ptr_tcp + 21) = 0x04;	
	*(ptr_tcp + 22) = 0x05;	
	*(ptr_tcp + 23) = 0xb4;	
	*(ptr_tcp + 24) = 0x01;	
	*(ptr_tcp + 25) = 0x01;	
	*(ptr_tcp + 26) = 0x08;	
	*(ptr_tcp + 27) = 0x0a;	
	*(ptr_tcp + 28) = 0x15;	
	*(ptr_tcp + 29) = 0x55;	
	*(ptr_tcp + 30) = 0x39;	
	*(ptr_tcp + 31) = 0x82;	
	*(ptr_tcp + 32) = 0x00;	
	*(ptr_tcp + 33) = 0x00;	
	*(ptr_tcp + 34) = 0x00;	
	*(ptr_tcp + 35) = 0x00;	
	*(ptr_tcp + 36) = 0x01;	
	*(ptr_tcp + 37) = 0x03;	
	*(ptr_tcp + 38) = 0x03;	
	*(ptr_tcp + 39) = 0x07;	

}



void build_pkt_66(struct rte_mbuf *pkt_mbuf)
{
	unsigned char *ptr_mac, *ptr_ip, *ptr_tcp, *ptr_payload;
	
	if (pkt_mbuf == NULL)
	{
		printf("alloc mbuf error!\n");
		return -1;
	}
	pkt_mbuf->data_len = 66;
	pkt_mbuf->pkt_len = 66;
	
	ptr_mac = pkt_mbuf->buf_addr + pkt_mbuf->data_off;
	ptr_ip = ptr_mac + 14;
	ptr_tcp = ptr_ip + 20;
	
	//dst mac addr
	*(ptr_mac + 0) = 0xaa;
	*(ptr_mac + 1) = 0xbb;
	*(ptr_mac + 2) = 0xcc;
	*(ptr_mac + 3) = 0xdd;
	*(ptr_mac + 4) = 0xee;
	*(ptr_mac + 5) = 0xff;

	//src_mac_addr
	*(ptr_mac + 6) = 0x90;
	*(ptr_mac + 7) = 0xe2;
	*(ptr_mac + 8 )= 0xba;
	*(ptr_mac + 9) = 0x16;
	*(ptr_mac + 10) = 0x1f;
	*(ptr_mac + 11) = 0xd0;

	
#if 0
	//src_mac_addr
	*(ptr_mac + 6) = 0x90;
	*(ptr_mac + 7) = 0xe2;
	*(ptr_mac + 8 )= 0xba;
	*(ptr_mac + 9) = 0x0e;
	*(ptr_mac + 10) = 0x35;
	*(ptr_mac + 11) = 0xdc;
#endif

	//layer 2 type 
	*(ptr_mac + 12) = 0x08;
	*(ptr_mac + 13) = 0x00;


	//IP packet length
	*(ptr_ip + 0) = 0x45;
	*(ptr_ip + 1) = 0x00;
	*(ptr_ip + 2) = 0x00;
	*(ptr_ip + 3) = 0x34;	
	*(ptr_ip + 4) = 0x00;	
	*(ptr_ip + 5) = 0x01;	
	*(ptr_ip + 6) = 0x40;	
	*(ptr_ip + 7) = 0x00;		
	*(ptr_ip + 8) = 0x40;
	*(ptr_ip + 9) = 0x06;	
	*(ptr_ip + 10) = 0x26;	
	*(ptr_ip + 11) = 0xb9;	
	*(ptr_ip + 12) = 0x0a;	
	*(ptr_ip + 13) = 0x00;	
	*(ptr_ip + 14) = 0x00;	
	*(ptr_ip + 15) = 0x06;	
	*(ptr_ip + 16) = 0x0a;	
	*(ptr_ip + 17) = 0x00;	
	*(ptr_ip + 18) = 0x00;	
	*(ptr_ip + 19) = 0x05;	

	//tcp head length
	*(ptr_tcp + 0) = 0x06;	
	*(ptr_tcp + 1) = 0x1e;	
	*(ptr_tcp + 2) = 0x00;	
	*(ptr_tcp + 3) = 0x50;	
	*(ptr_tcp + 4) = 0x29;	
	*(ptr_tcp + 5) = 0xf7;	
	*(ptr_tcp + 6) = 0xa9;	
	*(ptr_tcp + 7) = 0xb6;	
	*(ptr_tcp + 8) = 0x65;	
	*(ptr_tcp + 9) = 0x64;	
	*(ptr_tcp + 10) = 0x4e;	
	*(ptr_tcp + 11) = 0x7c;	
	*(ptr_tcp + 12) = 0x80;	
	*(ptr_tcp + 13) = 0x10;	
	*(ptr_tcp + 14) = 0x00;	
	*(ptr_tcp + 15) = 0x72;	
	*(ptr_tcp + 16) = 0x4c;	
	*(ptr_tcp + 17) = 0x6c;	
	*(ptr_tcp + 18) = 0x00;	
	*(ptr_tcp + 19) = 0x00;	
	*(ptr_tcp + 20) = 0x01;	
	*(ptr_tcp + 21) = 0x01;	
	*(ptr_tcp + 22) = 0x08;	
	*(ptr_tcp + 23) = 0x0a;	
	*(ptr_tcp + 24) = 0x15;	
	*(ptr_tcp + 25) = 0x55;	
	*(ptr_tcp + 26) = 0x39;	
	*(ptr_tcp + 27) = 0x84;	
	*(ptr_tcp + 28) = 0x15;	
	*(ptr_tcp + 29) = 0x55;	
	*(ptr_tcp + 30) = 0x23;	
	*(ptr_tcp + 31) = 0xaa;	
}
