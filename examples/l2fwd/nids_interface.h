#ifndef _MOD_INTERFASE_H__
#define _MOD_INTERFASE_H__

#ifdef __cplusplus
extern "C" {
#endif
    int process_init(void);
    int process_pkt_callback(void* data,uint16_t data_len);
        #ifdef __cplusplus
        }
        #endif

        #endif

struct buf{
				int state;
	            char *buffer;
	        	long len;
	            struct buf *prev;
	            struct buf *next;
		  };
	   extern struct buf *tail;
	   extern struct buf *head;
	   extern void get_function();
