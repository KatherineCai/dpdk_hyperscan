#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include "nids_interface.h"
#include "nids.h"
#include <time.h>
//#include "sniff.c"
#include <pthread.h>
#include <assert.h>
#define UNUSED(x)      (void)(x)

int g_proc_id = 0;
int g_port = 0;
FILE *write_file = NULL;
uint64_t pkt_num = 0;
struct timeval prev_time,cur_time;

// 10.0.0.1,1024,10.0.0.2,23
char * adres1 (struct tuple4 addr)
{
	static char buf[256];
	//strcpy (buf, int_ntoa (addr.saddr));
	sprintf (buf + strlen (buf), ",%i,", addr.source);
	//strcat (buf, int_ntoa (addr.daddr));
	sprintf (buf + strlen (buf), ",%i", addr.dest);
	return buf;
}

struct buf *head;
struct buf *tail;
pthread_mutex_t mutex;
long buffer_has_item = 0;
uint32_t buffer_put_count = 0;
void put_function( int size, char *data )
{
//	pthread_mutex_lock( &mutex );
	make_new_item( size, data );
	buffer_has_item++;
//	pthread_mutex_unlock( &mutex );
}
void get_function( void )
{
	while ( 1 )
	{
		struct buf* q = tail->prev;
		if(q->state == 1){
			if ( buffer_has_item > 0 )
			{
				//pthread_mutex_lock(&mutex);
				consume_item();
				//pthread_mutex_unlock(&mutex);
				buffer_has_item--;

			}
		}

	}
}


void make_new_item(int size, char *data )

{
	struct buf *con;

	if ( !(con = (struct buf *) malloc( sizeof(struct buf) ) ) )
	{
		assert( "con malloc fail!" );
	}

	if ( !(con->buffer = (char *) malloc( size * sizeof(char) ) ) )
	{
		assert( "con buffer malloc fail!" );
 	}

	memset( con->buffer, 0, size * sizeof(char) );

	memcpy( con->buffer, data, size * sizeof(char) );
    con->len  = size;
	con->prev = NULL;
	con->state= 0;
	con->next = NULL;

	if ( head->next == tail )
	{
		head->next = con;

		con->prev = head;
		con->next = tail;
		tail->prev = con;
	}else{
		con->prev = head;
		con->next = head->next;
//		head->next = con;
		head->next->prev = con;
		head->next = con;

		//con->prev = head->prev;
		//head->prev->next = con;
		//head->prev = con;
		//con->next = NULL;
	}
} 

void consume_item()
 
{ 
	int k;

	struct buf *p;

 	//printf("i am free this node!!");
	p = tail->prev;
	if(p->prev != head){
		tail->prev = p->prev;
   		p->prev->next = tail;
	}else{
		head->next = tail;
		tail->prev = head;
	}
	if ( p != head ){
		free( p );
		p = NULL;
		}
	
}
void init_dlink()
{ 
	if(!(head = (struct buf *)malloc(sizeof(struct buf)))){
		assert("head maclloc fail!!");
 	}
	if(!(tail = (struct buf *)malloc(sizeof(struct buf)))){
		assert("tail malloc fail!!");
 	}
	head->len  = 0;
	head->prev = NULL;
	head->state= 0;
	head->next =tail;

	tail->len  = 0;
	tail->prev = head;
	tail->next = NULL;
	tail->state = 0;

}
	
void tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{
	/////////
    int i=0;
    char content[10000];
    /////////
	char buf[1024];
	strcpy (buf, adres1 (a_tcp->addr)); // we put conn params into buf
	if (a_tcp->nids_state == NIDS_JUST_EST)
	{
		// connection described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
		a_tcp->client.collect++; // we want data received by a client
		a_tcp->server.collect++; // and by a server, too
		a_tcp->server.collect_urg++; // we want urgent data received by a
		// server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT

		a_tcp->client.collect_urg++; // if we don't increase this value,
		// we won't be notified of urgent data
	// arrival
#endif
	//	fprintf (stderr, "%s established\n", buf);
		return;
	}

	if (a_tcp->nids_state == NIDS_CLOSE)
	{
		//fprintf(stdout,"tcp has been in nids_close!!");
		// connection has been closed normally
		char  content2[1000];
        /*    for(tmp = hlf2->list;tmp != hlf2->listtail ; tmp = tmp->next){
            printf("/////////////  seq: %u  /////////// \n",tmp->seq); 
            fprintf(stderr,"//////  %u  //////",tmp->seq);
        }*/
        //fprintf (stderr, "%s closing\n", buf);
		return;
	}

	if (a_tcp->nids_state == NIDS_RESET)
	{
		// connection has been closed by RST
	//	fprintf (stderr, "%s reset\n", buf);
		return;
	}

	if (a_tcp->nids_state == NIDS_DATA)
	{
		// new data has arrived; gotta determine in what direction
		// and if it's urgent or not
		struct half_stream *hlf;
		if (a_tcp->server.count_new_urg)
		{
			// new byte of urgent data has arrived
			strcat(buf,"(urgent->)");
			buf[strlen(buf)+1]=0;
			// buf[strlen(buf)]=a_tcp->server.urgdata;
			//write(1,buf,strlen(buf));
			return;
		}
		
		// We don't have to check if urgent data to client has arrived,
		// because we haven't increased a_tcp->client.collect_urg variable.
		// So, we have some normal data to take care of.
		if (a_tcp->client.count_new)
		{
			// new data for client
			hlf = &a_tcp->client; // from now on, we will deal with hlf va
	//		printf("--------------client----------------------------");
        //	fprintf(stdout,"%s",hlf->data);
			put_function(hlf->count_new,hlf->data);
			buffer_put_count += 1;
	//        printf("--------------client----------------------------");
   //         printf("%s", buf);
           // memcpy(content,hlf->data,hlf->count_new);
   //         printf("##########  %u   ########3\n",hlf->seq);
            // which will point to client side of conn
	//		strcat (buf, "(<-)"); // symbolic direction of data
	     	
        }
		else
		{
			hlf = &a_tcp->server; // analogical
		//	fprintf(stdout,"%s",hlf->data);
			put_function(hlf->count_new,hlf->data);
	//		  printf("--------------server----------------------------");
    //        printf("--------------server----------------------------");
   //         printf("%s", buf);
   //         printf("######################  %u      ############\n",hlf->seq);
  //			strcat (buf, "(->)");
		}
//		fprintf(stderr,"%s",buf); // we print the connection parameters
		// (saddr, daddr, sport, dport) accompanied
		// by data flow direction (-> or <-)
		//write(2,hlf->data,hlf->count_new); // we print the newly arrived data
	}
	return ;
}
int process_init(void)
{
	//pthread_t thread;
	init_dlink();
	//pthread_mutex_init(&mutex,NULL);
	#if 1
	if (!nids_init ())
    {
        fprintf (stderr, "%s\n", nids_errbuf);
        exit (1);
	}                               
	//pthread_create(&thread,NULL,(void *)get_function,NULL);                                                                                    
	///////////////////////////////
   nids_register_tcp(tcp_callback);
    ///////////////////////////////
    #endif                                                                                                                                                                                        return 0;
}
int process_pkt_callback( void* data, uint16_t data_len )
{
	struct pcap_pkthdr pkthdr;                                                                     u_char *pkt_data = data;	
	pkthdr.caplen	= data_len;
	pkthdr.len	= data_len;
	nids_pcap_handler( 0, &pkthdr, pkt_data );
	return(0);
} 

