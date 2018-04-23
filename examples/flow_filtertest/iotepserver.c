#define _LARGEFILE64_SOURCE

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

#include <mtcp_api.h>
#include <mtcp_epoll.h>

#include "cpu.h"
#include "http_parsing.h"
#include "redis/redis.h"
#include "debug.h"
 

#define MAX_FLOW_NUM  (3020000)

#define RCVBUF_SIZE (2*1024)
#define SNDBUF_SIZE (8*1024)

#define MAX_EVENTS (MAX_FLOW_NUM * 3)

#define HTTP_HEADER_LEN 1024
#define URL_LEN 128

#define MAX_CPUS 24
#define MAX_FILES 30

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define HT_SUPPORT FALSE

#include <sched.h>

//add by songhui
uint64_t requests;
uint64_t responces;

/*----------------------------------------------------------------------------*/
struct file_cache
{
	char name[128];
	char fullname[256];
	uint64_t size;
	char *file;
};
/*----------------------------------------------------------------------------*/
struct server_vars
{
	char request[HTTP_HEADER_LEN];
	int recv_len;
	int request_len;
	long int total_read, total_sent;
	uint8_t done;
	uint8_t rspheader_sent;
	uint8_t keep_alive;

	int fidx;						// file cache index
	char fname[128];				// file name
	long int fsize;					// file size
};
/*----------------------------------------------------------------------------*/
struct thread_context
{
	mctx_t mctx;
	int ep;
	struct server_vars *svars;
};
/*----------------------------------------------------------------------------*/
static int num_cores;
static int core_limit;
static int nb_processors;
static pthread_t app_thread[MAX_CPUS];
static int done[MAX_CPUS];
/*----------------------------------------------------------------------------*/
const char *www_main;
static struct file_cache fcache[MAX_FILES];
static int nfiles;
/*----------------------------------------------------------------------------*/
static int finished;


/*----------------------------------------------------------------------------*/
static char *
StatusCodeToString(int scode)
{
	switch (scode) {
		case 200:
			return "OK";
			break;

		case 404:
			return "Not Found";
			break;
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
void
CleanServerVariable(struct server_vars *sv)
{
	sv->recv_len = 0;
	sv->request_len = 0;
	sv->total_read = 0;
	sv->total_sent = 0;
	sv->done = 0;
	sv->rspheader_sent = 0;
	sv->keep_alive = 0;
}
/*----------------------------------------------------------------------------*/
void 
CloseConnection(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
	mtcp_close(ctx->mctx, sockid);
}
/*----------------------------------------------------------------------------*/
static int 
SendUntilAvailable(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	int ret;
	int sent;
	int len;

	if (sv->done || !sv->rspheader_sent) {
		return 0;
	}

	sent = 0;
	ret = 1;
	while (ret > 0) {
		len = MIN(SNDBUF_SIZE, sv->fsize - sv->total_sent);
		if (len <= 0) {
			break;
		}
		ret = mtcp_write(ctx->mctx, sockid,  
				fcache[sv->fidx].file + sv->total_sent, len);
		if (ret < 0) {
			TRACE_APP("Connection closed with client.\n");
			break;
		}
		TRACE_APP("Socket %d: mtcp_write try: %d, ret: %d\n", sockid, len, ret);
		sent += ret;
		sv->total_sent += ret;
	}

	if (sv->total_sent >= fcache[sv->fidx].size) {
		struct mtcp_epoll_event ev;
		sv->done = TRUE;
		finished++;

		if (sv->keep_alive) {
			/* if keep-alive connection, wait for the incoming request */
			ev.events = MTCP_EPOLLIN;
			ev.data.sockid = sockid;
			mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);

			CleanServerVariable(sv);
		} else {
			/* else, close connection */
			CloseConnection(ctx, sockid, sv);
		}
	}

	return sent;
}

#define SUCCESS 1
#define FAILURE 0
#define SLIDE_WIN_SIZE 1024

#define NUM_REDIS_THREAD 4

struct server_stats {
    struct timeval redis_t_start;
    struct timeval redis_t_end;
    
    uint64_t queue_len;
    uint64_t sum_redis_time;
    uint64_t max_redis_time;
    uint64_t completes; 
    
    uint64_t queue_delay;    
    uint64_t queue_time[SLIDE_WIN_SIZE];  
    uint64_t redis_time[SLIDE_WIN_SIZE];
    uint16_t _size;
    
    uint64_t queue_time_95;
    uint64_t redis_time_95;

    //add by songhui
    uint64_t requests_counter;
    uint64_t responces_counter;
    uint64_t update_counter;
    
} g_stats[NUM_REDIS_THREAD];

struct ForwardPkt
{
    int sock_id;
    int core_id;    
    mctx_t mctx;
    struct timeval start_time;
    struct timeval end_time;
    
};


#define CAP_REDIS_BUFFER 1024
#define REDIS_DB
FILE *stats;

struct ForwardPktBuffer
{
    struct ForwardPkt pktQueue[CAP_REDIS_BUFFER];
    int capacity;
    int _size;
    int _head;
    int _tail;
    
    pthread_mutex_t mutex;
        
};

//add by songhui
struct ForwardPktBuffer forwardUpdate[NUM_REDIS_THREAD];

struct ForwardPktBuffer forwardQuery[NUM_REDIS_THREAD];

static int queryDatabase(const char *key, const char *cmpValue, clusterInfo *cluster, const int database, int core_id)
{
    char value[VALUE_LEN];
    int error;

    error = get(cluster, key, value, database, core_id);

    if (error == 0) {
        
        if (strcmp(value, "nil") == 0) 
        {
             set(cluster, key, cmpValue, database, core_id);
        }
        return SUCCESS;
    } else {
        return FAILURE;
    }
}

void initForwardBuffer(struct ForwardPktBuffer *forwardBuffer,int buffer_id) {
            
    int j;
    for (j = 0; j < CAP_REDIS_BUFFER; j ++) {
            forwardBuffer[buffer_id].pktQueue[j].sock_id = 0;
            forwardBuffer[buffer_id].pktQueue[j].core_id = 0;
    }
        
    forwardBuffer[buffer_id]._head = forwardBuffer[buffer_id]._tail = forwardBuffer[buffer_id]._size = 0;
    pthread_mutex_init(&forwardBuffer[buffer_id].mutex, NULL);
}

struct ForwardPkt* head(struct ForwardPktBuffer *forwardBuffer,int buffer_id) {
    return forwardBuffer[buffer_id].pktQueue + (forwardBuffer[buffer_id]._head % CAP_REDIS_BUFFER); 
}

void headNext(struct ForwardPktBuffer *forwardBuffer,int buffer_id) { 
    forwardBuffer[buffer_id]._head = (forwardBuffer[buffer_id]._head + 1) % CAP_REDIS_BUFFER; 
    forwardBuffer[buffer_id]._size --; 
}

struct ForwardPkt* tail(struct ForwardPktBuffer *forwardBuffer,int buffer_id) {
     return forwardBuffer[buffer_id].pktQueue + (forwardBuffer[buffer_id]._tail % CAP_REDIS_BUFFER); 
}

void tailNext(struct ForwardPktBuffer *forwardBuffer,int buffer_id) {
    forwardBuffer[buffer_id]._tail = (forwardBuffer[buffer_id]._tail + 1) % CAP_REDIS_BUFFER; 
    forwardBuffer[buffer_id]._size ++; 
}

u_int forwardBufferSize(struct ForwardPktBuffer *forwardBuffer,int buffer_id) {
    return forwardBuffer[buffer_id]._size;
}



struct server_stats total = {0};

void 
PrintStats() {
    
    if (!stats)
        stats = fopen("server_stats", "w");
                
    struct server_stats st;
    uint64_t avg_redis_time;
    uint64_t total_redis_time = 0;
    int i;
    int j, k;
    uint64_t temp;
    
    total._size ++;
    //if (total._size > 300) 
    //    return;
    
    for (i = 0; i < core_limit; i ++) {
        
        avg_redis_time = g_stats[i].completes ? g_stats[i].sum_redis_time / g_stats[i].completes : 0;        
        total.completes += g_stats[i].completes;
        total_redis_time += avg_redis_time;
        total.queue_len += g_stats[i].completes ? g_stats[i].queue_len / g_stats[i].completes : 0;
        total.queue_delay += g_stats[i].completes ? g_stats[i].queue_delay / g_stats[i].completes : 0;
        
        if (g_stats[i].max_redis_time > total.max_redis_time) {
            total.max_redis_time = g_stats[i].max_redis_time;
        }
        
        for (j = 0; j < g_stats[i]._size; j ++) {
            for (k = j + 1; k < g_stats[i]._size; k ++) {
                if (g_stats[i].queue_time[j] > g_stats[i].queue_time[k]) {
                    temp = g_stats[i].queue_time[j];
                    g_stats[i].queue_time[j] = g_stats[i].queue_time[k];
                    g_stats[i].queue_time[k] = temp;
                }
                
                if (g_stats[i].redis_time[j] > g_stats[i].redis_time[k]) {
                    temp = g_stats[i].redis_time[j];
                    g_stats[i].redis_time[j] = g_stats[i].redis_time[k];
                    g_stats[i].redis_time[k] = temp;
                }
            }
        }
        
        int m = g_stats[i]._size*0.99;

	total.requests_counter += g_stats[i].requests_counter;
	total.responces_counter += g_stats[i].requests_counter;	
	total.update_counter += g_stats[i].update_counter;
        
        total.queue_time_95 += g_stats[i].queue_time[m];
        total.redis_time_95 += g_stats[i].redis_time[m];
        
        g_stats[i].completes = 0;
        g_stats[i].max_redis_time = 0;
        g_stats[i].sum_redis_time = 0;
        g_stats[i].queue_len = 0;
        g_stats[i].queue_delay = 0;
        
        for (j = 0; j < g_stats[i]._size; j ++) {
            g_stats[i].queue_time[j] = 0;
            g_stats[i].redis_time[j] = 0;
        }
        
        g_stats[i]._size = 0;
	g_stats[i].requests_counter = 0;
	g_stats[i].responces_counter = 0;
	g_stats[i].update_counter = 0;
    }
    
	 
    /*fprintf(stderr, "[ALL] redis completes: %5u (redis time avg: %3lu, max: %5lu us), len: %2lu delay: %5lu 95th delay: %5lu 95th redis: %5lu\n", 
                    total.completes / core_limit, total_redis_time / core_limit, total.max_redis_time, total.queue_len / core_limit, 
                    total.queue_delay / core_limit, total.queue_time_95 / core_limit, total.redis_time_95 / core_limit);*/
    fprintf(stderr, "[ALL] redis completes: %5u, request packets: %5lu, response packets: %5lu, update packets: %5lu\n", 
                    total.completes, total.requests_counter, total.responces_counter, total.update_counter);
    /*
    if (total.completes)
        fprintf(stats, "completes: %5u redis: avg: %3lu max: %5lu 99th: %5lu queue: len: %2lu delay: %5lu 99th: %5lu\n", 
                    total.completes / core_limit, total_redis_time / core_limit, total.max_redis_time, total.redis_time_95 / core_limit, total.queue_len / core_limit, 
                    total.queue_delay / core_limit, total.queue_time_95 / core_limit);*/
    
    total.completes = 0;    
    total.queue_delay = 0;
    total.queue_len = 0;
    total.redis_time_95 = 0;
    total.queue_time_95 = 0;
    total.sum_redis_time = 0;
    total.max_redis_time = 0;
    
    total.requests_counter = 0;
    total.responces_counter = 0;   
    total.update_counter = 0;
}

void process_requests(clusterInfo *cluster,int id){
	
    mctx_t mctx;
    int sockid;
    int core_id;
    int ret = 0;
    struct timeval start_time;
    char response[HTTP_HEADER_LEN];
	
    struct ForwardPkt *req = head(forwardQuery,id); 
    mctx = req->mctx;
    sockid = req->sock_id;
    core_id = req->core_id;
    start_time = req->start_time;
    headNext(forwardQuery,id);            
    pthread_mutex_unlock(&forwardQuery[id].mutex); 
				
#ifdef REDIS_DB
    char buffer[33]; 
    sprintf(buffer, "%d", sockid);        
    queryDatabase(buffer, "2", cluster, 1, id);            
    queryDatabase(buffer, "4", cluster, 2, id);   
#endif

    if (core_id) {
    	sprintf(response, "HTTP/1.1 %d %s\r\n"
                    "Date: %s\r\n"
                    "Server: Webserver on Middlebox TCP (Ubuntu)\r\n"
                    "Content-Length: %ld\r\n"
                    "Connection: %s\r\n\r\n", 
                    200, StatusCodeToString(200), "25.11.1985", 100, "keepalive");
	
	response[6] = 0x3;
	
    	ret = mtcp_write(mctx, sockid, response, 146);
	if (ret != 146) {
	    fprintf(stderr, "socket id: %u, errno: %d\n", sockid, errno);
	} else {	
	    g_stats[id].responces_counter += 1;
	}	
    }

   g_stats[id].queue_len += forwardQuery[id]._size;
}

void process_updates(clusterInfo *cluster,int id){
	
    mctx_t mctx;
    int sockid;
    int core_id;
    int ret = 0;
    struct timeval start_time;
    char response[HTTP_HEADER_LEN];	
	
    struct ForwardPkt *req = head(forwardUpdate,id);
    mctx = req->mctx;
    sockid = req->sock_id;
    core_id = req->core_id;
    start_time = req->start_time;
    headNext(forwardUpdate,id);
    pthread_mutex_unlock(&forwardUpdate[id].mutex);

#ifdef REDIS_DB
    char buffer[33];
    sprintf(buffer, "%d", sockid);
    queryDatabase(buffer, "2", cluster, 1, id);
    queryDatabase(buffer, "4", cluster, 2, id);
#endif

}


void* 
redis_requests(void* args) {
        
    int id = *(int *)args;//sched_getcpu() % NUM_REDIS_BUFFER;
    
    mctx_t mctx;
    int sockid;
    int core_id;
    struct timeval start_time;
    
#ifdef REDIS_DB
    clusterInfo *cluster = connectRedis();    
#endif

    char response[HTTP_HEADER_LEN];
    srand((unsigned)time(NULL));
    
    int i = id;
    initForwardBuffer(forwardQuery,i);
    initForwardBuffer(forwardUpdate,i);        
    memset(&g_stats[i], 0, sizeof(struct server_stats));
 
    fprintf(stderr, "ID: %lu, CPU:%d, Buffer: %d\n", pthread_self(), sched_getcpu(), id);
                 
    while(TRUE) {
            gettimeofday(&g_stats[i].redis_t_start, NULL); 
            pthread_mutex_lock(&forwardQuery[i].mutex);           
            if (!forwardBufferSize(forwardQuery,i)) {                      
	        pthread_mutex_unlock(&forwardQuery[i].mutex);
                     pthread_mutex_lock(&forwardUpdate[i].mutex);
                     if (!forwardBufferSize(forwardUpdate,i)) {
                        pthread_mutex_unlock(&forwardUpdate[i].mutex);
                        continue;
                     }else{
                        process_updates(cluster,i);
		        pthread_mutex_lock(&forwardQuery[i].mutex);
		        if (!forwardBufferSize(forwardQuery,i))
		            pthread_mutex_unlock(&forwardQuery[i].mutex);
		        else{
			    process_requests(cluster,i);
		        }
                     }
		    continue;			     
	    	}else{
	    	    process_requests(cluster,i);
	    }

	    

	    gettimeofday(&g_stats[i].redis_t_end, NULL);
                             
            uint64_t tdiff = (g_stats[i].redis_t_end.tv_sec - g_stats[i].redis_t_start.tv_sec) * 1000000 +
                    (g_stats[i].redis_t_end.tv_usec - g_stats[i].redis_t_start.tv_usec);

            g_stats[i].sum_redis_time += tdiff;
            if (tdiff > g_stats[i].max_redis_time)
                g_stats[i].max_redis_time = tdiff;
            
            uint64_t delay = (g_stats[i].redis_t_end.tv_sec - start_time.tv_sec) * 1000000 +
                    (g_stats[i].redis_t_end.tv_usec - start_time.tv_usec);
            g_stats[i].queue_delay += delay;
            g_stats[i].completes ++;     
            
            if (g_stats[i]._size < SLIDE_WIN_SIZE) {                
                g_stats[i].queue_time[g_stats[i]._size] = delay;
                g_stats[i].redis_time[g_stats[i]._size] = tdiff;
                g_stats[i]._size ++;
            }
            
        
    }
 
#ifdef REDIS_DB
    disconnectDatabase(cluster);
#endif
}

int pos_query[MAX_CPUS] = {0};
int pos_update[MAX_CPUS] = {0};

//#define PIPE_LINE
/*----------------------------------------------------------------------------*/
static int 
HandleReadEvent(struct thread_context *ctx, int sockid, struct server_vars *sv, clusterInfo *cluster, int core_id)
{
	struct mtcp_epoll_event ev;
	char buf[HTTP_HEADER_LEN];
	char url[URL_LEN];
	char response[HTTP_HEADER_LEN];
	int scode;						// status code
	time_t t_now;
	char t_str[128];
	char keepalive_str[128];
	int rd;
	int i;
	int len;
	int sent;
       
        
	/* HTTP request handling */
	rd = mtcp_read(ctx->mctx, sockid, buf, HTTP_HEADER_LEN);
	if (rd <= 0) {
            fprintf(stderr, "error reading\n");
		return rd;
	}
        
	memcpy(sv->request + sv->recv_len, (char *)buf, MIN(rd, HTTP_HEADER_LEN - sv->recv_len));	
        
        //if (*(buf + 3) == 0x2)
        //    fprintf(stderr, "---%x---%d---\n", *(buf + 3), core_id);
            
        sv->recv_len += rd;
	
        //sv->request[rd] = '\0';
	//fprintf(stderr, "HTTP Request: %s\n", sv->request);        
       
        sv->keep_alive = TRUE;
	scode = 200;
      
	TRACE_APP("Socket %d File size: %ld (%ldMB)\n", 
			sockid, sv->fsize, sv->fsize / 1024 / 1024);

        
	/* Response header handling */
	time(&t_now);
	strftime(t_str, 128, "%a, %d %b %Y %X GMT", gmtime(&t_now));
                        
        
#ifndef PIPE_LINE
	if (buf[5] == 0x1){
		if (pos_query[core_id] == 0)
            	pos_query[core_id] = 0; //core_id*(NUM_REDIS_THREAD/core_limit);        
        	i = pos_query[core_id];
		
		g_stats[i].requests_counter += 1;
		requests++;
		
		pthread_mutex_lock(&forwardQuery[i].mutex);
        	struct ForwardPkt *req = tail(forwardQuery,i);
        	req->sock_id = sockid;
        	req->core_id = core_id;
		req->mctx = ctx->mctx;   
        	gettimeofday(&req->start_time, NULL);
        	tailNext(forwardQuery,i); 
		pthread_mutex_unlock(&forwardQuery[i].mutex);
		
		pos_query[core_id] ++;       
        	if (pos_query[core_id] == NUM_REDIS_THREAD)
			pos_query[core_id] = 0; //core_id*(NUM_REDIS_THREAD/core_limit); 
	}else{
		if (pos_update[core_id] == 0)
            	pos_update[core_id] = 0; //core_id*(NUM_REDIS_THREAD/core_limit);        
        	i = pos_update[core_id];

		g_stats[i].update_counter += 1;
		
		pthread_mutex_lock(&forwardUpdate[i].mutex);
        	struct ForwardPkt *req = tail(forwardUpdate,i);
        	req->sock_id = sockid;
		req->core_id = 0;
		req->mctx = ctx->mctx;   
        	gettimeofday(&req->start_time, NULL);
        	tailNext(forwardUpdate,i);
		pthread_mutex_unlock(&forwardUpdate[i].mutex);

		pos_update[core_id] ++;       
        	if (pos_update[core_id] == NUM_REDIS_THREAD)
			pos_update[core_id] = 0; //core_id*(NUM_REDIS_THREAD/core_limit); 
	} 
          		     
#else
                
	gettimeofday(&g_stats[i].redis_t_start, NULL); 
        
#ifdef REDIS_DB
        char buffer[33];        
        sprintf(buffer, "%d", sockid);        
        queryDatabase(buffer, "2", cluster, 1, i);
        queryDatabase(buffer, "4", cluster, 2, i);        
#endif
        
        gettimeofday(&g_stats[i].redis_t_end, NULL);

 	uint64_t tdiff = (g_stats[i].redis_t_end.tv_sec - g_stats[i].redis_t_start.tv_sec) * 1000000 +
                    (g_stats[i].redis_t_end.tv_usec - g_stats[i].redis_t_start.tv_usec);

        g_stats[i].sum_redis_time += tdiff;
        if (tdiff > g_stats[i].max_redis_time)
            g_stats[i].max_redis_time = tdiff;
        g_stats[i].completes ++;     
        
        
        if ((rand() % 100) < 5) {
            sprintf(response, "HTTP/1.1 %d %s\r\n"
                            "Date: %s\r\n"
                            "Server: Webserver on Middlebox TCP (Ubuntu)\r\n"
                            "Content-Length: %ld\r\n"
                            "Connection: %s\r\n\r\n", 
                            scode, StatusCodeToString(scode), t_str, sv->fsize, keepalive_str);

            len = 146;
            TRACE_APP("Socket %d HTTP Response: \n%s", sockid, response);

            sent = mtcp_write(ctx->mctx, sockid, response, len);
            TRACE_APP("Socket %d Sent response header: try: %d, sent: %d\n", 
                            sockid, len, sent);
            sv->rspheader_sent = TRUE;
        
        }

#endif        

        CleanServerVariable(sv);
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);                      
	
	return rd;
}
/*----------------------------------------------------------------------------*/
int 
AcceptConnection(struct thread_context *ctx, int listener)
{
	mctx_t mctx = ctx->mctx;
	struct server_vars *sv;
	struct mtcp_epoll_event ev;
	int c;

	c = mtcp_accept(mctx, listener, NULL, NULL);

	if (c >= 0) {
		if (c >= MAX_FLOW_NUM) {
                    fprintf(stderr, "%d larger than %d\n", c, MAX_FLOW_NUM);
			TRACE_ERROR("Invalid socket id %d.\n", c);
			return -1;
		}

		sv = &ctx->svars[c];
		CleanServerVariable(sv);
		TRACE_APP("New connection %d accepted.\n", c);
		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = c;
		mtcp_setsock_nonblock(ctx->mctx, c);
		mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, c, &ev);
		TRACE_APP("Socket %d registered.\n", c);

	} else {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    fprintf(stderr, "mtcp_accept() error\n");
			TRACE_ERROR("mtcp_accept() error %s\n", 
					strerror(errno));
		}
	}

	return c;
}
/*----------------------------------------------------------------------------*/
struct thread_context *
InitializeServerThread(int core)
{
	struct thread_context *ctx;

	/* affinitize application thread to a CPU core */
#if HT_SUPPORT
	mtcp_core_affinitize(core + (num_cores / 2));
#else
	mtcp_core_affinitize(core);
#endif /* HT_SUPPORT */

	ctx = (struct thread_context *)calloc(1, sizeof(struct thread_context));
	if (!ctx) {
		TRACE_ERROR("Failed to create thread context!\n");
		return NULL;
	}

	/* create mtcp context: this will spawn an mtcp thread */
	ctx->mctx = mtcp_create_context(core);
	if (!ctx->mctx) {
		TRACE_ERROR("Failed to create mtcp context!\n");
		return NULL;
	}

	/* create epoll descriptor */
	ctx->ep = mtcp_epoll_create(ctx->mctx, MAX_EVENTS);
	if (ctx->ep < 0) {
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}

	/* allocate memory for server variables */
	ctx->svars = (struct server_vars *)
			calloc(MAX_FLOW_NUM, sizeof(struct server_vars));
	if (!ctx->svars) {
		TRACE_ERROR("Failed to create server_vars struct!\n");
		return NULL;
	}

	return ctx;
}
/*----------------------------------------------------------------------------*/
int 
CreateListeningSocket(struct thread_context *ctx)
{
	int listener;
	struct mtcp_epoll_event ev;
	struct sockaddr_in saddr;
	int ret;

	/* create socket and set it as nonblocking */
	listener = mtcp_socket(ctx->mctx, AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}
	ret = mtcp_setsock_nonblock(ctx->mctx, listener);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}

	/* bind to port 80 */
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(80);
	ret = mtcp_bind(ctx->mctx, listener, 
			(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	/* listen (backlog: 4K) */
	ret = mtcp_listen(ctx->mctx, listener, 100000);
	if (ret < 0) {
            
		TRACE_ERROR("mtcp_listen() failed!\n");
		return -1;
	}
	
	/* wait for incoming accept events */
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, listener, &ev);

	return listener;
}



/*----------------------------------------------------------------------------*/
void *
RunServerThread(void *arg)
{
	int core = *(int *)arg;
	struct thread_context *ctx;
	mctx_t mctx;
	int listener;
	int ep;
	struct mtcp_epoll_event *events;
	int nevents;
	int i, ret;
	int do_accept;
              
	//clusterInfo *cluster = connectRedis();    
        
	/* initialization */
	ctx = InitializeServerThread(core);
	if (!ctx) {
		TRACE_ERROR("Failed to initialize server thread.\n");
		return NULL;
	}
	mctx = ctx->mctx;
	ep = ctx->ep;

	events = (struct mtcp_epoll_event *)
			calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}

	listener = CreateListeningSocket(ctx);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket.\n");
		exit(-1);
	}
        
 	srand((unsigned)time(NULL));
                     
        struct timeval cur_tv, prev_tv;
        gettimeofday(&cur_tv, NULL);
        
        prev_tv = cur_tv;
        
	while (!done[core]) {
            gettimeofday(&cur_tv, NULL);
            
            if (core == 1 && cur_tv.tv_sec > prev_tv.tv_sec) {
                PrintStats();
                prev_tv = cur_tv;
            }
                                
            nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
            if (nevents < 0) {
                    if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                            perror("mtcp_epoll_wait");
                    break;
            }

		do_accept = FALSE;
		for (i = 0; i < nevents; i++) {
                        
			if (events[i].data.sockid == listener) {
				/* if the event is for the listener, accept connection */
				do_accept = TRUE;                                

			} else if (events[i].events & MTCP_EPOLLERR) {
				int err;
				socklen_t len = sizeof(err);

				/* error on the connection */
				TRACE_APP("[CPU %d] Error on socket %d\n", 
						core, events[i].data.sockid);
				if (mtcp_getsockopt(mctx, events[i].data.sockid, 
						SOL_SOCKET, SO_ERROR, (void *)&err, &len) == 0) {
					if (err != ETIMEDOUT) {
						fprintf(stderr, "Error on socket %d: %s\n", 
								events[i].data.sockid, strerror(err));
					}
				} else {
					perror("mtcp_getsockopt");
				}
				CloseConnection(ctx, events[i].data.sockid, 
						&ctx->svars[events[i].data.sockid]);

			} else if (events[i].events & MTCP_EPOLLIN) {        
				//printf("\nenter mtcp_in\n");                   
				ret = HandleReadEvent(ctx, events[i].data.sockid, 
						&ctx->svars[events[i].data.sockid], NULL, core);
                                
                                
                               
                                
				if (ret == 0) 
                                {
                                    /* connection closed by remote host */
                                    fprintf(stderr, "socket %d connection closed by remote host\n", events[i].data.sockid);
                                    CloseConnection(ctx, events[i].data.sockid, 
							&ctx->svars[events[i].data.sockid]);
				} 
                                else if (ret < 0) 
                                {
                                    /* if not EAGAIN, it's an error */                                    
                                    fprintf(stderr, "socket %d error connection\n", events[i].data.sockid);
                                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
						CloseConnection(ctx, events[i].data.sockid, 
								&ctx->svars[events[i].data.sockid]);
                                    }
				}

			} else if (events[i].events & MTCP_EPOLLOUT) {
				//printf("\nenter mtcp_out\n");                   
				struct server_vars *sv = &ctx->svars[events[i].data.sockid];
				if (sv->rspheader_sent) {
					SendUntilAvailable(ctx, events[i].data.sockid, sv);
				} else {
					TRACE_APP("Socket %d: Response header not sent yet.\n", 
							events[i].data.sockid);
				}

			} else {
				assert(0);
			}
		}

		/* if do_accept flag is set, accept connections */
		if (do_accept) {
			while (1) {
				ret = AcceptConnection(ctx, listener);
				if (ret < 0)
					break;
			}
		}

	}

	/* destroy mtcp context: this will kill the mtcp thread */
	mtcp_destroy_context(mctx);
	pthread_exit(NULL);
        
    
       
        
	return NULL;
}
/*----------------------------------------------------------------------------*/
void
SignalHandler(int signum)
{
	int i;

	for (i = 0; i < core_limit; i++) {
		if (app_thread[i] == pthread_self()) {
			//TRACE_INFO("Server thread %d got SIGINT\n", i);
			done[i] = TRUE;
		} else {
			if (!done[i]) {
				pthread_kill(app_thread[i], signum);
			}
		}
	}
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	DIR *dir;
	struct dirent *ent;
	int fd;
	int ret;
	uint64_t total_read;
	struct mtcp_conf mcfg;
	int cores[MAX_CPUS];
	int i;
        
        redis_init_global();
        
	// @wangzhuang 
	//num_cores = GetNumCPUs();
	num_cores = 23;
	core_limit = num_cores;

	if (argc < 2) {
		TRACE_ERROR("$%s directory_to_service\n", argv[0]);
		return FALSE;
	}
   
	/* open the directory to serve */
	www_main = argv[1];
	dir = opendir(www_main);
	if (!dir) {
		TRACE_ERROR("Failed to open %s.\n", www_main);
		perror("opendir");
		return FALSE;
	}

	for (i = 0; i < argc - 1; i++) {
		if (strcmp(argv[i], "-N") == 0) {
			core_limit = atoi(argv[i + 1]);
			if (core_limit > num_cores) {
				TRACE_CONFIG("CPU limit should be smaller than the "
						"number of CPUS: %d\n", num_cores);
				return FALSE;
			}
			/** 
			 * it is important that core limit is set 
			 * before mtcp_init() is called. You can
			 * not set core_limit after mtcp_init()
			 */
			mtcp_getconf(&mcfg);
			mcfg.num_cores = core_limit;
                    mcfg.max_concurrency = 3000000;

                        mcfg.max_num_buffers = 3000000;
			mtcp_setconf(&mcfg);
		}
	}

     
	nfiles = 0;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0)
			continue;
		else if (strcmp(ent->d_name, "..") == 0)
			continue;

		strcpy(fcache[nfiles].name, ent->d_name);
		sprintf(fcache[nfiles].fullname, "%s/%s", www_main, ent->d_name);
		fd = open(fcache[nfiles].fullname, O_RDONLY);
		if (fd < 0) {
			perror("open");
			continue;
		} else {
			fcache[nfiles].size = lseek64(fd, 0, SEEK_END);
			lseek64(fd, 0, SEEK_SET);
		}

		fcache[nfiles].file = (char *)malloc(fcache[nfiles].size);
		if (!fcache[nfiles].file) {
			TRACE_ERROR("Failed to allocate memory for file %s\n", 
					fcache[nfiles].name);
			perror("malloc");
			continue;
		}

		TRACE_INFO("Reading %s (%lu bytes)\n", 
				fcache[nfiles].name, fcache[nfiles].size);
		total_read = 0;
		while (1) {
			ret = read(fd, fcache[nfiles].file + total_read, 
					fcache[nfiles].size - total_read);
			if (ret < 0) {
				break;
			} else if (ret == 0) {
				break;
			}
			total_read += ret;
		}
		if (total_read < fcache[nfiles].size) {
			free(fcache[nfiles].file);
			continue;
		}
		close(fd);
		nfiles++;

		if (nfiles >= MAX_FILES)
			break;
	}

	finished = 0;

	/* initialize mtcp */
	ret = mtcp_init("epserver.conf");
	if (ret) {
		TRACE_ERROR("Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}

	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);

	TRACE_INFO("Application initialization finished.\n");
        nb_processors = NUM_REDIS_THREAD;//num_cores - core_limit;
        pthread_t process_requests[nb_processors];
        pthread_attr_t attr;
        cpu_set_t cpus;
        pthread_attr_init(&attr);
        
        int buffer[NUM_REDIS_THREAD];
        
	for (i = 0; i < NUM_REDIS_THREAD; i ++) {
            buffer[i] = i;
            CPU_ZERO(&cpus);                    
            CPU_SET(core_limit + i%(num_cores - core_limit) , &cpus);                        
            pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
            pthread_create(&process_requests[i], &attr, redis_requests, (void *) &buffer[i]);
        }       
        
	/*
        for (i = nb_processors/2; i < nb_processors; i ++) {
            buffer[i] = i;
            CPU_ZERO(&cpus);            
            CPU_SET(num_cores - 1 - i + nb_processors/2, &cpus);            
            pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
            pthread_create(&process_requests[i], &attr, redis_requests, (void *) &buffer[i]);
        }       
        */

       
        for (i = 0; i < core_limit; i++) {
		cores[i] = i;
		done[i] = FALSE;
		
		if (pthread_create(&app_thread[i], 
				   NULL, RunServerThread, (void *)&cores[i])) {
			perror("pthread_create");
			TRACE_ERROR("Failed to create server thread.\n");
			exit(-1);
		}
	}
	
        
        
        
	for (i = 0; i < core_limit; i++) {
            pthread_join(app_thread[i], NULL);
	}
	
        for (i = 0; i < nb_processors; i ++) {
            pthread_join(process_requests[i], NULL);
        }
        
       
	mtcp_destroy();
	closedir(dir);
	return 0;
}
