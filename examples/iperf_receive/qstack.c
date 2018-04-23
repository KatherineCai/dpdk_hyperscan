
/* for io_module_func def'ns */
#include "./include/io_module.h"
#include "./include/datatype.h"
#include "./include/qstack.h"
#include "./include/io_module.h"
/* for errno */
#include <errno.h>
#include <assert.h>
/* for rte_max_eth_ports */
#include <rte_common.h>
/* for rte_eth_rxconf */
#include <rte_ethdev.h>
/* for delay funcs */
#include <rte_cycles.h>
#include <rte_errno.h>
#define ENABLE_STATS_IOCTL		1
#ifdef ENABLE_STATS_IOCTL
/* for close */
#include <unistd.h>
/* for open */
#include <fcntl.h>
/* for ioctl */
#include <sys/ioctl.h>
#endif /* !ENABLE_STATS_IOCTL */
/* for ip pseudo-chksum */
#include <rte_ip.h>
//#define IP_DEFRAG			1



static mtcp_manager_t 
InitializeMTCPManager(struct mtcp_thread_context* ctx)
{

	mtcp_manager_t mtcp;
	char log_name[100];
	int i;
	mtcp = (mtcp_manager_t)calloc(1, sizeof(struct mtcp_manager));
	if (!mtcp) {
		printf(stderr, "Failed to allocate mtcp_manager.\n");
		return NULL;
	}
        mtcp->ctx = ctx;
        mtcp->iom = current_iomodule_func;
        return mtcp;
}


struct mtcp_thread_context* MTCPRunThread(int core,int queue)
{
//	mctx_t mctx = (mctx_t)arg;
        
	int cpu = core;
        
	int working;
	struct mtcp_manager *mtcp;
	struct mtcp_thread_context *ctx;

	/* affinitize the thread to this core first */
//	mtcp_core_affinitize(cpu);

	/* memory alloc after core affinitization would use local memory
 * 	   most time */
	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		perror("calloc");
		printf("Failed to calloc mtcp context.\n");
		exit(-1);
	}
//	ctx->thread = pthread_self();
	ctx->cpu = cpu;
        ctx->queue = queue;
	mtcp = ctx->mtcp_manager = InitializeMTCPManager(ctx);
	if (!mtcp) {
		printf("Failed to initialize mtcp manager.\n");
		exit(-1);
	}
	/* assign mtcp context's underlying I/O module */
	mtcp->iom = current_iomodule_func;

	/* I/O initializing */
	mtcp->iom->init_handle(ctx);

    return ctx;

}
