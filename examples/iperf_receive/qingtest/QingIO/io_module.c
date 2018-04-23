/* for I/O module def'ns */
#include "./include/io_module.h"
/* std lib funcs */
#include <stdlib.h>
/* std io funcs */
#include <stdio.h>
/* strcmp func etc. */
#include <string.h>
/* for ifreq struct */
#include <net/if.h>
/* for ioctl */
#include <sys/ioctl.h>
#ifndef DISABLE_DPDK
/* for dpdk ethernet functions (get mac addresses) */
#include <rte_ethdev.h>
#endif
/* for inet_* */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* for getopt() */
#include <unistd.h>
/* for getifaddrs */
#include <sys/types.h>
#include <ifaddrs.h>
/*----------------------------------------------------------------------------*/
io_module_func *current_iomodule_func = &dpdk_module_func;
#define ALL_STRING			"all"
#define MAX_PROCLINE_LEN		1024
#define MAX(a, b) 			((a)>(b)?(a):(b))
#define MIN(a, b) 			((a)<(b)?(a):(b))
/*----------------------------------------------------------------------------*/
static int
GetNumQueues()
{
	FILE *fp;
	char buf[MAX_PROCLINE_LEN];
	int queue_cnt = 4;


	return queue_cnt;
}
/*----------------------------------------------------------------------------*/
int
SetInterfaceInfo(char* dev_name_list)
{
	struct ifreq ifr;
	int eidx = 0;
	int i, j;
        int num_devices;
        int num_queues = 8;
        int num_cores = 4;
	int set_all_inf = (strncmp(dev_name_list, ALL_STRING, sizeof(ALL_STRING))==0);

//	TRACE_CONFIG("Loading interface setting\n");
/*
	CONFIG.eths = (struct eth_table *)
			calloc(MAX_DEVICES, sizeof(struct eth_table));
	if (!CONFIG.eths) {
		TRACE_ERROR("Can't allocate space for CONFIG.eths\n");
		exit(EXIT_FAILURE);
	}
*/
		/* To Do: Parse dev_name_list rather than use strstr */
	if (current_iomodule_func == &dpdk_module_func) {
#ifndef DISABLE_DPDK
		int cpu = 4;//CONFIG.num_cores;
		uint32_t cpumask = 0;
		char cpumaskbuf[10];
		char mem_channels[5];
		int ret;
		static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

		/* get the cpu mask */
		for (ret = 0; ret < cpu; ret++)
			cpumask = (cpumask | (1 << ret));
		sprintf(cpumaskbuf, "%X", cpumask);

		/* initialize the rte env first, what a waste of implementation effort!  */
		char *argv[] = {"",
				"-c",
				cpumaskbuf,
				"-n",
				mem_channels,
				"--proc-type=auto",
				""
		};
		const int argc = 6;

		/*
		 * re-set getopt extern variable optind.
		 * this issue was a bitch to debug
		 * rte_eal_init() internally uses getopt() syscall
		 * mtcp applications that also use an `external' getopt
		 * will cause a violent crash if optind is not reset to zero
		 * prior to calling the func below...
		 * see man getopt(3) for more details
		 */
		optind = 0;

		/* initialize the dpdk eal env */
		ret = rte_eal_init(argc, argv);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Invalid EAL args!\n");
		/* give me the count of 'detected' ethernet ports */
		num_devices = rte_eth_dev_count();
		if (num_devices == 0) {
			rte_exit(EXIT_FAILURE, "No Ethernet port!\n");
		}

		/* get mac addr entries of 'detected' dpdk ports */
		for (ret = 0; ret < num_devices; ret++)
			rte_eth_macaddr_get(ret, &ports_eth_addr[ret]);

		num_queues = MIN(num_cores, MAX_CPUS);


#endif /* !DISABLE_DPDK */
	} 

	return 0;
}
/*----------------------------------------------------------------------------*/
int
FetchEndianType()
{
#ifndef DISABLE_DPDK
	char *argv;
	char **argp = &argv;
	/* dpdk_module_func logic down below */
//	dpdk_module_func.dev_ioctl(NULL, CONFIG.eths[0].ifindex, DRV_NAME, (void *)argp);
//	if (!strcmp(*argp, "net_i40e"))
//		return 1;

	return 0;
#else
	return 1;
#endif
}
/*----------------------------------------------------------------------------*/
