cmd_eal_timer.o = gcc -Wp,-MD,./.eal_timer.o.d.tmp -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ  -I/root/dpdk-16.07/build/include -include /root/dpdk-16.07/build/include/rte_config.h -I/root/dpdk-16.07/lib/librte_eal/linuxapp/eal/include -I/root/dpdk-16.07/lib/librte_eal/common -I/root/dpdk-16.07/lib/librte_eal/common/include -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -O3 -D_GNU_SOURCE  -o eal_timer.o -c /root/dpdk-16.07/lib/librte_eal/linuxapp/eal/eal_timer.c 
