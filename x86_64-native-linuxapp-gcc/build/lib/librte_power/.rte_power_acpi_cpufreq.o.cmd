cmd_rte_power_acpi_cpufreq.o = gcc -Wp,-MD,./.rte_power_acpi_cpufreq.o.d.tmp -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ  -I/root/dpdk-16.07/x86_64-native-linuxapp-gcc/include -include /root/dpdk-16.07/x86_64-native-linuxapp-gcc/include/rte_config.h -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -I/root/dpdk-16.07/lib/librte_power -O3 -fno-strict-aliasing   -o rte_power_acpi_cpufreq.o -c /root/dpdk-16.07/lib/librte_power/rte_power_acpi_cpufreq.c 
