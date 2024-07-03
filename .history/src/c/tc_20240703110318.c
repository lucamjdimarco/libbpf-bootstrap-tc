// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <net/if.h>  // for if_nametoindex
#include "tc.skel.h"
#include "common.h"
#include "../../influxdb-connector/influxdb_wrapper_int.h"

//make CFLAGS_EXTRA="-DCLASS=1"


static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int initialize_map_fd(const char* map_type, struct tc_bpf *skel, int* map_fd, int* map_fd_flow) {
	if (strcmp(map_type, "ipv4") == 0) {
		#ifdef CLASSIFY_IPV4
		*map_fd = bpf_map__fd(skel->maps.my_map);
		*map_fd_flow = bpf_map__fd(skel->maps.ipv4_flow);
		#elif defined(CLASSIFY_ONLY_ADDRESS_IPV4)
		*map_fd = bpf_map__fd(skel->maps.map_only_addr_ipv4);
		*map_fd_flow = bpf_map__fd(skel->maps.ipv4_flow);
		#elif defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
		*map_fd = bpf_map__fd(skel->maps.map_only_dest_ipv4);
		*map_fd_flow = bpf_map__fd(skel->maps.ipv4_flow);
		#endif
	} else if (strcmp(map_type, "ipv6") == 0) {
		#ifdef CLASSIFY_IPV6
		*map_fd = bpf_map__fd(skel->maps.my_map_ipv6);
		*map_fd_flow = bpf_map__fd(skel->maps.ipv6_flow);
		#elif defined(CLASSIFY_ONLY_ADDRESS_IPV6)
		*map_fd = bpf_map__fd(skel->maps.map_only_addr_ipv6);
		*map_fd_flow = bpf_map__fd(skel->maps.ipv6_flow);
		#elif defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
		*map_fd = bpf_map__fd(skel->maps.map_only_dest_ipv6);
		*map_fd_flow = bpf_map__fd(skel->maps.ipv6_flow);
		#endif
	} else {
		fprintf(stderr, "Invalid map type\n");
		return -1;
	}

	if (*map_fd < 0 || *map_fd_flow < 0) {
		fprintf(stderr, "Failed to get map file descriptor\n");
		return -1;
	}
	return 0;
}


int main(int argc, char **argv)
{

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <interface> <ipv4|ipv6>\n", argv[0]);
		return 1;
	}

	/*-----------------------*/

	/*MHandler_t *h = create_influxdb("http://localhost:8086?db=tc_db");
	if (!h) {
		printf("Cannot create MHandler\n");
		return -EINVAL;
	}

	show_databases_influxdb(h);
	write_temp_influxdb(h, "Rome", 14.1);

	destroy_influxdb(h);
	h = NULL;

	printf(" *** Done ***\n");*/

	/*-----------------------*/

	const char *interface_name = argv[1];
	const char *map_type = argv[2];
	int index = if_nametoindex(interface_name);
	if (index == 0) {
		perror("if_nametoindex");
		return 1;
	}
	//DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = LO_IFINDEX,
			    //.attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = index,
			    .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	bool hook_created = false;
	struct tc_bpf *skel;
	int err;

	int map_fd;
	int map_fd_flow;

	libbpf_set_print(libbpf_print_fn);

	skel = tc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	if (initialize_map_fd(map_type, skel, &map_fd, &map_fd_flow) != 0) {
		goto detach;
	}

	while (!exiting) {
		if (strcmp(map_type, "ipv4") == 0) {
			process_ipv4_map(map_fd, map_type);
		} else if (strcmp(map_type, "ipv6") == 0) {
			process_ipv6_map(map_fd, map_type);
		}

		sleep(3);
	}

	printf("Printing the flow map: \n");
	if (strcmp(map_type, "ipv4") == 0) {
		print_ipv4_flow(map_fd_flow);
	} else if (strcmp(map_type, "ipv6") == 0) {
		print_ipv6_flow(map_fd_flow);
	}
	
detach:
	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	tc_bpf__destroy(skel);
	return -err;
}
