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

#ifdef MY_DIRECTIVE
    #define MY_VALUE MY_DIRECTIVE
#else
    #define MY_VALUE "valore_predefinito"
#endif

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void print_ipv6_address(uint8_t *addr) {
    printf("IPv6 Address: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", addr[i]);
        if (i % 2 == 1 && i < 15) {
            printf(":");
        }
    }
    printf("\n");
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <interface> <ipv4|ipv6>\n", argv[0]);
		return 1;
	}

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

	#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV6)
	int map_fd;
	#endif
	//struct packet_info key;
  	//struct value_packet value;

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

	#ifdef CLASSIFY_IPV4
	if(strcmp(map_type, "ipv4") == 0) {
		map_fd = bpf_map__fd(skel->maps.my_map);
		if (map_fd < 0) {
			fprintf(stderr, "Failed to get map file descriptor\n");
			return 1;
		}
	} else {
		fprintf(stderr, "Invalid map type\n");
		return 1;
	}
	#endif

	#ifdef CLASSIFY_IPV6
	printf("Recupero mappa\n");
	if(strcmp(map_type, "ipv6") == 0) {
		map_fd = bpf_map__fd(skel->maps.my_map_ipv6);
		if (map_fd < 0) {
			fprintf(stderr, "Failed to get map file descriptor\n");
			return 1;
		}
	} else {
		fprintf(stderr, "Invalid map type\n");
		return 1;
	}
	#endif
	/*map_fd = bpf_map__fd(skel->maps.my_map);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get map file descriptor\n");
		return 1;
	}*/

	while (!exiting) {
		/*fprintf(stderr, ".");
		sleep(1);*/

		int counter = 0;
		#ifdef CLASSIFY_IPV4
        if (strcmp(map_type, "ipv4") == 0) {
            struct packet_info key;
            struct value_packet value;
            memset(&key, 0, sizeof(key));

            while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
                counter++;

                int ret = bpf_map_lookup_elem(map_fd, &key, &value);
                if (ret) {
                    fprintf(stderr, "Failed to lookup map element\n");
                    return 1;
                }

                __u8 byte1 = key.src_ip & 0xFF;
                __u8 byte2 = (key.src_ip >> 8) & 0xFF;
                __u8 byte3 = (key.src_ip >> 16) & 0xFF;
                __u8 byte4 = (key.src_ip >> 24) & 0xFF;

                printf("---------------\n");
                printf("Key: Source IP: %u.%u.%u.%u\n", byte1, byte2, byte3, byte4);

                byte1 = key.dst_ip & 0xFF;
                byte2 = (key.dst_ip >> 8) & 0xFF;
                byte3 = (key.dst_ip >> 16) & 0xFF;
                byte4 = (key.dst_ip >> 24) & 0xFF;
                printf("Key: Destination IP: %u.%u.%u.%u\n", byte1, byte2, byte3, byte4);

                printf("Key: Source Port: %u\n", key.src_port);
                printf("Key: Destination Port: %u\n", key.dst_port);
                printf("Key: Protocol: %u\n", key.protocol);
                printf("Value: Counter: %u\n", value.counter);
                printf("---------------\n");
            }
        }
		#endif

		#ifdef CLASSIFY_IPV6
		if (strcmp(map_type, "ipv6") == 0) {
			struct packet_info_ipv6 key;
			struct value_packet value;
			memset(&key, 0, sizeof(key));

			while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
				counter++;

				int ret = bpf_map_lookup_elem(map_fd, &key, &value);
				if (ret) {
					fprintf(stderr, "Failed to lookup map element\n");
					return 1;
				}

				printf("---------------\n");
				printf("Key: Source IP: ");
				print_ipv6_address(key.src_ip);
				printf("Key: Destination IP: ");
				print_ipv6_address(key.dst_ip);
				printf("Key: Source Port: %u\n", key.src_port);
				printf("Key: Destination Port: %u\n", key.dst_port);
				printf("Key: Protocol: %u\n", key.protocol);
				printf("Value: Counter: %u\n", value.counter);
				printf("---------------\n");
			}
        }
		#endif

        printf("The map has %d elements\n", counter);
        printf("******************************************************************************\n");

        sleep(3);
    

	}

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
