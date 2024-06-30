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
//#include "../../influxdb-connector/influxdb_wrapper_int.h"

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

// Funzione per stampare il contenuto della mappa ipv4_flow
void print_ipv4_flow(int map_fd) {
    __u64 key = 0, next_key;
    struct packet_info value;

    printf("IPv4 Flow Map:\n");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            printf("Key: %llu\n", next_key);
            printf("  src_ip: %u, dst_ip: %u, src_port: %u, dst_port: %u, protocol: %u\n",
                   value.src_ip, value.dst_ip, value.src_port, value.dst_port, value.protocol);
        }
        key = next_key;
    }
}

// Funzione per stampare il contenuto della mappa ipv6_flow
void print_ipv6_flow(int map_fd) {
    __u64 key = 0, next_key;
    struct packet_info_ipv6 value;

    printf("IPv6 Flow Map:\n");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            printf("Key: %llu\n", next_key);
            printf("  src_ip: ");
            for (int i = 0; i < 16; i++) {
                printf("%02x", value.src_ip[i]);
                if (i % 2 == 1 && i < 15) {
                    printf(":");
                }
            }
            printf(", dst_ip: ");
            for (int i = 0; i < 16; i++) {
                printf("%02x", value.dst_ip[i]);
                if (i % 2 == 1 && i < 15) {
                    printf(":");
                }
            }
            printf(", src_port: %u, dst_port: %u, protocol: %u\n",
                   value.src_port, value.dst_port, value.protocol);
        }
        key = next_key;
    }
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

	// #ifdef CLASSIFY_IPV4
	// printf("CLASSIFY_IPV4 is defined\n");
	// #endif

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

	#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
	int map_fd;
	int map_fd_flow;
	#endif
	//struct packet_info key;
  	//struct value_packet value;
	struct bpf_object *obj;

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
		map_fd_flow = bpf_object__find_map_fd_by_name(obj, "ipv4_flow");
		if (map_fd < 0 || map_fd_flow < 0) {
			fprintf(stderr, "Failed to get map file descriptor\n");
			goto detach;
		}
	} else {
		fprintf(stderr, "Invalid map type\n");
		goto detach;
	}
	#endif

	#ifdef CLASSIFY_IPV6
	if(strcmp(map_type, "ipv6") == 0) {
		map_fd = bpf_map__fd(skel->maps.my_map_ipv6);
		map_fd_flow = bpf_object__find_map_fd_by_name(obj, "ipv6_flow");
		if (map_fd < 0 || map_fd_flow < 0) {
			fprintf(stderr, "Failed to get map file descriptor\n");
			goto detach;
		}
	} else {
		fprintf(stderr, "Invalid map type\n");
		goto detach;
	}
	#endif

	#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
	if(strcmp(map_type, "ipv4") == 0) {
		map_fd = bpf_map__fd(skel->maps.map_only_addr_ipv4);
		if (map_fd < 0) {
			fprintf(stderr, "Failed to get map file descriptor\n");
			goto detach;
		}
	} else {
		fprintf(stderr, "Invalid map type\n");
		goto detach;
	}
	#endif

	#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
	if(strcmp(map_type, "ipv6") == 0) {
		map_fd = bpf_map__fd(skel->maps.map_only_addr_ipv6);
		if (map_fd < 0) {
			fprintf(stderr, "Failed to get map file descriptor\n");
			goto detach;
		}
	} else {
		fprintf(stderr, "Invalid map type\n");
		goto detach;
	}
	#endif

	#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
	if(strcmp(map_type, "ipv4") == 0) {
		map_fd = bpf_map__fd(skel->maps.map_only_dest_ipv4);
		if (map_fd < 0) {
			fprintf(stderr, "Failed to get map file descriptor\n");
			goto detach;
		}
	} else {
		fprintf(stderr, "Invalid map type\n");
		goto detach;
	}
	#endif

	#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
	if(strcmp(map_type, "ipv6") == 0) {
		map_fd = bpf_map__fd(skel->maps.map_only_dest_ipv6);
		if (map_fd < 0) {
			fprintf(stderr, "Failed to get map file descriptor\n");
			goto detach;
		}
	} else {
		fprintf(stderr, "Invalid map type\n");
		goto detach;
	}
	#endif
	

	while (!exiting) {
		/*fprintf(stderr, ".");
		sleep(1);*/

		int counter = 0;
		#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
        if (strcmp(map_type, "ipv4") == 0) {

			#ifdef CLASSIFY_IPV4
            struct packet_info key;
			#endif
			#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
			struct only_addr_ipv4 key;
			#endif
			#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
			struct only_dest_ipv4 key;
			#endif

            struct value_packet value;
            memset(&key, 0, sizeof(key));

            while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
                counter++;

                int ret = bpf_map_lookup_elem(map_fd, &key, &value);
                if (ret == -1) {
                    fprintf(stderr, "Failed to lookup map element\n");
                    goto detach;
                }
				__u8 byte1;
				__u8 byte2;
				__u8 byte3;
				__u8 byte4;

				#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4)
                byte1 = key.src_ip & 0xFF;
                byte2 = (key.src_ip >> 8) & 0xFF;
                byte3 = (key.src_ip >> 16) & 0xFF;
                byte4 = (key.src_ip >> 24) & 0xFF;

                printf("---------------\n");
                printf("Key: Source IP: %u.%u.%u.%u\n", byte1, byte2, byte3, byte4);
				#endif

                byte1 = key.dst_ip & 0xFF;
                byte2 = (key.dst_ip >> 8) & 0xFF;
                byte3 = (key.dst_ip >> 16) & 0xFF;
                byte4 = (key.dst_ip >> 24) & 0xFF;
                printf("Key: Destination IP: %u.%u.%u.%u\n", byte1, byte2, byte3, byte4);

				#ifdef CLASSIFY_IPV4
                printf("Key: Source Port: %u\n", key.src_port);
                printf("Key: Destination Port: %u\n", key.dst_port);
                printf("Key: Protocol: %u\n", key.protocol);
				#endif

                printf("Value: Counter: %u\n", value.counter);
				printf("Value: Bytes Counter: %llu\n", value.bytes_counter);
                printf("---------------\n");
            }
        }
		#endif

		#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
		if (strcmp(map_type, "ipv6") == 0) {
			
			#ifdef CLASSIFY_IPV6
			struct packet_info_ipv6 key;
			#endif
			#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
			struct only_addr_ipv6 key;
			#endif
			#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
			struct only_dest_ipv6 key;
			#endif

			struct value_packet value;
			memset(&key, 0, sizeof(key));

			while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
				counter++;

				int ret = bpf_map_lookup_elem(map_fd, &key, &value);
				if (ret == -1) {
					fprintf(stderr, "Failed to lookup map element\n");
					goto detach;
				}

				printf("---------------\n");
				#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6)
				printf("Key: Source IP: ");
				print_ipv6_address(key.src_ip);
				#endif

				printf("Key: Destination IP: ");
				print_ipv6_address(key.dst_ip);

				#ifdef CLASSIFY_IPV6
				printf("Key: Source Port: %u\n", key.src_port);
				printf("Key: Destination Port: %u\n", key.dst_port);
				printf("Key: Protocol: %u\n", key.protocol);
				#endif

				printf("Value: Counter: %u\n", value.counter);
				printf("Value: Bytes Counter: %llu\n", value.bytes_counter);
				printf("---------------\n");
			}
        }
		#endif

		printf("The map has %d elements\n", counter);
        printf("******************************************************************************\n");
        sleep(3);
	}

	#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
	print_ipv4_flow(map_fd_flow);
	#endif

	#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
	print_ipv6_flow(map_fd_flow);
	#endif

	goto detach;

	/*printf("Printing the flow map: \n");
	#ifdef CLASSIFY_IPV4
	map_fd = bpf_map__fd(skel->maps.ipv4_flow);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get map file descriptor\n");
		return 1;
	}
    printf("map_fd: %d\n", map_fd);  // Debug: stampa il valore di map_fd
	__u64 key_flow = 0;
	struct packet_info packet;
    printf("key_flow: %llu\n", key_flow);  // Debug: stampa il valore di key_flow

    int ret;
	while ((ret = bpf_map_get_next_key(map_fd, &key_flow, &key_flow)) == 0) {
		ret = bpf_map_lookup_elem(map_fd, &key_flow, &packet);
		if (ret) {
			fprintf(stderr, "Failed to lookup map element\n");
			return 1;
		}

		printf("Flow: %llu\n", key_flow);

		__u8 byte1 = packet.src_ip & 0xFF;
		__u8 byte2 = (packet.src_ip >> 8) & 0xFF;
		__u8 byte3 = (packet.src_ip >> 16) & 0xFF;
		__u8 byte4 = (packet.src_ip >> 24) & 0xFF;

		printf("---------------\n");
		printf("Key: Source IP: %u.%u.%u.%u\n", byte1, byte2, byte3, byte4);

		byte1 = packet.dst_ip & 0xFF;
		byte2 = (packet.dst_ip >> 8) & 0xFF;
		byte3 = (packet.dst_ip >> 16) & 0xFF;
		byte4 = (packet.dst_ip >> 24) & 0xFF;
		printf("Key: Destination IP: %u.%u.%u.%u\n", byte1, byte2, byte3, byte4);

		printf("Key: Source Port: %u\n", packet.src_port);
		printf("Key: Destination Port: %u\n", packet.dst_port);
		printf("Key: Protocol: %u\n", packet.protocol);
		printf("---------------\n");
	}

    if (ret != 0) {
        fprintf(stderr, "bpf_map_get_next_key returned: %d, errno: %d (%s)\n", ret, errno, strerror(errno));
    }

	#endif

	#ifdef CLASSIFY_IPV6
	map_fd = bpf_map__fd(skel->maps.ipv6_flow);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get map file descriptor\n");
		return 1;
	}
	__u64 key_flow = 0;
	struct packet_info_ipv6 packet;

	while (bpf_map_get_next_key(map_fd, &key_flow, &key_flow) == 0) {
		int ret = bpf_map_lookup_elem(map_fd, &key_flow, &packet);
		if (ret) {
			fprintf(stderr, "Failed to lookup map element\n");
			return 1;
		}

		printf("Flow: %llu\n", key_flow);

		printf("---------------\n");
		printf("Key: Source IP: ");
		print_ipv6_address(packet.src_ip);
		printf("Key: Destination IP: ");
		print_ipv6_address(packet.dst_ip);
		printf("Key: Source Port: %u\n", packet.src_port);
		printf("Key: Destination Port: %u\n", packet.dst_port);
		printf("Key: Protocol: %u\n", packet.protocol);
		printf("---------------\n");
	}
	#endif*/

	
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
