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

//make -j6 CFLAGS_EXTRA="-DCLASS=1"

#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
void print_ipv4_address(__u32 ip) {
    __u8 byte1 = ip & 0xFF;
    __u8 byte2 = (ip >> 8) & 0xFF;
    __u8 byte3 = (ip >> 16) & 0xFF;
    __u8 byte4 = (ip >> 24) & 0xFF;
    printf("%u.%u.%u.%u\n", byte1, byte2, byte3, byte4);
}

void print_ipv4_flow_details(__u64 key, struct packet_info *value) {
    printf("Flow: %llu\n", key);
    printf("---------------\n");
    printf("Key: Source IP: ");
	#if defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_IPV4)
    print_ipv4_address(value->src_ip);
	#endif
    printf("\nKey: Destination IP: ");
    print_ipv4_address(value->dst_ip);
	#if defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_IPV4)
    printf("\nKey: Source Port: %u\n", value->src_port);
    printf("Key: Destination Port: %u\n", value->dst_port);
    printf("Key: Protocol: %u\n", value->protocol);
	#endif
    printf("---------------\n");
}

// Funzione per stampare il contenuto della mappa ipv4_flow
void print_ipv4_flow(int fd) {

	__u64 *key, *prev_key;
	struct packet_info *value;
	unsigned int num_elems = 0;
	int err;

	key = malloc(sizeof(__u64));
	prev_key = NULL;
	value = malloc(sizeof(struct packet_info));

    printf("IPv4 Flow Map:\n");

	while(true) {
		err = bpf_map_get_next_key(fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		if (!bpf_map_lookup_elem(fd, key, value)) {
			print_ipv4_flow_details(*key, value);
		} else {
			printf("No value found\n");
		}
		prev_key = key;
	}

	free(key);
	free(value);

}

void process_ipv4_map(int fd, const char* map_type) {
	int counter = 0;
	struct value_packet *value;
	#ifdef CLASSIFY_IPV4
	struct packet_info *key, *prev_key;
	key = malloc(sizeof(struct packet_info));
	#endif
	#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
	struct only_addr_ipv4 *key, *prev_key;
	key = malloc(sizeof(struct only_addr_ipv4));
	#endif
	#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
	struct only_dest_ipv4 *key, *prev_key;
	key = malloc(sizeof(struct only_dest_ipv4));
	#endif

	prev_key = NULL;
	value = malloc(sizeof(struct value_packet));
	int err;

	while(true){
		err = bpf_map_get_next_key(fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		if (!bpf_map_lookup_elem(fd, key, value)) {
			/*__u8 byte1 = key->src_ip & 0xFF;
			__u8 byte2 = (key->src_ip >> 8) & 0xFF;
			__u8 byte3 = (key->src_ip >> 16) & 0xFF;
			__u8 byte4 = (key->src_ip >> 24) & 0xFF;
			printf("---------------\n");
			printf("Key: Source IP: %u.%u.%u.%u\n", byte1, byte2, byte3, byte4);
			byte1 = key->dst_ip & 0xFF;
			byte2 = (key->dst_ip >> 8) & 0xFF;
			byte3 = (key->dst_ip >> 16) & 0xFF;
			byte4 = (key->dst_ip >> 24) & 0xFF;
			printf("Key: Destination IP: %u.%u.%u.%u\n", byte1, byte2, byte3, byte4);
			printf("Value: Counter: %u\n", value->counter);
			printf("Value: Bytes Counter: %llu\n", value->bytes_counter);*/

			#if defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_IPV4)
			print_ipv4_address(key->src_ip);
			#endif
			print_ipv4_address(key->dst_ip);
			printf("Value: Counter: %u\n", value->counter);
			printf("Value: Bytes Counter: %llu\n", value->bytes_counter);


			printf("---------------\n");
		} else {
			printf("No value found\n");
		}
		prev_key = key;
		counter++;
	}

	free(key);
	free(value);

	printf("The map has %d elements\n", counter);
}
#endif

#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
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

// Funzione per stampare il contenuto della mappa ipv6_flow
void print_ipv6_flow(int map_fd) {
    __u64 *key, *prev_key;

    struct packet_info_ipv6 *value;
	int err;

	key = malloc(sizeof(__u64));
	prev_key = NULL;
	value = malloc(sizeof(struct packet_info_ipv6));


    printf("IPv6 Flow Map:\n");

	while(true) {
		err = bpf_map_get_next_key(map_fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		
		if (!bpf_map_lookup_elem(map_fd, key, value)) {
			printf("Flow: %llu\n", *key);
			printf("---------------\n");
			#if defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_IPV6)
			printf("Key: Source IP: ");
			print_ipv6_address(value->src_ip);
			#endif
			printf("Key: Destination IP: ");
			print_ipv6_address(value->dst_ip);
			#if defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_IPV6)
			printf("Key: Source Port: %u\n", value->src_port);
			printf("Key: Destination Port: %u\n", value->dst_port);
			printf("Key: Protocol: %u\n", value->protocol);
			#endif
			printf("---------------\n");
		} else {
			printf("Valore non trovato\n");
		}
		prev_key = key;
	}

	free(key);
	free(value);
}

void process_ipv6_map(int map_fd, const char* map_type) {
	int counter = 0;
	struct value_packet *value;

	#ifdef CLASSIFY_IPV6
	struct packet_info_ipv6 *key, *prev_key;
	key = malloc(sizeof(struct packet_info_ipv6));
	#endif

	#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
	struct only_addr_ipv6 *key, *prev_key;
	key = malloc(sizeof(struct only_addr_ipv6));
	#endif

	#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
	struct only_dest_ipv6 *key, *prev_key;
	key = malloc(sizeof(struct only_dest_ipv6));
	#endif

	prev_key = NULL;
	value = malloc(sizeof(struct value_packet));

	while(true){
		err = bpf_map_get_next_key(fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		if (!bpf_map_lookup_elem(fd, key, value)) {
			printf("---------------\n");
			printf("Key: Source IP: ");
			print_ipv6_address(key.src_ip);
			printf("Key: Destination IP: ");
			print_ipv6_address(key.dst_ip);
			printf("Value: Counter: %u\n", value.counter);
			printf("Value: Bytes Counter: %llu\n", value.bytes_counter);
			printf("---------------\n");
		} else {
			printf("No value found\n");
		}
		prev_key = key;
		counter++;
	}

	printf("The map has %d elements\n", counter);
}
#endif

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

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// --------------------------------------------

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event_t *event = data;
	
    MHandler_t *influx_handler = (MHandler_t *)ctx;

	if(!influx_handler) {
		fprintf(stderr, "Error: influx_handler is NULL\n");
	}

    printf("Event: ts=%llu flowid=%llu counter=%llu\n", event->ts, event->flowid, event->counter);

    // Write data to InfluxDB
    int ret = write_data_influxdb(influx_handler, event->ts, event->flowid, event->counter);
    if (ret != 0) {
        fprintf(stderr, "Failed to write data to InfluxDB\n");
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

	MHandler_t *h = create_influxdb("http://localhost:8086?db=tc_db");
	if (!h) {
		printf("Cannot create MHandler\n");
		return -EINVAL;
	}

	show_databases_influxdb(h);
	
	/*write_temp_influxdb(h, "Rome", 14.1);

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

	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, h, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

	while (!exiting) {
		if (strcmp(map_type, "ipv4") == 0) {
			#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);
			if (err < 0) {
				fprintf(stderr, "Error polling ring buffer: %d\n", err);
				goto cleanup;
			}
			process_ipv4_map(map_fd, map_type);
			#endif
		} else if (strcmp(map_type, "ipv6") == 0) {
			#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
			// err = ring_buffer__poll(rb, 100 /* timeout, ms */);
			// if (err < 0) {
			// 	fprintf(stderr, "Error polling ring buffer: %d\n", err);
			// 	goto cleanup;
			// }
			process_ipv6_map(map_fd, map_type);
			#endif
		} else {
			fprintf(stderr, "Invalid map type\n");
			goto detach;
		}

		sleep(3);
	}

	printf("Printing the flow map: \n");
	if (strcmp(map_type, "ipv4") == 0) {
		#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
		print_ipv4_flow(map_fd_flow);
		#endif
	} else if (strcmp(map_type, "ipv6") == 0) {
		#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
		print_ipv6_flow(map_fd_flow);
		#endif
	} else {
		fprintf(stderr, "Invalid map type\n");
		goto detach;
	}

	//show_data_influxdb(h, "flow_data");
	
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
	destroy_influxdb(h);
	return -err;
}
