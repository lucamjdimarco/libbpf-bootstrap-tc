// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <net/if.h> // for if_nametoindex
#include "tc.skel.h"
#include "common.h"
#include <time.h>
#include <pthread.h>
#include <hiredis/hiredis.h>
//#include "../../influxdb-connector/influxdb_wrapper_int.h"
#include "influxdb_wrapper_int.h"
#include <sys/stat.h>

#define REDIS_HOST "10.89.0.50"
#define REDIS_PORT 6379

#define BATCH_SIZE  3
#define TIMEOUT_SEC 40

struct event_t_formatted events_buffer[BATCH_SIZE];
int events_count = 0;
int last_watched_event_time;
int current_time;
char machine_id[MAX_MACHINE_ID_SIZE];
const char *interface_name;
const char *friendlyname;

typedef struct {
    char *measurement; 
    char *machine_id;
	char *interface;
	char *fname;
	uint64_t flowid;
    double counter;    
    uint64_t timestamp;
} InfluxDBPoint;

/* Struttura per passare i dati al thread */
struct thread_args {
    struct ring_buffer *rb;
    const char *ring_buffer_name;
};

#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || \
	defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
#define INFLUXDB_URL "http://influxdb:8086?db=tc_db"
#elif defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || \
	defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
#define INFLUXDB_URL "http://10.89.0.30:8086?db=tc_db"
#endif

#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || \
	defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
void print_ipv4_address(__u32 ip)
{
	__u8 byte1 = ip & 0xFF;
	__u8 byte2 = (ip >> 8) & 0xFF;
	__u8 byte3 = (ip >> 16) & 0xFF;
	__u8 byte4 = (ip >> 24) & 0xFF;
	printf("%u.%u.%u.%u\n", byte1, byte2, byte3, byte4);
	fflush(stdout);
	fflush(stderr);
}

void print_flow_id_info_ipv4_details(__u64 key, struct packet_info *value)
{
	printf("Flow: %llu\n", key);
	printf("---------------\n");
	printf("Key: Source IP: ");
#if defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_IPV4)
	print_ipv4_address(value->src_ip);
#endif
	printf("Key: Destination IP: ");
	print_ipv4_address(value->dst_ip);
#if defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_IPV4)
	printf("Key: Source Port: %u\n", value->src_port);
	printf("Key: Destination Port: %u\n", value->dst_port);
	printf("Key: Protocol: %u\n", value->protocol);
#endif
	printf("---------------\n");
	fflush(stdout);
	fflush(stderr);
}

// Funzione per stampare il contenuto della mappa flow_id_info_ipv4
void print_flow_id_info_ipv4(int fd)
{
	__u64 *key, *prev_key;
	struct packet_info *value;
	int err;

	key = malloc(sizeof(__u64));
	prev_key = NULL;
	value = malloc(sizeof(struct packet_info));

	printf("IPv4 Flow Map:\n");

	while (true) {
		err = bpf_map_get_next_key(fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		if (!bpf_map_lookup_elem(fd, key, value)) {
			print_flow_id_info_ipv4_details(*key, value);
		} else {
			printf("No value found\n");
		}
		prev_key = key;
	}

	free(key);
	free(value);

	fflush(stdout);
	fflush(stderr);
}

//funzione principale per il processamento in caso di utilizzo del filtro in IPv4
void process_ipv4_map(int fd, const char *map_type)
{
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

	while (true) {
		err = bpf_map_get_next_key(fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		if (!bpf_map_lookup_elem(fd, key, value)) {
#if defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_IPV4)
			printf("Source IP: ");
			print_ipv4_address(key->src_ip);
#endif
			printf("Destination IP: ");
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
	fflush(stdout);
	fflush(stderr);
}
#endif

// Funzione per stampare l'indirizzo IPv6
#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || \
	defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
void print_ipv6_address(uint8_t *addr)
{
	printf("IPv6 Address: ");
	for (int i = 0; i < 16; i++) {
		printf("%02x", addr[i]);
		if (i % 2 == 1 && i < 15) {
			printf(":");
		}
	}
	printf("\n");
	fflush(stdout);
	fflush(stderr);
}

// Funzione per stampare il contenuto della mappa flow_id_info_ipv6
void print_flow_id_info_ipv6(int map_fd)
{
	__u64 *key, *prev_key;

	struct packet_info_ipv6 *value;
	int err;

	key = malloc(sizeof(__u64));
	prev_key = NULL;
	value = malloc(sizeof(struct packet_info_ipv6));

	printf("IPv6 Flow Map:\n");

	while (true) {
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

	fflush(stdout);
	fflush(stderr);
}

// Funzione per processare la mappa in caso di utilizzo del filtro in IPv6
void process_ipv6_map(int map_fd, const char *map_type)
{
	int counter = 0;
	struct value_packet *value;

	int err;

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

	while (true) {
		err = bpf_map_get_next_key(map_fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		if (!bpf_map_lookup_elem(map_fd, key, value)) {
			printf("---------------\n");
#if defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_IPV6)
			printf("Key: Source IP: ");
			print_ipv6_address(key->src_ip);
#endif
			printf("Key: Destination IP: ");
			print_ipv6_address(key->dst_ip);
			printf("Value: Counter: %u\n", value->counter);
			printf("Value: Bytes Counter: %llu\n", value->bytes_counter);
			printf("---------------\n");
		} else {
			printf("No value found\n");
		}
		prev_key = key;
		counter++;
	}

	printf("The map has %d elements\n", counter);

	fflush(stdout);
	fflush(stderr);
}
#endif

// Funzione per inizializzare i file descriptor delle mappe
int initialize_map_fd(const char *map_type, struct tc_bpf *skel, int *map_fd, int *map_fd_flow)
{
	if (strcmp(map_type, "ipv4") == 0) {
#ifdef CLASSIFY_IPV4
		*map_fd = bpf_map__fd(skel->maps.flow_info_ipv4);
		*map_fd_flow = bpf_map__fd(skel->maps.flow_id_info_ipv4);
#elif defined(CLASSIFY_ONLY_ADDRESS_IPV4)
		*map_fd = bpf_map__fd(skel->maps.flow_info_only_addr_ipv4);
		*map_fd_flow = bpf_map__fd(skel->maps.flow_id_info_ipv4);
#elif defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
		*map_fd = bpf_map__fd(skel->maps.flow_info_only_dest_ipv4);
		*map_fd_flow = bpf_map__fd(skel->maps.flow_id_info_ipv4);
#endif
	} else if (strcmp(map_type, "ipv6") == 0) {
#ifdef CLASSIFY_IPV6
		*map_fd = bpf_map__fd(skel->maps.flow_info_ipv6);
		*map_fd_flow = bpf_map__fd(skel->maps.flow_id_info_ipv6);
#elif defined(CLASSIFY_ONLY_ADDRESS_IPV6)
		*map_fd = bpf_map__fd(skel->maps.flow_info_only_addr_ipv6);
		*map_fd_flow = bpf_map__fd(skel->maps.flow_id_info_ipv6);
#elif defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
		*map_fd = bpf_map__fd(skel->maps.flow_info_only_dest_ipv6);
		*map_fd_flow = bpf_map__fd(skel->maps.flow_id_info_ipv6);
#endif
	} else {
		fprintf(stderr, "Invalid map type\n");
		fflush(stdout);
		fflush(stderr);
		return -1;
	}

	if (*map_fd < 0 || *map_fd_flow < 0) {
		fprintf(stderr, "Failed to get map file descriptor\n");
		fflush(stdout);
		fflush(stderr);
		return -1;
	}

	fflush(stdout);
	fflush(stderr);
	return 0;
}

static volatile sig_atomic_t exiting = 0;

// Funzione per gestire il segnale di interruzione
static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// --------------------------------------------
//uint64_t flowid
InfluxDBPoint *create_influxdb_point(const char *measurement, const char *machine_id, const char *interface, const char *fname,
                                     uint64_t flowid , double counter, uint64_t timestamp)
{
	InfluxDBPoint *point = (InfluxDBPoint *)malloc(sizeof(InfluxDBPoint));
	if (!point) {
		fprintf(stderr, "Memory allocation failed for InfluxDBPoint\n");
		fflush(stdout);
		fflush(stderr);
		return NULL;
	}

	point->measurement = strdup(measurement);
	if (!point->measurement) {
        fprintf(stderr, "Memory allocation failed for measurement\n");
		fflush(stdout);
		fflush(stderr);
        free(point);
        return NULL;
    }

	/* Gestione dei tag */
	point->machine_id = strdup(machine_id);
    if (!point->machine_id) {
        fprintf(stderr, "Memory allocation failed for machine_id\n");
		fflush(stdout);
		fflush(stderr);
        free(point->measurement);
        free(point);
        return NULL;
    }
	point->interface = strdup(interface);
    if (!point->interface) {
        fprintf(stderr, "Memory allocation failed for interface\n");
		fflush(stdout);
		fflush(stderr);
        free(point->machine_id);
        free(point->measurement);
        free(point);
        return NULL;
    }
	point->fname = strdup(fname);
    if (!point->interface) {
        fprintf(stderr, "Memory allocation failed for interface\n");
		fflush(stdout);
		fflush(stderr);
        free(point->machine_id);
		free(point->interface);
        free(point->measurement);
        free(point);
        return NULL;
    }
	point->flowid = flowid;
	point->counter = counter;
	point->timestamp = timestamp;

	return point;
}

void free_influxdb_point(InfluxDBPoint *point)
{
	if (point) {
		free(point->measurement);
		/* -- Aggiunto --*/
		//free(point->str_identifier);
		free(point->machine_id);
        free(point->interface);
		free(point->fname);
		/* -- Fine --*/
		free(point);
	}
}

InfluxDBPoint **create_points_batch(struct event_t_formatted *events_buffer, int events_count)
{
	InfluxDBPoint **points_batch =
		(InfluxDBPoint **)malloc(events_count * sizeof(InfluxDBPoint *));
	if (!points_batch) {
		fprintf(stderr, "Memory allocation failed for points batch\n");
		fflush(stdout);
		fflush(stderr);
		return NULL;
	}

	for (int i = 0; i < events_count; i++) {
        points_batch[i] = create_influxdb_point(
            "rate",                                  // Misurazione
            events_buffer[i].machine_id,             // machine_id
            events_buffer[i].interface,              // interface
			events_buffer[i].fname,                  // friendlyname
            events_buffer[i].flowid,                 // flowid
            (double)events_buffer[i].counter,        // counter
            events_buffer[i].ts                      // timestamp
        );

        // Verifica se la creazione del punto è riuscita
        if (!points_batch[i]) {
            fprintf(stderr, "Failed to create point for event %d\n", i);
            // Libera i punti e le loro risorse allocate finora in caso di errore
            for (int j = 0; j < i; j++) {
                free_influxdb_point(points_batch[j]);
            }
            free(points_batch);
			fflush(stdout);
			fflush(stderr);
            return NULL;
        }
    }

	return points_batch;
}

// Funzione per scrivere i dati in InfluxDB
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	printf("**********\n");
	printf("Received event in the ring buffer\n");
	struct event_t *event = data;

	struct event_t_formatted event_formatted = {
		.ts = event->ts,
		.machine_id = machine_id,
		.interface = interface_name,
		.fname = friendlyname,
		.flowid = event->flowid,
		.counter = event->counter,
	};

	MHandler_t *influx_handler = (MHandler_t *)ctx;

	if (!influx_handler) {
		fprintf(stderr, "Error: influx_handler is NULL\n");
	}
	//current_time = time(NULL);
	last_watched_event_time = time(NULL);
	if (events_count < BATCH_SIZE - 1) {
		events_buffer[events_count] = event_formatted;
		events_count++;
	} else {
		events_buffer[events_count] = event_formatted;
		events_count++;

		/*-------------------invio dati batch-------------------*/
		//Array per contenere i dati del buffer
		uint64_t timestamps[BATCH_SIZE];
		const char *machine_ids[BATCH_SIZE];
		const char *interfaces[BATCH_SIZE];
		const char *fnames[BATCH_SIZE];
		uint64_t flowids[BATCH_SIZE];
		uint64_t counters[BATCH_SIZE];

		// Copia i dati dal buffer negli array
		for (int i = 0; i < events_count; i++) {
			timestamps[i] = events_buffer[i].ts;
			machine_ids[i] = events_buffer[i].machine_id;
			interfaces[i] = events_buffer[i].interface;
			fnames[i] = events_buffer[i].fname;
			flowids[i] = events_buffer[i].flowid;
			counters[i] = events_buffer[i].counter;
		}

		int ret = write_data_influxdb_batch(influx_handler, timestamps, machine_ids, interfaces, fnames, flowids, counters, events_count);
		if (ret != 0) {
			fprintf(stderr, "Failed to write data to InfluxDB\n");
		} else {
			printf("Events written to InfluxDB\n");
		}
		events_count = 0;
		memset(events_buffer, 0, sizeof(events_buffer));
		/*------------------- fine invio dati batch-------------------*/

		last_watched_event_time = current_time;
	}

	printf("**********\n");
	fflush(stdout);
	fflush(stderr);

	return 0;
}

void publish_flow_id(uint64_t flow_id) {
    redisContext *c;
    redisReply *reply;

    c = redisConnect(REDIS_HOST, REDIS_PORT);
    if (c == NULL || c->err) {
        if (c) {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
        return;
    }

    char flow_id_str[32];
    snprintf(flow_id_str, sizeof(flow_id_str), "%llu", (unsigned long long)flow_id);

    // Pubblica il messaggio sul canale "flow_channel"
    reply = redisCommand(c, "PUBLISH flow_channel %s", flow_id_str);
    if (reply == NULL) {
        printf("Failed to publish flow_id to Redis\n");
        redisFree(c);
        return;
    }

    printf("Published flow_id: %llu to Redis\n", (unsigned long long)flow_id);

    freeReplyObject(reply);
    redisFree(c);
}


/* Funzione per il polling del secondo thread */

static int handle_event_rb2(void *ctx, void *data, size_t data_sz) {
    if (data_sz != sizeof(__u64)) {
        fprintf(stderr, "Unexpected data size: %zu\n", data_sz);
        return -1;
    }

    __u64 flow_id = *(__u64 *)data; 
    printf("[RB2] Received flow ID: %llu\n", flow_id);
    fflush(stdout);

	publish_flow_id(flow_id);

    return 0;
}


void *poll_second_ring_buffer(void *args) {
    struct thread_args *targs = (struct thread_args *)args;

    printf("Starting polling on %s\n", targs->ring_buffer_name);

    while (!exiting) {
        int err = ring_buffer__poll(targs->rb, 1000 /* timeout in ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling %s: %d\n", targs->ring_buffer_name, err);
            break;
        }
        // Se err == 0, nessun evento; continua il polling
    }

    printf("Stopped polling on %s\n", targs->ring_buffer_name);
    return NULL;
}

/* ----- */


void remove_newline(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0'; 
    }
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <interface> <ipv4|ipv6> <friendlyname>\n", argv[0]);
		fflush(stdout);
		fflush(stderr);
		return 1;
	}

	// Save the friendlyname
	friendlyname = argv[3];
	last_watched_event_time = time(NULL);

	char *pin_dir = "/sys/fs/bpf";
	int map_fd;
	int map_fd_flow;

	MHandler_t *h = create_influxdb(INFLUXDB_URL);
	if (!h) {
		printf("Cannot create MHandler\n");
		fflush(stdout);
		fflush(stderr);
		return -EINVAL;
	}

	show_databases_influxdb(h);

	
	interface_name = argv[1];	

	// eth0 reserverd for control network
	if (strcmp(interface_name, "eth0") == 0) {
        fprintf(stderr, "Error: eBPF instance cannot be started on interface 'eth0'.\n");
        return -EINVAL;
    }

	const char *map_type = argv[2];
	int index = if_nametoindex(interface_name);
	if (index == 0) {
		perror("if_nametoindex");
		fflush(stdout);
		fflush(stderr);
		return -EINVAL;
	}

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = index, .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	bool hook_created = false;
	struct tc_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = tc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	char *pin_path = malloc(strlen("/sys/fs/bpf") + 1); 
	if (pin_path) {
		strcpy(pin_path, "/sys/fs/bpf/");
		strcat(pin_path, interface_name);
	}
	
	if (mkdir(pin_path, 0755) && errno != EEXIST) {
		perror("Failed to create BPF subdirectory");
		return -1;
	}

	bpf_map__set_pin_path(skel->maps.flow_info_ipv4, pin_path);
	bpf_map__set_pin_path(skel->maps.flow_id_info_ipv4, pin_path);

	if (tc_bpf__load(skel)) {
		fprintf(stderr, "Failed to load skeleton\n");
		tc_bpf__destroy(skel);
		return 1;
	}

	/*skel = tc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		fflush(stdout);
		fflush(stderr);
		return 1;
	}*/

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
		fflush(stdout);
		fflush(stderr);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		fflush(stdout);
		fflush(stderr);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		fflush(stdout);
		fflush(stderr);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");
	fflush(stdout);
	fflush(stderr);
	
    FILE *file = fopen("/etc/machine-id", "r");
    if (!file) {
        perror("Failed to open /etc/machine-id");
		fflush(stdout);
		fflush(stderr);
        goto detach;
    }

	if (fgets(machine_id, sizeof(machine_id), file) == NULL) {
        perror("Failed to read machine-id");
		fflush(stdout);
		fflush(stderr);
        fclose(file);
        goto detach;
    }
    fclose(file);

	remove_newline(machine_id);

	// --------------------------------

	if (initialize_map_fd(map_type, skel, &map_fd, &map_fd_flow) != 0) {
		goto detach;
	}

	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rbuf_events), handle_event, h, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		fflush(stdout);
		fflush(stderr);
		goto cleanup;
	}

	/* Aggiunta di un nuovo ringbuffer per la gestione dei nuovi flows */
	struct ring_buffer *rb2 = NULL;
	rb2 = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_signaling_new_flow), handle_event_rb2, h, NULL);
    if (!rb2) {
        fprintf(stderr, "Failed to create second ring buffer\n");
        return 1;
    }

	pthread_t thread2;

	struct thread_args args2 = { .rb = rb2, .ring_buffer_name = "rb for new flows" };

	if (pthread_create(&thread2, NULL, poll_second_ring_buffer, &args2) != 0) {
        perror("pthread_create for rb for new flows");
        return 1;
    }


	/* ---- */




	// Main loop per processare i dati
	while (!exiting) {
		if (strcmp(map_type, "ipv4") == 0) {
#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || \
	defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
			// Polling ring buffer per processare i dati
			err = ring_buffer__poll(rb, 5000 /* timeout, ms */);
			if (err < 0) {
				fprintf(stderr, "Error polling ring buffer: %d\n", err);
				fflush(stdout);
				fflush(stderr);
				goto detach;
			} else if (err == 0) {
				/* se err == 0 allora è scaduto il timeout --> nessun dato è passato nel ring_buff */
				continue;
			} else {
				current_time = time(NULL);
				if (current_time - last_watched_event_time >= TIMEOUT_SEC &&
				    events_count > 0) {
					printf("events_count=%d\n", events_count);
					for (int i = 0; i < events_count; i++) {
						int ret = write_data_influxdb(
							h, events_buffer[i].ts,
							events_buffer[i].machine_id,
							events_buffer[i].interface,
							events_buffer[i].fname,
							events_buffer[i].flowid,
							events_buffer[i].counter);
						if (ret != 0) {
							fprintf(stderr,
								"Failed to write event %d to InfluxDB\n",
								i);
							fflush(stdout);
							fflush(stderr);
						}
						fflush(stdout);
						fflush(stderr);
					}
					printf("Events written to InfluxDB for timeout\n");
					fflush(stdout);
					fflush(stderr);
					events_count = 0;
					last_watched_event_time = current_time;
				}
				process_ipv4_map(map_fd, map_type);
			}

#endif
		} else if (strcmp(map_type, "ipv6") == 0) {
#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || \
	defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
			err = ring_buffer__poll(rb, 5000 /* timeout, ms */);
			if (err < 0) {
				fprintf(stderr, "Error polling ring buffer: %d\n", err);
				fflush(stdout);
				fflush(stderr);
				goto detach;
			} else if (err == 0) {
				continue;
			} else {
				current_time = time(NULL);
				if (current_time - last_watched_event_time >= TIMEOUT_SEC &&
				    events_count > 0) {
					for (int i = 0; i < events_count; i++) {
						int ret = write_data_influxdb(
							h, events_buffer[i].ts,
							events_buffer[i].machine_id,
							events_buffer[i].interface,
							events_buffer[i].fname,
							events_buffer[i].flowid,
							events_buffer[i].counter);
						if (ret != 0) {
							fprintf(stderr,
								"Failed to write event %d to InfluxDB\n",
								i);
							fflush(stdout);
							fflush(stderr);
						}
					}
					printf("Events written to InfluxDB for timeout\n");
					events_count = 0;
					last_watched_event_time = current_time;
					fflush(stdout);
					fflush(stderr);
				}
				process_ipv6_map(map_fd, map_type);
			}
#endif
		} else {
			fprintf(stderr, "Invalid map type\n");
			fflush(stdout);
			fflush(stderr);
			goto detach;
		}

		sleep(3);
	}

	printf("Printing the flow map: \n");
	if (strcmp(map_type, "ipv4") == 0) {
#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || \
	defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)
		print_flow_id_info_ipv4(map_fd_flow);
#endif
	} else if (strcmp(map_type, "ipv6") == 0) {
#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || \
	defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
		print_flow_id_info_ipv6(map_fd_flow);
#endif
	} else {
		fprintf(stderr, "Invalid map type\n");
		goto detach;
	}

	/* Attesa per il secondo thread */
	pthread_join(thread2, NULL);

	//show_data_influxdb(h, "flow_data");

// funzione per detachment del programma BPF
detach:
	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		fflush(stdout);
		fflush(stderr);
		goto cleanup;
	}

	ring_buffer__free(rb);
    ring_buffer__free(rb2);

// funzione per cleanup
cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	tc_bpf__destroy(skel);
	destroy_influxdb(h);
	return -err;
}
