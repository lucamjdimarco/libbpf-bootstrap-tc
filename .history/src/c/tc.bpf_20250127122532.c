#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include "common.h"

#define CLOCK_BOOTTIME 7
#define SWIN_SCALER	   10000000000ul /* 10 seconds in nanoseconds */
#define SWIN_TIMER_TIMEOUT (SWIN_SCALER << 1ul)

__u64 counter = 0;
__u64 flow_id = -1;
__u32 ifindex = -1;

enum FlowIdType { QUINTUPLA = 0, ONLY_ADDRESS = 1, ONLY_DEST_ADDRESS = 2 };

struct classify_packet_args {
	void *map_name;
	void *new_info;
	void *map_flow;
	__u64 *counter;
	__u32 flow_type;
	__u32 packet_length;
};

/* ---- */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} last_flow_id_by_ifindex SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ringbuf_signaling_new_flow SEC(".maps");
/* ---- */

#ifdef CLASSIFY_IPV4
//flowinfo 
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_5tuple_ipv4);
	__type(value, struct value_packet);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_info_ipv4 SEC(".maps");
#endif

#ifdef CLASSIFY_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_5tuple_ipv6);
	__type(value, struct value_packet);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_info_ipv6 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_only_addr_ipv4);
	__type(value, struct value_packet);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_info_only_addr_ipv4 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_only_addr_ipv6);
	__type(value, struct value_packet);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_info_only_addr_ipv6 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_only_dest_ipv4);
	__type(value, struct value_packet);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_info_only_dest_ipv4 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_only_dest_ipv6);
	__type(value, struct value_packet);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_info_only_dest_ipv6 SEC(".maps");
#endif

//flow_id_info 
#ifdef CLASSIFY_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct key_5tuple_ipv4);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_id_info_ipv4 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct key_only_addr_ipv4);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_id_info_ipv4 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct key_only_dest_ipv4);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_id_info_ipv4 SEC(".maps");
#endif

#ifdef CLASSIFY_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct key_5tuple_ipv6);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_id_info_ipv6 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct key_only_addr_ipv6);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_id_info_ipv6 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct key_only_dest_ipv6);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_id_info_ipv6 SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MB di spazio
} rbuf_events SEC(".maps");

static __always_inline __u64 build_flowid(__u8 first_byte, __u64 counter)
{
	return ((__u64)first_byte << 56) | (counter & 0x00FFFFFFFFFFFFFF);
}

static __always_inline int update_window_start_timer(struct value_packet *packet, __u64 timeout)
{
	int rc;

	if (!__sync_bool_compare_and_swap(&packet->timer_started, 0, 1)) {
		bpf_printk("Timer already started by another CPU\n");
		return 0;
	}

	rc = bpf_timer_start(&packet->timer, timeout, 0);
	if (!rc)
		__sync_bool_compare_and_swap(&packet->timer_started, 1, 0);

	return 0;

}

static __always_inline int prepare_ring_buffer_write(void *map, struct event_t **pevent)
{
	if (!pevent)
		return -EINVAL;

	*pevent = bpf_ringbuf_reserve(&rbuf_events, sizeof(**pevent), 0);
	if (!(*pevent))
		return -ENOMEM;

	return 0;
}

static __always_inline int update_window(struct value_packet *packet, __u64 packet_length, __u64 ts,
					 bool start_timer)
{
	const __u64 cur_tsw = ts / SWIN_SCALER;
	struct event_t *event = NULL;
	__u32 counter_val;
	int rc;

	rc = prepare_ring_buffer_write(&rbuf_events, &event);
	if (rc) {
		bpf_printk("Failed to reserve space in ring buffer\n");
		return 0;
	}

	bpf_spin_lock(&packet->lock);
	if (packet->counter < MAX_COUNTER) {
		packet->counter += 1;
		packet->bytes_counter += packet_length;
	}

	__u64 tsw = packet->tsw;
	__u32 *counter = &packet->counter; 

	if (cur_tsw <= tsw) {
		bpf_spin_unlock(&packet->lock);
		bpf_ringbuf_discard(event, 0);
		bpf_printk("skipping event, cur_tsw: %llu, tsw: %llu\n", cur_tsw, tsw);
		return 0;
	}

	counter_val = *counter;

	if (!event) {
		bpf_spin_unlock(&packet->lock);
		bpf_ringbuf_discard(event, 0);
		bpf_printk("Event is null, cannot process\n");
		return -EINVAL;
	}

	event->ts = ts;
	event->flowid = packet->flow_id;
	event->counter = counter_val;


	packet->tsw = cur_tsw;
	bpf_spin_unlock(&packet->lock);

	if (!start_timer)
		return 0;

	/* Avvia il timer associato a questa finestra */

	rc = update_window_start_timer(packet, SWIN_TIMER_TIMEOUT);
	if (rc) {
		bpf_ringbuf_discard(event, 0);
		bpf_printk("Failed to start timer\n");
		return -EINVAL;
	}

	bpf_printk("Sending event: %llu %llu %u\n", event->ts, event->flowid, event->counter);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

/**
 * This function classifies a packet and updates the corresponding flow map.
 * 
 * The function first attempts to look up an existing packet entry in the flow map using the provided 
 * arguments (`args->map_name` and `args->new_info`). If the packet is not found, a new flow ID is created 
 * using the `build_flowid` function, and the flow ID is updated in the map `last_flow_id_by_ifindex` for 
 * the current interface index (`ifindex`). The function then signals a new flow event by reserving space 
 * in a ring buffer and sending the flow ID to user space.
 * 
 * A new `value_packet` structure is created with the flow ID, packet length, and initialized with default values. 
 * This new packet information is inserted into the flow map. Additionally, the flow map is updated with the new 
 * flow information using the flow ID as the key.
 * 
 * If the packet is successfully inserted into the map, a timer is initialized atomically using `bpf_timer_init`. 
 * The timer is associated with the flow map and set to use the `CLOCK_BOOTTIME` clock. If the timer initialization 
 * fails, the initialization flag is reset to allow for a retry.
 * 
 * If the packet is already present in the flow map, the function updates the existing flow's counters and 
 * window with the new packet data.
 * 
 * Error handling is included for various operations, such as flow ID creation, map updates, ring buffer 
 * reservations, and timer initialization. In case of failure, appropriate error messages are logged and 
 * the function returns corresponding error codes.
 */

static __always_inline int classify_packet_and_update_map(struct classify_packet_args *args)
{
	struct value_packet *packet = NULL;
	//int ret;
	//u32 key = 0; 

	//__u64 flow_id = -1;

	packet = bpf_map_lookup_elem(args->map_name, args->new_info);

	if (!packet) {
		flow_id = build_flowid(args->flow_type, __sync_fetch_and_add(args->counter, 1));

		if (flow_id == -1) {
			bpf_printk("Failed to build flow_id\n");
			return -EFAULT;
		}

		/* ---- */
		// Copy the original flow_id into a temporary variable
		__u64 flow_id_temp = flow_id;
		// Mask out the first byte of the temporary variable
		flow_id_temp &= 0x00FFFFFFFFFFFFFF;
		int ret = bpf_map_update_elem(&last_flow_id_by_ifindex, &ifindex, &flow_id_temp, BPF_ANY);
		if (ret) {
			bpf_printk("Failed to update map for ifindex %u\n", ifindex);
			return TC_ACT_OK;
		}

		bpf_printk("Updated map for ifindex %u with new flowid: %llu\n", ifindex, flow_id);

		__u64 *new_flow_event = bpf_ringbuf_reserve(&ringbuf_signaling_new_flow, sizeof(__u64), 0);
		if (!new_flow_event) {
			bpf_printk("Failed to reserve ring buffer space\n");
			return -ENOMEM;
		}


		*new_flow_event = flow_id;
		bpf_printk("Flow ID %llu sent to user-space\n", *new_flow_event);
		bpf_ringbuf_submit(new_flow_event, 0);

		/* ---- */

		// ret = bpf_map_update_elem(&last_flow_id_by_ifindex, &key, &counter, BPF_ANY);
		// if(ret){
		// 	bpf_printk("Failed to update flow_id\n");
		// 	return TC_ACT_OK;
		// }

		// Crea un nuovo valore per il pacchetto
		struct value_packet new_value = {
			.counter = 1,
			.bytes_counter = args->packet_length,
			.flow_id = flow_id,
			.tsw = 0,
			.initialized = 0,
		};

		// Inserisci il nuovo valore nella mappa
		ret = bpf_map_update_elem(args->map_name, args->new_info, &new_value, BPF_ANY);
		if (ret) {
			bpf_printk("Failed to insert new item in map_name\n");
			return -ENOMEM;
		}

		// Aggiorna la mappa dei flussi
		ret = bpf_map_update_elem(args->map_flow, &flow_id, args->new_info, BPF_ANY);
		if (ret) {
			bpf_printk("Failed to insert new item in map_flow\n");
			return -ENOMEM;
		}

		// Ricarica l'elemento aggiornato dalla mappa
		packet = bpf_map_lookup_elem(args->map_name, args->new_info);
		if (!packet) {
			bpf_printk("Failed to lookup newly inserted item in map_name\n");
			return -ENOENT;
		}

		// Inizializza il timer in modo atomico
		if (__sync_bool_compare_and_swap(&packet->initialized, 0, 1)) {
			int rc = bpf_timer_init(&packet->timer, args->map_name, CLOCK_BOOTTIME);
			if (rc) {
				bpf_printk("Failed to initialize timer\n");
				// Se fallisce, ripristina il flag di inizializzazione
				__sync_bool_compare_and_swap(&packet->initialized, 1, 0);
				return -EFAULT;
			}
		}
	} else {
		// Aggiorna i contatori nella finestra temporale
		update_window(packet, args->packet_length, bpf_ktime_get_tai_ns(), true);
	}

	return TC_ACT_OK;
}

/**
 * This function classifies an IPv4 packet and extracts relevant information based on its protocol.
 * 
 * The function begins by verifying that the IPv4 header is complete by checking if the pointer to the 
 * next field (`ip + 1`) is within the packet bounds (`data_end`). If the IPv4 header is incomplete, 
 * an error message is printed and the function returns `-EFAULT`.
 * 
 * The `protocol` field of the IPv4 header is used to determine the protocol type, which could be TCP, 
 * UDP, or ICMP. Depending on the protocol type, the corresponding header structure is parsed:
 * 
 * - For TCP (protocol 6), the TCP header is extracted, and the source and destination ports are 
 *   retrieved using `bpf_ntohs` to convert them from network byte order to host byte order.
 * - For UDP (protocol 17), the UDP header is similarly processed, and the source and destination ports 
 *   are extracted.
 * - For ICMP (protocol 1), no further fields are extracted, as it does not have source and destination 
 *   port information.
 * - For any other protocol, the function logs an error message indicating an unknown protocol and 
 *   returns `-EFAULT`.
 * 
 * The extracted packet information, including source and destination IPs and ports, as well as the protocol,
 * is stored in the provided `info` structure.
 * 
 * The function returns `TC_ACT_OK` to indicate that the packet classification was successful.
 */

#ifdef CLASSIFY_IPV4
static __always_inline int classify_ipv4_packet(struct key_5tuple_ipv4 *info, void *data_end,
						void *data)
{
	struct iphdr *ip = (struct iphdr *)data;

	if ((void *)(ip + 1) > data_end) {
		bpf_printk("IPv4 header is not complete\n");
		return -EFAULT;
	}

	__u8 protocol = ip->protocol;

	info->src_ip = ip->saddr;
	info->dst_ip = ip->daddr;
	info->src_port = 0;
	info->dst_port = 0;
	info->protocol = ip->protocol;

	switch (protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (struct tcphdr *)(ip + 1);
		if ((void *)(tcph + 1) > data_end) {
			bpf_printk("TCP header is not complete\n");
			return -EFAULT;
		}

		info->src_port = bpf_ntohs(tcph->source);
		info->dst_port = bpf_ntohs(tcph->dest);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = (struct udphdr *)(ip + 1);
		if ((void *)(udph + 1) > data_end) {
			bpf_printk("UDP header is not complete\n");
			return -EFAULT;
		}

		info->src_port = bpf_ntohs(udph->source);
		info->dst_port = bpf_ntohs(udph->dest);
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmph = (struct icmphdr *)(ip + 1);
		if ((void *)(icmph + 1) > data_end) {
			bpf_printk("ICMP header is not complete\n");
			return -EFAULT;
		}
		break;
	}
	default: {
		bpf_printk("Unknown protocol\n");
		return -EFAULT;
	}
	}

	return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv6
#ifdef CLASSIFY_IPV6
static __always_inline int classify_ipv6_packet(struct key_5tuple_ipv6 *info, void *data_end,
						void *data)
{
	struct ipv6hdr *ip6 = (struct ipv6hdr *)data;

	if ((void *)(ip6 + 1) > data_end) {
		bpf_printk("IPv6 header is not complete\n");
		return -EFAULT;
	}

	__u8 temp_src_ip[16];
	__u8 temp_dst_ip[16];

	memcpy(temp_src_ip, ip6->saddr.in6_u.u6_addr8, 16);
	memcpy(temp_dst_ip, ip6->daddr.in6_u.u6_addr8, 16);

	// Controllo se l'indirizzo sorgente o destinazione è link-local (fe80::/10)
	if (temp_src_ip[0] == 0xfe &&
	    (temp_src_ip[1] & 192) == 0x80) { //corretto bug altrimenti controllava una /12
		bpf_printk("Packet with link-local source address fe80::/10\n");
		return -EFAULT;
	}

	if (temp_dst_ip[0] == 0xfe && (temp_dst_ip[1] & 192) == 0x80) {
		bpf_printk("Packet with link-local destination address fe80::/10\n");
		return -EFAULT;
	}

	// Controllo se l'indirizzo sorgente o destinazione è unspecified (::/128)
	//__u8 zero_addr[16] = { 0 }; // Indirizzo "unspecified" è tutto zero
	// bpf_printk("Zero address: %u\n", zero_addr[0]);
	//bpf_printk("Temp source address: %u\n", temp_src_ip[0]);

	//TO FIX: elimminare la cattura dei pacchetti con indirizzo sorgente o destinazione unspecified (0::/128)

	// if (memcmp(temp_src_ip, zero_addr, 16) == 0) {
	//     //TODO: non entra mai in questo if
	//     bpf_printk("Packet with unspecified source address ::\n");
	//     return TC_ACT_OK;
	// }

	// if (memcmp(temp_dst_ip, zero_addr, 16) == 0) {
	//     bpf_printk("Packet with unspecified destination address ::\n");
	//     return TC_ACT_OK;
	// }

	// if (temp_src_ip[0] == 0x00) {
	// 	bpf_printk("Packet with unspecified source address ::\n");

	// 	return TC_ACT_OK;
	// }

	// if (temp_dst_ip[0] == 0x00) {
	// 	bpf_printk("Packet with unspecified destination address ::\n");
	// 	return TC_ACT_OK;
	// }

	memcpy(&info->src_ip, ip6->saddr.in6_u.u6_addr8, 16);
	memcpy(&info->dst_ip, ip6->daddr.in6_u.u6_addr8, 16);
	info->protocol = ip6->nexthdr;

	__u8 protocol = ip6->nexthdr;

	switch (protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (struct tcphdr *)(ip6 + 1);
		if ((void *)(tcph + 1) > data_end) {
			bpf_printk("TCP header is not complete\n");
			return -EFAULT;
		}

		info->src_port = bpf_ntohs(tcph->source);
		info->dst_port = bpf_ntohs(tcph->dest);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = (struct udphdr *)(ip6 + 1);
		if ((void *)(udph + 1) > data_end) {
			bpf_printk("UDP header is not complete\n");
			return -EFAULT;
		}

		info->src_port = bpf_ntohs(udph->source);
		info->dst_port = bpf_ntohs(udph->dest);
		break;
	}
	case IPPROTO_ICMPV6: {
		struct icmp6hdr *icmph = (struct icmp6hdr *)(ip6 + 1);
		if ((void *)(icmph + 1) > data_end) {
			bpf_printk("ICMPv6 header is not complete\n");
			return -EFAULT;
		}
		//bpf_printk("ICMPv6 packet\n");
		break;
	}
	default: {
		bpf_printk("Unknown protocol\n");
		return -EFAULT;
	}
	}

	return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv4 con solo gli indirizzi
#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
static __always_inline int classify_ONLY_ADDRESS_ipv4_packet(struct key_only_addr_ipv4 *info,
							     void *data_end, void *data)
{
	struct iphdr *ip = (struct iphdr *)data;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("IPv4 header is not complete\n");
		return -EFAULT;
	}

	info->src_ip = ip->saddr;
	info->dst_ip = ip->daddr;

	return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv6 con solo gli indirizzi
#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
static __always_inline int classify_ONLY_ADDRESS_ipv6_packet(struct key_only_addr_ipv6 *info,
							     void *data_end, void *data)
{
	struct ipv6hdr *ip6 = (struct ipv6hdr *)data;
	__u8 temp_src_ip[16];
	__u8 temp_dst_ip[16];

	if ((void *)(ip6 + 1) > data_end) {
		bpf_printk("IPv6 header is not complete\n");
		return -EFAULT;
	}

	memcpy(temp_src_ip, ip6->saddr.in6_u.u6_addr8, 16);
	memcpy(temp_dst_ip, ip6->daddr.in6_u.u6_addr8, 16);

	// Controllo se l'indirizzo sorgente o destinazione è link-local (fe80::/10)
	if (temp_src_ip[0] == 0xfe &&
	    (temp_src_ip[1] & 192) == 0x80) { //corretto bug altrimenti controllava una /12
		bpf_printk("Packet with link-local source address fe80::/10\n");
		return -EFAULT;
	}

	if (temp_dst_ip[0] == 0xfe && (temp_dst_ip[1] & 192) == 0x80) {
		bpf_printk("Packet with link-local destination address fe80::/10\n");
		return -EFAULT;
	}

	memcpy(&info->src_ip, ip6->saddr.in6_u.u6_addr8, 16);
	memcpy(&info->dst_ip, ip6->daddr.in6_u.u6_addr8, 16);

	return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv4 con solo l'indirizzo di destinazione
#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
static __always_inline int classify_ONLY_DEST_ADDRESS_ipv4_packet(struct key_only_dest_ipv4 *info,
								  void *data_end, void *data)
{
	struct iphdr *ip = (struct iphdr *)data;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("IPv4 header is not complete\n");
		return -EFAULT;
	}

	info->dst_ip = ip->daddr;

	return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv6 con solo l'indirizzo di destinazione
#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
static __always_inline int classify_ONLY_DEST_ADDRESS_ipv6_packet(struct key_only_dest_ipv6 *info,
								  void *data_end, void *data)
{
	struct ipv6hdr *ip6 = (struct ipv6hdr *)data;
	__u8 temp_dst_ip[16];

	if ((void *)(ip6 + 1) > data_end) {
		bpf_printk("IPv6 header is not complete\n");
		return -EFAULT;
	}

	memcpy(temp_dst_ip, ip6->daddr.in6_u.u6_addr8, 16);

	if (temp_dst_ip[0] == 0xfe && (temp_dst_ip[1] & 192) == 0x80) {
		bpf_printk("Packet with link-local destination address fe80::/10\n");
		return -EFAULT;
	}

	memcpy(&info->dst_ip, ip6->daddr.in6_u.u6_addr8, 16);

	return TC_ACT_OK;
}
#endif

/**
 * Main eBPF function for processing ingress packets.
 * 
 * It handles the classification of IPv4 and IPv6 packets based on different modes (e.g., full, source/destination address only).
 * - If the flow ID is not initialized, it looks it up from a map.
 * - It checks the Ethernet header for VLAN tags and processes IP packets.
 * - Depending on the packet's protocol (IPv4/IPv6), it classifies the packet based on the defined classification mode.
 * - If the packet matches one of the modes (e.g., QUINTUPLA, ONLY_ADDRESS), it updates a map with packet details.
 * - Returns TC_ACT_OK to pass the packet.
 */
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end; // set the pointer to the end of the packet
	void *data = (void *)(__u64)ctx->data;		   // set the pointer to the beginning of the packet
	struct ethhdr *eth;
	struct vlan_hdr *vlan;
	int ret;

	//u32 key = 0; 

	/** Check if the flow_id is uninitialized (set to -1). If so, retrieve the flow_id 
	*   from the BPF map using the interface index (ifindex) from the packet context.
	*/
	if(flow_id == -1){
		ifindex = ctx->ifindex;
		u64 *flow_id_ret = bpf_map_lookup_elem(&last_flow_id_by_ifindex, &ifindex);

		if(flow_id_ret == NULL){
			bpf_printk("flow_id not found - skip\n");
			return TC_ACT_OK;
		} else {
			flow_id = *flow_id_ret;
			counter = *flow_id_ret;
			bpf_printk("flow_id found: %llu\n", flow_id);
		}
	}
	
	

	__u32 packet_length = ctx->len;

	struct classify_packet_args args = { .map_name = NULL,
					     .new_info = NULL,
					     .map_flow = NULL,
					     .counter = &counter,
					     .flow_type = 0,
					     .packet_length = packet_length };

	/**
	 * Check if the packet is an IP packet (IPv4 or IPv6).
	 */
	if (ctx->protocol != bpf_htons(ETH_P_IP) && ctx->protocol != bpf_htons(ETH_P_IPV6)) {
		bpf_printk("Not an IP packet\n");
		return TC_ACT_OK;
	}

	eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("Ethernet header is not complete\n");
		return TC_ACT_OK;
	}

	__u16 eth_proto = eth->h_proto;
	if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
		vlan = (struct vlan_hdr *)(eth + 1);
		if ((void *)(vlan + 1) > data_end) {
			bpf_printk("VLAN header is not complete\n");
			return TC_ACT_OK;
		}

		eth_proto = vlan->h_vlan_encapsulated_proto;
		data = (void *)vlan + 1;

		if ((void *)(data + 1) > data_end) {
			bpf_printk("Packet data is not complete after VLAN header\n");
			return TC_ACT_OK;
		}

		bpf_printk("VLAN tag detected, running in access mode\n");
	} else {
		data = (void *)(eth + 1);
	}


	/**
	 * This section of the code processes IPv4 packets based on the Ethernet protocol type (eth_proto).
	 * 
	 * It first checks if the Ethernet packet is IPv4 (ETH_P_IP). If it is, it proceeds to classify the packet 
	 * by calling the `classify_ipv4_packet` function, which analyzes the packet's contents and stores the 
	 * classification information in the `new_info` structure.
	 * 
	 * If the classification is successful, the arguments required to update the flow map (`flow_info_ipv4`) are set up. 
	 * These include the new classification information (`new_info`), the corresponding flow ID map (`flow_id_info_ipv4`), 
	 * and the flow type (e.g. QUINTUPLA).
	 * 
	 * The function `classify_packet_and_update_map` is then called to update the flow map with the new information.
	 * If any part of the process fails (either classification or map update), the function returns early and skips further processing.
	 * 
	 * The switch block is exited after the IPv4 packet is processed.
	 * 
	 * This is done for every supported classification mode (e.g., QUINTUPLA, ONLY_ADDRESS, ONLY_DEST_ADDRESS) and for both IPv4 and IPv6 packets.
	 */
	switch (eth_proto) {
#ifdef CLASSIFY_IPV4
	case bpf_htons(ETH_P_IP): {
		struct key_5tuple_ipv4 new_info = {};
		ret = classify_ipv4_packet(&new_info, data_end, data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &flow_info_ipv4;
		args.new_info = &new_info;
		args.map_flow = &flow_id_info_ipv4;
		args.flow_type = QUINTUPLA;
		//ret = classify_packet_and_update_map(&args, ctx);
		ret = classify_packet_and_update_map(&args);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		break;
	}
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
	case bpf_htons(ETH_P_IP): {
		struct key_only_addr_ipv4 new_info_only_addr_ipv4 = {};
		ret = classify_ONLY_ADDRESS_ipv4_packet(&new_info_only_addr_ipv4, data_end, data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &flow_info_only_addr_ipv4;
		args.new_info = &new_info_only_addr_ipv4;
		args.map_flow = &flow_id_info_ipv4;
		args.flow_type = ONLY_ADDRESS;
		ret = classify_packet_and_update_map(&args);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		break;
	}
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
	case bpf_htons(ETH_P_IP): {
		struct key_only_dest_ipv4 new_info_only_dest_ipv4 = {};
		ret = classify_ONLY_DEST_ADDRESS_ipv4_packet(&new_info_only_dest_ipv4, data_end,
							     data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &flow_info_only_dest_ipv4;
		args.new_info = &new_info_only_dest_ipv4;
		args.map_flow = &flow_id_info_ipv4;
		args.flow_type = ONLY_DEST_ADDRESS;
		ret = classify_packet_and_update_map(&args);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		break;
	}
#endif

#ifdef CLASSIFY_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct key_5tuple_ipv6 new_info_ipv6 = {};
		ret = classify_ipv6_packet(&new_info_ipv6, data_end, data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &flow_info_ipv6;
		args.new_info = &new_info_ipv6;
		args.map_flow = &flow_id_info_ipv6;
		args.flow_type = QUINTUPLA;
		ret = classify_packet_and_update_map(&args);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		break;
	}
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct key_only_addr_ipv6 new_info_only_addr_ipv6 = {};
		ret = classify_ONLY_ADDRESS_ipv6_packet(&new_info_only_addr_ipv6, data_end, data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &flow_info_only_addr_ipv6;
		args.new_info = &new_info_only_addr_ipv6;
		args.map_flow = &flow_id_info_ipv6;
		args.flow_type = ONLY_ADDRESS;
		ret = classify_packet_and_update_map(&args);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		break;
	}
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct key_only_dest_ipv6 new_info_only_dest_ipv6 = {};
		ret = classify_ONLY_DEST_ADDRESS_ipv6_packet(&new_info_only_dest_ipv6, data_end,
							     data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &flow_info_only_dest_ipv6;
		args.new_info = &new_info_only_dest_ipv6;
		args.map_flow = &flow_id_info_ipv6;
		args.flow_type = ONLY_DEST_ADDRESS;
		ret = classify_packet_and_update_map(&args);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		break;
	}
#endif

	default:
		bpf_printk("Unknown protocol\n");
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";