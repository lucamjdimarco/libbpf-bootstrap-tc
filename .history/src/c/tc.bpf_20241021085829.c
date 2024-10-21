// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include "common.h"

#define CLOCK_BOOTTIME 7
// #define SWIN_SCALER		1000000000ul /* 1sec in nanosec */
#define SWIN_SCALER	   10000000000ul /* 10 seconds in nanoseconds */
#define SWIN_TIMER_TIMEOUT (SWIN_SCALER << 1ul)

__u64 counter = 0;
__u8 isFirst = 0;

enum FlowIdType { QUINTUPLA = 0, ONLY_ADDRESS = 1, ONLY_DEST_ADDRESS = 2 };

struct classify_packet_args {
	void *map_name;
	void *new_info;
	void *map_flow;
	__u64 *counter;
	__u32 flow_type;
	__u32 packet_length;
};

#ifdef CLASSIFY_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct packet_info);
	__type(value, struct value_packet);
} map_ipv4 SEC(".maps");
#endif

#ifdef CLASSIFY_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct packet_info_ipv6);
	__type(value, struct value_packet);
} map_ipv6 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct only_addr_ipv4);
	__type(value, struct value_packet);
} map_only_addr_ipv4 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct only_addr_ipv6);
	__type(value, struct value_packet);
} map_only_addr_ipv6 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct only_dest_ipv4);
	__type(value, struct value_packet);
} map_only_dest_ipv4 SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct only_dest_ipv6);
	__type(value, struct value_packet);
} map_only_dest_ipv6 SEC(".maps");
#endif

#ifdef CLASSIFY_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct packet_info);
} ipv4_flow SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct only_addr_ipv4);
} ipv4_flow SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct only_dest_ipv4);
} ipv4_flow SEC(".maps");
#endif

#ifdef CLASSIFY_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct packet_info_ipv6);
} ipv6_flow SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct only_addr_ipv6);
} ipv6_flow SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct only_dest_ipv6);
} ipv6_flow SEC(".maps");
#endif

// Ring buffer per gli eventi
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MB di spazio
} rbuf_events SEC(".maps");

// Funzione per costruire l'ID del flusso
static __always_inline __u64 build_flowid(__u8 first_byte, __u64 counter)
{
	return ((__u64)first_byte << 56) | (counter & 0x00FFFFFFFFFFFFFF);
}

static __always_inline int update_window_start_timer(struct value_packet *packet, __u64 timeout)
{
	int rc;

	// Controlla se il timer è già stato avviato da un'altra CPU
	if (!__sync_bool_compare_and_swap(&packet->timer_started, 0, 1)) {
		// Se il timer è già avviato, stampa un messaggio e ritorna
		bpf_printk("Timer already started by another CPU\n");
		return 0;
	}

	rc = bpf_timer_start(&packet->timer, timeout, 0);
	if (!rc)
		// Se fallisce l'avvio del timer, ripristina lo stato del flag
		__sync_bool_compare_and_swap(&packet->timer_started, 1, 0);

	return 0;

	// if (rc == -EINVAL) {
	// 	/* This use case can be tolerated, as it is very rare.
	// 	 * If we have arrived at this point, it indicates that
	// 	 * two packets are being processed simultaneously on
	// 	 * two different CPUs, and both are attempting to
	// 	 * initialize the corresponding element. However, the
	// 	 * operation is intended to be performed by only one
	// 	 * CPU.
	// 	 * Therefore, it is possible that while one CPU is
	// 	 * initializing the timer, the completed operation may
	// 	 * not yet be visible on the current CPU.
	// 	 */
	// 	bpf_printk("bpf_timer is not initialized yet");
	// 	return 0;
	// }

	// return rc;
}

static __always_inline int prepare_ring_buffer_write(void *map, struct event_t **pevent)
{
	if (!pevent)
		return -EINVAL;

	/* let's send data to userspace using ring buffer */
	*pevent = bpf_ringbuf_reserve(&rbuf_events, sizeof(**pevent), 0);
	if (!(*pevent))
		/* no space left on ring buffer */
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

	//questo prova a mettere giu
	// puo accadere che se il buffer è pieno non faccio mai la logica sotto
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
	__u32 *counter = &packet->counter; //no puntatore

	if (cur_tsw <= tsw) {
		bpf_spin_unlock(&packet->lock);
		bpf_ringbuf_discard(event, 0);
		bpf_printk("skipping event, cur_tsw: %llu, tsw: %llu\n", cur_tsw, tsw);
		return 0;
	}

	//scompare
	counter_val = *counter;

	// event->ts = tsw;
	// event->flowid = packet->flow_id;
	// event->counter = counter_val;

	if (!event) {
		bpf_spin_unlock(&packet->lock);
		bpf_ringbuf_discard(event, 0);
		bpf_printk("Event is null, cannot process\n");
		return -EINVAL;
	}

	//event->ts = tsw;
	/* --- */
	event->ts = ts;
	/* --- */
	event->flowid = packet->flow_id;
	event->counter = counter_val;

	//goto update_win;

	//update_win:
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

	//Riserva spazio nel rbuf per poter poi aggiungere l'evento secondo la logica commit/abort
	// rc = prepare_ring_buffer_write(&rbuf_events, &event);
	// if (rc) {
	// 	bpf_printk("Failed to reserve space in ring buffer\n");
	// 	return 0;
	// }
	//bpf_printk("Failed to reserve space in ring buffer\n");
	//goto update_win;

	bpf_printk("Sending event: %llu %llu %u\n", event->ts, event->flowid, event->counter);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

static __always_inline int classify_packet_and_update_map(struct classify_packet_args *args)
{
	struct value_packet *packet = NULL;
	int ret;

	__u64 flow_id = -1;

	// Cerca l'elemento nella mappa
	packet = bpf_map_lookup_elem(args->map_name, args->new_info);

	if (!packet) {
		// Costruisci un nuovo flow_id
		flow_id = build_flowid(args->flow_type, __sync_fetch_and_add(args->counter, 1));

		if (flow_id == -1) {
			bpf_printk("Failed to build flow_id\n");
			return -EFAULT;
		}

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
		//update_window(packet, args->packet_length, bpf_ktime_get_ns(), true);
		update_window(packet, args->packet_length, bpf_ktime_get_tai_ns(), true);
	}

	return TC_ACT_OK;
}

// classificazione dei pacchetti IPv4
#ifdef CLASSIFY_IPV4
static __always_inline int classify_ipv4_packet(struct packet_info *info, void *data_end,
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
static __always_inline int classify_ipv6_packet(struct packet_info_ipv6 *info, void *data_end,
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
static __always_inline int classify_ONLY_ADDRESS_ipv4_packet(struct only_addr_ipv4 *info,
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
static __always_inline int classify_ONLY_ADDRESS_ipv6_packet(struct only_addr_ipv6 *info,
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
static __always_inline int classify_ONLY_DEST_ADDRESS_ipv4_packet(struct only_dest_ipv4 *info,
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
static __always_inline int classify_ONLY_DEST_ADDRESS_ipv6_packet(struct only_dest_ipv6 *info,
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

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *eth;
	struct vlan_hdr *vlan;
	int ret;

	/* -------- */

	//controllo se è la prima volta che tc ingress viene chiamato
	/*if (isFirst == 0) {
		//recupero il primissimo tempo in ns
		__u64 ts = bpf_ktime_get_ns();
		//muovo il tempo in ns verso il lato utente
		struct event_t *event = NULL;
		int rc = prepare_ring_buffer_write(&rbuf_events, &event);
		if (rc) {
			bpf_printk("Failed to reserve space in ring buffer\n");
			return 0;
		}
		//inizializzo l'evento
		event->ts = ts;
		event->flowid = 0;
		event->counter = 0;
		//mando l'evento
		bpf_ringbuf_submit(event, 0);
		//porto isFirst a 1 così da non eseguire più questa parte di codice
		isFirst = 1;
	}*/
	/* -------- */

	__u32 packet_length = ctx->len;

	struct classify_packet_args args = { .map_name = NULL,
					     .new_info = NULL,
					     .map_flow = NULL,
					     .counter = &counter,
					     .flow_type = 0,
					     .packet_length = packet_length };

	// Controllo se il pacchetto è un pacchetto IP
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

	// Process IPv4 and IPv6 packets
	switch (eth_proto) {
#ifdef CLASSIFY_IPV4
	case bpf_htons(ETH_P_IP): {
		struct packet_info new_info = {};
		ret = classify_ipv4_packet(&new_info, data_end, data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &map_ipv4;
		args.new_info = &new_info;
		args.map_flow = &ipv4_flow;
		args.flow_type = QUINTUPLA;
		ret = classify_packet_and_update_map(&args);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		break;
	}
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
	case bpf_htons(ETH_P_IP): {
		struct only_addr_ipv4 new_info_only_addr_ipv4 = {};
		ret = classify_ONLY_ADDRESS_ipv4_packet(&new_info_only_addr_ipv4, data_end, data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &map_only_addr_ipv4;
		args.new_info = &new_info_only_addr_ipv4;
		args.map_flow = &ipv4_flow;
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
		struct only_dest_ipv4 new_info_only_dest_ipv4 = {};
		ret = classify_ONLY_DEST_ADDRESS_ipv4_packet(&new_info_only_dest_ipv4, data_end,
							     data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &map_only_dest_ipv4;
		args.new_info = &new_info_only_dest_ipv4;
		args.map_flow = &ipv4_flow;
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
		struct packet_info_ipv6 new_info_ipv6 = {};
		ret = classify_ipv6_packet(&new_info_ipv6, data_end, data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &map_ipv6;
		args.new_info = &new_info_ipv6;
		args.map_flow = &ipv6_flow;
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
		struct only_addr_ipv6 new_info_only_addr_ipv6 = {};
		ret = classify_ONLY_ADDRESS_ipv6_packet(&new_info_only_addr_ipv6, data_end, data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &map_only_addr_ipv6;
		args.new_info = &new_info_only_addr_ipv6;
		args.map_flow = &ipv6_flow;
		args.flow_type = ONLY_ADDRESS;
		ret = classify_packet_and_update_map(&args);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		break;
	}
#endif

//TOFIX: non funziona!!!
#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct only_dest_ipv6 new_info_only_dest_ipv6 = {};
		ret = classify_ONLY_DEST_ADDRESS_ipv6_packet(&new_info_only_dest_ipv6, data_end,
							     data);
		if (ret < 0) {
			return TC_ACT_OK;
		}
		args.map_name = &map_only_dest_ipv6;
		args.new_info = &new_info_only_dest_ipv6;
		args.map_flow = &ipv6_flow;
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