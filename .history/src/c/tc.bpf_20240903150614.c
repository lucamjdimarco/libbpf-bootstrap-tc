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

#define CLOCK_BOOTTIME		7
// #define SWIN_SCALER		1000000000ul /* 1sec in nanosec */
#define SWIN_SCALER 10000000000ul /* 10 seconds in nanoseconds */
#define SWIN_TIMER_TIMEOUT	(SWIN_SCALER << 1ul)

enum FlowIdType {
        QUINTUPLA = 0,
        ONLY_ADDRESS = 1,
        ONLY_DEST_ADDRESS = 2
};

struct param {
    void *map_name;
    void *new_info; 
    int flow_type;
    void *map_flow; 
    __u64 packet_length;
    __u64 *counter;
};

#ifdef CLASSIFY_IPV4
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct packet_info);
    __type(value, struct value_packet);
} map_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct packet_info);
} ipv4_flow SEC(".maps");
#endif

#ifdef CLASSIFY_IPV6
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct packet_info_ipv6);
    __type(value, struct value_packet);
} map_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct packet_info_ipv6);
} ipv6_flow SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct only_addr_ipv4);
    __type(value, struct value_packet);
} map_only_addr_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct only_addr_ipv4);
} ipv4_flow SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct only_addr_ipv6);
    __type(value, struct value_packet);
} map_only_addr_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct only_addr_ipv6);
} ipv6_flow SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct only_dest_ipv4);
    __type(value, struct value_packet);
} map_only_dest_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct only_dest_ipv4);
} ipv4_flow SEC(".maps");
#endif

#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct only_dest_ipv6);
    __type(value, struct value_packet);
} map_only_dest_ipv6 SEC(".maps");

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
static __always_inline __u64 build_flowid(__u8 first_byte, __u64 counter) {
    return ((__u64)first_byte << 56) | (counter & 0x00FFFFFFFFFFFFFF);
}

static __always_inline
int update_window_start_timer(struct bpf_timer *timer, __u64 timeout)
{
	int rc;

	rc = bpf_timer_start(timer, timeout, 0);
	if (!rc)
		return 0;

	if (rc == -EINVAL) {
		/* This use case can be tolerated, as it is very rare.
		 * If we have arrived at this point, it indicates that
		 * two packets are being processed simultaneously on
		 * two different CPUs, and both are attempting to
		 * initialize the corresponding element. However, the
		 * operation is intended to be performed by only one
		 * CPU.
		 * Therefore, it is possible that while one CPU is
		 * initializing the timer, the completed operation may
		 * not yet be visible on the current CPU.
		 */
		bpf_printk("bpf_timer is not initialized yet");
		return 0;
	}

	return rc;
}


static __always_inline int
prepare_ring_buffer_write(void *map, struct event_t **pevent)
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


// static __always_inline int swin_timer_init(void *map, struct bpf_timer *timer)
// {
// 	int rc;

// 	rc = bpf_timer_init(timer, map, CLOCK_BOOTTIME);
// 	if (rc)
// 		return rc;

// 	return bpf_timer_set_callback(timer, 0);
// }

static __always_inline
int update_window(struct value_packet *packet, __u64 packet_length, __u64 ts, bool start_timer) {

    const __u64 cur_tsw = ts / SWIN_SCALER;
    struct event_t *event = NULL;
    __u32 counter_val;

    int rc;
    
    bpf_spin_lock(&packet->lock);
    if (packet->counter < MAX_COUNTER) {
        packet->counter += 1;
        packet->bytes_counter += packet_length;
    }
    __u64 tsw = packet->tsw;
    __u32 *counter = &packet->counter;

    if (cur_tsw <= tsw) {
        bpf_spin_unlock(&packet->lock);
        //goto update;
        return 0;
    }

    counter_val = *counter;

    event->ts = tsw;
    event->flowid = packet->flow_id;
    event->counter = counter_val;

    goto update_win;

update_win:
    packet->tsw = cur_tsw;
    bpf_spin_unlock(&packet->lock);

    if (!start_timer)
        return 0;

    /* Avvia il timer associato a questa finestra */
    rc = update_window_start_timer(&packet->timer, SWIN_TIMER_TIMEOUT);
    if (rc)
        return -EINVAL;


    //Riserva spazio nel rbuf per poter poi aggiungere l'evento secondo la logica commit/abort
    rc = prepare_ring_buffer_write(&rbuf_events, &event);
    if (rc)
        goto update_win;
    
    bpf_printk("Event: %llu %llu %u\n", event->ts, event->flowid, event->counter);

    bpf_ringbuf_submit(event, 0);

    return 0;

// err:
//     return -EINVAL;
}

// #define CLASSIFY_PACKET_AND_UPDATE_MAP(map_name, new_info, flow_type, map_flow) do { \
//     struct value_packet *packet = NULL; \
//     int ret; \
//     packet = bpf_map_lookup_elem(&map_name, &new_info); \
//     if (!packet) { \
//         flow_id = build_flowid(flow_type, __sync_fetch_and_add(&counter, 1)); \
//         struct value_packet new_value = { \
//             .counter = 1, \
//             .bytes_counter = packet_length, \
//             .flow_id = flow_id, \
//             .tsw = 0, \
//             .initialized = 0, \
//         }; \
//         /* inserimento della nuova istanza rappresentante il flusso */ \
//         ret = bpf_map_update_elem(&map_name, &new_info, &new_value, BPF_ANY); \
//         if (ret) { \
//             bpf_printk("Failed to insert new item in map_name\n"); \
//             return TC_ACT_OK; \
//         } \
//         /* inserimento del nuovo flusso nella mappa dei flussi */ \
//         ret = bpf_map_update_elem(&map_flow, &flow_id, &new_info, BPF_ANY); \
//         if (ret) { \
//             bpf_printk("Failed to insert new item in map_flow\n"); \
//             return TC_ACT_OK; \
//         } \
//         /* Ricarica l'elemento aggiornato dalla mappa per ottenere l'indirizzo corretto del timer */ \
//         packet = bpf_map_lookup_elem(&map_name, &new_info); \
//         if (!packet) { \
//             bpf_printk("Failed to lookup newly inserted item in map_name\n"); \
//             return TC_ACT_OK; \
//         } \
//         if (__sync_bool_compare_and_swap(&packet->initialized, 0, 1)) { \
//             int rc = bpf_timer_init(&packet->timer, &map_name, CLOCK_BOOTTIME); \
//             if (rc) { \
//                 bpf_printk("Failed to initialize timer\n"); \
//                 /* Se fallisce, ripristina il flag di inizializzazione */ \
//                 __sync_bool_compare_and_swap(&packet->initialized, 1, 0); \
//                 return TC_ACT_OK; \
//             } \
//         } \
//     } else { \
//         /* gestione del flusso già esistente. Aggiornamento dei contatori nella mappa e controllo finestra */ \
//         update_window(packet, packet_length, bpf_ktime_get_ns(), true); \
//     } \
// } while (0)


//int classify_packet_and_update_map(void *map_name, void *new_info, int flow_type, void *map_flow, __u64 packet_length, __u64 *counter)
static __always_inline 
int classify_packet_and_update_map(struct param p) {
    struct value_packet *packet = NULL;
    int ret;
    __u64 flow_id;

    //static __u64 *counter = 0;

    // Cerca il pacchetto nella mappa
    packet = bpf_map_lookup_elem(p.map_name, p.new_info);
    if (!packet) {
        // Costruisce un nuovo flow_id
        //flow_id = build_flowid(flow_type, __sync_fetch_and_add(counter, 1));
        flow_id = build_flowid(p.flow_type, __sync_fetch_and_add(p.counter, 1));

        // Inizializza una nuova struttura value_packet
        struct value_packet new_value = {
            .counter = 1,
            .bytes_counter = p.packet_length,
            .flow_id = flow_id,
            .tsw = 0,
            .initialized = 0,
        };

        // Inserimento della nuova istanza rappresentante il flusso
        ret = bpf_map_update_elem(p.map_name, p.new_info, &new_value, BPF_ANY);
        if (ret) {
            bpf_printk("Failed to insert new item in map_name\n");
            return TC_ACT_OK;
        }

        // Inserimento del nuovo flusso nella mappa dei flussi
        ret = bpf_map_update_elem(p.map_flow, &flow_id, p.new_info, BPF_ANY);
        if (ret) {
            bpf_printk("Failed to insert new item in map_flow\n");
            return TC_ACT_OK;
        }

        // Ricarica l'elemento aggiornato dalla mappa per ottenere l'indirizzo corretto del timer
        packet = bpf_map_lookup_elem(p.map_name, p.new_info);
        if (!packet) {
            bpf_printk("Failed to lookup newly inserted item in map_name\n");
            return TC_ACT_OK;
        }

        // Inizializzazione del timer
        if (__sync_bool_compare_and_swap(&packet->initialized, 0, 1)) {
            int rc = bpf_timer_init(&packet->timer, p.map_name, CLOCK_BOOTTIME);
            if (rc) {
                bpf_printk("Failed to initialize timer\n");
                // Se fallisce, ripristina il flag di inizializzazione
                __sync_bool_compare_and_swap(&packet->initialized, 1, 0);
                return TC_ACT_OK;
            }
        }
    } else {
        // Gestione del flusso già esistente. Aggiornamento dei contatori nella mappa e controllo finestra
        update_window(packet, p.packet_length, bpf_ktime_get_ns(), true);
    }

    return TC_ACT_OK;
}


// classificazione dei pacchetti IPv4
#ifdef CLASSIFY_IPV4
static __always_inline int classify_ipv4_packet(struct packet_info *info, void *data_end, void *data) {
    struct iphdr *ip = (struct iphdr *)data;
    if ((void *)(ip + 1) > data_end) {
        bpf_printk("IPv4 header is not complete\n");
        return TC_ACT_OK;
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
                return TC_ACT_OK;
            }

            info->src_port = bpf_ntohs(tcph->source);
            info->dst_port = bpf_ntohs(tcph->dest);
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udph = (struct udphdr *)(ip + 1);
            if ((void *)(udph + 1) > data_end) {
                bpf_printk("UDP header is not complete\n");
                return TC_ACT_OK;
            }

            info->src_port = bpf_ntohs(udph->source);
            info->dst_port = bpf_ntohs(udph->dest);
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr *icmph = (struct icmphdr *)(ip + 1);
            if ((void *)(icmph + 1) > data_end) {
                bpf_printk("ICMP header is not complete\n");
                return TC_ACT_OK;
            }
            break;
        }
        default: {
            bpf_printk("Unknown protocol\n");
            return TC_ACT_OK;
        }
    }

    return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv6
#ifdef CLASSIFY_IPV6
static __always_inline int classify_ipv6_packet(struct packet_info_ipv6 *info, void *data_end, void *data) {
    struct ipv6hdr *ip6 = (struct ipv6hdr *)data;
    if ((void *)(ip6 + 1) > data_end) {
        bpf_printk("IPv6 header is not complete\n");
        return TC_ACT_OK;
    }

    memcpy(&info->src_ip, ip6->saddr.in6_u.u6_addr8, 16);
    memcpy(&info->dst_ip, ip6->daddr.in6_u.u6_addr8, 16);
    info->protocol = ip6->nexthdr;

    __u8 protocol = ip6->nexthdr;

    switch (protocol) {
        case IPPROTO_TCP: {
            struct tcphdr *tcph = (struct tcphdr *)(ip6 + 1);
            if ((void *)(tcph + 1) > data_end) {
                bpf_printk("TCP header is not complete\n");
                return TC_ACT_OK;
            }

            info->src_port = bpf_ntohs(tcph->source);
            info->dst_port = bpf_ntohs(tcph->dest);
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udph = (struct udphdr *)(ip6 + 1);
            if ((void *)(udph + 1) > data_end) {
                bpf_printk("UDP header is not complete\n");
                return TC_ACT_OK;
            }

            info->src_port = bpf_ntohs(udph->source);
            info->dst_port = bpf_ntohs(udph->dest);
            break;
        }
        case IPPROTO_ICMPV6: {
            struct icmp6hdr *icmph = (struct icmp6hdr *)(ip6 + 1);
            if ((void *)(icmph + 1) > data_end) {
                bpf_printk("ICMPv6 header is not complete\n");
                return TC_ACT_OK;
            }
            bpf_printk("ICMPv6 packet\n");
            break;
        }
        default: {
            bpf_printk("Unknown protocol\n");
            return TC_ACT_OK;
        }
    }

    return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv4 con solo gli indirizzi
#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
static __always_inline int classify_ONLY_ADDRESS_ipv4_packet(struct only_addr_ipv4 *info, void *data_end, void *data) {
    struct iphdr *ip = (struct iphdr *)data;
    if ((void *)(ip + 1) > data_end) {
        bpf_printk("IPv4 header is not complete\n");
        return TC_ACT_OK;
    }

    info->src_ip = ip->saddr;
    info->dst_ip = ip->daddr;

    return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv6 con solo gli indirizzi
#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
static __always_inline int classify_ONLY_ADDRESS_ipv6_packet(struct only_addr_ipv6 *info, void *data_end, void *data) {
    struct ipv6hdr *ip6 = (struct ipv6hdr *)data;
    if ((void *)(ip6 + 1) > data_end) {
        bpf_printk("IPv6 header is not complete\n");
        return TC_ACT_OK;
    }

    memcpy(&info->src_ip, ip6->saddr.in6_u.u6_addr8, 16);
    memcpy(&info->dst_ip, ip6->daddr.in6_u.u6_addr8, 16);

    return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv4 con solo l'indirizzo di destinazione
#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
static __always_inline int classify_ONLY_DEST_ADDRESS_ipv4_packet(struct only_dest_ipv4 *info, void *data_end, void *data) {
    struct iphdr *ip = (struct iphdr *)data;
    if ((void *)(ip + 1) > data_end) {
        bpf_printk("IPv4 header is not complete\n");
        return TC_ACT_OK;
    }

    info->dst_ip = ip->daddr;

    return TC_ACT_OK;
}
#endif

// classificazione dei pacchetti IPv6 con solo l'indirizzo di destinazione
#ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
static __always_inline int classify_ONLY_DEST_ADDRESS_ipv6_packet(struct only_dest_ipv6 *info, void *data_end, void *data) {
    struct ipv6hdr *ip6 = (struct ipv6hdr *)data;
    if ((void *)(ip6 + 1) > data_end) {
        bpf_printk("IPv6 header is not complete\n");
        return TC_ACT_OK;
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
    //struct vlan_hdr *vlan;

    //static __u64 *counter;
    //__u64 flow_id = 0;
    
    //*counter = 0;


    __u64 packet_length = ctx->len;

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

    // Process IPv4 and IPv6 packets
    switch (eth_proto) {
        #ifdef CLASSIFY_IPV4
        case bpf_htons(ETH_P_IP): {
            struct packet_info new_info = {};
            classify_ipv4_packet(&new_info, data_end, data);
            struct param p = {
                .map_name = &map_ipv4,
                .new_info = &new_info,
                .flow_type = QUINTUPLA,
                .map_flow = &ipv4_flow,
                .packet_length = packet_length,
            };

            *p.counter = 0;

            classify_packet_and_update_map(p);
            break;
        }
        #endif

        #ifdef CLASSIFY_ONLY_ADDRESS_IPV4
        case bpf_htons(ETH_P_IP): {
            struct only_addr_ipv4 new_info_only_addr_ipv4 = {};
            classify_ONLY_ADDRESS_ipv4_packet(&new_info_only_addr_ipv4, data_end, data);
            classify_packet_and_update_map(map_only_addr_ipv4, new_info_only_addr_ipv4, ONLY_ADDRESS, ipv4_flow);
            break;
        }
        #endif

        #ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
        case bpf_htons(ETH_P_IP): {
            struct only_dest_ipv4 new_info_only_dest_ipv4 = {};
            classify_ONLY_DEST_ADDRESS_ipv4_packet(&new_info_only_dest_ipv4, data_end, data);
            classify_packet_and_update_map(map_only_dest_ipv4, new_info_only_dest_ipv4, ONLY_DEST_ADDRESS, ipv4_flow);
            break;
        }
        #endif

        #ifdef CLASSIFY_IPV6
        case bpf_htons(ETH_P_IPV6): {
            struct packet_info_ipv6 new_info_ipv6 = {};
            classify_ipv6_packet(&new_info_ipv6, data_end, data);
            classify_packet_and_update_map(map_ipv6, new_info_ipv6, QUINTUPLA, ipv6_flow);
            break;
        }
        #endif

        #ifdef CLASSIFY_ONLY_ADDRESS_IPV6
        case bpf_htons(ETH_P_IPV6): {
            struct only_addr_ipv6 new_info_only_addr_ipv6 = {};
            classify_ONLY_ADDRESS_ipv6_packet(&new_info_only_addr_ipv6, data_end, data);
            classify_packet_and_update_map(map_only_addr_ipv6, new_info_only_addr_ipv6, ONLY_ADDRESS, ipv6_flow);
            break;
        }
        #endif

        //TOFIX: non funziona!!!
        #ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
        case bpf_htons(ETH_P_IPV6): {
            struct only_dest_ipv6 new_info_only_dest_ipv6 = {};
            classify_ONLY_DEST_ADDRESS_ipv6_packet(&new_info_only_dest_ipv6, data_end, data);
            classify_packet_and_update_map(map_only_dest_ipv6, new_info_only_dest_ipv6, ONLY_DEST_ADDRESS, ipv6_flow);
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
