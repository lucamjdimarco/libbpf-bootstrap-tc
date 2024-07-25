// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include "common.h"

#ifdef CLASSIFY_IPV4
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct packet_info);
    __type(value, struct value_packet);
} my_map SEC(".maps");
#endif

#ifdef CLASSIFY_IPV6
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct packet_info_ipv6);
    __type(value, struct value_packet);
} my_map_ipv6 SEC(".maps");
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

#if defined(CLASSIFY_IPV4) || defined(CLASSIFY_ONLY_ADDRESS_IPV4) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV4)

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

#endif

#if defined(CLASSIFY_IPV6) || defined(CLASSIFY_ONLY_ADDRESS_IPV6) || defined(CLASSIFY_ONLY_DEST_ADDRESS_IPV6)
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
#endif

// Ring buffer per gli eventi
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB di spazio
} events SEC(".maps");

// Funzione per costruire l'ID del flusso
static __always_inline __u64 build_flowid(__u8 first_byte, __u64 counter) {
    return ((__u64)first_byte << 56) | (counter & 0x00FFFFFFFFFFFFFF);
}

static __always_inline void handle_packet_event(struct value_packet *packet, __u64 flow_id, __u64 packet_length) {
    if (packet->counter < MAX_COUNTER) {
        bpf_spin_lock(&packet->lock);
        packet->counter += 1;
        packet->bytes_counter += packet_length;
        bpf_spin_unlock(&packet->lock);
    } else {
        bpf_printk("Counter is at maximum value\n");
    }
    

    struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    event->ts = bpf_ktime_get_ns();
    event->flowid = packet->flow_id;
    event->counter = packet->counter;
    bpf_ringbuf_submit(event, 0);
}

#define CLASSIFY_PACKET_AND_UPDATE_MAP(map_name, new_info, flow_type, map_flow) do { \
    struct value_packet *packet = NULL; \
    packet = bpf_map_lookup_elem(&map_name, &new_info); \
    if (!packet) { \
        flow_id = build_flowid(flow_type, __sync_fetch_and_add(&counter, 1)); \
        ret = bpf_map_update_elem(&map_flow, &flow_id, &new_info, BPF_ANY); \
        if (ret == -1) { \
            bpf_printk("Failed to insert new item in flow maps\n"); \
            return TC_ACT_OK; \
        } \
        struct value_packet new_value = { \
            .counter = 1, \
            .bytes_counter = packet_length, \
            .flow_id = flow_id \
        }; \
        ret = bpf_map_update_elem(&map_name, &new_info, &new_value, BPF_ANY); \
        if (ret) { \
            bpf_printk("Failed to insert new item in flow maps\n"); \
            return TC_ACT_OK; \
        } \
        struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0); \
        if (!event) { \
            return TC_ACT_OK; \
        } \
        event->ts = bpf_ktime_get_ns(); \
        event->flowid = flow_id; \
        event->counter = 1; \
        bpf_ringbuf_submit(event, 0); \
    } else { \
        handle_packet_event(packet, flow_id, packet_length); \
    } \
} while (0)



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
	//struct iphdr *ip;
    struct vlan_hdr *vlan;
    //struct ipv6hdr *ip6;

    static __u64 counter = 0;
    __u64 flow_id = 0;

    enum FlowIdType {
        QUINTUPLA = 0,
        ONLY_ADDRESS = 1,
        ONLY_DEST_ADDRESS = 2
    };

    
    long ret;
    /*__u64 packet_length = ctx->data_end - ctx->data;*/
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
            classify_ipv4_packet(&new_info, data_end, data);
            CLASSIFY_PACKET_AND_UPDATE_MAP(my_map, new_info, QUINTUPLA, ipv4_flow);
            break;
        }
        #endif

        #ifdef CLASSIFY_ONLY_ADDRESS_IPV4
        case bpf_htons(ETH_P_IP): {
            struct only_addr_ipv4 new_info_only_addr_ipv4 = {};
            classify_ONLY_ADDRESS_ipv4_packet(&new_info_only_addr_ipv4, data_end, data);
            CLASSIFY_PACKET_AND_UPDATE_MAP(map_only_addr_ipv4, new_info_only_addr_ipv4, ONLY_ADDRESS, ipv4_flow);
            break;
        }
        #endif

        #ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV4
        case bpf_htons(ETH_P_IP): {
            struct only_dest_ipv4 new_info_only_dest_ipv4 = {};
            classify_ONLY_DEST_ADDRESS_ipv4_packet(&new_info_only_dest_ipv4, data_end, data);
            CLASSIFY_PACKET_AND_UPDATE_MAP(map_only_dest_ipv4, new_info_only_dest_ipv4, ONLY_DEST_ADDRESS, ipv4_flow);
            break;
        }
        #endif

        #ifdef CLASSIFY_IPV6
        case bpf_htons(ETH_P_IPV6): {
            struct packet_info_ipv6 new_info_ipv6 = {};
            classify_ipv6_packet(&new_info_ipv6, data_end, data);
            CLASSIFY_PACKET_AND_UPDATE_MAP(my_map_ipv6, new_info_ipv6, QUINTUPLA, ipv6_flow);
            break;
        }
        #endif

        #ifdef CLASSIFY_ONLY_ADDRESS_IPV6
        case bpf_htons(ETH_P_IPV6): {
            struct only_addr_ipv6 new_info_only_addr_ipv6 = {};
            classify_ONLY_ADDRESS_ipv6_packet(&new_info_only_addr_ipv6, data_end, data);
            CLASSIFY_PACKET_AND_UPDATE_MAP(map_only_addr_ipv6, new_info_only_addr_ipv6, ONLY_ADDRESS, ipv6_flow);
            break;
        }
        #endif

        //TOFIX: non funziona!!!
        #ifdef CLASSIFY_ONLY_DEST_ADDRESS_IPV6
        case bpf_htons(ETH_P_IPV6): {
            struct only_dest_ipv6 new_info_only_dest_ipv6 = {};
            classify_ONLY_DEST_ADDRESS_ipv6_packet(&new_info_only_dest_ipv6, data_end, data);
            CLASSIFY_PACKET_AND_UPDATE_MAP(map_only_dest_ipv6, new_info_only_dest_ipv6, ONLY_DEST_ADDRESS, ipv6_flow);
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
