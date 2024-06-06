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

#ifdef CLASSIFY_IPV4
#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct packet_info);
} ipv4_flow SEC(".maps");
#endif
#endif

#ifdef CLASSIFY_IPV6
#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct packet_info_ipv6);
} ipv6_flow SEC(".maps");
#endif
#endif

static __always_inline __u64 build_flowid(__u8 first_byte, __u64 counter) {
    return ((__u64)first_byte << 56) | (counter & 0x00FFFFFFFFFFFFFF);
}

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

#ifdef CLASSIFY_ONLY_ADDRESS_IPV4
static __always_inline int classify_only_address_ipv4_packet(struct only_addr_ipv4 *info, void *data_end, void *data) {
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

#ifdef CLASSIFY_ONLY_ADDRESS_IPV6
static __always_inline int classify_only_address_ipv6_packet(struct only_addr_ipv6 *info, void *data_end, void *data) {
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

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *eth;
	struct iphdr *ip;
    struct vlan_hdr *vlan;
    struct ipv6hdr *ip6;

    struct packet_info new_info = {};
    struct packet_info_ipv6 new_info_ipv6 = {};

    struct value_packet *packet;
    int ret, cpu;


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


    if(eth_proto == bpf_htons(ETH_P_IP)) {
        /*bpf_printk("IPv4 packet\n");
        ip = (struct iphdr *)data;
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        __u8 protocol = ip->protocol;
        
        new_info.src_ip = ip->saddr,
        new_info.dst_ip = ip->daddr,
        new_info.src_port = 0,
        new_info.dst_port = 0,
        new_info.protocol = ip->protocol;

        switch(protocol) {
            case IPPROTO_TCP: {
                struct tcphdr *tcph = (struct tcphdr *)(ip + 1);
                if ((void *)(tcph + 1) > data_end){
                    bpf_printk("TCP header is not complete\n");
                    return TC_ACT_OK;
                }

                new_info.src_port = bpf_ntohs(tcph->source);
                new_info.dst_port = bpf_ntohs(tcph->dest);
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr *udph = (struct udphdr *)(ip + 1);
                if ((void *)(udph + 1) > data_end) {
                    bpf_printk("UDP header is not complete\n");
                    return TC_ACT_OK;
                }

                new_info.src_port = bpf_ntohs(udph->source);
                new_info.dst_port = bpf_ntohs(udph->dest);
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
            
        }*/

    }

    else if(eth_proto == bpf_htons(ETH_P_IPV6)) {
        bpf_printk("IPv6 packet\n");
        ip6 = (struct ipv6hdr *)data;
        if ((void *)(ip6 + 1) > data_end){
            bpf_printk("IPv6 header is not complete\n");
            return TC_ACT_OK;
        }
            //return TC_ACT_OK;

        //new_info_ipv6.src_ip = ip6->saddr;
        memcpy(&new_info_ipv6.src_ip, ip6->saddr.in6_u.u6_addr8, 16);
        memcpy(&new_info_ipv6.dst_ip, ip6->daddr.in6_u.u6_addr8, 16);
        new_info_ipv6.protocol = ip6->nexthdr;

        __u8 protocol = ip6->nexthdr;

        switch(protocol) {
            case IPPROTO_TCP: {
                struct tcphdr *tcph = (struct tcphdr *)(ip6 + 1);
                if ((void *)(tcph + 1) > data_end) {
                    bpf_printk("TCP header is not complete\n");
                    return TC_ACT_OK;
                }

                new_info_ipv6.src_port = bpf_ntohs(tcph->source);
                new_info_ipv6.dst_port = bpf_ntohs(tcph->dest);
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr *udph = (struct udphdr *)(ip6 + 1);
                if ((void *)(udph + 1) > data_end) {
                    bpf_printk("UDP header is not complete\n");
                    return TC_ACT_OK;
                }

                new_info_ipv6.src_port = bpf_ntohs(udph->source);
                new_info_ipv6.dst_port = bpf_ntohs(udph->dest);
                break;
            }
            case IPPROTO_ICMPV6: {
                struct icmp6hdr *icmph = (struct icmp6hdr *)(ip6 + 1);
                if ((void *)(icmph + 1) > data_end) {
                    bpf_printk("ICMP header is not complete\n");
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
    }

    else {
        bpf_printk("Unknown protocol\n");
        return TC_ACT_OK;
    }

    cpu = bpf_get_smp_processor_id();
    bpf_printk("Il codice BPF sta eseguendo sulla CPU %u\n", cpu);

    switch(eth_proto) {
        case bpf_htons(ETH_P_IP): {
            packet = bpf_map_lookup_elem(&my_map, &new_info);
            bpf_printk("IPv4 packet\n");
            if(!packet) {
                struct value_packet new_value = {
                    .counter = 1
                };

                bpf_printk("Create new item in IPv4 maps with counter 1\n");


                bpf_printk("-----------------------------------------------------");
                ret = bpf_map_update_elem(&my_map, &new_info, &new_value, BPF_ANY);
                if (ret) {
                    bpf_printk("Failed to insert new item in IPv4 maps\n");
                    return TC_ACT_OK;
                }
	        } else {

                bpf_printk("Found item in IPv4 maps\n");

                if (packet->counter < MAX_COUNTER) {
                    bpf_spin_lock(&packet->lock);
                    packet->counter += 1;
                    bpf_spin_unlock(&packet->lock);
                } else {
                    bpf_printk("Counter is at maximum value\n");
                }

                bpf_printk("Counter: %u\n", packet->counter);

                bpf_printk("-----------------------------------------------------");

	        }
            break;
        }
    
        case bpf_htons(ETH_P_IPV6): {
            packet = bpf_map_lookup_elem(&my_map_ipv6, &new_info_ipv6);
            bpf_printk("IPv6 packet\n");
            if(!packet) {
                struct value_packet new_value = {
                    .counter = 1
                };

                bpf_printk("Create new item in IPv6 maps with counter 1\n");


                bpf_printk("-----------------------------------------------------");
                ret = bpf_map_update_elem(&my_map_ipv6, &new_info_ipv6, &new_value, BPF_ANY);
                if (ret) {
                    bpf_printk("Failed to insert new item in IPv4 maps\n");
                    return TC_ACT_OK;
                }
	        } else {

                bpf_printk("Found item in IPv6 maps\n");

                if (packet->counter < MAX_COUNTER) {
                    bpf_spin_lock(&packet->lock);
                    packet->counter += 1;
                    bpf_spin_unlock(&packet->lock);
                } else {
                    bpf_printk("Counter is at maximum value\n");
                }

                bpf_printk("Counter: %u\n", packet->counter);

                bpf_printk("-----------------------------------------------------");

	        }
            break;
        }
        default: {
            bpf_printk("Unknown packet\n");
            return TC_ACT_OK;
        }
    }

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
