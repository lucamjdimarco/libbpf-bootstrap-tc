// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct packet_info);
    __type(value, struct value_packet);
} my_map SEC(".maps");


SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *eth;
	struct iphdr *ip;
    struct vlan_hdr *vlan;

    struct packet_info new_info = {};

    struct value_packet *packet;
    int ret, cpu;


	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

    __u16 eth_proto = eth->h_proto;
    if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
        vlan = (struct vlan_hdr *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;

        eth_proto = vlan->h_vlan_encapsulated_proto;
        data = vlan + 1;

        bpf_printk("VLAN tag detected, running in access mode\n");
    } else {
        data = eth + 1;
    }

	ip = (struct iphdr *)data;
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

    __u8 protocol = ip->protocol;
    
    new_info.src_ip = ip->saddr,
    new_info.dst_ip = ip->daddr,
    new_info.src_port = 0,
    new_info.dst_port = 0,
    new_info.protocol = ip->protocol;
	

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(ip + 1);
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_OK;

        new_info.src_port = bpf_ntohs(tcph->source);
        new_info.dst_port = bpf_ntohs(tcph->dest);

    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(ip + 1);
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;

        new_info.src_port = bpf_ntohs(udph->source);
        new_info.dst_port = bpf_ntohs(udph->dest);

    }
    if(protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)(ip + 1);
        if ((void *)(icmph + 1) > data_end)
            return TC_ACT_OK;

    }

    /* --- IMPLEMENTAZIONE DELLA HASH MAP ---*/

    
	cpu = bpf_get_smp_processor_id();
    bpf_printk("Il codice BPF sta eseguendo sulla CPU %u\n", cpu);
	packet = bpf_map_lookup_elem(&my_map, &new_info);

	if(!packet) {
		struct value_packet new_value = {
			.counter = 1
		};

        bpf_printk("Create new item with counter 1\n");


		bpf_printk("-----------------------------------------------------");
		ret = bpf_map_update_elem(&my_map, &new_info, &new_value, BPF_ANY);
        if (ret) {
			bpf_printk("Failed to insert new item\n");
			return TC_ACT_OK;
		}
	} else {

        bpf_printk("Found item\n");

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

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
