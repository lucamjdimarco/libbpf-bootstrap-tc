
#ifndef COMMON_HEADER_H
#define COMMON_HEADER_H

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/
#define IPPROTO_TCP 6   /* TCP protocol */
#define IPPROTO_UDP 17  /* UDP protocol */
#define IPPROTO_ICMP 1  /* ICMP protocol */
#define MAX_ENTRIES 256
#define MAX_COUNTER 4294967295 /* 2 ^ 32 */

struct event {
	__u64 ts;
	__u64 flowid;
	__u64 counter;
};

struct packet_info {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
};

struct value_packet {
	//sizeof(bpf_spin_lock) = 4 byte
	struct bpf_spin_lock lock;
	__u32 counter; 
};

#endif // COMMON_HEADER_H
