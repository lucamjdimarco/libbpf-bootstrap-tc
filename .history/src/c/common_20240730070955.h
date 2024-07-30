
#ifndef COMMON_HEADER_H
#define COMMON_HEADER_H

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 */
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header */
#define ETH_P_8021AD 0x88A8 /* Q-in-Q */
#define IPPROTO_TCP 6   /* TCP protocol */
#define IPPROTO_UDP 17  /* UDP protocol */
#define IPPROTO_ICMP 1  /* ICMP protocol */
#define IPPROTO_ICMPV6 0x3A /* ICMPv6 protocol */
#define MAX_ENTRIES 256
#define MAX_COUNTER 4294967295 /* 2 ^ 32 */

#if CLASS == 1
#define CLASSIFY_IPV4
#elif CLASS == 2
#define CLASSIFY_IPV6
#elif CLASS == 3
#define CLASSIFY_ONLY_ADDRESS_IPV4
#elif CLASS == 4
#define CLASSIFY_ONLY_ADDRESS_IPV6
#elif CLASS == 5
#define CLASSIFY_ONLY_DEST_ADDRESS_IPV4
#elif CLASS == 6
#define CLASSIFY_ONLY_DEST_ADDRESS_IPV6
#endif

/*struct event {
	__u64 ts;
	__u64 flowid;
	__u64 counter;
};*/

struct event_t {
    __u64 ts;
    __u64 flowid;
    __u64 counter;
};

struct packet_info {
	__u32 src_ip; //IPv4 source address
	__u32 dst_ip; //IPv4 destination address
	__u16 src_port; //Source port
	__u16 dst_port; //Destination port
	__u8 protocol; //Protocol
	__u8 padding[3]; // padding to align the structure
};

struct packet_info_ipv6 {
	__u8 src_ip[16];   // IPv6 source address
	__u8 dst_ip[16];   // IPv6 destination address
	__u16 src_port;  // Source port
	__u16 dst_port;  // Destination port
	__u8 protocol;   // Protocol
	__u8 padding[3]; // Padding to align the structure size to a multiple of 8 bytes
};

struct only_addr_ipv4 {
	__u32 src_ip; //IPv4 source address
	__u32 dst_ip; //IPv4 destination address
};

struct only_addr_ipv6 {
	__u8 src_ip[16];   // IPv6 source address
	__u8 dst_ip[16];   // IPv6 destination address
};

struct only_dest_ipv4 {
	__u32 dst_ip; //IPv4 destination address
};

struct only_dest_ipv6 {
	__u8 dst_ip[16];   // IPv6 destination address
};


struct value_packet {
	//sizeof(bpf_spin_lock) = 4 byte
	struct bpf_spin_lock lock;
	__u32 counter; 
	__u64 bytes_counter;
	__u64 flow_id;
	//struct bpf_timer timer;

	__u64 sync;
	__u64 init;
	__u64 tsw;
	__u64 cnt;
	struct bpf_timer timer;
};

#endif // COMMON_HEADER_H
