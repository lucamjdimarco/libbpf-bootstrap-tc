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

typedef __u8  __attribute__((__may_alias__))  __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8_alias_t  *) res = *(volatile __u8_alias_t  *) p; break;
	case 2: *(__u16_alias_t *) res = *(volatile __u16_alias_t *) p; break;
	case 4: *(__u32_alias_t *) res = *(volatile __u32_alias_t *) p; break;
	case 8: *(__u64_alias_t *) res = *(volatile __u64_alias_t *) p; break;
	default:
		barrier();
		__builtin_memcpy((void *)res, (const void *)p, size);
		barrier();
	}
}

#define READ_ONCE(x)					\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__c = { 0 } };			\
	__read_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile  __u8_alias_t *) p = *(__u8_alias_t  *) res; break;
	case 2: *(volatile __u16_alias_t *) p = *(__u16_alias_t *) res; break;
	case 4: *(volatile __u32_alias_t *) p = *(__u32_alias_t *) res; break;
	case 8: *(volatile __u64_alias_t *) p = *(__u64_alias_t *) res; break;
	default:
		barrier();
		__builtin_memcpy((void *)p, (const void *)res, size);
		barrier();
	}
}

#define WRITE_ONCE(x, val)				\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__val = (val) }; 			\
	__write_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

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
/*------------------------------------------------*/ 
// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 1);
// 	__type(key, __u64);
// 	__type(value, struct slotted_window);
// } hmapsw SEC(".maps");

// struct slotted_window {
// 	/* avoid multiple concurrent window updates */
// 	__u64 sync;
// 	__u64 init;

// 	__u64 tsw;
// 	__u64 cnt;
// 	//__u64 avg;

// 	struct bpf_timer timer;
// };

/*------------------------------------------------*/ 

// Ring buffer per gli eventi
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB di spazio
} events SEC(".maps");

// Funzione per costruire l'ID del flusso
static __always_inline __u64 build_flowid(__u8 first_byte, __u64 counter) {
    return ((__u64)first_byte << 56) | (counter & 0x00FFFFFFFFFFFFFF);
}




/*------------------------------------------------*/ 

// #define try_swin_lock(sw)	__sync_lock_test_and_set(&(sw)->sync, 1)
// #define swin_unlock(sw)					\
// 	do {						\
// 		__sync_fetch_and_and(&(sw)->sync, 0);	\
// 		barrier();				\
// 	} while(0)


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
	*pevent = bpf_ringbuf_reserve(&events, sizeof(**pevent), 0);
	if (!(*pevent))
		/* no space left on ring buffer */
		return -ENOMEM;

	return 0;
}


static __always_inline int swin_timer_init(void *map, struct bpf_timer *timer)
{
	int rc;

	rc = bpf_timer_init(timer, map, CLOCK_BOOTTIME);
	if (rc)
		return rc;

	return bpf_timer_set_callback(timer, 0);
}

// static __always_inline
// struct slotted_window *slotted_window_init_or_get(void *map, __u64 *key)
// {
// 	struct slotted_window *sw, init;
// 	int rc;
    
//     //cerco nella mappa per il batch, se esiste gia un elemento appartenente
//     //allo stesso flusso
//     //come key deve essere usato il flowid (?)
// 	sw = bpf_map_lookup_elem(map, key);
//     //se è stato trovao un elemento, ritorno il puntatore
// 	if (sw)
// 		return sw;

// 	memset(&init, 0, sizeof(init));

// 	/* note that updating an hashtable element is an atomic op */
// 	rc = bpf_map_update_elem(map, key, &init, BPF_NOEXIST);
// 	if (rc) {
// 		if (rc == -EEXIST)
// 			/* another cpu has just createed the entry, give up */
// 			goto lookup;

// 		return NULL;
// 	}

// lookup:
//     sw = bpf_map_lookup_elem(map, key);
//     if (!sw)
//         return NULL;

//     /* see https://reviews.llvm.org/D72184 */
//     if (__sync_lock_test_and_set(&sw->init, 1))
//         /* already initialized */
//         return sw;

//     /* only a single CPU can be here */

//     /* we want to initialize a timer only once.
//     * A timer needs to be defined inside a map element which is already
//     * stored in the map. For this reason, we cannot  use a
//     * publish/subscribe approach - e.g. create a map element, initialize
//     * the timer within it and finally update the map with that element.
//     * Publish allows cpus to see the whole map element fully initialized
//     * or not.
//     *
//     * Our approach in this case, is to allow *only* a  CPU to initialized
//     * the timer when a new map element is createde and pushed into the
//     * map. However, in the mean while the CPU is taking the element lock
//     * and initialize the timer, another CPU could reference to that
//     * element finding that timer is not still initialized. We admit this
//     * corner case as it could happen only the first time a new map element
//     * is created inside the map.
//     */

//     //inizializzo il timer
//     rc = swin_timer_init(map, &sw->timer);
//     if (rc)
//         return NULL;

//     return sw;
// }


// static __always_inline
// int update_window(struct slotted_window *sw, __u64 ts, bool start_timer, struct value_packet *packet, __u64 flow_id,)
// {
// 	const __u64 cur_tsw = ts / SWIN_SCALER; // normalizzo il timestamp
// 	__u64 tsw = READ_ONCE(sw->tsw); // leggo il timestamp della finestra
// 	__u64 *cnt = &sw->cnt; // puntatore al contatore della finestra
// 	struct event_t *event; // evento da inserire nel ring buffer    
// 	__u64 cnt_val; // valore del contatore
// 	// __u64 delta; 
// 	// __u64 avg;
// 	int rc;

// 	if (cur_tsw <= tsw)
//         /* the current window is still open */
// 		goto update;

// 	if (try_swin_lock(sw))
// 		/* busy, another cpu is currently closing the window */
// 		goto update;

// 	/* the current window must be closed */
// 	// delta = cur_tsw - tsw;
// 	// if (delta <= DECAY_TABLE_MAX) {
// 	// 	if (delta < 1)
// 	// 		/* impossibile, uhm? */
// 	// 		goto err;

// 	// 	cnt_val = READ_ONCE(*cnt);

// 	// 	avg = __LOG_SCALE_OUT((__LOG_SCALE_IN(cnt_val) *
// 	// 			      decay_table[(delta - 1)])) +
// 	// 		/* sw->avg is only read in this section */
// 	// 	      __LOG_SCALE_OUT(sw->avg * decay_table[delta]);
// 	// } else {
// 	// 	avg = 0;
// 	// }

// 	// WRITE_ONCE(sw->avg, avg);

//     //sono nel caso in cui la finestra è stata chiusa

// 	/* write the content on ring buffer */
// 	rc = prepare_ring_buffer_write(&events, &event);
//     int counter_to_write = READ_ONCE(*cnt);
// 	if (rc)
// 		goto update_win;

//     //inserisco l'evento nel ring buffer
// 	event->ts = tsw;
// 	event->flowid = packet->flow_id;
// 	event->counter = counter_to_write;

// 	bpf_ringbuf_submit(event, 0);

// update_win:
// 	/* time to create a new window */
// 	WRITE_ONCE(*cnt, 0);
// 	WRITE_ONCE(sw->tsw, cur_tsw);

// 	/* we cannot rely upon the __sync_lock_release() semantic, so we need
// 	 * to use a workaround, e.g.: manually set the sw->sync back to 0.
// 	 */
// 	swin_unlock(sw);

// 	if (!start_timer)
// 		goto update;

// 	/* start timer bound to this window */
// 	rc = update_window_start_timer(&sw->timer, SWIN_TIMER_TIMEOUT);
// 	if (rc)
// 		goto err;

// update:
// 	__sync_fetch_and_add(cnt, 1);
// 	return 0;

// err:
// 	return -EINVAL;
// }

static __always_inline
int update_window(struct value_packet *packet, __u64 ts, bool start_timer) {
    const __u64 cur_tsw = ts / SWIN_SCALER; // Normalizzo il timestamp
    __u64 tsw = READ_ONCE(packet->tsw); // Leggo il timestamp della finestra
    //__u64 *cnt = &packet->cnt; // Puntatore al contatore della finestra
    struct event_t *event; // Evento da inserire nel ring buffer    
    //__u64 cnt_val; // Valore del contatore
    __u32 *counter = &packet->counter; // Puntatore al contatore mio
    __u32 counter_val; // Valore del contatore mio

    // Acquisisci il lock
    //bpf_spin_lock(&packet->lock);

    //__u64 tsw = packet->tsw;
    //__u32 *counter = &packet->counter;

    if (cur_tsw <= tsw) {
        //bpf_spin_unlock(&packet->lock);
        /* La finestra corrente è ancora aperta */
        goto update;
    }
        

    // if (try_swin_lock(&packet->lock))
    //     /* Occupato, un altro CPU sta chiudendo la finestra */
    //     goto update;

    /* La finestra corrente deve essere chiusa */
    //cnt_val = READ_ONCE(*cnt);
    counter_val = READ_ONCE(*counter);

    /* Invia il contenuto nel ring buffer */
    int rc = prepare_ring_buffer_write(&events, &event);
    if (rc)
        goto update_win;

    event->ts = tsw;
    event->flowid = packet->flow_id;
    event->counter = counter_val;
    bpf_printk("Event: %llu %llu %u\n", event->ts, event->flowid, event->counter);

    bpf_ringbuf_submit(event, 0);

update_win:
    /* Creare una nuova finestra */
    //WRITE_ONCE(*cnt, 0);
    //WRITE_ONCE(*counter, 0);
    WRITE_ONCE(packet->tsw, cur_tsw); // Aggiorno il timestamp della finestra

    //swin_unlock(&packet->lock);

    if (!start_timer)
        goto update;

    /* Avvia il timer associato a questa finestra */
    rc = update_window_start_timer(&packet->timer, SWIN_TIMER_TIMEOUT);
    if (rc)
        return -EINVAL;

update:
    //__sync_fetch_and_add(cnt, 1);
    return 0;

err:
    return -EINVAL;
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
    
    update_window(packet, bpf_ktime_get_ns(), true);
    
    // struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    // if (!event) {
    //     return;
    // }

    // event->ts = bpf_ktime_get_ns();
    // event->flowid = packet->flow_id;
    // event->counter = packet->counter;
    // bpf_ringbuf_submit(event, 0);
}



/*------------------------------------------------*/ 

// #define CLASSIFY_PACKET_AND_UPDATE_MAP(map_name, new_info, flow_type, map_flow) do { \
//     struct value_packet *packet = NULL; \
//     packet = bpf_map_lookup_elem(&map_name, &new_info); \
//     if (!packet) { \
//         flow_id = build_flowid(flow_type, __sync_fetch_and_add(&counter, 1)); \
//         ret = bpf_map_update_elem(&map_flow, &flow_id, &new_info, BPF_ANY); \
//         if (ret == -1) { \
//             bpf_printk("Failed to insert new item in flow maps\n"); \
//             return TC_ACT_OK; \
//         } \
//         struct value_packet new_value = { \
//             .counter = 1, \
//             .bytes_counter = packet_length, \
//             .flow_id = flow_id \
//         }; \
//         ret = bpf_map_update_elem(&map_name, &new_info, &new_value, BPF_ANY); \
//         if (ret) { \
//             bpf_printk("Failed to insert new item in flow maps\n"); \
//             return TC_ACT_OK; \
//         } \
//         rc = swin_timer_init(&map_name, &packet->timer); \
//         if (rc) \
//             return TC_ACT_OK; \
//         struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0); \
//         if (!event) { \
//             return TC_ACT_OK; \
//         } \
//         /*event->ts = bpf_ktime_get_ns(); \
//         event->flowid = flow_id; \
//         event->counter = 1; \
//         bpf_ringbuf_submit(event, 0); \*/
//     } else { \
//         handle_packet_event(packet, flow_id, packet_length); \
//     } \
// } while (0)

#define CLASSIFY_PACKET_AND_UPDATE_MAP(map_name, new_info, flow_type, map_flow) do { \
    struct value_packet *packet = NULL; \
    packet = bpf_map_lookup_elem(&map_name, &new_info); \
    if (!packet) { \
        flow_id = build_flowid(flow_type, __sync_fetch_and_add(&counter, 1)); \
        struct value_packet new_value = { \
            .counter = 1, \
            .bytes_counter = packet_length, \
            .flow_id = flow_id, \
            .tsw = 0, \
        }; \
        /* inserimento della nuova istanza rappresentante il flusso */ \
        int ret = bpf_map_update_elem(&map_name, &new_info, &new_value, BPF_ANY); \
        if (ret) { \
            bpf_printk("Failed to insert new item in map_name\n"); \
            return TC_ACT_OK; \
        } \
        /* inserimento del nuovo flusso nella mappa dei flussi */ \
        ret = bpf_map_update_elem(&map_flow, &flow_id, &new_info, BPF_ANY); \
        if (ret) { \
            bpf_printk("Failed to insert new item in map_flow\n"); \
            return TC_ACT_OK; \
        } \
        /* Ricarica l'elemento aggiornato dalla mappa per ottenere l'indirizzo corretto del timer */ \
        packet = bpf_map_lookup_elem(&map_name, &new_info); \
        if (!packet) { \
            bpf_printk("Failed to lookup newly inserted item in map_name\n"); \
            return TC_ACT_OK; \
        } \
        /* Inizializzazione del timer */ \
        int rc = bpf_timer_init(&packet->timer, &map_name, CLOCK_BOOTTIME); \
        if (rc) { \
            bpf_printk("Failed to initialize timer\n"); \
            return TC_ACT_OK; \
        } \
    } else { \
        /* gestione del flusso già esistente. Aggiornamento dei contatori nella mappa e controllo finestra */ \
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

    
    //long ret;
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

     // Invio dei dati batch al ring buffer in base a una condizione (ad esempio, ogni 1000 pacchetti)
    // if (counter % 1000 == 0) {
    //     submit_batch_to_ringbuf();
    // }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
