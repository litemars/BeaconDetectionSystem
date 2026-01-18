#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

#define TRACK_TCP 1
#define TRACK_UDP 1

struct connection_event {
    __u64 timestamp_ns;      /* Kernel timestamp in nanoseconds */
    __u32 src_ip;            /* Source IP address (network byte order) */
    __u32 dst_ip;            /* Destination IP address (network byte order) */
    __u16 src_port;          /* Source port (host byte order) */
    __u16 dst_port;          /* Destination port (host byte order) */
    __u32 packet_size;       /* Total packet size in bytes */
    __u8  protocol;          /* IP protocol (IPPROTO_TCP or IPPROTO_UDP) */
    __u8  tcp_flags;         /* TCP flags (0 for UDP) */
    __u8  direction;         /* 0 = ingress, 1 = egress */
    __u8  padding;           /* Alignment padding */
};

BPF_RINGBUF_OUTPUT(events, 1 << 16);  /* 64KB ring buffer per CPU */

BPF_HASH(recent_connections, __u64, __u64, 65536);

BPF_ARRAY(stats, __u64, 8);

#define STAT_PACKETS_TOTAL     0
#define STAT_PACKETS_IPV4      1
#define STAT_PACKETS_TCP       2
#define STAT_PACKETS_UDP       3
#define STAT_EVENTS_SUBMITTED  4
#define STAT_EVENTS_DROPPED    5
#define STAT_DEDUP_HITS        6
#define STAT_PARSE_ERRORS      7

/* Deduplication window in nanoseconds (100ms) */
#define DEDUP_WINDOW_NS 100000000ULL


static __always_inline void update_stat(__u32 index) {
    __u64 *counter = stats.lookup(&index);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline int is_duplicate(__u32 src_ip, __u32 dst_ip, 
                                         __u16 src_port, __u16 dst_port,
                                         __u64 now_ns) {
    /* Create connection key by XORing addresses and ports */
    __u64 conn_key = ((__u64)src_ip << 32) | dst_ip;
    conn_key ^= ((__u64)src_port << 16) | dst_port;
    
    __u64 *last_seen = recent_connections.lookup(&conn_key);
    if (last_seen) {
        if ((now_ns - *last_seen) < DEDUP_WINDOW_NS) {
            update_stat(STAT_DEDUP_HITS);
            return 1; 
        }
    }
    
    recent_connections.update(&conn_key, &now_ns);
    return 0;
}

static __always_inline int process_ipv4(void *data, void *data_end,
                                        struct ethhdr *eth, __u8 direction) {
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        update_stat(STAT_PARSE_ERRORS);
        return -1;
    }
    
    update_stat(STAT_PACKETS_IPV4);
    
    __u8 protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        return 0;
    }
    
    __u32 ip_hdr_len = ip->ihl << 2;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        update_stat(STAT_PARSE_ERRORS);
        return -1;
    }
    
    void *transport = (void *)ip + ip_hdr_len;
    
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 tcp_flags = 0;
    
    if (protocol == IPPROTO_TCP) {
        #if TRACK_TCP
        struct tcphdr *tcp = (struct tcphdr *)transport;
        if ((void *)(tcp + 1) > data_end) {
            update_stat(STAT_PARSE_ERRORS);
            return -1;
        }
        
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        
        /* Extract TCP flags */
        tcp_flags = 0;
        if (tcp->syn) tcp_flags |= 0x02;
        if (tcp->ack) tcp_flags |= 0x10;
        if (tcp->fin) tcp_flags |= 0x01;
        if (tcp->rst) tcp_flags |= 0x04;
        if (tcp->psh) tcp_flags |= 0x08;
        if (tcp->urg) tcp_flags |= 0x20;
        
        update_stat(STAT_PACKETS_TCP);
        #else
        return 0;
        #endif
    } else if (protocol == IPPROTO_UDP) {
        #if TRACK_UDP
        struct udphdr *udp = (struct udphdr *)transport;
        if ((void *)(udp + 1) > data_end) {
            update_stat(STAT_PARSE_ERRORS);
            return -1;
        }
        
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
        tcp_flags = 0;
        
        update_stat(STAT_PACKETS_UDP);
        #else
        return 0;
        #endif
    }
    
    //timestamp
    __u64 now_ns = bpf_ktime_get_ns();
    
    if (is_duplicate(ip->saddr, ip->daddr, src_port, dst_port, now_ns)) {
        return 0;
    }
    
    // Reserve space in ring buffer
    struct connection_event *event = events.ringbuf_reserve(sizeof(struct connection_event));
    if (!event) {
        update_stat(STAT_EVENTS_DROPPED);
        return -1;
    }
    
    // Populate event structure
    event->timestamp_ns = now_ns;
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->packet_size = bpf_ntohs(ip->tot_len);
    event->protocol = protocol;
    event->tcp_flags = tcp_flags;
    event->direction = direction;
    event->padding = 0;
    
    // Submit event to ring buffer 
    events.ringbuf_submit(event, 0);
    update_stat(STAT_EVENTS_SUBMITTED);
    
    return 0;
}

// XDP enry point for connection tracking
int xdp_connection_tracker(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    update_stat(STAT_PACKETS_TOTAL);
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // Egress direction = 0 for XDP
    process_ipv4(data, data_end, eth, 0);
    
    // Pass all packets to the network stack
    return XDP_PASS;
}

// Alternative TC ingress program for tracking inbound connections
int tc_ingress_tracker(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    update_stat(STAT_PACKETS_TOTAL);
    
    // Ethernet header bounds check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    // Ingress direction only
    process_ipv4(data, data_end, eth, 0);
    
    return TC_ACT_OK;
}


int tc_egress_tracker(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    update_stat(STAT_PACKETS_TOTAL);
    
    // Ethernet header bounds check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    // Egress direction only
    process_ipv4(data, data_end, eth, 1);
    
    return TC_ACT_OK;
}
