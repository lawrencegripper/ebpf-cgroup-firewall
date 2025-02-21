//go:build ignore

#include <stdbool.h>
#include <linux/bpf.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf.h"

#define __section(NAME)

struct svc_addr
{
    __be32 addr;
    __be16 port;
};

struct event
{
    __u32 pid;
    __u16 port;
    bool allowed;
    __be32 ip;
    __be32 originalIp;
    bool isDns;
    __u16 dnsTransactionId;
    bool pidResolved;
};
struct event *unused __attribute__((unused));

// Force emitting struct event into the ELF.
// struct event *unused __attribute__((unused));
// Force emitting struct event into the ELF.
// const struct event *unused __attribute__((unused));

// ring buffer used to by userspace to subscribe to events
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Map the original destination to socket cookie */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u64);
    __type(value, struct svc_addr);
    __uint(max_entries, 256 * 1024); // Roughly 256k entries. Using ~2MB of memory
} service_mapping SEC(".maps");

/* Map for allowed IP addresses from userspace. This is populated with the responses to dns queries */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256 * 1024); // Roughly 256k entries. Using ~2MB of memory
    // This is a guess at the number of unique IPs we might see while this eBPF is loaded
    // TODO: Look at clearing out old ips from the list or handling it's size some other way
} firewall_ip_map SEC(".maps");

/* Map for tracking socket cookie to pid mapping */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 10000);
} socket_pid_map SEC(".maps");

/* DNS Proxy Port - This is set by the go code when loading the eBPF so each cgroup has its own DNS proxy */
volatile const __u32 const_dns_proxy_port;
/* DNS Proxy PID - This is set by the go code when loading the eBPF so each cgroup has its own DNS proxy
    It prevents a circular dependency where the DNS proxy is trying to resolve the DNS query with the upstream
    server.
*/
volatile const __u32 const_dns_proxy_pid;

/* Firewall mode - This is set by the go code when loading the eBPF so we can run in firewall mode
 0 = allow all outbound - logOnly mode
 1 = block all outbound other than items on allow list
 2 = block outbound to items on the block list
*/
volatile const __u16 const_firewall_mode;

const __u16 FIREWALL_MODE_LOG_ONLY = 0;
const __u16 FIREWALL_MODE_ALLOW_LIST = 1;
const __u16 FIREWALL_MODE_BLOCK_LIST = 2;

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    struct sockaddr_in sa = {};
    struct svc_addr *orig;

    __u64 socketCookie = bpf_get_socket_cookie(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&socket_pid_map, &socketCookie, &pid, BPF_ANY);

    if (ctx->user_port == bpf_htons(80) && (bpf_get_current_pid_tgid() >> 32) != const_dns_proxy_pid)
    {
        // /* Store the original destination so we can map it back when a response is received */
        // orig = bpf_sk_storage_get(&service_mapping, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
        // if (!orig)
        //     return 0;

        // orig->addr = ctx->user_ip4;
        // orig->port = ctx->user_port;

        /* This is the hexadecimal representation of 127.0.0.1 address */
        ctx->user_ip4 = bpf_htonl(0x7f000001);
        ctx->user_port = bpf_htons(6775);
    }

    bool didRedirect = false;

    /* For DNS Query (*:53) rewire service to backend 127.0.0.1:8853. */
    if (ctx->user_port == bpf_htons(53) && (bpf_get_current_pid_tgid() >> 32) != const_dns_proxy_pid)
    {
        didRedirect = true;

        /* This is the hexadecimal representation of 127.0.0.1 address */
        ctx->user_ip4 = bpf_htonl(0x7f000001);
        ctx->user_port = bpf_htons(const_dns_proxy_port);

        struct event info = {
            .pid = pid,
            .pidResolved = true,
            .port = ctx->user_port,
            .allowed = true,
            .ip = ctx->user_ip4,
            .originalIp = orig->addr,
            .isDns = true,
        };

        bpf_ringbuf_output(&events, &info, sizeof(info), 0);
    }

    if (didRedirect)
    {
        /* Create storage for the original destination */
        struct svc_addr orig_addr = {0};
        orig = &orig_addr;

        orig->addr = ctx->user_ip4;
        orig->port = ctx->user_port;

        /* Store the original destination of the request */
        bpf_map_update_elem(&service_mapping, &socketCookie, orig, BPF_ANY);
    }

    return 1;
}

SEC("cgroup/getpeername4")
int getpeername4(struct bpf_sock_addr *ctx)
{
    struct svc_addr *orig;
    return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb)
{
    struct iphdr iph;
    /* Load packet header */
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
    /* Use the socket cookie to lookup the calling PID */
    __u64 socketCookie = bpf_get_socket_cookie(skb);
    __u32 *pid = bpf_map_lookup_elem(&socket_pid_map, &socketCookie);


    /* 
    * Intercept UDP requests to the DNS Proxy to parse out the TransactionID
    * this allows us to correlate the DNS request to the PID that made it in the userspace DNS server.
    */
    if (iph.protocol == IPPROTO_UDP)
    {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, sizeof(struct iphdr), &udp, sizeof(struct udphdr)) < 0) {
            return 1;
        }

        bool isProxiedDnsRequest = udp.uh_dport == bpf_htons(const_dns_proxy_port);
        if (isProxiedDnsRequest)
        {
            __u16 skbReadOffset = sizeof(struct iphdr) + sizeof(struct udphdr);
            __u16 dnsTransactionId = getTransactionIdFromDnsHeader(skb, skbReadOffset);

            struct event info = {
                .port = bpf_ntohs(udp.uh_dport),
                .allowed = true,
                .ip = iph.daddr,
                .pid = pid ? *pid : 0,
                .pidResolved = pid ? true : false,
                .originalIp = iph.daddr,
                .isDns = true,
                .dnsTransactionId = dnsTransactionId,
            };

            bpf_ringbuf_output(&events, &info, sizeof(info), 0);
            
            return 1;
        }
    }
    /* Check if the destination IPs are in "blocked" map */
    bool mode_block_list = const_firewall_mode == FIREWALL_MODE_BLOCK_LIST;
    bool mode_allow_list = const_firewall_mode == FIREWALL_MODE_ALLOW_LIST;
    bool mode_log_only = const_firewall_mode == FIREWALL_MODE_LOG_ONLY;

    // Setup default action based on firewall mode
    bool destination_allowed;
    if (mode_log_only)
    {
        // Logonly: Allow all
        destination_allowed = true;
    }
    else if (mode_block_list)
    {
        // Blocklist: Allow by default unless on the block list
        destination_allowed = true;
    }
    else if (mode_allow_list)
    {
        // AllowList: Block by default unless on the allow list
        destination_allowed = false;
    }

    bool ip_present_in_firewall_list = bpf_map_lookup_elem(&firewall_ip_map, &iph.daddr);

    // Override destination_allowed based on firewall mode
    // and whether or not the IP is in the firewall list
    if (mode_block_list && ip_present_in_firewall_list)
    {
        // Block list and IP is present - block
        destination_allowed = false;
    }
    else if (mode_allow_list && ip_present_in_firewall_list)
    {
        // Allow list and IP is present - allow
        destination_allowed = true;
    }

    struct event info = {
            .port = skb->remote_port,
            .ip = iph.daddr,
            .originalIp = iph.daddr,
            .allowed = destination_allowed,
            .isDns = false,
        };

    info.pid = pid ? *pid : 0;
    info.pidResolved = pid ? true : false;
    bpf_ringbuf_output(&events, &info, sizeof(info), 0);
    return destination_allowed;
}

__u16 getTransactionIdFromDnsHeader(struct __sk_buff *skb, __u16 skbReadOffset)
{
    /* We want to correlate the DNS request to the PID that made it.
     * To do this we extract the transaction ID from the DNS header
     * then match it in the userspace DNS server.
     *
     * DNS header information from the network packet.
     * DNS Header structure:
     *                                 1  1  1  1  1  1
     * 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                      ID                       |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                    QDCOUNT                    |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                    ANCOUNT                    |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                    NSCOUNT                    |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                    ARCOUNT                    |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * The code loads first 12 bytes of DNS header after IP header and UDP header (8 bytes).
     */
    __u16 transaction_id;
    if (bpf_skb_load_bytes(skb, skbReadOffset, &transaction_id, sizeof(transaction_id)) < 0) {
        return 0;
    }
    return bpf_ntohs(transaction_id);
}