//go:build ignore

#include <stdbool.h>
#include <linux/bpf.h>
#include <netinet/ip.h>
#include <string.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define __section(NAME)

char _license[12] SEC("license") = "Dual MIT/GPL";

struct svc_addr {
    __be32 addr;
    __be16 port;
};

/* Map the original destination for dns requests to map back on response */
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct svc_addr);
} service_mapping SEC(".maps");

/* Map for allowed IP addresses from userspace. This is populated with the responses to dns queries */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 256*1024); // Roughly 256k entries. Using ~2MB of memory
    // This is a guess at the number of unique IPs we might see while this eBPF is loaded
    // TODO: Look at clearing out old ips from the list or handling it's size some other way
} allowed_ips_map SEC(".maps");


/* DNS Proxy Port - This is set by the go code when loading the eBPF so each cgroup has its own DNS proxy */
volatile const __u32 const_dns_proxy_port;
/* DNS Proxy PID - This is set by the go code when loading the eBPF so each cgroup has its own DNS proxy 
    It prevents a circular dependency where the DNS proxy is trying to resolve the DNS query with the upstream 
    server.
*/
volatile const __u32 const_dns_proxy_pid;

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    struct sockaddr_in sa = {};
    struct svc_addr *orig;

    /* For DNS Query (*:53) rewire service to backend 127.0.0.1:8853. */
    if (ctx->user_port == bpf_htons(53) && (bpf_get_current_pid_tgid() >> 32) != const_dns_proxy_pid) {
        /* Store the original destination so we can map it back when a response is received */
        orig = bpf_sk_storage_get(&service_mapping, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
        if (!orig)
            return 0;

        orig->addr = ctx->user_ip4;
        orig->port = ctx->user_port;

        /* This is the hexadecimal representation of 127.0.0.1 address */
        ctx->user_ip4 = bpf_htonl(0x7f000001);
        ctx->user_port = bpf_htons(const_dns_proxy_port);
    }
    return 1;
}

SEC("cgroup/getpeername4")
int getpeername4(struct bpf_sock_addr *ctx)
{   
    struct svc_addr *orig;

    /* Expose service *:53 as peer instead of backend. */
    /* Use the mapping data captured in the connect4 function to map the response back to the original destination */
    if (ctx->user_port == bpf_htons(const_dns_proxy_port)) {
        orig = bpf_sk_storage_get(&service_mapping, ctx->sk, 0, 0);
        if (orig) {
            ctx->user_ip4 = orig->addr;
            ctx->user_port = orig->port;
        }
    }
    return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb)
{
    struct iphdr iph;
    /* Load packet header */
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
    /* Allow requests on 53 as we'll capture these and forward to our DNS server*/
    // if (skb->remote_port == bpf_htons(53)) {
    //     return 1;
    // }
    /* Check if the destination IPs are in "blocked" map */
    bool destination_allowed = bpf_map_lookup_elem(&allowed_ips_map, &iph.daddr);

    if (destination_allowed) {
        bpf_trace_printk("IP %x is allowed\n", sizeof("IP %x is allowed\n"), iph.daddr);
        return 1;
    } else {
        bpf_trace_printk("IP %x is not allowed\n", sizeof("IP %x is not allowed\n"), iph.daddr);
        return 0;
    }

    /* Return whether it should be allowed or dropped */
    return destination_allowed;
}