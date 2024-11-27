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

struct svc_addr {
    __be32 addr;
    __be16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct svc_addr);
} service_mapping SEC(".maps");

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