//go:build ignore

#include <stdbool.h>
#include <linux/bpf.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <string.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf.h"

#define __section(NAME)

// This event is sent via the ring buffer to userspace to log the actions of the
// firewall
struct event {
  __u32 pid;
  __u16 port;
  bool allowed;
  __u32 ip;
  __u32 originalIp;
  __u8 eventType;
  __u16 dnsTransactionId;
  bool pidResolved;
  bool hasBeenRedirected;
};
struct event *unused __attribute__((unused));

// These consts are used to identify what kind of evens
const __u16 DNS_PROXY_PACKET_BYPASS_TYPE = 1;
const __u16 DNS_REDIRECT_TYPE = 11;
const __u16 LOCALHOST_PACKET_BYPASS_TYPE = 12;
const __u16 HTTP_PROXY_PACKET_BYPASS_TYPE = 2;
const __u16 HTTP_REDIRECT_TYPE = 22;
const __u16 PROXY_PID_BYPASS_TYPE = 23;

// These are real consts to help with reability only

const __u32 ADDRESS_LOCALHOST_NETBYTEORDER = bpf_htonl(0x7f000001);
// Different firewall modes
const __u16 FIREWALL_MODE_LOG_ONLY = 0;
const __u16 FIREWALL_MODE_ALLOW_LIST = 1;
const __u16 FIREWALL_MODE_BLOCK_LIST = 2;
// Return codes for Egress program
const bool EGRESS_ALLOW_PACKET = 1;
const bool EGRESS_DENY_PACKET = 0;

// These consts are set by the userland program at runtime

// DNS Proxy Port - This is set by the go code when loading the eBPF so each
// cgroup has its own DNS proxy
volatile const __u32 const_dns_proxy_port;

// DNS Proxy PID - This is set by the go code when loading the eBPF so each
// cgroup has its own DNS proxy server.
volatile const __u32 const_proxy_pid;

// Ports where the userland transparent http proxy runs
volatile const __u32 const_http_proxy_port;
volatile const __u32 const_https_proxy_port;

// Firewall mode - This is set by the go code when loading the eBPF
// see FIREWALL_MODE_* consts for values
volatile const __u16 const_firewall_mode;

/*
This is the address where the DNS and HTTP proxy server is listening.
In the case of docker cgroup this might be 172.17.0.1 or in the normal
case of non-isolated network cgrou it'll be 127.0.0.1
*/
volatile const __u32 const_mitm_proxy_address = ADDRESS_LOCALHOST_NETBYTEORDER;

// ring buffer used to by userspace to subscribe to events
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Note:
// Two socket are relevant. SockClient and SockServer
// SockClient is the one created when calling the server
// SockServer is the one create on receiving server
// These two are mapped together based on us being both the client
// and the server. We can track src port on sockClient and
// match to sockServer via `sockops` ebpf progam
// We use src port to map from server back to client

// Map the original destination to socket cookie
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, __u64);
  __type(value, __be32);
  __uint(max_entries, 256 * 1024); // Roughly 256k entries. Using ~2MB of memory
} sock_client_to_original_ip SEC(".maps");

// Map the original destination port (before redirect) to client socket cookie
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, __u64);
  __type(value, __u16);
  __uint(max_entries, 256 * 1024); // Roughly 256k entries. Using ~2MB of memory
} sock_client_to_original_port SEC(".maps");

// Used by proxy on receiving request. Maps the src port to the client socket
// cookie
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, __u16);
  __type(value, __u64);
  __uint(max_entries, 256 * 1024); // Roughly 256k entries. Using ~2MB of memory
} src_port_to_sock_client SEC(".maps");

// Map for tracking socket cookie to pid mapping
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, __u32);
  __uint(max_entries, 10000);
} socket_pid_map SEC(".maps");

// Map for IPs only allowed for HTTP/HTTPS requests
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 256 * 1024); // Roughly 256k entries. Using ~2MB of memory
  // This is a guess at the number of unique IPs we might see while this eBPF is
  // loaded
  // TODO: Look at clearing out old ips from the list or handling it's size some
  // other way
} firewall_allowed_http_ips_map SEC(".maps");

// Map for IPs only allowed for any requests
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 256 * 1024); // Roughly 256k entries. Using ~2MB of memory
  // This is a guess at the number of unique IPs we might see while this eBPF is
  // loaded
  // TODO: Look at clearing out old ips from the list or handling it's size some
  // other way
} firewall_allowed_ips_map SEC(".maps");

// eBPF Programs

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) {
  __u64 socketCookie = bpf_get_socket_cookie(ctx);
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  bpf_map_update_elem(&socket_pid_map, &socketCookie, &pid, BPF_ANY);

  bool didRedirect = false;

  bool isFromProxyPid = (bpf_get_current_pid_tgid() >> 32) == const_proxy_pid;
  if (isFromProxyPid) {
    // Allow the ebpf-firewall process out with no redirects
    return 1;
  }

  // TODO: Store this in host byte order too
  __be32 original_ip = ctx->user_ip4;
  // Convert to host byte order from network byte order
  __u16 original_port = bpf_ntohs(ctx->user_port);

  // TODO: This shoul detect if the packet shape is HTTPish rather than relying
  // on ports
  bool isHttpOrHttpsPort =
      ctx->user_port == bpf_htons(80) || ctx->user_port == bpf_htons(443);
  if (isHttpOrHttpsPort) {
    didRedirect = true;

    /* This is the hexadecimal representation of 127.0.0.1 address */
    ctx->user_ip4 = const_mitm_proxy_address;

    // TODO: Determine if the connection is https and send by taking a look at
    // it rather than relying on ports
    if (ctx->user_port == bpf_htons(80)) {
      ctx->user_port = bpf_htons(const_http_proxy_port);
    }

    if (ctx->user_port == bpf_htons(443)) {
      ctx->user_port = bpf_htons(const_https_proxy_port);
    }

    struct event info = {
        .pid = pid,
        .pidResolved = true,
        .port = bpf_ntohs(ctx->user_port),
        .allowed = true,
        .ip = bpf_ntohl(ctx->user_ip4),
        .originalIp = original_ip,
        .eventType = HTTP_REDIRECT_TYPE,
        .hasBeenRedirected = true,
    };

    bpf_ringbuf_output(&events, &info, sizeof(info), 0);
  } else if (ctx->user_port == bpf_htons(53)) {
    /* For DNS Query (*:53) rewire service to backend
     * 127.0.0.1:const_dns_proxy_port */
    didRedirect = true;

    /* This is the hexadecimal representation of 127.0.0.1 address */
    ctx->user_ip4 = const_mitm_proxy_address;
    ctx->user_port = bpf_htons(const_dns_proxy_port);

    struct event info = {
        .pid = pid,
        .pidResolved = true,
        .port = bpf_ntohs(ctx->user_port),
        .allowed = true,
        .ip = bpf_ntohl(ctx->user_ip4),
        .originalIp = original_ip,
        .eventType = DNS_REDIRECT_TYPE,
        .hasBeenRedirected = true,
    };

    bpf_ringbuf_output(&events, &info, sizeof(info), 0);
  }

  if (didRedirect) {
    /* Store the original destination of the request */
    bpf_map_update_elem(&sock_client_to_original_ip, &socketCookie,
                        &original_ip, BPF_ANY);
    bpf_map_update_elem(&sock_client_to_original_port, &socketCookie,
                        &original_port, BPF_ANY);
  }

  return 1;
}

// Map the outgoing socket to the incoming socket seen in userland proxy
// via the src port and the socket cookie
SEC("sockops")
int cg_sock_ops(struct bpf_sock_ops *ctx) {
  if (ctx->family != AF_INET)
    return 0;

  // Outbound connection established (ie. Client calling out)
  // So a client program has done `curl example.com`
  if (ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    __u16 src_port = ctx->local_port;
    bpf_map_update_elem(&src_port_to_sock_client, &src_port, &cookie, 0);
  }

  // Allow things to continue, we only need this for correlation
  return 0;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
  struct iphdr iph;
  // Load packet header
  bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
  // Use the socket cookie to lookup the calling PID
  __u64 socketCookie = bpf_get_socket_cookie(skb);
  __u32 *pid = bpf_map_lookup_elem(&socket_pid_map, &socketCookie);

  bool isFromProxyPid = (pid ? *pid : -1) == const_proxy_pid;
  if (isFromProxyPid) {
    // Allow the ebpf-firewall process to have full outbound access
    struct event info = {
        .port = -1,
        .allowed = true,
        .ip = bpf_ntohl(iph.daddr),
        .pid = pid ? *pid : 0,
        .pidResolved = pid ? true : false,
        .eventType = PROXY_PID_BYPASS_TYPE,
    };

    bpf_ringbuf_output(&events, &info, sizeof(info), 0);
    return EGRESS_ALLOW_PACKET;
  }

  __u32 destination_ip = iph.daddr;
  __u32 *original_ip_ptr =
      bpf_map_lookup_elem(&sock_client_to_original_ip, &socketCookie);

  if (original_ip_ptr) {
    // We did a redirect, so for the purposes of the firewall check we'll
    // consider the original ip that was being targetted
    destination_ip = *original_ip_ptr;
  }

  // If the request was redirected consider the original ip as the destination
  // if it wasn't redirected then consider the destination ip as the destination
  __u32 original_ip = original_ip_ptr ? *original_ip_ptr : destination_ip;
  bool isRedirectedByToOurProxy = false;

  // Allow traffic if original address was to localhost
  if (original_ip == const_mitm_proxy_address) {
    struct event info = {
        .port = -1,
        .allowed = true,
        .ip = bpf_ntohl(iph.daddr),
        .originalIp = bpf_ntohl(original_ip),
        .pid = pid ? *pid : 0,
        .pidResolved = pid ? true : false,
        .hasBeenRedirected = isRedirectedByToOurProxy,
        .eventType = LOCALHOST_PACKET_BYPASS_TYPE,
    };

    bpf_ringbuf_output(&events, &info, sizeof(info), 0);

    return EGRESS_ALLOW_PACKET;
  }

  /*
   * Intercept UDP requests to the DNS Proxy to parse out the TransactionID
   * this allows us to correlate the DNS request to the PID that made it in the
   * userspace DNS server.
   */
  __u16 port = 0;

  if (iph.protocol == IPPROTO_UDP) {
    struct udphdr udp;
    if (bpf_skb_load_bytes(skb, sizeof(struct iphdr), &udp,
                           sizeof(struct udphdr)) < 0) {
      // TODO: Think this is an error condition, we should fail closed
      return EGRESS_DENY_PACKET;
    }

    port = udp.uh_dport;

    // return EGRESS_ALLOW_PACKET;

    bool isProxiedDnsRequest =
        udp.uh_dport == bpf_htons(const_dns_proxy_port) &&
        iph.daddr == const_mitm_proxy_address;
    if (isProxiedDnsRequest) {
      __u16 skbReadOffset = sizeof(struct iphdr) + sizeof(struct udphdr);
      __u16 dnsTransactionId =
          getTransactionIdFromDnsHeader(skb, skbReadOffset);

      struct event info = {
          .port = bpf_ntohs(udp.uh_dport),
          .allowed = true,
          .ip = bpf_ntohl(iph.daddr),
          .pid = pid ? *pid : 0,
          .pidResolved = pid ? true : false,
          .originalIp = bpf_ntohl(original_ip),
          .hasBeenRedirected = isRedirectedByToOurProxy,
          .eventType = DNS_PROXY_PACKET_BYPASS_TYPE,
          .dnsTransactionId = dnsTransactionId,
      };

      bpf_ringbuf_output(&events, &info, sizeof(info), 0);

      return EGRESS_ALLOW_PACKET;
    }
  } else if (iph.protocol == IPPROTO_TCP) {
    // Ignore the VSCode errors C doesn't understand eBPF quite right here, this
    // works
    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, sizeof(struct iphdr), &tcp,
                           sizeof(struct tcphdr)) < 0) {
      // TODO: Think this is an error condition, we should fail closed
      return EGRESS_DENY_PACKET;
    }
    port = tcp.dest;
  }

  // Check if the destination IPs are in "blocked" map
  bool mode_log_only = const_firewall_mode == FIREWALL_MODE_LOG_ONLY;

  // Setup default action based on firewall mode
  bool destination_allowed = false;
  
  // Is the ip allowed for any ports?
  bool ip_present_in_firewall_list =
      bpf_map_lookup_elem(&firewall_allowed_ips_map, &original_ip);

  // Is the ip allowed for http/https ports?
  bool ip_present_in_http_firewall_list =
      bpf_map_lookup_elem(&firewall_allowed_http_ips_map, &original_ip);

  // Only destinations added to the firewall are allowed (or we're in log only
  // mode)
  if (mode_log_only || ip_present_in_firewall_list) {
    destination_allowed = true;
  }

  bool is_http_proxy_port = (
    port == bpf_htons(const_http_proxy_port) ||
    port == bpf_htons(const_https_proxy_port)
  );

  bool is_redirected_to_http_proxy = (
    iph.daddr == const_mitm_proxy_address && is_http_proxy_port
  );

  if (is_redirected_to_http_proxy && ip_present_in_http_firewall_list) {
    destination_allowed = true;
  }

  // Only allow the http request through to the http proxy if the destination of
  // the packet is allowed. This gives us defense in depth. DNS must add allowed
  // IP, Packet validates it's allowed then it gets through to the http proxy
  // which can validate the url
  if (destination_allowed && is_redirected_to_http_proxy) {
    struct event info = {
        .port = bpf_ntohs(port),
        .allowed = true,
        .ip = bpf_ntohl(iph.daddr),
        .pid = pid ? *pid : 0,
        .pidResolved = pid ? true : false,
        .originalIp = bpf_ntohl(original_ip),
        .hasBeenRedirected = isRedirectedByToOurProxy,
        .eventType = HTTP_PROXY_PACKET_BYPASS_TYPE,
    };

    bpf_ringbuf_output(&events, &info, sizeof(info), 0);
    return EGRESS_ALLOW_PACKET;
  }

  struct event info = {
      .port = bpf_ntohs(port),
      .ip = bpf_ntohl(iph.daddr),
      .originalIp = bpf_ntohl(original_ip),
      .hasBeenRedirected = isRedirectedByToOurProxy,
      .allowed = destination_allowed,
      .eventType = 0,
  };

  info.pid = pid ? *pid : 0;
  info.pidResolved = pid ? true : false;
  bpf_ringbuf_output(&events, &info, sizeof(info), 0);
  return destination_allowed;
}

// Helper functions used in eBPF programs

__u16 getTransactionIdFromDnsHeader(struct __sk_buff *skb,
                                    __u16 skbReadOffset) {
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
   * The code loads first 12 bytes of DNS header after IP header and UDP header
   * (8 bytes).
   */
  __u16 transaction_id;
  if (bpf_skb_load_bytes(skb, skbReadOffset, &transaction_id,
                         sizeof(transaction_id)) < 0) {
    return 0;
  }
  return bpf_ntohs(transaction_id);
}
