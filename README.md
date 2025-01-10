# eBPF CGroup Outbound Firewall

Doesn't it suck that firewalls are IP based and you can't easily track which process made a request?

This projects aims fix that.

It gives a simple, easy, **outbound firewall accepting DNS names or IPs for block/allow lists**.

Most firewalls inspect trafic at the whole machine, making it feel like a needle in a haystack when looking for a single programs activity.

**This works on a process**, or group of process, **to give you control over what individual programs can reached out to** when you run.

It does this by using:

- eBPF to intercept [DNS requests](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/) and [allow/block packets](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SKB/)
- [socket cookies](https://docs.ebpf.io/linux/helper-function/bpf_get_socket_cookie/) and [DNS Transaction IDs](https://beta.computer-networking.info/syllabus/default/protocols/dns.html) to correlate which command made a request and tracks which IP's resolved from which domains
- [cGroups](https://man7.org/linux/man-pages/man7/cgroups.7.html) to target a single process or group of linux processes

For each dns request or packet this means it has:
- The command which initiated it and it's PID `ip=1.1.1.1 ipResolvedForDomains="No Domains"` vs `ip=142.250.187.206 ipResolvedForDomains=google.com`
- The IP requested and which DNS request resolved to it `pid=56253 cmd="curl --max-time 1 1.1.1.1 || curl google.com "`
- Why the decision was made ie. `explaination="Matched Domain Prefix: google.com" blocked=true blockedAt=dns domain=google.com`

## Example Usage

Try it out, here are some examples

### Block `google.com`

`./ebpf-cgroup-firewall run --block-list google.com "curl google.com"`

> WARN DNS BLOCKED reason=FromDNSRequest explaination="Matched Domain Prefix: google.com" blocked=true blockedAt=dns domain=google.com. pid=266767 cmd="curl google.com " firewallMethod=blocklist

### Allow mix of DNS and IP Addresses

`./ebpf-cgroup-firewall run --block-list 1.1.1.1,google.com "curl 1.1.1.1 || curl google.com"`

> WARN Packet BLOCKED blockedAt=packet blocked=true ip=1.1.1.1 ipResolvedForDomains="No Domains" pid=56253 cmd="curl --max-time 1 1.1.1.1 || curl google.com " reason=UserSpecified explaination="Blocked IP as on explicit block list" firewallMethod=blocklist
>
> curl: (28) Connection timed out after 1004 milliseconds
>
> WARN DNS BLOCKED reason=FromDNSRequest explaination="Matched Domain Prefix: google.com" blocked=true blockedAt=dns domain=google.com. pid=56253 cmd="curl --max-time 1 1.1.1.1 || curl google.com " firewallMethod=blocklist
>
> curl: (6) Could not resolve host: google.com

### Attach to the current CGroup only allowing `google.com` then `curl bing.com` in another terminal

`systemd` runs a cgroup per login session so attaching to that current group applies the firewall
to all processes that the user is running.

Here we see `ebpf-cgroup-firewall attach` in one terminal and the `curl` in another terminal/process being blocked.

![Image](https://github.com/user-attachments/assets/d6806f53-cafd-49de-8f65-8dfef898a49a)

## How does it work?

1. When a call UDP request is made on port 53 the eBPF program (`cgroup/connect4`) redirects it to the userspace DNS proxy.

   It captures the PID from the process that made the request and `Transaction ID` from the DNS request.

   The PID is tracked via a socket cookie so we can retrieve it in another eBPF program which is
   intercepting packets (`cgroup_skb/egress`).

2. The userspace DNS proxy resolves the domains IP via downstream DNS server and, if allowed by the 
   rules, adds the IP to the allowlist for `cgroup/connect4` which means outbound calls can be made to the IP.

   It uses the `transaction id` capture in eBPF to correlate the DNS request to the PID that submitted it.
    
   This means we have rich information about the originating program, such as the command run and why it triggered a block.

   > WARN DNS BLOCKED reason=FromDNSRequest explaination="Matched Domain Prefix: google.com" blocked=true blockedAt=dns domain=google.com. pid=52031 cmd="curl -s --max-time 1 google.com " firewallMethod=blocklist

3. `cgroup_skb/egress` ensures that, even a program can work around the DNS Proxy, the request would be blocked at the packet level as the IP would not be in the allowed allowlist.

    We can show this by running with `--allow-dns-request` which tells the DNS proxy to resolve the IP but not add it to the allowlist.

    > $> ebpf-cgroup-firewall run --block-list google.com --allow-dns-request "curl -s --max-time 1 google.com"

    > WARN Packet BLOCKED blockedAt=packet blocked=true ip=142.250.187.206 ipResolvedForDomains=google.com. pid=52061 cmd="curl -s --max-time 1 google.com " reason=FromDNSRequest explaination="Matched Domain Prefix: google.com" firewallMethod=blocklist
