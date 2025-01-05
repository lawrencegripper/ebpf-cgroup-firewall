# eBPF CGroup Firewall

Doesn't it suck that firewalls are IP based and you can't easily track which process made a blocked request? They're also broad, looking at the whole machine, making it feel like a needle in a haystack.

This projects aims fix that.

It does this by using:

- eBPF to intercept and block DNS requests and/or network egress
- works at cGroup level allowing targetting a single process or group of processes
- socket cookies and DNS Transaction IDs requets are correlated to the PID and Command which made them

## Example Usage

## Run a curl command while blocking `*.google.com`

```bash
$> ebpf-cgroup-firewall run --block-list google.com "curl google.com"

2025/01/05 21:35:03 WARN DNS BLOCKED reason=FromDNSRequest explaination="Matched Domain Prefix: google.com" blocked=true blockedAt=dns domain=google.com. pid=266767 cmd="curl google.com " firewallMethod=blocklist
```

## Attach to the current CGroup with log only



```bash

```