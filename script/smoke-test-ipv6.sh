#!/bin/bash

set -eu

# Kill the ebpf-cgroup-firewall process if there are any running already
ps aux | grep './bin/ebpf-cgroup-firewall' | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill

source "$(dirname "$0")/helpers.sh"

# Why on host only?
# Docker doesn't configure ipv6 by default, so we can't test it in the container
# Actions doesn't support ipv6 so can't run that test
open_fold "IPv6: Block IPv6 Traffic as not supported in the proxy currently (Allow DNS)"
    ipv6_address=$(dig hostname A ifconfig.co AAAA +short | tail -n 1)
    # Run it without blocking anything to ensure it's getting stopped before the ip rules are taken into account
    run_firewall_test "--debug --allow-dns-request" "nc -zv -w 1 $ipv6_address 80"
    assert_exit_code 1
    assert_output_contains "WARN PACKET BLOCKED because=IPv6AlwaysBlocked blocked=true blockedAt=packet"
close_fold