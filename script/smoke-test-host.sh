#!/bin/bash

set -eu

# Kill the ebpf-cgroup-firewall process if there are any running already
ps aux | grep './bin/ebpf-cgroup-firewall' | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill

open_fold "Docker Attach: Curl google when blocked"
    attach_container_firewall_test "--debug --block-list google.com" "curl $default_curl_args google.com"
    assert_exit_code 6
    assert_output_contains "Matched Domain Prefix: google.com"
close_fold
