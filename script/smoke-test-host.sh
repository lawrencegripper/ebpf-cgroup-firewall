#!/bin/bash

set -eu

# Kill the ebpf-cgroup-firewall process if there are any running already
ps aux | grep './bin/ebpf-cgroup-firewall' | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill

source "$(dirname "$0")/helpers.sh"

open_fold "Docker Attach: Curl google when blocked"
    attach_container_firewall_test "--block-list google.com" "curl $default_curl_args google.com"
    assert_exit_code 6
    assert_output_contains "Matched Domain Prefix: google.com"
close_fold

open_fold "Docker Attach: Curl bing when google blocked"
    attach_container_firewall_test "--block-list google.com" "curl $default_curl_args bing.com"
    assert_exit_code 0
close_fold
