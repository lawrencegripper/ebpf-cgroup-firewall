#!/bin/bash

set -eu

# Kill the ebpf-cgroup-firewall process if there are any running already
ps aux | grep './bin/ebpf-cgroup-firewall' | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill

source "$(dirname "$0")/helpers.sh"

# Why on host only?
# Docker in docker complicates attach tests
open_fold "Docker Attach block list: Curl google when blocked"
    attach_container_firewall_test "--block-list google.com" "curl $default_curl_args google.com"
    assert_exit_code 6
    assert_output_contains "Domain matched blocklist prefix: google.com"
close_fold

open_fold "Docker Attach block list: Curl google when blocked (Allow DNS)"
    attach_container_firewall_test "--allow-dns-request --block-list google.com" "curl $default_curl_args google.com"
    assert_exit_code 28
    assert_output_contains '"msg":"PACKET BLOCKED","because":"IPNotAllowed","blocked":true,"blockedAt":"packet"'
close_fold

open_fold "Docker Attach block list: Curl bing when google blocked"
    attach_container_firewall_test "--block-list google.com" "curl $default_curl_args bing.com"
    assert_exit_code 0
close_fold

open_fold "Docker Attach allow list: Curl google when only bing is allowed"
    attach_container_firewall_test "--allow-list bing.com" "curl $default_curl_args google.com"
    assert_exit_code 6
    assert_output_contains "Domain doesn't match any allowlist prefixes"
close_fold

open_fold "Docker Attach allow list: Curl bing when bing allowed"
    attach_container_firewall_test "--allow-list bing.com" "curl $default_curl_args bing.com"
    assert_exit_code 0
close_fold