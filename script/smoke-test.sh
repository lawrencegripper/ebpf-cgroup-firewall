#!/bin/bash

set -eu

assert_exit_code() {
    local expected=$1
    local actual=$exitCode
    if [ "$actual" -ne "$expected" ]; then
        echo -e "\033[0;31m❌ Expected exit code $expected but got $actual\033[0m"
        exit 1
    else
        echo -e "\033[0;32m✅ Exit Code $actual == $expected \033[0m"
    fi
}

assert_output_contains() {
    local expected="$1"
    if [[ "$cmdOutput" == *"$expected"* ]]; then
        echo -e "\033[0;32m✅ Output contains: $expected \033[0m"
    else
        echo -e "\033[0;31m❌ Expected output to contain: $expected\033[0m"
        echo "Actual output was:"
        echo "$cmdOutput" | pr -to10
        exit 1
    fi
}

open_fold() {
    local title="$1"
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "::group::$title"
    else
        echo -e "\033[0;33m▼ $title\033[0m"
    fi
}

close_fold() {
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "::endgroup::"
    else
        echo -e "\033[0;33m▲ End\033[0m"
    fi
}

run_firewall_test() {
    local args="$1"
    local cmd="$2"

    set +e
    cmdOutput=$(./bin/ebpf-cgroup-firewall run $args "$cmd" 2>&1)
    exitCode=$?
    set -e

    echo -e "\033[0;34m⬇️ Command Output:\033[0m"
    echo "$cmdOutput" | pr -to10
}


# Expect call to google to be blocked

open_fold "BlockList: Block google"

    run_firewall_test "--block-list google.com" "curl -s --max-time 1 google.com"
    assert_exit_code 6
    
close_fold

open_fold "BlockList: Block google. (Allow DNS)"

    run_firewall_test "--block-list google.com --allow-dns-request" "curl -s --max-time 1 google.com"
    assert_exit_code 28
    assert_output_contains "blocked"
    assert_output_contains "Matched Domain Prefix: google.com"
    
close_fold

open_fold "BlockList: Block google. Bing succeeds"

    run_firewall_test "--block-list google.com" "curl -s --max-time 1 bing.com"
    assert_exit_code 0

close_fold

open_fold "AllowList: Allow google. Block everything else"

    run_firewall_test "--allow-list google.com" "curl -s --max-time 1 google.com"
    assert_exit_code 0

close_fold

open_fold "AllowList: Block bing when only google allowed"

    run_firewall_test "--allow-list google.com" "curl -s --max-time 1 bing.com"
    assert_exit_code 6

close_fold

open_fold "AllowList: Block bing when only google allowed (allow dns resolution)"

    run_firewall_test "--allow-list google.com --allow-dns-request" "curl -s --max-time 1 bing.com"
    assert_exit_code 28
    assert_output_contains "blocked"

close_fold