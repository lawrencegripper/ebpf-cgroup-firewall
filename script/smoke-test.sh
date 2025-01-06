#!/bin/bash

set -eu

assert_exit_code() {
    local expected=$1
    local actual=$exitCode
    if [ "$actual" -ne "$expected" ]; then
        echo -e "\033[0;31m❌ Expected exit code $expected but got $actual\033[0m"
        exit 1
    else
        echo -e "\033[0;32m✅ Exit Code $actual == $expected \033[0m" | pr -to5
    fi
}

assert_output_contains() {
    local expected="$1"
    if [[ "$cmdOutput" == *"$expected"* ]]; then
        echo -e "\033[0;32m✅ Output contains: $expected \033[0m" | pr -to5
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

    echo -e "\033[0;34m⬇️ Command:\033[0m"
    echo "run $args \"$cmd\"" | pr -to10

    set +e
    cmdOutput=$(./bin/ebpf-cgroup-firewall run $args "$cmd" 2>&1)
    exitCode=$?
    set -e

    echo -e "\033[0;34m⬇️ Command Output:\033[0m"
    echo "$cmdOutput" | pr -to10
}

attach_firewall_test() {
    local args="$1"
    local cmd="$2"

    echo -e "\033[0;34m⬇️ Command:\033[0m"
    echo "attach $args; then execute \"$cmd\" in current cgroup" | pr -to10

    log_file="/tmp/firewall-${RANDOM}.json"
    ./bin/ebpf-cgroup-firewall attach --log-file $log_file $args &
    pid=$!

    if ! ps -p $pid > /dev/null; then
        echo "Firewall process failed to start" >&2
        exit 1
    fi

    set +e
    $cmd
    exitCode=$?
    set -e

    kill $pid

    cmdOutput=$(cat "$log_file")

    echo -e "\033[0;34m⬇️ Command Output:\033[0m"
    echo "$cmdOutput" | pr -to10
}


# Expect call to google to be blocked

open_fold "BlockList: Block google"

    run_firewall_test "--block-list google.com" "curl -s --max-time 1 google.com"
    assert_exit_code 6
    # 2025/01/05 21:16:27 WARN DNS BLOCKED reason=FromDNSRequest explaination="Matched Domain Prefix: google.com" blocked=true blockedAt=dns domain=google.com. pid=258400 cmd="curl -s --max-time 1 google.com " firewallMethod=blocklist
    assert_output_contains "curl -s --max-time 1 google.com"
    assert_output_contains "DNS BLOCKED"
    assert_output_contains "Matched Domain Prefix: google.com"
    assert_output_contains "blockedAt=dns"
    
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
    assert_output_contains "curl -s --max-time 1 bing.com"
    assert_output_contains "DNS BLOCKED"
    assert_output_contains "Domain doesn't match any allowlist prefixes"
    assert_output_contains "blockedAt=dns"

close_fold

open_fold "AllowList: Block bing when only google allowed (allow dns resolution)"

    run_firewall_test "--allow-list google.com --allow-dns-request" "curl -s --max-time 1 bing.com"
    assert_exit_code 28
    assert_output_contains "blocked"

close_fold

open_fold "LogFile: Test --log-file option"

    rm -f /tmp/firewall_test.log # Clear log file if it exists

    log_file="/tmp/firewall_test.log"
    run_firewall_test "--block-list google.com --log-file $log_file" "curl -s --max-time 1 google.com"
    assert_exit_code 6

    echo -e "\033[0;34m⬇️ Log File Output:\033[0m"
    cat "$log_file" | pr -to10
    cmdOutput=$(cat "$log_file")
    assert_output_contains "Matched Domain Prefix: google.com"

close_fold

open_fold "Attach: Curl google when blocked"

    attach_firewall_test "--block-list google.com " "curl -s --max-time 1 google.com"
    assert_exit_code 6
    assert_output_contains "Matched Domain Prefix: google.com"

close_fold


open_fold "Attach: Curl google when bing blocked"

    attach_firewall_test "--block-list bing.com " "curl -s --max-time 1 google.com"
    assert_exit_code 0

close_fold
