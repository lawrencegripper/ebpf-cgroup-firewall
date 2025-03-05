#!/bin/bash

set -eu

# What are all these random `| $indent_twice`?
# They indend the command output to make it easily to distinguish each tests output
indent_once="pr -to5"
indent_twice="pr -to10"

default_curl_args="-s --fail-with-body --output /dev/null --max-time 1"
slow_curl_args="-s --fail-with-body --output /dev/null --max-time 5"

assert_exit_code() {
    local expected=$1
    local actual=$exitCode
    if [ "$actual" -ne "$expected" ]; then
        echo -e "\033[0;31m❌ Expected exit code $expected but got $actual\033[0m"
        exit 1
    else
        echo -e "\033[0;32m✅ Exit Code $actual == $expected \033[0m" | $indent_once
    fi
}

assert_output_contains() {
    local expected="$1"
    if [[ "$cmdOutput" == *"$expected"* ]]; then
        echo -e "\033[0;32m✅ Output contains: $expected \033[0m" | $indent_once
    else
        echo -e "\033[0;31m❌ Expected output to contain: $expected\033[0m"
        echo "Actual output was:"
        echo "$cmdOutput" | $indent_twice
        exit 1
    fi
}

open_fold() {
    echo ""
    local title="$1"
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "::group::$title"
    else
        echo -e "\033[0;34m▼ $title\033[0m"
    fi
}

close_fold() {
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "::endgroup::"
    else
        echo -e "\033[0;34m▲ End\033[0m"
    fi
}

run_firewall_test() {
    local args="$1"
    local cmd="$2"

    echo -e "\033[0;96m⬇️ Command:\033[0m" | $indent_once
    echo "run $args \"$cmd\"" | $indent_twice

    set +e
    cmdOutput=$(./bin/ebpf-cgroup-firewall run $args "$cmd" 2>&1)
    exitCode=$?
    set -e

    echo -e "\033[0;96m⬇️ Command Output:\033[0m" | $indent_once
    echo "$cmdOutput" | $indent_twice
}

attach_firewall_test() {
    local args="$1"
    local cmd="$2"

    echo -e "\033[0;96m⬇️ Command:\033[0m" | $indent_once
    echo "attach $args; then execute \"$cmd\" in current cgroup" | $indent_twice

    log_file="/tmp/firewall-${RANDOM}.json"
    ./bin/ebpf-cgroup-firewall attach --log-file $log_file $args &
    pid=$!

    if ! ps -p $pid > /dev/null; then
        echo "Firewall process failed to start" >&2
        cat $log_file
        exit 1
    fi

    # give the proxy some time to start 
    sleep 1

    set +e
    $cmd
    exitCode=$?
    set -e

    kill $pid || echo "Process failed"

    cmdOutput=$(cat "$log_file")
    rm $log_file # tidy up

    echo -e "\033[0;96m⬇️ Command Output:\033[0m" | $indent_once
    echo "$cmdOutput" | $indent_twice
}

open_fold "AllowList: Allows https google"

    run_firewall_test "--allow-list google.com" "curl $default_curl_args https://google.com"
    assert_exit_code 0
    
close_fold

open_fold "AllowList: allow github.com/lawrencegripper"

    run_firewall_test "--allow-list https://github.com/lawrencegripper" "curl $default_curl_args https://github.com/lawrencegripper"
    assert_exit_code 0
    
close_fold

open_fold "AllowList: allow github.com/lawrencegripper but call github.com/github"

    run_firewall_test "--allow-list https://github.com/lawrencegripper" "curl $default_curl_args https://github.com/github"
    assert_exit_code 22
    assert_output_contains "blocked"
    assert_output_contains "http proxy blocked url not on allow list: https://github.com/lawrencegripper"
    
close_fold

open_fold "BlockList: Block https google. (Allow DNS)"

    run_firewall_test "--block-list google.com --allow-dns-request" "curl -s --fail-with-body --max-time 1 https://google.com"
    assert_exit_code 22
    assert_output_contains "blocked"
    assert_output_contains "http proxy blocked domain: google.com"
    
close_fold


open_fold "BlockList: Block google"

    run_firewall_test "--block-list google.com" "curl $default_curl_args google.com"
    assert_exit_code 6
    # 2025/01/05 21:16:27 WARN DNS BLOCKED reason=FromDNSRequest explaination="Matched Domain Prefix: google.com" blocked=true blockedAt=dns domain=google.com. pid=258400 cmd="curl -s --max-time 1 google.com " firewallMethod=blocklist
    assert_output_contains "curl $default_curl_args google.com"
    assert_output_contains "DNS BLOCKED"
    assert_output_contains "Matched Domain Prefix: google.com"
    assert_output_contains "blockedAt=dns"
    
close_fold

open_fold "BlockList: Block google. (Allow DNS)"

    run_firewall_test "--block-list google.com --allow-dns-request" "curl -s --fail-with-body --max-time 1 google.com"
    assert_exit_code 22
    assert_output_contains "blocked"
    assert_output_contains "http proxy blocked domain: google.com"
    # TODO: Currently when using the `run` the http proxy is outside the cgroup so doesn't intercept DNS requests
    # or there is some other thing broken here 
    # assert_output_contains "Matched Domain Prefix: google.com"
    
close_fold

open_fold "AllowList: curl raw IP without dns request blocked"

    run_firewall_test "--debug --allow-list bing.com " "curl -s --fail-with-body --max-time 1 http://1.1.1.1"
    assert_exit_code 22

close_fold

open_fold "BlockList: Block google. Bing succeeds"

    run_firewall_test "--block-list google.com" "curl $default_curl_args bing.com"
    assert_exit_code 0

close_fold

open_fold "AllowList: Allow google. Block everything else"

    run_firewall_test "--allow-list google.com" "curl $default_curl_args google.com"
    assert_exit_code 0

close_fold

open_fold "AllowList: Block bing when only google allowed"

    run_firewall_test "--allow-list google.com" "curl $default_curl_args bing.com"
    assert_exit_code 6
    assert_output_contains "curl $default_curl_args bing.com"
    assert_output_contains "DNS BLOCKED"
    assert_output_contains "Domain doesn't match any allowlist prefixes"
    assert_output_contains "blockedAt=dns"

close_fold

open_fold "AllowList: Block bing when only google allowed (allow dns resolution)"

    run_firewall_test "--allow-list google.com --allow-dns-request" "curl $default_curl_args bing.com"
    assert_exit_code 22
    assert_output_contains "blocked"

close_fold

open_fold "LogFile: Test --log-file option"

    rm -f /tmp/firewall_test.log # Clear log file if it exists

    log_file="/tmp/firewall_test.log"
    run_firewall_test "--block-list google.com --log-file $log_file" "curl $default_curl_args google.com"
    assert_exit_code 6

    echo -e "\033[0;34m⬇️ Log File Output:\033[0m" | $indent_once
    cat "$log_file" | $indent_twice
    cmdOutput=$(cat "$log_file")
    assert_output_contains "Matched Domain Prefix: google.com"

close_fold

open_fold "Attach: Curl google when blocked"

    attach_firewall_test "--debug --block-list google.com " "curl $default_curl_args google.com"
    assert_exit_code 6
    assert_output_contains "Matched Domain Prefix: google.com"

close_fold


open_fold "Attach: Curl google when bing blocked"

    attach_firewall_test "--debug --block-list bing.com " "curl $slow_curl_args --max-time 5 google.com"
    assert_exit_code 0

close_fold

open_fold "Attach: Curl http://example.com when bing blocked"

    attach_firewall_test "--debug --block-list bing.com " "curl $slow_curl_args http://example.com/"
    assert_exit_code 0

close_fold

open_fold "Attach: Curl http://bing.com when bing blocked"

    attach_firewall_test "--debug --allow-dns-request --block-list bing.com " "curl $slow_curl_args http://bing.com/"
    assert_exit_code 22

close_fold

open_fold "Attach: curl raw IP without dns request blocked"

    attach_firewall_test "--debug --allow-list bing.com " "curl $slow_curl_args http://1.1.1.1"
    assert_exit_code 22

close_fold
