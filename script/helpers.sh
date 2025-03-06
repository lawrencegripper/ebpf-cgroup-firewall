#!/bin/bash

set -eu

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
