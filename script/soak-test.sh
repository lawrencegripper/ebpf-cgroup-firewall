#!/bin/bash

set -eu

# Kill the ebpf-cgroup-firewall process if there are any running already
ps aux | grep './bin/ebpf-cgroup-firewall' | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill

log_file="/tmp/firewall.jsonl"
rm -rf $log_file
pid=""
source "$(dirname "$0")/helpers.sh"
trap "echo 'Script failed. Outputting logs:'; sleep 1; cat $log_file; kill $pid" ERR

end_time=$((SECONDS + 900)) # 15 minutes from now

run_test_command() {
    local cmd="$1"
    echo -e "\033[0;96m⬇️ Command:\033[0m" | $indent_once
    echo "$cmd" | $indent_twice
    set +e
    cmdOutput=$(eval "$cmd" 2>&1)
    exitCode=$?
    set -e
    # echo $cmdOutput
}

./bin/ebpf-cgroup-firewall attach \
    --log-file $log_file \
    --allow-list google.com,https://httpbin.org/anything/allowed \
    --allow-dns-request &
# Capture the PID of the background process
pid=$!

sleep 5

echo "Firewall pid: $pid"


while [ $SECONDS -lt $end_time ]; do
    open_fold "Curl (Allow): HTTPS requuest to google"
        run_test_command "curl $really_slow_curl_args https://google.com"
        assert_exit_code 0
    close_fold

    open_fold "Curl (Allow): HTTP requuest to google"
        run_test_command "curl $really_slow_curl_args http://google.com"
        assert_exit_code 0
    close_fold

    open_fold "Curl (Allow): Request nested endpoint"
        run_test_command "curl $really_slow_curl_args https://httpbin.org/anything/allowed/nested/path"
        assert_exit_code 0
    close_fold

    open_fold "Curl (Deny): HTTP request to denied endpoint"
        run_test_command "curl $really_slow_curl_args http://httpbin.org/anything/denied"
        assert_exit_code 22
    close_fold

    open_fold "Curl (Deny): HTTPS request to denied endpoint"
        run_test_command "curl $really_slow_curl_args https://httpbin.org/anything/also-denied"
        assert_exit_code 22
    close_fold

    open_fold "SSH (Allow): smtp.google.com:25 (SMTP)"
        run_test_command "nc -zv -w 1 smtp.google.com 25"
        assert_exit_code 0
    close_fold

    open_fold "SSH (Deny): Block SSH to sourceforge (SSH) as not allowed"
        run_test_command "nc -zv -w 1 test.git.sourceforge.net 22"
        assert_exit_code 1
    close_fold
done

echo "Script finished"