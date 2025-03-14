#!/bin/bash

set -eu

# Kill the ebpf-cgroup-firewall process if there are any running already
ps aux | grep './bin/ebpf-cgroup-firewall' | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill

log_file="/tmp/firewall-${RANDOM}.json"
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
    --allow-list google.com,bing.com,https://bbc.co.uk/news/politics \
    --allow-dns-request &
# Capture the PID of the background process
pid=$!

sleep 5

echo "Firewall pid: $pid"


while [ $SECONDS -lt $end_time ]; do
    open_fold "Parallel Test (Allow): Multiple HTTPS requests to allowed endpoints"
        run_test_command "curl $really_slow_curl_args --parallel --parallel-immediate --parallel-max 10 https://google.com https://bing.com https://bbc.co.uk/news/politics"
        assert_exit_code 0
    close_fold

    open_fold "Parallel Test (Allow): Multiple HTTPS requests to denied endpoints"
        run_test_command "curl $slow_curl_args --parallel --parallel-immediate --parallel-max 10 https://bbc.co.uk/news https://bbc.co.uk/news/world https://bbc.co.uk/news/uk"
        assert_exit_code 22
    close_fold

    open_fold "Soak Test: Allow smtp.google.com:25 (SMTP)"
        run_test_command "nc -zv -w 1 smtp.google.com 25"
        assert_exit_code 0
    close_fold

    open_fold "Soak Test: Block SSH to sourceforge (SSH) as not allowed"
        run_test_command "nc -zv -w 1 test.git.sourceforge.net 22"
        assert_exit_code 1
    close_fold
done

echo "Script finished"