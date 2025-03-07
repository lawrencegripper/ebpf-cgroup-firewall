#!/bin/bash

set -eu

source "$(dirname "$0")/helpers.sh"

# Creating failing test for the overlap issue
open_fold "Packet vs Http Interop: allow only google, curl google then try telnet to yahoo smtp"
    attach_firewall_test "--debug --allow-dns-request --allow-list google.com" "sleep 1; curl $default_curl_args https://google.com; ssh -o ConnectTimeout=1 -T github.com"
    assert_exit_code 255
close_fold

# open_fold "Packet vs Http Interop: allow only google, curl google then try telnet to yahoo smtp"
#     # TODO: Validate that the gmail.com one completes successfully
#     attach_firewall_test "--allow-dns-request --allow-list ggmail.com" "sleep 1; nc -zv -w 1 smtp.gmail.com 25; nc -zv -w 1 github.com 22"
#     assert_exit_code 1
# close_fold

# open_fold "Parallel Test allow-list: Multiple HTTPS requests"
#     # Run parallel curl tests with allowlist
#     run_firewall_test "--debug --allow-list google.com,bing.com,example.com" "curl --parallel --parallel-immediate --parallel-max 10 https://google.com $default_curl_args https://bing.com $default_curl_args https://example.com $default_curl_args"
#     assert_exit_code 0
# close_fold

# open_fold "Parallel Test block-list: Multiple HTTPS requests"
#     # Run parallel curl tests with allowlist
#     run_firewall_test "--debug --block-list test.com" "curl --parallel --parallel-immediate --parallel-max 10 https://bing.com "
#     assert_exit_code 0
# close_fold

# open_fold "Parallel Test block-list: Mixed HTTP and HTTPS requests"
#     run_firewall_test "--block-list test.com,bbc.com" "curl --parallel --parallel-immediate --parallel-max 10 https://google.com $default_curl_args https://bing.com $default_curl_args http://example.com $default_curl_args"
#     assert_exit_code 0
# close_fold

open_fold "AllowList: Non-http calls to smtp.google.com:25 when google.com is allowed"
    run_firewall_test "--debug --allow-list google.com" "nc -zv -w 5 smtp.google.com 25"
    assert_exit_code 0
close_fold

open_fold "AllowList: Non-http calls to smtp.google.com:25 when only bing.com is allowed"
    run_firewall_test "--allow-list bing.com" "nc -zv -w 5 smtp.google.com 25"
    assert_exit_code 2
close_fold

open_fold "AllowList: Non-http calls to smtp.google.com:25 when only bing.com is allowed (Allow DNS)"
    run_firewall_test "--allow-list bing.com --allow-dns-request" "nc -zv -w 1 smtp.google.com 25"
    assert_exit_code 1
close_fold

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
    assert_output_contains "HTTP BLOCKED reason=NotInAllowList explaination=\"Url doesn't match any allowlist prefixes\" blocked=true"
close_fold

open_fold "Parallel Test (Allow): Multiple HTTPS requests with specific URLs"
    # Run parallel curl tests with allowlist for specific URLs
    run_firewall_test "--allow-list https://github.com/lawrencegripper,https://github.com/github" "curl --parallel --parallel-immediate --parallel-max 10 https://github.com/lawrencegripper $default_curl_args https://github.com/github $default_curl_args"
    assert_exit_code 0
close_fold

open_fold "Parallel Test (Block): Multiple HTTPS requests with specific URLs"
    run_firewall_test "--allow-dns-request --block-list https://github.com/lawrencegripper,https://github.com/github" "curl --parallel --parallel-immediate --parallel-max 10 https://github.com/lawrencegripper $default_curl_args https://github.com/github $default_curl_args"
    assert_exit_code 22
    assert_output_contains "blocked"
    assert_output_contains "HTTP BLOCKED reason=InBlockList"
close_fold

open_fold "BlockList: Block https google. (Allow DNS)"
    run_firewall_test "--block-list google.com --allow-dns-request" "curl -s --fail-with-body --max-time 1 https://google.com"
    assert_exit_code 22
    assert_output_contains "blocked"
    assert_output_contains 'HTTP BLOCKED reason=InBlockList explaination="Matched Domain Prefix: google.com'
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
    assert_output_contains 'HTTP BLOCKED reason=InBlockList explaination="Matched Domain Prefix: google.com"'
    # TODO: Currently when using the `run` the HTTP proxy is outside the cgroup so doesn't intercept DNS requests
    # or there is some other thing broken here 
    # assert_output_contains "Matched Domain Prefix: google.com"
close_fold

open_fold "AllowList: curl raw IP without dns request blocked"
    run_firewall_test "--debug --allow-list bing.com" "curl -s --fail-with-body --max-time 1 http://1.1.1.1"
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
    attach_firewall_test "--debug --block-list google.com" "curl $default_curl_args google.com"
    assert_exit_code 6
    assert_output_contains "Matched Domain Prefix: google.com"
close_fold

open_fold "Attach: Curl google when bing blocked"
    attach_firewall_test "--debug --block-list bing.com" "curl $slow_curl_args --max-time 5 google.com"
    assert_exit_code 0
close_fold

open_fold "Attach: Curl http://example.com when bing blocked"
    attach_firewall_test "--debug --block-list bing.com" "curl $slow_curl_args http://example.com/"
    assert_exit_code 0
close_fold

open_fold "Attach: Curl http://bing.com when bing blocked"
    attach_firewall_test "--debug --allow-dns-request --block-list bing.com" "curl $slow_curl_args http://bing.com/"
    assert_exit_code 22
close_fold

open_fold "Attach: curl raw IP without dns request blocked"
    attach_firewall_test "--debug --allow-list bing.com" "curl $slow_curl_args http://1.1.1.1"
    assert_exit_code 28
close_fold
