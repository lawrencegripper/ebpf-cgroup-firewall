#!/bin/bash

set -eu

# Kill the ebpf-cgroup-firewall process if there are any running already
ps aux | grep './bin/ebpf-cgroup-firewall' | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill

source "$(dirname "$0")/helpers.sh"

open_fold "IPv6: Block IPv6 Traffic as not supported in the proxy currently"
    run_firewall_test "--debug --allow-list ifconfig.co" "curl -6 $default_curl_args https://ifconfig.co"
    assert_exit_code 7 # Validate that curl can't resolve a ipv6 address for the domain
close_fold

open_fold "Odd: allow github url expect port 22 to remain blocked"
    run_firewall_test "--debug --allow-dns-request --allow-list https://github.com" "nc -zv -w 1 github.com 22"
    assert_exit_code 1
close_fold

open_fold "Odd: block github url expect port 22 to be open"
    run_firewall_test "--debug --allow-dns-request --block-list https://github.com" "nc -zv -w 1 github.com 22"
    assert_exit_code 0
close_fold

open_fold "Odd: allow github domain as well as github url expect port 22 to remain blocked"
    run_firewall_test "--debug --allow-dns-request --allow-list github.com,https://github.com" "nc -zv -w 1 github.com 22"
    assert_exit_code 0
close_fold

open_fold "Odd: curl http then try blocked http"
    run_firewall_test "--debug --allow-dns-request --allow-list google.com" "curl $default_curl_args http://google.com; curl $default_curl_args http://bing.com"
    assert_exit_code 28
close_fold

# Creating failing test for the overlap issue
open_fold "Odd: allow only google, curl google then try telnet to github ssh"
    attach_firewall_test "--debug --allow-dns-request --allow-list google.com" "sleep 1; curl $default_curl_args https://google.com; nc -zv -w 1 github.com 22"
    assert_exit_code 1
close_fold

open_fold "Odd: allow only google, telnet google smtp then try telnet to github ssh"
    # TODO: Validate that the gmail.com one completes successfully
    attach_firewall_test "--allow-dns-request --allow-list ggmail.com" "sleep 1; curl $default_curl_args https://google.com; nc -zv -w 1 smtp.gmail.com 25; nc -zv -w 1 github.com 22"
    assert_exit_code 1
close_fold

open_fold "Parallel Test allow-list: Multiple HTTPS requests"
    # Run parallel curl tests with allowlist
    run_firewall_test "--debug --allow-list google.com,bing.com,example.com" "curl --parallel --parallel-immediate --parallel-max 10 https://google.com $default_curl_args https://bing.com $default_curl_args https://example.com $default_curl_args"
    assert_exit_code 0
close_fold

open_fold "Parallel Test block-list: Mixed HTTP and HTTPS requests"
    run_firewall_test "--block-list test.com,bbc.com" "curl --parallel --parallel-immediate --parallel-max 10 https://google.com $default_curl_args https://bing.com $default_curl_args http://example.com $default_curl_args"
    assert_exit_code 0
close_fold

open_fold "AllowList: Non-http calls to smtp.google.com:25 when google.com is allowed"
    run_firewall_test "--debug --allow-list google.com" "nc -zv -w 5 smtp.google.com 25"
    assert_exit_code 0
close_fold

open_fold "AllowList: Non-http calls to smtp.google.com:25 when only bing.com is allowed"
    run_firewall_test "--allow-list bing.com" "nc -zv -w 5 smtp.google.com 25"
    assert_exit_code 2
    assert_output_contains "WARN DNS BLOCKED because=NotInAllowList blocked=true blockedAt=dns domains=smtp.google.com. ruleSource=NotInAllowList"
close_fold

open_fold "AllowList: Non-http calls to smtp.google.com:25 when only bing.com is allowed (Allow DNS)"
    run_firewall_test "--allow-list bing.com --allow-dns-request" "nc -zv -w 1 smtp.google.com 25"
    assert_exit_code 1
close_fold

open_fold "AllowList: Allows https google"
    run_firewall_test "--allow-list google.com" "curl $default_curl_args https://google.com"
    assert_exit_code 0
close_fold

open_fold "AllowList: allow https://www.bbc.co.uk/news"
    run_firewall_test "--allow-list https://www.bbc.co.uk/news" "curl $default_curl_args https://www.bbc.co.uk/news"
    assert_exit_code 0
close_fold

open_fold "AllowList: allow https://www.bbc.co.uk/news but call https://www.bbc.co.uk/"
    run_firewall_test "--debug --allow-list https://www.bbc.co.uk/news" "curl $default_curl_args https://www.bbc.co.uk"
    assert_exit_code 22
    assert_output_contains "blocked"
    assert_output_contains "WARN HTTP BLOCKED because=NotInAllowList blocked=true blockedAt=http domains=www.bbc.co.uk ruleSource=NotInAllowList ruleSourceComment=\"URL doesn't match any allowlist prefixes\""
close_fold

open_fold "Parallel Test (Allow): Multiple HTTPS requests with specific URLs"
    # Run parallel curl tests with allowlist for specific URLs
    run_firewall_test "--allow-list https://www.bbc.co.uk/news/uk,https://www.bbc.co.uk/news/world" "curl --parallel --parallel-immediate --parallel-max 10 https://www.bbc.co.uk/news/uk $default_curl_args https://www.bbc.co.uk/news/world $default_curl_args"
    assert_exit_code 0
close_fold

open_fold "Parallel Test (Block): Multiple HTTPS requests with specific URLs"
    run_firewall_test "--debug --allow-dns-request --block-list https://github.com/lawrencegripper,https://github.com/github" "curl --parallel --parallel-immediate --parallel-max 10 https://github.com/lawrencegripper $default_curl_args https://github.com/github $default_curl_args"
    assert_exit_code 22
    assert_output_contains "blocked"
    assert_output_contains "HTTP BLOCKED because=MatchedBlockListDomain blocked=true blockedAt=http domains=github.com ruleSource=MatchedBlockListDomain"
close_fold

open_fold "BlockList: Block https google. (Allow DNS)"
    run_firewall_test "--block-list google.com --allow-dns-request" "curl -s --fail-with-body --max-time 1 https://google.com"
    assert_exit_code 28
    assert_output_contains "blocked"
    assert_output_contains 'PACKET BLOCKED because=IPNotAllowed blocked=true blockedAt=packet domains=None ruleSource=Unknown'
close_fold

open_fold "BlockList: block https://www.bbc.co.uk/news/world but hit https://www.bbc.co.uk/news/uk"
    run_firewall_test "--block-list https://www.bbc.co.uk/news/uk" "curl $default_curl_args https://www.bbc.co.uk/news/world"
    assert_exit_code 0
close_fold

open_fold "BlockList: Block google"
    run_firewall_test "--block-list google.com" "curl $default_curl_args google.com"
    assert_exit_code 6
    # 2025/01/05 21:16:27 WARN DNS BLOCKED reason=FromDNSRequest explaination="Matched Domain Prefix: google.com" blocked=true blockedAt=dns domain=google.com. pid=258400 cmd="curl -s --max-time 1 google.com " firewallMethod=blocklist
    assert_output_contains "curl $default_curl_args google.com"
    assert_output_contains "BLOCKED"
    assert_output_contains "ruleSource=MatchedBlockListDomain ruleSourceComment=\"Domain matched blocklist prefix: google.com\""
    assert_output_contains "blockedAt=dns"
close_fold

open_fold "BlockList: Block google. (Allow DNS)"
    run_firewall_test "--block-list google.com --allow-dns-request" "curl -s --fail-with-body --max-time 1 google.com"
    assert_exit_code 28
    assert_output_contains "blocked"
    assert_output_contains 'blockedAt=packet'
    # TODO: Currently when using the `run` the HTTP proxy is outside the cgroup so doesn't intercept DNS requests
    # or there is some other thing broken here 
    # assert_output_contains "Matched Domain Prefix: google.com"
close_fold

open_fold "AllowList: curl raw IP without dns request blocked"
    run_firewall_test "--debug --allow-list bing.com" "curl -s --fail-with-body --max-time 1 http://1.1.1.1"
    assert_exit_code 28
    assert_output_contains "blocked"
    assert_output_contains 'PACKET BLOCKED because=IPNotAllowed blocked=true blockedAt=packet domains=None'
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
    assert_output_contains "BLOCKED"
    assert_output_contains "Domain doesn't match any allowlist prefixes"
    assert_output_contains "blockedAt=dns"
close_fold

open_fold "AllowList: Block bing when only google allowed (allow dns resolution)"
    run_firewall_test "--allow-list google.com --allow-dns-request" "curl $default_curl_args bing.com"
    assert_exit_code 28
    assert_output_contains "blocked"
    assert_output_contains 'blockedAt=packet'
close_fold

open_fold "LogFile: Test --log-file option"
    rm -f /tmp/firewall_test.log # Clear log file if it exists

    log_file="/tmp/firewall_test.log"
    run_firewall_test "--block-list google.com --log-file $log_file" "curl $default_curl_args google.com"
    assert_exit_code 6

    echo -e "\033[0;34m⬇️ Log File Output:\033[0m" | $indent_once
    cat "$log_file" | $indent_twice
    cmdOutput=$(cat "$log_file")
    assert_output_contains "Domain matched blocklist prefix: google.com"
close_fold

open_fold "Attach: Curl google when blocked"
    attach_firewall_test "--debug --block-list google.com" "curl $default_curl_args google.com"
    assert_exit_code 6
    assert_output_contains "Domain matched blocklist prefix: google.com"
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
    assert_exit_code 28
    assert_output_contains 'BLOCKED'
    assert_output_contains '"msg":"PACKET BLOCKED","because":"IPNotAllowed","blocked":true,"blockedAt":"packet"'
close_fold

open_fold "Attach: curl raw IP without dns request blocked"
    attach_firewall_test "--debug --allow-list bing.com" "curl $slow_curl_args http://1.1.1.1"
    assert_exit_code 28
    assert_output_contains 'BLOCKED'
    assert_output_contains '"msg":"PACKET BLOCKED","because":"IPNotAllowed","blocked":true,"blockedAt":"packet"'
close_fold

echo "All tests passed 🥳"