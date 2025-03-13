#!/bin/bash

set -eu

# Source helper functions
source "$(dirname "$0")/helpers.sh"

# Check if we should attach eBPF program
if [ "${ATTACH:-false}" = "true" ]; then
    echo "Attaching eBPF firewall..." | $indent_once
    ./bin/ebpf-cgroup-firewall attach --log-file /tmp/ebpf-cgroup-firewall.log &
fi

open_fold "Traefik Build Test"

    # Start timing the whole process
    start_time=$(date +%s)

    cd /tmp

    echo "Cloning traefik repository..." | $indent_once
    time git clone https://github.com/traefik/traefik.git | $indent_twice

    cd traefik

    echo "Checking out v3.3..." | $indent_once
    time git checkout v3.3 | $indent_twice

    echo "Running make..." | $indent_once
    time make | $indent_twice

    echo "Running make lint..." | $indent_once
    time make lint | $indent_twice

    echo "Running make test..." | $indent_once
    time make test | $indent_twice

    # Calculate and display the total execution time
    end_time=$(date +%s)
    total_time=$((end_time - start_time))
    echo "Total execution time for Traefik Build: $total_time seconds" | $indent_once

close_fold

open_fold "Ubuntu ISO Download Test"
    start_time=$(date +%s)
    echo "Downloading Ubuntu ISO..." | $indent_once
    time curl -JLO https://releases.ubuntu.com/24.04.2/ubuntu-24.04.2-live-server-amd64.iso | $indent_twice
    end_time=$(date +%s)
    total_time=$((end_time - start_time))
    echo "Total execution time for Ubuntu ISO Download: $total_time seconds" | $indent_once
close_fold