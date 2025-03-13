#!/bin/bash

set -eu

# Source helper functions
source "$(dirname "$0")/helpers.sh"

cd /tmp
open_fold "Traefik Build Test"
    echo "Cloning traefik repository..." | $indent_once
    git clone https://github.com/traefik/traefik.git | $indent_twice

    cd traefik

    echo "Checking out v3.3..." | $indent_once
    git checkout v3.3 | $indent_twice

    echo "Running make..." | $indent_once
    make | $indent_twice

    echo "Running make lint..." | $indent_once
    make lint | $indent_twice

    echo "Running make test..." | $indent_once
    make test | $indent_twice
close_fold

open_fold "Ubuntu ISO Download Test"
    echo "Downloading Ubuntu ISO..." | $indent_once
    time curl -JLO https://releases.ubuntu.com/24.04.2/ubuntu-24.04.2-live-server-amd64.iso | $indent_twice
close_fold