#!/bin/bash

set -eu

# Start timing the whole process
start_time=$(date +%s)

cd /tmp

echo "Cloning traefik repository..."
time git clone https://github.com/traefik/traefik.git

cd traefik

time git checkout v3.3

echo "Running make..."
time make

echo "Running make lint..."
time make lint

echo "Running make test..."
time make test

# Calculate and display the total execution time
end_time=$(date +%s)
total_time=$((end_time - start_time))
echo "Total execution time: $total_time seconds"