#!/usr/bin/env bash
# create-sandbox-net.sh — Create Docker network for sandbox isolation
set -euo pipefail

NET_NAME="${1:-sandbox-net}"

if docker network inspect "$NET_NAME" >/dev/null 2>&1; then
    echo "Network '$NET_NAME' already exists."
else
    docker network create \
        --driver bridge \
        --subnet=172.28.0.0/16 \
        --gateway=172.28.0.1 \
        --label "security-agent=sandbox" \
        "$NET_NAME"
    echo "Created network '$NET_NAME' (172.28.0.0/16)"
fi
