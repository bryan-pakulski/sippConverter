#!/bin/bash
if [[ ! -d "scenarios" ]]; then
    echo "generate scenarios first!"
    exit 1
fi

docker compose up