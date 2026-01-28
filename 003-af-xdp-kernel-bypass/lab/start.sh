#!/usr/bin/env bash
 
SCRIPT_DIR="${SCRIPT_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )}"
cd "$SCRIPT_DIR"

docker compose --profile base build --no-cache

docker compose up -d #--remove-orphans
