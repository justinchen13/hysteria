#!/usr/bin/env bash
# Prepared only. Dedicated public CI runner; never invoke on the proxy host.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]]
[[ "${GITHUB_REPOSITORY:-}" == justinchen13/hysteria ]]
[[ "${GITHUB_REF:-}" == refs/heads/pcs/udp-resolution-context ]]
[[ $# == 2 ]]
fixture_dir=$(cd -- "$(dirname -- "$0")" && pwd)
unit="pcs-hy-context-chain-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
# The transient unit owns all descendants. Its hard timeout kills that unit's
# processes, never another job/container. No CPU-quota relaxation or retries.
sudo systemd-run --unit="$unit" --wait --collect --pipe \
  -p CPUQuota=100% -p MemoryMax=768M -p MemorySwapMax=0 \
  -p RuntimeMaxSec=780s -p TimeoutStopSec=5s -p KillMode=control-group \
  -p "WorkingDirectory=$fixture_dir" \
  /usr/bin/env "PATH=$PATH" "GITHUB_ACTIONS=true" \
  "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" "GITHUB_REF=$GITHUB_REF" \
  "GITHUB_SHA=${GITHUB_SHA:?}" "GITHUB_RUN_ID=$GITHUB_RUN_ID" \
  "GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT" \
  python3 "$fixture_dir/run.py" --repository-dir "$1" --output "$2"
python3 "$fixture_dir/adjudicate.py" "$2"
