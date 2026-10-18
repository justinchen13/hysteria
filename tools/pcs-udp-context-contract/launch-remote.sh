#!/usr/bin/env bash
# Prepared only. Dedicated public CI runner; never invoke on the proxy host.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]]
[[ "${GITHUB_REPOSITORY:-}" == justinchen13/hysteria ]]
[[ "${GITHUB_REF:-}" == refs/heads/pcs/udp-resolution-context ]]
[[ $# == 2 ]]
fixture_dir=$(cd -- "$(dirname -- "$0")" && pwd)
unit="pcs-hy-context-chain-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
# A system service need not inherit HOME/GOPATH from the runner. Give Go only
# this attempt's private disposable cache paths; do not change HOME.
umask 077
cache_root=$(mktemp -d /tmp/pcs-hy-context-cache.XXXXXXXX)
trap 'rm -rf -- "$cache_root"' EXIT
mkdir -p "$cache_root/gopath/pkg/mod" "$cache_root/build" "$cache_root/tmp"
printf 'remote_go_cache_root=%s; cache_scope=current_attempt_only\n' "$cache_root"
# The transient unit owns all descendants. Its hard timeout kills that unit's
# processes, never another job/container. No CPU-quota relaxation or retries.
sudo systemd-run --unit="$unit" --wait --collect --pipe \
  -p CPUQuota=100% -p MemoryMax=768M -p MemorySwapMax=0 \
  -p Delegate=yes \
  -p RuntimeMaxSec=780s -p TimeoutStopSec=5s -p KillMode=control-group \
  -p "WorkingDirectory=$fixture_dir" \
  /usr/bin/env "PATH=$PATH" "GITHUB_ACTIONS=true" \
  "GOPATH=$cache_root/gopath" "GOMODCACHE=$cache_root/gopath/pkg/mod" \
  "GOCACHE=$cache_root/build" "GOTMPDIR=$cache_root/tmp" "GOENV=off" \
  "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" "GITHUB_REF=$GITHUB_REF" \
  "GITHUB_SHA=${GITHUB_SHA:?}" "GITHUB_RUN_ID=$GITHUB_RUN_ID" \
  "GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT" \
  python3 "$fixture_dir/run.py" --repository-dir "$1" --output "$2"
python3 "$fixture_dir/adjudicate.py" "$2"
