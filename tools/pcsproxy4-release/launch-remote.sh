#!/usr/bin/env bash
# Dedicated remote build-only runner; no tests, application execution or deployment.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]]
[[ "${GITHUB_REPOSITORY:-}" == justinchen13/hysteria ]]
[[ "${GITHUB_REF:-}" == refs/heads/pcs/udp-resolution-context ]]
fixture_dir=$(cd -- "$(dirname -- "$0")" && pwd)
unit="pcs-hy-release4-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
umask 077
cache_root=$(mktemp -d /tmp/pcs-hy-release4-cache.XXXXXXXX)
trap 'rm -rf -- "$cache_root"' EXIT
mkdir -p "$cache_root/gopath/pkg/mod" "$cache_root/build" "$cache_root/tmp"
sudo systemd-run --unit="$unit" --wait --collect --pipe \
  -p CPUQuota=100% -p MemoryMax=768M -p MemorySwapMax=0 \
  -p RuntimeMaxSec=780s -p TimeoutStopSec=5s -p KillMode=control-group \
  -p "WorkingDirectory=$fixture_dir" \
  /usr/bin/env "PATH=$PATH" "GITHUB_ACTIONS=true" \
  "GOPATH=$cache_root/gopath" "GOMODCACHE=$cache_root/gopath/pkg/mod" \
  "GOCACHE=$cache_root/build" "GOTMPDIR=$cache_root/tmp" "GOENV=off" \
  "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" "GITHUB_REF=$GITHUB_REF" \
  "GITHUB_SHA=${GITHUB_SHA:?}" "GITHUB_RUN_ID=$GITHUB_RUN_ID" \
  "GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT" \
  python3 "$fixture_dir/build.py"
