# Scoped remote verification — UDP resolution error context

Prepared for review, not authorized to trigger yet. Adding this workflow on the
dedicated `pcs/udp-resolution-context` branch will run it on that branch's next
push; do not push these workflow files until the parent reviewer approves.
The previously pushed static source commit used `[skip ci]` and contained no
new workflow.

The source pair is frozen in `inputs.json`: production `206921c72` and context
candidate `06ab4ea`. The workflow runs only on `justinchen13/hysteria` and this
branch, with `contents: read`, no secrets, deployment, tag publication or image
push. It uses a standard public Ubuntu 24.04 runner, Go 1.25.6 linux/amd64/v1,
and pinned official actions recorded in `actions-lock.json` (reused from the
same session's verified official tag/commit/action.yml records). Total timeout
is 15 minutes; success and failure artifacts are retained for 7 days.

`verify.py` refuses execution outside that remote workflow identity. It exports
exact immutable `core`, `extras`, and `app` trees, verifies all six module files,
and fetches only actual build/test dependency closure with `go list -deps` and
`-mod=readonly`. It does not use `go mod download all`, mutate module locks, or
silently restore changed files. After dependency acquisition, Go commands use
`GOPROXY=off`/`GOSUMDB=off`; the test cases themselves are pure. The runner is not
claimed to be an OS-level network-isolated machine.

The exact allowlist contains the 8 new context cases and the 14 existing UDP
error/cache cases. Baseline runs its 14 cases; candidate runs 22. Each runs in
normal and race modes (`CGO_ENABLED=1` only for race, system GCC identity retained).
The JSON test output must prove every expected top-level case passed, with no
skip, failure or unexpected top-level execution. No broad `./...` suite, ACK
algorithm test, route test, socket fixture or application binary is executed.

A test-only, identical benchmark file is temporarily copied into both archives
for an ABBA comparison. Three cases report ns/op, B/op and allocs/op: successful
cache resolution, a supplied no-IPv4 failure, and cache fill followed by the
existing failed-write eviction. All fail before socket I/O and use synthetic
resolver data. Each benchmark is bounded at 200 ms per case and process timeout
30 s. It measures the direct outbound work, including error wrapping, not core
JSON publication, full collector cost, kernel networking, successful UDP writes
or Internet throughput. Full per-arm samples and medians are retained. These
results are descriptive and cannot independently approve deployment or establish
zero overhead. Existing error-state size/privacy regression checks remain active.

Both CLI sources are built with CGO disabled, `-trimpath`, `-buildvcs=false`,
readonly modules and fixed CI metadata. The candidate is built a second time
with identical inputs and must have an identical SHA-256. `go version -m` reads
metadata without executing either binary. Artifacts include both binaries,
test/dependency/benchmark/build logs, command timing/child CPU evidence, complete
source file hashes, module/action/workflow inputs and SHA256SUMS. They use a
`pcs-ci` identity and are **not production release binaries**; actual CLI/security,
consumer persistence, resource acceptance and deployment remain separate gates.

No local Go command, test or benchmark has been run to prepare these files.
Only source formatting, Python AST parsing, and `git diff --check` are allowed
local static validation for this preparation.
