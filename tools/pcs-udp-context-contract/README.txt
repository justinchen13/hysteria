The previous remote attempts and local capacity diagnostic remain failed
contracts, preserved in the parent's private evidence ledger. This revised
fixture is prepared for review; no new execution is authorized by this file.

Scope
The same test-only bridge and fixture are copied into disposable archives of
206921c72 and 06ab4eae. A dedicated build tag exposes the real core Feed,
recordError, snapshot and JSON representation to actual extras WriteTo failure
branches. It starts no server, worker, route, DNS lookup, socket or application.
The successful path is real cache resolution + Feed + a pure memory sink. It
does not measure successful OS UDP send, QUIC/TLS, peer delivery or Internet
speed. Authentication gating is exercised directly, not with a TLS handshake.
The bridge is never committed to production source or included in an app build.

The two consumer files are immutable test-input snapshots of the installed
consumer and the reviewed candidate. They remain managed by PCS; these copies
do not establish a new deployed implementation. The driver calls their actual
sanitize and EvidenceState.record methods, including fsync and atomic replace.

Contract
Five real pure branch cases, each at one retained connection; success and the
cached failure also at128. Actual generated JSON feeds both consumers. Verify
return/payload preservation, classified deltas, exact optional fields, unknown
values, bounded privacy-safe state, reload, and no replay double count. Context
eviction at the existing256KiB cap is reported. Five single-session cases still
require full counters, exact context, reload, and zero replay delta. The two128
cases are explicitly an overload contract: only identities whose counter chain
actually survived phase0 may contribute phase1 deltas. Missing identities must
be reported as fresh baselines, never fabricated historical increments. The
original1024-call assertion failed correctly:107 retained chains gave856 calls,
with21 fresh baselines. Whole-entry and optional-context evictions, retained
counts, state bytes and unobserved calls are retained in every result. No cap
is enlarged, no input is removed, and no complete128-history claim remains.
No modification to existing pure regression outcomes or failed import records.

Cost is intentionally small
Producer ABBAABBA, six pure benchmarks,250ms each, processCPU plus wall and alloc.
Consumer ABBA for success/error128-input cases, one real advancing write each:
only8 measured commits, plus their setup baselines. No sustained IO pressure.
JSON bytes are measured from actual serialized records. Budget arithmetic uses
the existing producer maximum64 records/sec and consumer10s cadence, not a claim
that real traffic has1000 errors/sec. These are diagnostic-overhead bounds.

Execution remains blocked by plan.status=PREPARED_FOR_ROOT_REVIEW. After explicit
review/freeze, a dedicated remote workflow may invoke launch-remote.sh <repo>
<new-output>. It requires Go1.25.6 via existing official pinned setup actions.
No local Go build, workflow push, CI trigger, network fixture or deployment is
authorized by this document. Previously rejected ACK-height and AnyTLS route/HOL
actions are not copied, selected or run. Commands select only the new named
contract and benchmark; no ./... tests or CLI main execution.

Any functional, privacy, source/hash/module, memory or numerical budget failure
stops and stays FAIL/HOLD. No automatic retry/threshold change. A passing result
means only PURE_DIAGNOSTIC_CONTRACT_AND_BUDGET_PASS. Root owns final release
identity and any monitored production switch; existing image/config is rollback.

Run6 staged resource contract (prepared, not executed)
Run5 completed all functional and numeric cost gates, but whole-unit
memory.events.max increased403. Its HOLD is permanent; the missing phase
snapshots cannot identify which commands caused those events.

The new runner uses one aggregate1CPU/768MiB/Swap0 delegated service. Its
single-threaded controller moves into a96MiB control child before enabling cpu
and memory controllers, then runs serial fresh workers under the same parent.
Each worker has1CPU/768MiB/Swap0; these are nested limits, not extra budgets.
No concurrent build or consumer worker exists. The parent's original path is
retained explicitly, including initialization failures after controller move.

Prepare, four normal/race builds, four functional runs, and one cost phase each
save before/after parent+worker snapshots, dev/inode generation, monotonic time,
limits, CPU counters, memory.current/peak/stat/events and cleanup outcome.
Only explicitly attributed build-phase memory.max increments are allowed as
compilation pressure. Build high/OOM/kill/timeout fails. Prepare, functional
and cost require zero high/max/OOM/kill in both fresh worker and full aggregate
parent window. Outside-phase events also fail. Missing/generation-inconsistent
data fails closed. Parent memory.peak is cumulative across earlier phases and
cache; it is never described as a cost-only peak. Fresh-worker peak does not
replace parent-window checks.

Each fixed source produces normal and race .test executables with go test -c.
The exact normal/race binary SHA executes the unchanged named contract through
go tool test2json. Cost directly executes the same functionally qualified normal
.test SHA with the unchanged ABBAABBA order,250ms benchmark duration, and cases.
No Go build occurs in functional or cost workers. Original128 consumer inputs,
all allocation/CPU/JSON/state thresholds and total resource ceilings remain.
Test binaries are disposable and their SHA/build command/source identity remain
in the artifact. The explicit artifact namespace grows from83 to112 files to
include phase reports, returns, build command logs and the binary manifest.

test_staged.py is a small pure mock contract: no cgroup mutation, subprocess,
fork, Go or network. It checks strict resource attribution, generation/window
boundaries, missing snapshots, path ownership, payload write failure, output
uniqueness and fixed functional-to-cost binary identity. It does not emulate
kernel accounting or certify real remote execution; only a separately reviewed
sixth run can do that. It never changes or re-adjudicates run5.
