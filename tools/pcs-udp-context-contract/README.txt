PREPARED ONLY — nothing in this directory has been built or run.

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
eviction at the existing256KiB cap is reported; all128 counter chains must stay.
No modification to existing pure regression outcomes or failed import records.

Cost is intentionally small
Producer ABBAABBA, six pure benchmarks,250ms each, processCPU plus wall and alloc.
Consumer ABBA for success/error128-state cases, one real advancing write each:
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
