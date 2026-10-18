# Bounded UDP outbound error evidence

This candidate starts from production source `224825dbc5e0dd01e55c27785d67caeb6e72a969`.
It describes fast outbound UDP errors that previously had only an aggregate
counter. It does not repair or explain TCP downstream QUIC write stalls.

Status on 2026-10-18: **HOLD, not deployed**. Tested runtime source is
`206921c72fb2d8f3d53b6f60507daff345a617ee`; subsequent documentation/result commits
must not silently replace that runtime pin. Functional, race, security,
fragment-accounting and injected UDP-error recovery checks passed. The original
mixed-load performance profile is **RESOURCE_INCONCLUSIVE** because CPU quota
interfered. It is retained and cannot be replaced by a favorable microbenchmark
or a later paced-load result. Production forwarding/configuration is unchanged.

## Behavior retained

`udpSessionEntry.Feed` returns the same `n, err`; `udpSessionManager.feed`
continues to ignore the return. There is no new retry, socket replacement,
entry/QUIC close, DNS lookup or address-family policy. Hook/ACL and connection
creation failures retain their fail-fast child close. Fragment handling,
authorization-before-send, accounting and QUIC/TLS settings are unchanged.

Only a non-nil error invokes classification and the short error-state mutex.
Successful writes neither classify nor acquire that mutex. The existing
target-write counters now update before the slow-operation completion snapshot,
so such a snapshot can include its own failure. Counts and returned values retain
their meanings. In particular, `n > 0, err != nil` keeps the actual written bytes;
a short write with nil error is not converted into an error by this observer.

The existing private direct-outbound error types gain a fixed-class method.
Their concrete identity, Error text and Unwrap behavior are retained. Core uses
a structural interface, not an import of extras. Unknown method values are
ignored. DNS/errno classification uses types and `errors.Is/As`, never raw error
strings. Error destination address family is emitted only as ipv4/ipv6/unknown from
a typed error address; no raw address is retained. A `no_ipv6` selection error is not proof
that a kernel IPv6 send was attempted.

## Schema and measurement bounds

When the existing authenticated UDP observer is enabled, `udp.error_detail`
contains:

- `version: 1`, a cumulative error `sequence`, `sample_unix_ms` and
  `sample_auth_age_us`. The pair is an independent capture time; do not attach
  an old cached value to a new log time.
- `counters`: at most 40 nonzero entries, two phases (`init`, `target_write`)
  times 20 fixed error classes. Each has `count`, `first_auth_age_us` and
  `last_auth_age_us`. Summing the init rows gives init failures, which are not
  target-write calls. Missing classes in a supported complete snapshot mean
  zero; missing/unsupported `error_detail` means unknown.
- `latest`: at most one error descriptor per phase, with fixed class/layer,
  `error_address_family` enum from the typed error destination address, completion authentication age, requested/returned bytes,
  optional operation duration and observed UDP-entry/QUIC close flags.
  `duration_us: null` means the eight existing operation slots were occupied;
  the error itself is still counted.
- `best_effort: true` and `post_close_updates_may_be_unpublished: true`.

No new event type or per-error log is emitted. Existing periodic and close
snapshots carry the bounded addition. The error state is internally coherent
under its mutex but is not atomic with legacy UDP/QUIC counters. Only counters
are differentiated by same-epoch/session consumers; sequence and first/latest
timestamps are gauges. First observation establishes a baseline. Window gaps,
resets and old schemas remain explicit. First/latest times describe lifetime
endpoints; they cannot reconstruct every intermediate error.

The UDP entry's existing `closed` bool remains protected by `connLock`. A new
evidence-only atomic marker is set before underlying Close and read on errors;
there is no extra acquisition of `connLock` in the failure path. QUIC ended is a
separate existing atomic. These flags describe the state observed at return,
not which event caused the error. For example, an init failure closes its own
entry before returning and consequently reports entry-closing true.

The QUIC close snapshot can precede an in-flight UDP error return. This candidate
does not wait for that operation or add a late log. A later snapshot, if one is
otherwise emitted, may contain the increment; otherwise it remains unpublished.
The explicit coverage flag prevents a close snapshot from claiming final
completeness. It also avoids changing shutdown behavior to improve diagnostics.

The fixed error state has an asserted limit of 2 KiB per tracked connection
(up to 256 KiB at the existing 128-connection cap). A fully occupied error-detail
JSON object is tested below 12 KiB. There is no per-target or per-child-session
map, payload, error text, user identifier, IP, port or native UDP session ID.

## Validation and release requirements

New deterministic tests cover wrapped DNS/errno and fixed private-type hints,
unknown enums, missing address/family, partial and zero-byte returns, manager
ignore-and-continue behavior, init failures and observer-off behavior, saturated
operation slots, serialization privacy, immutable snapshots and fixed bounds.
A channel-controlled Close/WriteTo test exercises the entry-closing atomic and
the documented late-final snapshot gap, concurrently with snapshots.

Root must schedule core server and extras outbound tests plus race checks under
the shared experiment lock and existing CPU/memory budget. No timing sleeps or
public network target are needed for the new tests. Existing protocol, ACL,
DNS-cache, UDP fragment and accounting regressions remain required. For example,
from the repository's configured Go workspace, run the targeted new tests first,
then the existing relevant packages; the exact builder/cache is assigned by the
coordinator, not downloaded or rebuilt speculatively here.

Before release, update the collector's fixed whitelist to consume this schema;
the current collector will ignore the new object. Test old-schema unknown,
repeated snapshots, reset/epoch/gap/restart boundaries, enum/array limits and
timestamp gauges. The existing 24-hour rollup does not automatically include
these new fields. Collector integration is outside this source-only candidate.

Performance acceptance remains production observer versus this observer using
frozen paired workloads: at least 95% goodput, no more than 20% CPU per completed
payload byte, and at most 16 MiB increase in child-server peak RSS. The frozen
small-request guard fails when P95 exceeds both baseline 1.20x and baseline plus
50 ms. Startup peak RSS, whole-container memory and allocations have distinct
meanings and are reported separately. Resource
throttling over the predeclared limit makes the result inconclusive. Include a
bounded fast-error workload to check worst-case classification/log volume and a
TCP-plus-UDP regression; an observer microbenchmark alone is insufficient.
Any later deployment requires a reviewed rollback and at least 30 minutes of
observation with persistent collection. No traffic or no observed errors is not
proof of repaired behavior, and evidence improvements are not proxy speed gains.

The `error_address_family` field describes `net.OpError.Addr` only. It does not
identify the socket family: a dual-stack socket can send to an IPv4 destination.
Missing or non-UDP typed error addresses remain `unknown`; no socket-family
inference is made from a no-address selection error. The earlier unbuilt draft
name `socket_family` was corrected before source or collector deployment.

## Validation snapshot and limits

The [unit/race results](results/udp-error-evidence-20261018/udp-error-unit-race-summary.json)
contain 34 core-server and 15 outbound top-level tests in both functional and race
runs. The exact race expressions are recorded; this is not a claim that every
app package received a race run. Tests used Go 1.25.6, one Go scheduler thread,
0.4 CPU and 512 MiB with no extra swap, offline loopback containers and an
exclusive shared test lock. There was no production or public-network load.

The [paired microbenchmarks](results/udp-error-evidence-20261018/udp-error-benchmark-summary.json)
show the cost of the new evidence, not a performance gain:

- Fixed struct growth: 1,176 bytes per tracked connection. Allocator growth in
  the retained-128 fixture was 1,344 bytes per connection, or 172,032 bytes total.
- Empty UDP snapshot JSON: median 630 to 816 bytes. Snapshot plus JSON elapsed
  time under the fixed CPU quota: median 4.701 to 7.932 microseconds.
- One error class: median 630 to 1,167 JSON bytes and 4.820 to 12.984 microseconds.
- All 40 cells plus two latest descriptors: 5,153 JSON bytes, below 12 KiB.
- At a hypothetical 128 continuously observed authenticated connections and
  one snapshot every five seconds, 186 added bytes imply about 411 MB/day of
  extra log payload. This is not measured production volume; other emitted
  stream/close records can add snapshots. Existing rotation bounds remain
  relevant. The fixed state cap also includes tracked unauthenticated handshakes.

Before running any benchmark, its initial test-only custom metrics were found
before `B.ResetTimer`, which clears them in Go 1.25.6. Separate v2 fixtures moved
those fixed metrics after `StopTimer`. No original benchmark was run, no source
behavior or measured loop was changed, and the earlier unit/race inputs remain
preserved. This correction is not a discarded unfavorable benchmark result.

The [real protocol and mixed-load summary](results/udp-error-evidence-20261018/udp-error-mixed-v2-summary.json)
records valid/invalid trust, hostname and auth behavior, observer-off/on checks,
1/4-connection UDP fragmentation/accounting and denial-before-send behavior.
A deterministic test-only outbound produced one typed WriteTo error. An explicit
complete-zero snapshot preceded it; the collector observed exactly one increment,
did not recount replayed events and restored its persistent baseline. The same
UDP child and another child recovered. A shared TCP stream already established
but waiting at a gated origin subsequently completed a 2 MiB SHA check: this does
not claim that TCP payload was actively downloading at the instant of injection.
Close races, occupied timing slots and late-final gaps were verified separately
by deterministic unit/race tests.

The original one-connection mixed test ran eight fixed ABBAABBA rounds. All
payloads and the numerical regression gates passed, but seven rounds spent
15.7–26.0% of workload wall time throttled, exceeding the predeclared 10% limit.
Consequently it is **RESOURCE_INCONCLUSIVE**. Its group medians (2.374 to 2.364
MB/s, small P95 82.64 to 75.58 ms and CPU per byte about -4.3%) cannot establish
an improvement or successful overhead acceptance. The original four-connection
profile was not run after this resource failure. Maximum throughput remains
unknown.

A separately frozen calibration retains every payload and connection count,
limits the synthetic bulk origin to an aggregate 500,000 bytes/s in chunks no
larger than 8 KiB, and distributes small/UDP operations across its planned bulk
duration. Both first-second and whole-workload throttling must stay at or below 10%,
and real concurrency/periodic samples must be observed. This paced stratum is
separate from saturated capacity. No candidate paired result or release approval
is implied by baseline resource calibration. Scheduled lateness is reported
separately from request-start-to-completion small-operation latency.
