# Bounded UDP outbound error evidence

This candidate starts from production source `224825dbc5e0dd01e55c27785d67caeb6e72a969`.
It describes fast outbound UDP errors that previously had only an aggregate
counter. It does not repair or explain TCP downstream QUIC write stalls.

Status: source and deterministic tests prepared; formatting/parser and
`git diff --check` checks passed. No Go compilation, unit/race execution,
performance acceptance, deployment or production parameter change has occurred.
The candidate must remain on hold until those checks are scheduled and pass.

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
strings. Socket family is emitted only as ipv4/ipv6/unknown from a typed error
address; no raw address is retained. A `no_ipv6` selection error is not proof
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
  socket-family enum, completion authentication age, requested/returned bytes,
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
frozen paired workloads: at least 95% goodput, no more than 20% CPU per delivered
MB or small-request P95 increase, and at most 16 MiB memory increase. Resource
throttling over the predeclared limit makes the result inconclusive. Include a
bounded fast-error workload to check worst-case classification/log volume and a
TCP-plus-UDP regression; an observer microbenchmark alone is insufficient.
Any later deployment requires a reviewed rollback and at least 30 minutes of
observation with persistent collection. No traffic or no observed errors is not
proof of repaired behavior, and evidence improvements are not proxy speed gains.
