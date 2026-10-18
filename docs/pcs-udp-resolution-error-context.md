# UDP resolution context on failed direct writes

Status: static candidate, based on production source
`206921c72fb2d8f3d53b6f60507daff345a617ee`. No test, build, network
experiment or deployment has been performed for this candidate.

A failed IPv6 `WriteTo` does not by itself distinguish an IPv6 literal from a
hostname whose existing resolution had only an IPv6 result. In this version,
UDP `direct:auto` already prefers an available IPv4 result. This change records
the decisions that actually preceded an error; it does not perform a second
lookup or change forwarding, family preference, cache lifetime or eviction.

The optional `udp.error_detail.latest[].outbound` object is attached only when
the error came from the instrumented direct outbound. Existing error counts,
latest-per-phase bounds, timestamps and error-detail version 1 are retained.
Other outbounds and older errors omit the object. The consumer must retain this
additive object before it is usable from its own persisted rollup; current
consumer support has not been changed or validated here.

| Field | Meaning and unknown boundary |
| --- | --- |
| `target_kind` | `hostname`, `ipv4_literal`, `ipv6_literal`, or `unknown`, from the original `AddrEx.Host`. IPv4-mapped literals are classified as IPv4. A scoped IPv6 literal remains a literal; parsing/sending behavior is unchanged. |
| `resolution_path` | `supplied`, `literal_input`, `system`, `cache_hit`, `cache_miss`, `cache_unavailable`, or `unknown`. This is the branch actually taken, not a second DNS observation. A miss may include a usable result that was not inserted because another lookup won the race. |
| `resolved_ipv4_present`, `resolved_ipv6_present` | Whether each result was present in the `ResolveInfo` used for this attempt. JSON `null` means no such evidence. False does not establish permanent lack of an A/AAAA record or Internet reachability. |
| `cache_hit` | True/false for an actual cache hit/miss. Null if the cache was bypassed or its state was unavailable. |
| `cache_age_at_error_ms` | On a hit only, elapsed time from the cached result's existing insertion time to the failed operation's return. This is local reuse age, not DNS TTL or age at syscall start; a blocked send may return after the 10-second reuse deadline. Other branches use null. |
| `resolution_error_class` | Fixed `none`, `no_address`, `dns_timeout`, `dns_not_found`, `dns_temporary`, `dns_other`, `other`, or `unknown`. A partially usable result may also retain a resolver error. |
| `selected_family` | IPv4/IPv6 only when the actual failed `net.OpError` has operation `write` and a UDP destination. Otherwise unknown. This is not the bound socket address family. |

No destination, hostname, IP, port, account, child-session identifier, raw error
string or payload is added to this object. Labels are whitelisted again by the
core and pointer values are copied before retention and snapshot publication.
Only the existing two latest error records retain the object; no target history,
timer, goroutine or new registry is introduced. Previous success for the same
target remains unavailable: aggregate bytes on a shared socket cannot prove it.

The wrapper is created only on a failed direct write and preserves `Error()`
text, `Unwrap()`, `errors.Is` and `errors.As`. Concrete error type/equality and a
direct type assertion on the outer error are not preserved. The in-repository
UDP adapter/Feed path passes the error through for classification and returns
it to the manager, which retains its existing handling. Successful writes add
only branch metadata bookkeeping, with no context allocation, label parsing,
clock read or logging. Wrapping errors is independent of whether evidence is
enabled, so evidence-off failure-path cost still needs validation.

The test fixtures are synthetic and do not bind sockets or perform DNS/network
I/O. They cover the actual supplied-result/no-address/DNS-error write branches,
an injected cache's hit/miss/expiry/close/failed-send eviction, missing versus
false fields, partial DNS results, family classification, legacy error-chain
behavior, label filtering, and snapshot ownership. Gofmt has parsed the source;
that is not compilation or test success. Subject to separate approval, the
candidate-only pure cases are selected by `^TestUDPOutboundContext` in
`core/server` and `extras/outbounds`. Existing cache/error regressions and
bounded cost checks remain release gates. This work does not include or execute
any ACK-height algorithm regression or other previously rejected action.

This diagnostic can explain a future failure's input and selection, not restore
IPv6 connectivity. Changing mode to IPv4-only merely changes the failure for an
IPv6-only destination. An absent configured global prefix/default route cannot
be supplied by changing an IPv6 enable/disable sysctl.
