# Authenticated loopback regression

The 2026-10-19 test uses a private loopback QUIC server and UDP/TCP echo endpoints inside a network-disabled container. The old source deterministically times out on the second fragmented message with the same completed PacketID. The candidate delivers both distinct payloads in two independent sessions, including a duplicated in-flight fragment and reversed fragment arrival order. TCP payload integrity and invalid certificate, hostname and authentication rejection are also checked.

The initial run exposed a separate client cleanup bug: non-233 authentication responses were returned without closing the HTTP3 response body, leaving its request cancellation goroutine. Closing that body before closing the failed connection preserves authentication rejection and releases the request resource. The explicit rejected-auth old negative and the original test failure remain recorded. No goleak suppression is used.

The adjacent JSON gives normal/race results and hashes. Production speed and the cause of historical stalls are outside this fixture's scope.
