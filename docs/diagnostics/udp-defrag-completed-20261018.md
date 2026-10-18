# Completed UDP fragment assembly lifetime

When a completed fragmented datagram is immediately followed by another datagram with the same 16-bit PacketID and fragment count, the previous Defragger keeps every fragment slot occupied. The second datagram is silently discarded. The bundled client and server choose random nonzero 16-bit IDs, so immediate reuse is possible.

The fix clears only the completed assembly after constructing its independent output payload. The in-progress duplicate checks, ordering, one-packet-at-a-time policy, and wire format are unchanged. A complete application-level replay can be delivered again; this function is not a session-wide UDP replay cache. The returned UDPMessage still aliases the final input message as before.

Validation on 2026-10-18 used Go 1.25.6 in a network-disabled container, with the same test input against base 06ab4eaea8e6c0ad85e0eebeb43d51773af7fcc4 and the candidate. The original implementation failed the deterministic second-message test. All candidate fragment tests passed normally and with the race detector: 8 top-level tests and 14 subtests each. Cases cover same-ID reuse in either order, in-flight duplicates, returned payload lifetime, replay semantics, fragment-count boundaries, and invalid-index preservation. No external or live proxy traffic was generated.

The initial minimal test fixture omitted a local package and offline QUIC module mapping; no tests ran in that attempt. A corrected fixture ran all tests. Its report wrapper then incorrectly searched for an unescaped `<nil>` string in raw JSON; decoded Go test output independently confirms the expected negative and positive outcomes. Both failed wrapper records remain preserved, and no tests were rerun to change that classification. See the adjacent JSON for hashes and boundaries.

This is not proof that PacketID reuse caused the earlier old-runtime cost-test failure: that run did not record PacketIDs. It is not a production performance result. No deployment or end-to-end integration acceptance was performed in this round, which ended at the user's request.
