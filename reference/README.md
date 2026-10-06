# Bilyon reference implementation

Executable versions of the algorithms in [RFC 0001](../docs/rfc/0001-bilyon-platform/README.md).
The RFC pseudocode is normative; this code is informative. It exists to prove that the
algorithms work as specified, and the tests cover the edge cases the RFC lists. It is not
production code: keys are software stand-ins for Secure Enclave / StrongBox keys, storage is
in memory, and there is no networking.

| Package | RFC section | What it covers |
|---|---|---|
| `internal/cbor` | §2.1 | Deterministic CBOR (RFC 8949 §4.2.1) with a strict decoder |
| `offline` | §2.1, §3.A | COSE_Sign1 artefacts, Tier K wallet with crash-safe WAL, payee verifier with time floor and double-spend radar, server reconciliation (fork proofs, guarantee fund, clawback), Tier S single-use coin keys with Merkle proofs |
| `kinetic` | §3.B, §4.4 | World-frame flick detector, Bayesian UWB target lock with hysteresis, shake detection and clique grouping, largest-remainder split, NTP-style clock sync, animation timeline |
| `fx` | §3.C | Liquidity graph over depth ladders, hop-bounded max-output DP (checked against brute force), water-filling split, lock-buffer pricing, firm quotes with reservations and an extreme-move breaker |

```sh
cd reference
go test ./...          # Go 1.24+, standard library only
go test -v -run 'TestWireSizes|TestTargetLockPicksAlignedPeer|TestClockSyncWithinBound' ./...
```
