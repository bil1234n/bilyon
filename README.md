# Bilyon

A low-fee payment platform that works online and offline, authorises with hardware-backed biometrics,
and lets people pay with gestures: **flick** money to the phone you point at, **shake** phones together to
split a bill, **grab** a payment off a table. Social handles work as payment addresses, and an SDK brings
the same flows into third-party social and livestream apps.

## Contents

| Path | What it is |
|---|---|
| [`docs/rfc/0001-bilyon-platform/`](docs/rfc/0001-bilyon-platform/README.md) | **RFC 0001**: the system architecture and technical blueprint (architecture, data models and crypto protocols, Algorithms A–C, social identity and realtime sync, roadmap, security) |
| [`reference/`](reference/README.md) | Executable reference implementation of the RFC's algorithms, in Go (standard library only), with tests for the edge cases the RFC specifies |
| [`backend/`](backend/) | The production backend in Go: the ledger, the FX engine and the API gateway (see [Backend](#backend)) |
| [`deploy/`](deploy/docker-compose.yml) | Local stack: PostgreSQL, Redis, NATS JetStream, TigerBeetle |

## Where to start

- **Overview, goals and SLOs:** [RFC README](docs/rfc/0001-bilyon-platform/README.md)
- **Architecture diagram and flick-to-pay sequence:** [§1](docs/rfc/0001-bilyon-platform/01-architecture.md)
- **Offline token format and double-spend algorithm:** [§2.1](docs/rfc/0001-bilyon-platform/02a-offline-artefacts.md), [§3.A](docs/rfc/0001-bilyon-platform/03a-algorithm-offline.md)
- **Flick detection and UWB target lock maths:** [§3.B](docs/rfc/0001-bilyon-platform/03b-algorithm-kinetic.md)
- **FX routing and rate locks:** [§3.C](docs/rfc/0001-bilyon-platform/03c-algorithm-fx.md)
- **How animations stay in sync within 50 ms:** [§4.4](docs/rfc/0001-bilyon-platform/04b-realtime-sync.md)
- **Phased plan:** [§5](docs/rfc/0001-bilyon-platform/05-roadmap.md)

## Running the reference tests

```sh
cd reference
go test ./...
```

Requires Go 1.24 or newer. There are no third-party dependencies.

## Backend

Three daemons, each a thin `cmd/` wrapper around an `internal/<name>` package whose `Config` documents
every environment variable:

| Daemon | Role |
|---|---|
| `ledgerd` | The double-entry ledger (§2.3): PostgreSQL engine with hot-account striping, holds, reserves and reversals behind a gRPC command API with mTLS + SPIFFE ACLs; hold expiry, balance audit and an outbox relay to NATS. `tbshadow` mirrors it into TigerBeetle |
| `fxd` | The FX engine (§3.C): liquidity graph fed from NATS, arbitrage quarantine, max-output routing and split execution, firm quotes with HMAC-signed rate locks, crash-safe execution against the ledger; one leader elected through PostgreSQL |
| `gatewayd` | The API the apps call (§1.1): passkey (WebAuthn) registration and login, DPoP-bound sessions, App Attest / Key Attestation / Play Integrity device binding, the payee directory with its transparency log and signed PARs, accounts, TxAuth-authorised payment intents (flicks, drops, splits, handle and QR payments) and FX quotes over REST; an internal gRPC API for the realtime gateway; the intent sweeper; NATS events |

Packages worth reading first: `internal/ledger` (the ledger contract), `internal/intents` (the payment
state machine), `internal/txauth` and `internal/cose` (signed artefacts), `internal/devicebind`,
`internal/identity`, `internal/fx`. Database schemas live in `backend/migrations`; `migrations/ops`
holds the least-privilege grants for the runtime roles.

### Running locally

```sh
make up                       # PostgreSQL, Redis, NATS, TigerBeetle
make build                    # ./bin/ledgerd, ./bin/fxd, ./bin/gatewayd, ./bin/tbshadow
./bin/gatewayd migrate        # each daemon migrates its own schema; see `<daemon> help`
```

### Tests

Every test runs against real servers: PostgreSQL (databases cloned per test from migrated templates),
`redis-server`, embedded NATS, `tigerbeetle`, software FIDO2 authenticators and simulated iPhones and
Android phones producing real attestation formats. With the servers installed:

```sh
BILYON_REQUIRE_INFRA=1 make ci   # lint + every test with the race detector
```

`BILYON_TEST_DATABASE_URL`, `BILYON_TEST_REDIS_URL` and `BILYON_TIGERBEETLE_BIN` point the tests at
existing servers; without `BILYON_REQUIRE_INFRA=1`, tests whose server is missing are skipped.
