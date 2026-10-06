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
