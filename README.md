# Themis

Themis is an open-source Go backend security-intelligence platform. It ingests SBOM and VEX documents,
correlates vulnerabilities against live CVE feeds, applies VEX overlay semantics, governs enterprise
positions, and publishes actionable artifacts — all without touching your build system. Backed by
PostgreSQL. No agents. No daemons. No lock-in.

> **Current direction — the Phase-3 greenfield rebuild.** Themis is being rebuilt as a set of
> **independently-deployable, Domain-Driven bounded-context services** (Evidence → Knowledge → Governance →
> Communication, over a Registry/Kernel foundation, with an optional Intelligence AI Gateway beside it).
> This is the **sole go-forward**; the original single binary (`cmd/themis`) is **frozen at v0.3.x** and
> kept as reference. Start at [`docs/engineering/PHASE3-STATUS.md`](docs/engineering/PHASE3-STATUS.md).

---

## What Themis Does

| Capability | Description |
| ---------- | ----------- |
| **Artifact trust** | Schema validation, SHA-256 integrity, deduplication, provenance checks on every SBOM/VEX document |
| **SBOM parsing** | CycloneDX 1.4/1.5/1.6, SPDX 2.3/3.0, Trivy JSON — normalised to one canonical model |
| **SBOM ingestion** | REST upload + HMAC-verified webhook; async pipeline with idempotency and lifecycle tracking |
| **Vulnerability correlation** | Component catalog matched against NVD and OSV by PURL and version range |
| **VEX overlay** | VEX applied as a contextual layer; raw findings are never deleted — safe to revoke anytime |
| **CVE watch** | Background NVD/OSV polling; new findings auto-created for matching catalog components |
| **Human triage** | Triage decisions record a VEX assertion that survives rescans and re-applies to future ingestions |
| **Enterprise positions** | Findings + append-only Enterprise Positions (Phase-3 Governance): AI proposes, humans decide |
| **Notifications & publications** | SMTP/Teams delivery (v0.3.x); deterministic VEX/advisory/report publication (Phase-3 Communication) |
| **Threat signals** | Daily EPSS/KEV, ExploitDB, upstream vendor VEX; retroactive re-enrichment of open findings |
| **Deterministic prioritisation** | Layer-1 rules (CVSS, KEV, EPSS, public exploit) set `deterministic_level` at ingest |
| **Blast radius** | Product → Microservice → Deployment → Customer graph drives a score multiplier and team routing |
| **VEX export** | CycloneDX 1.5+ and OpenVEX per product version; upstream-vendor-VEX coverage aggregate |
| **AI enrichment (optional)** | Intelligence Gateway turns a Finding into an **advisory** position recommendation — advisory-only, disable-able |
| **Observability** | Structured console logs + OpenTelemetry, correlated by stable business identifiers |

---

## Documentation

| Guide | What's in it |
| ----- | ------------ |
| **[INSTALLATION.md](INSTALLATION.md)** | Prerequisites, build/run for the Phase-3 services and the v0.3.x binary, configuration reference, project layout |
| **[TESTING.md](TESTING.md)** | Manual API walkthroughs (Intelligence Gateway, the SBOM flow), troubleshooting, the developer test suite |
| **[API.md](API.md)** | Index of every OpenAPI spec (monolith + the 6 Phase-3 contexts) with endpoint summaries |

Deeper references under [`docs/`](docs/):

| Area | Location |
| ---- | -------- |
| Phase-3 status & backlog | [`docs/engineering/PHASE3-STATUS.md`](docs/engineering/PHASE3-STATUS.md) · [`PHASE3-BACKLOG.md`](docs/engineering/PHASE3-BACKLOG.md) |
| Engineering decision records (per context) | [`docs/engineering/decisions/`](docs/engineering/decisions/) |
| Stack, conventions, AI harness | [`STACK.md`](docs/engineering/STACK.md) · [`CONVENTIONS.md`](docs/engineering/CONVENTIONS.md) · [`THEMIS-AI-HARNESS.md`](docs/engineering/THEMIS-AI-HARNESS.md) |
| Architecture book & ADRs | [`docs/architecture/`](docs/architecture/) · [`docs/adr/`](docs/adr/) |
| v0.3.x product context | [`docs/current-changes/`](docs/current-changes/) |
| Release notes | [`docs/release-notes/`](docs/release-notes/) |
| Change specs (system of record) | [`openspec/`](openspec/) |

---

## Quick start

```sh
go build ./...     # build every service
make check         # full quality gate

# run a Phase-3 service (see INSTALLATION.md for the full set + config):
THEMIS_GOVERNANCE_MIGRATE=1 go run ./cmd/governance   # :8083

# or the v0.3.x monolith:
make build && ./bin/themis                            # :8080
```

Full setup → [INSTALLATION.md](INSTALLATION.md). Testing it → [TESTING.md](TESTING.md).

---

## Contributing

1. Run `make check` before every commit — all gates must pass (build · lint · clean-arch · arch-test ·
   coverage incl. integration · deadcode).
2. No `TODO:` / `FIXME:` left at the end of a task group; every new exported symbol needs a consumer.
3. Keep domain/app rings free of framework imports and cross-context imports — `make clean-arch` +
   `tests/architecture` enforce it.
4. Design decisions and implementation tasks live under [`openspec/`](openspec/) and
   [`docs/engineering/decisions/`](docs/engineering/decisions/); see
   [`openspec/STATUS.md`](openspec/STATUS.md) for active changes.

---

## License

[MIT](LICENSE)
