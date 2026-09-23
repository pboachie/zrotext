# ZROtext

**Your phone. Your number. Your SMS API.**

Early implementation of an open-source Android SMS gateway with a planned managed service at `zrotext.com`.

**Status: M0 feasibility work in progress, with M1 foundation slices underway.** The Rust state simulator, migration-gated local Compose stack, auth/enrollment/delivery libraries, and Android gateway spike build locally. The public source repository is live and the domain is owned, but DNS and the service are not deployed. There is no working SMS send/receive gateway, verified carrier delivery, or security audit. The design preview uses sample data.

## Start implementation

1. Read [implementation status](docs/implementation-status.md) for tested M0 evidence and open gates.
2. For a later coding session, use [the implementation handoff](docs/AGENT-HANDOFF.md) and its continuation prompt. Supply the separate private operator brief as local context; keep it outside both repositories.
3. Continue from the exact [implementation status](docs/implementation-status.md). M1 foundations may be built in parallel, but the real-phone and restoreable hosting gates remain open and no SMS service should be presented as live.

The implementation agent reads the detailed plans. You do not need to work through every document before starting. Brand and product descriptions should stand on ZROtext's own features, with no competitor references or comparisons.

## Planning documents

1. [Product and launch plan](docs/PLAN.md)
2. [Architecture and API contract](docs/ARCHITECTURE.md)
3. [Security and encryption design](docs/SECURITY-DESIGN.md)
4. [Milestones and acceptance criteria](docs/IMPLEMENTATION.md)
5. [Ready-to-paste GPT-6 Sol handoff](docs/AGENT-HANDOFF.md)
6. [Brand and screen specifications](docs/DESIGN.md)
7. [Research and corrections to the original plan](docs/RESEARCH.md)
8. [Preview verification](docs/PREVIEW-QA.md)
9. [PVE-first hosting and migration](docs/HOSTING.md)
10. [Two-location routing, load balancing and failover](docs/MULTI-LOCATION.md)
11. [Public/private repository boundary](docs/REPOSITORIES.md)

## Preview

The visual reference belongs in the separate private `zrotext-ops` working folder under `marketing/preview`. Its README describes the local preview. It is not required to build the public gateway. The landing page, fleet console, Android concept, pricing, and topology diagram use sample data; they do not transmit SMS, create accounts, or take payments.

## Decisions

- **Confirmed by the founder:** AGPLv3 open source plus paid hosting.
- **Confirmed by the founder:** architecture supports two locations and load steering; active API/hubs share one authoritative database writer and fenced device ownership.
- **Recommended launch pricing:** Free; Pro $5.99/month; Fleet $19.99/month. Prices and allowances are hypotheses until the pilot validates costs.
- **Recommended implementation:** Rust modular monolith, PostgreSQL, Kotlin/Compose Android app, server-rendered dashboard. Small, explicitly reviewed client cryptography module later in the launch sequence.
- **Launch boundary:** SMS first. Sealed content must pass independent review before the paid public launch. MMS, OPAQUE, Rust-on-Android, and large fleet scaling follow evidence of demand.

The implementation agent should work in this workspace root. Do not create `phosphor/` or a nested `zrotext/` project.

## Local development foundation

With Docker available, copy `.env.example` to `.env`, replace the example database password in both values with the same long random local secret, then run:

```sh
docker compose --env-file .env -f deploy/compose/compose.yaml up -d --build
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

Add `--profile two-hub` before `up` to start a second local app instance on `127.0.0.1:8081`; both connect to one PostgreSQL writer. The `migrate` service applies numbered SQL before the API starts. Existing pre-migrator M0 volumes need the [documented baseline procedure](deploy/compose/README.md) after backup. This is a test foundation with dispatch disabled, not a functioning SMS gateway or production hosting guide. The PostgreSQL data volume remains after `docker compose down`. See [implementation status](docs/implementation-status.md) for verified results and open gates.
