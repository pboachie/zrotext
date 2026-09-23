# Implementation status

Updated 2026-09-22. **M0 is in progress; its real-phone and hosting gates remain open.** This record distinguishes local builds and simulation from radio and production evidence. The private operator brief and detailed hosting preflight remain outside both repositories.

## M0 task progress

| Task | Implemented locally | Verified evidence | Open gate |
|---|---|---|---|
| ZT-001 repository foundations | Initialized Git at workspace root. Added `AGPL-3.0-only` license, DCO, contribution/security/conduct docs, issue templates, pinned Rust workspace and Android toolchains, versioned protocol schemas, `.env.example`, PostgreSQL 18.6 Compose and unprivileged fork-PR CI. No nested project. | Rust and Android local builds pass; Compose database and both app instances start; `/healthz` and `/readyz` return 200 with writer available. | No hosted CI run, clean-checkout reproduction, public repository or production release yet. Private reporting contact and release SBOM/license review are pending. |
| ZT-002 Android feasibility | Compose gateway-mode UI with permission request, SIM selector, authenticated WSS heartbeat spike, foreground notification Pause action, and explicit no-SMS warning. Provisional `remoteMessaging` foreground-service type and direct signed-APK pilot path are documented in [ANDROID-M0-TEST.md](ANDROID-M0-TEST.md). | `:app:assembleDebug` succeeds with JDK 21 / SDK 36; debug APK produced. Local `adb devices -l` found no attached device. | No real Pixel/Samsung, SIM/carrier, screen-off, 24-hour, background restriction or SMS delivery evidence. Service-type and Play-permission review remain open. No signed pilot APK. |
| ZT-003 protocol/state ADR | [ADR 0001](adr/0001-m0-runtime-and-delivery.md), JSON metadata schemas, pure message-state model, single-writer authority with session epochs, global idempotency, per-device grant fence, and deterministic two-hub simulator. M0 server exposes a token-gated WebSocket heartbeat endpoint and minimal liveness/write-readiness; graceful drain is wired. | Seven Rust tests pass. Simulator records `submitting → unknown`, rejects the second hub's retry, and rejects writes without writer access. Local WebSocket handshake with bearer test token returned `heartbeat_ack`. Stopping local PostgreSQL changed `/readyz` to 503; restarting restored 200. Both local hubs reached the same writer. | Model and fresh-DB schema are not yet M1 durable queue/device-journal transactions. No actual radio boundary, cross-site partition, standby promotion, or real-phone failover test. |
| ZT-004 hosting preflight | Read the private infrastructure rules and relevant runbooks. Inspected PVE inventory and capacity read-only through approved tooling. Wrote a detailed operator-only proposal outside both repositories and a sanitized [public summary](M0-DEPLOYMENT-PREFLIGHT.md). | Live snapshot showed aggregate memory and storage headroom for considering a small dedicated VM; existing guest count/IDs were checked privately. No infrastructure was changed. | VM ID/address are not reserved, sustained load/disk latency and isolation are unverified, backup failure-domain and disposable restore are unverified, and no concrete priced incremental budget exists. No VM/tunnel/site was provisioned. |

## Exact local checks

- `cargo fmt --all --check`: pass (Rust 1.97.1 MSVC host toolchain).
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: pass.
- `cargo test --locked --workspace`: pass, **7 domain tests**; server and simulator binaries compile.
- `cargo run --locked -p zrotext-device-sim`: pass, deterministic JSON timeline ends `unknown`, models one radio call, rejects replacement grant and writer-isolated write.
- `android/gradlew.bat :app:assembleDebug --write-locks --no-daemon`: pass, 37 tasks; JDK 21, Android SDK 36, AGP 8.13.0. Debug APK is a build artifact, not a tested phone app.
- `docker compose --env-file .env.example -f deploy/compose/compose.yaml config --quiet`: pass. The default and `two-hub` local profiles built and started; both `/readyz` checks returned 200 against one PostgreSQL writer. The token-gated test socket acknowledged one synthetic heartbeat. With the DB stopped, `/readyz` returned 503; after restart, 200. PostgreSQL initialization recorded deployment epoch 1 with dispatch disabled.
- `adb devices -l`: no devices attached. No carrier or SMS test ran.

## Current product boundary

The server does not accept customer messages, authenticate customers/devices, dispatch SMS, run a production migration workflow, or implement sealed content. The Android spike cannot send or receive SMS. The local Compose profile demonstrates wiring and safety responses only. The design preview remains sample data. No independent security review, public deployment, purchase, payment integration, or geographic redundancy is claimed.

## Next bounded M0 work

1. Run the [real-phone matrix](ANDROID-M0-TEST.md) on a dedicated Pixel and Samsung with consented SIM/carrier plans, current and prior Android versions, then record exact heartbeat gaps and manual recovery. Decide whether the foreground-service and distribution path is viable from those results. A third OEM follows before launch.
2. Complete the private dedicated-VM deployment review with measured storage latency, network isolation, inventory reservation, independent encrypted backup/restore and a priced incremental budget. Keep site-specific information outside public source. Only then decide whether M0's hosting gate is met.
3. Re-run clean-checkout builds and hosted CI once a repository and monitored private vulnerability intake exist. Do not enter M1 until M0's architecture decisions remain recorded and its go/no-go evidence is evaluated; do not call M0 complete without real-phone results.
