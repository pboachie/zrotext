# Implementation backlog and launch gates

The task definitions below are the planning baseline. Current progress and verified evidence are in [implementation-status.md](implementation-status.md). The design preview does not count as SMS implementation.

## Stage map

| Stage | Estimated engineering effort | Exit evidence |
|---|---:|---|
| M0 — phone and hosting feasibility | 1–2 weeks | Real-phone background matrix, runtime ADR, read-only PVE capacity snapshot |
| M1 — durable SMS vertical slice | 3–4 weeks | One real send/reply, crash-safe unknown state, simulator fault suite |
| M2 — reviewed sealed protocol and clients | 4–6 weeks | Review, vectors, recovery/rotation tests, no plaintext relay canaries |
| M3 — usable self-host/hosted beta | 2–3 weeks | Onboarding, signed APK, SDK, PVE restore and external access tests |
| M4 — payments and economics pilot | 2–3 weeks | Stripe lifecycle suite, quota tests, pilot readiness evidence |
| M5 — release review and operations | 2–4 weeks | Independent review remediation, release provenance, incident/rollback drill |

Total 14–22 engineering weeks. Review lead times and phone/carrier access can extend calendar time. Some documentation/UI work overlaps, but M2 cannot be rubber-stamped by the same agent writing the crypto. Public paid availability follows M5; participants can enter a clearly labeled, reviewed paid pilot after equivalent security/billing gates are met.

## M0: resolve risks first

**ZT-001 Repository foundations.** Initialize Git if absent; root AGPL-3.0-only plus component-license plan; DCO, CONTRIBUTING, SECURITY, code of conduct, issue templates, Cargo workspace domain/server/device-sim, Android shell, `.env.example`, and public self-host Compose. Pin current supported versions; build/check in CI. No generated implementation of speculative MMS/OPAQUE crates. Proof: clean checkout compiles, no secrets, safe unprivileged PR CI. Dependencies: none.

**ZT-002 Android feasibility spike.** Implement explicit gateway-mode UI, permissions, SIM selector, authenticated test socket, screen-off heartbeat and pause. Select service type through current official rules; document distribution strategy. Test a dedicated Pixel and a Samsung at minimum, including current supported Android version and one prior version; add a third OEM before launch. Test charging/unplugged, Doze, battery saver, Wi-Fi/mobile switch, airplane mode, force-stop, reboot, revoked permission, SIM removal, no default SIM, app upgrade and 24-hour idle. Log only test identifiers. Proof: dated matrix with exact models, OS/build, settings, connection gaps and manual-recovery steps. Emulators are insufficient for radio reliability. Dependency: ZT-001.

**ZT-003 Protocol/state ADR.** Finalize the explicit unknown/retry policy and JSON contracts. Device simulator models dropped ACKs and crashes before/after the radio boundary. Proof: timeline diagrams and executable state-transition tests. Dependency: ZT-001.

ZT-003 also includes the required site/instance configuration, device session epochs, global idempotency, health/drain contracts and two-hub simulator from MULTI-LOCATION. This design work is not deferred until cloud provisioning.

**ZT-004 PVE deployment preflight.** Read the founder's infra project and current rules; inspect capacity/inventory read-only using approved tooling when implementation is authorized. Produce a dedicated-VM plan, reserved IDs via inventory, network/backup approach, priced incremental budget and exact config diff. Operator-specific deployment timing stays in the private operations brief. No changes to existing unrelated workloads. Proof: private preflight record with sanitized public summary. Dependency: none; can proceed while hardware tests wait.

M0 go/no-go: a legitimate Android runtime strategy exists on the supported matrix, and a restoreable isolated PVE deployment fits capacity. If phone connection is unreliable, narrow support or request the specific product decision about wake-only push; do not disguise it with long polling claims.

## M1: real SMS, durable delivery

**ZT-005 Accounts and tenant isolation.** Maintained auth, Argon2id tuning, verified email, cookies/CSRF, API scopes and session/key revocation. Proof: cross-account IDs cannot read/mutate devices, messages, webhook or billing state; revoked sessions fail. MFA before paid launch.

**ZT-006 Device enrollment and auth.** One-use 5-minute pairing, user comparison code, Keystore P-256 challenge, replay defense, explicit revocation. Proof: expired/reused pairing, wrong device, replayed challenge and revoked socket tests. Dependencies: 003,005.

**ZT-007 Queue and Android adapter.** Transactional outbox, fenced claims, Room attempt journal, individual segment callbacks, durable event reconciliation, expiry/cancellation/backpressure and default pacing. Proof: at each crash boundary there is either one known radio submission or an honest unknown state; never a blind second send. Dependencies: 002,003,006.

**ZT-008 Inbound and signed webhooks.** Multipart normalization, event IDs, durable outbox, HMAC/replay window, SSRF controls, bounded retry and manual replay. Proof: duplicate inbound events stored once; webhook timeout/500/redirect/rebinding handled; unknown source rejected. Dependency: 007.

M1 demo: controlled test number receives one SMS, replies, dashboard shows truthful timeline, webhook receives one logical event despite retries. Synthetic/sacrificial content only until sealed path passes M2.

## M2: content security

**ZT-009 Threat model and protocol review.** Refine SECURITY-DESIGN into versioned byte-level spec; select maintained compatible implementations and expert reviewer. Resolve every open cryptographic question before production crypto. Deliver threat diagram and decisions; record review limitations.

**ZT-010 Shared vectors and client SDK.** Implement reviewed envelope library plus TypeScript SDK, Kotlin decryption/inbound encryption, scoped signing/decryption credentials and client key-manifest verification. Proof: published known-answer and cross-client vectors, tamper/replay/rollback tests, no plaintext accepted by public sealed endpoint. Dependency: 009.

**ZT-011 Vault/recovery/rotation.** Separate login and content unlock, recovery kit with confirmation, new-device approval, revocation, key generation/rotation, encrypted export and local dashboard decrypt. Proof: lost-login reset cannot read old history; recovery can; revoked device cannot receive future envelopes; old ciphertext limitations disclosed. Dependency: 010.

**ZT-012 Leakage and security remediation.** Canary scan across database/backup/logs/errors/webhooks plus independent audit fixes. Dependency: 010,011. Proof: reviewer-approved retest and documented residual risks. Do not bypass a missing review by renaming the same unreviewed code “secure.”

## M3: product beta on PVE

**ZT-013 Dashboard and landing.** Implement the design reference with real auth/state: activation checklist, device health, message timeline, local content unlock, API keys, webhook history, settings and recovery. Empty/error/offline/loading/revoked/limit states; keyboard and reduced-motion checks. No fake analytics in production. Dependencies: 007–011.

**ZT-014 Self-host and release.** One-command documented Compose, environment validation, migrations, backup/restore, no mandatory vendor login, signed APK, hash/signature verification, source/tag/digest correspondence. Proof: a fresh machine can send/reply with only documented steps. Dependency: 012,013.

**ZT-015 PVE deployment.** Implement HOSTING plan in private infra repo with resource/egress isolation, dedicated tunnel, external health, redacted monitoring, bounded logs, off-site encrypted backup and restore drill. Test WSS outside the LAN, cloud-edge restart, power/internet loss simulation and queued-event reconciliation. Dependencies: 004,014. Domain and production secret setup are founder dependencies.

## M4: charge fairly and validate demand

**ZT-016 Durable metering.** Atomic quota reservation, refunds, period boundaries, inbound cap/backlog gaps, concurrent API submissions and idempotency conflict. Proof: 100 simultaneous requests at one remaining unit yield one acceptance; refunds cannot be duplicated; replay across month boundary cannot double charge. Dependency: 007.

**ZT-017 Billing lifecycle.** Checkout/Portal, event signature/dedupe, subscription reconciliation, upgrades, downgrades, grace periods, cancellation/refund handling. Proof: successful checkout, failed payment, duplicate/out-of-order event, charge refund and downgrade-with-too-many-devices tests in Stripe test mode. Dependency: 016.

**ZT-018 Pilot economics.** 10–20 onboarded test users, support minutes, actual storage/CPU, device reliability and opt-in willingness to pay. Enable paid pilot only after security/payment readiness. Keep financial analysis and deployment timing in private operator notes; public code must not encode business thresholds. Dependencies: 012,015,017.

## M5: launch

**ZT-019 External reviews and operations.** Close high-severity findings, legal/terms/privacy/abuse checks for selected countries, publish audit scope and support expectations, restore and incident drill, dependency/signature/SBOM checks, freeze tested versions. Independent review is required even when agents write most code.

**ZT-020 Public launch package.** README, contribution guide, self-host guide, real screenshot set, short real-phone demo, current pricing comparison, changelog, status URL, support/recovery docs. Screenshots scrub real recipients/API keys and distinguish sample data. Performance claims show hardware/workload/date and exclude carrier latency. Domain/live endpoint check before publishing.

**ZT-021 Migration.** After operational readiness and a concrete deployment budget, execute single-writer cutover with rollback proof. No independently writable PVE/remote send queues. Dependency: 018 and HOSTING checklist.

**ZT-022 Two-location traffic.** Enable the required active API/hub topology across PVE and remote with a single writer, standby, tested weighted/failover routing and fenced device ownership. Test the MULTI-LOCATION failure matrix locally before enabling real origins. Preserve PVE as a participating site after authority moves. Dependencies: 003,015,021. Automatic database promotion remains off until external quorum/fencing has passed a separate review/drill; independent writable send queues are prohibited. Add 1–2 engineering weeks for initial dual-site deployment/rehearsal after deployment readiness, and 2–4+ additional weeks if automatic DB failover/strict-sync mode is commissioned.

## Test matrix to keep meaningful

| Layer | Required evidence |
|---|---|
| Domain | Allowed/forbidden transitions, expiry, ambiguous attempts, multipart partial success |
| Database | Tenant bounds, transactional quotas, SKIP LOCKED concurrency, migration/restore integrity |
| Protocol | Authenticated enrollment, replay/key rollback, exact vectors, malformed bounded parsing |
| Integration | Fake device socket, outbound+inbound, SDK decrypt, webhook retry, billing event lifecycle |
| Android hardware | Radio send/receive, screen-off, reboot, OEM battery policies, SIM/permission changes |
| UI | Activation, real health updates, locked/unlocked content, revoke, quota and recovery; accessibility |
| Ops | Restore, no body/secret logging, external WSS, DB port isolation, stale-writer fencing, rollback |

Simulator tests run per PR. Heavy load tests run on scheduled/release runs, with a quick queue regression test per PR. Real-phone tests and independent review are explicit manual gates. Report unrun checks honestly; a screenshot is not a radio test.

## Evidence and continuation

For each task, write `docs/implementation-status.md` with task ID, commit/files, commands and results, real/simulated distinction, remaining risk and exact next task. Each agent session tackles one stage or a small dependency-complete slice. Avoid a single “implement everything” prompt. If a human dependency blocks part of a stage, finish independent work and name the missing evidence rather than claiming the whole stage passed.
