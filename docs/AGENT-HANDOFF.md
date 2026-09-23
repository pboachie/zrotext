# GPT-6 Sol implementation handoff

Use **GPT-6 Sol**, reasoning **high**, as requested. The configured app exposes this model/effort combination; official model documentation also lists high reasoning support. This task has prepared the handoff only; it has not changed your model or started a separate task. [Model reference](https://developers.openai.com/api/docs/models/gpt-6-sol)

## First-session prompt — paste this

```text
Implement the first stage of zrotext in the current workspace root. Use GPT-6 Sol with high reasoning. This is a new AGPLv3 open-source Android SMS gateway with a paid managed service. The founder has approved AGPLv3 plus paid hosting. Consult the separately supplied private operator brief for deployment constraints; never copy its private criteria into repository files. Do not create a phosphor/ or nested zrotext/ directory.

Read README.md, docs/PLAN.md, docs/IMPLEMENTATION.md, docs/ARCHITECTURE.md, docs/SECURITY-DESIGN.md, docs/HOSTING.md and docs/DESIGN.md. The current planning package and confirmed founder decisions govern implementation. Do not reintroduce superseded content from the original pasted proposal. Develop and describe ZROtext independently; keep competitor names, URLs and comparisons out of project files, code, UI and marketing. The private visual prototype is a sample-data specification, not a working gateway.
Read docs/REPOSITORIES.md as well. The sample-data visual reference is in the separate private zrotext-ops working folder under marketing/preview. The authenticated production dashboard and all gateway behavior must remain public; marketing/production configuration are separate. The public gateway must build without private repo access.

Also read docs/MULTI-LOCATION.md. The founder requires two-location architecture with load balancing/traffic redirection. Include site/instance configuration, a single authoritative database writer, device-session fencing, global idempotency, health/drain contracts, and a two-hub local simulation in the initial architecture. Actual second-location provisioning follows the private operator brief and a reviewed deployment plan. Both sites may serve API/device traffic; independently writable queues and automatic database promotion without quorum/fencing are prohibited.

Implement M0 tasks ZT-001 through ZT-004 as far as the available environment allows. Start by inspecting existing files, repository state and installed toolchains. Scaffold a small Rust workspace (domain, server, device-sim), PostgreSQL self-host Compose, a Kotlin/Compose Android app, versioned protocol schemas and safe CI. Pin supported versions and preserve upstream notices. Add AGPL-3.0-only for application code, DCO and contribution/security docs; keep SDK licensing separate. Do not add OPAQUE, custom MMS PDU, NATS, Redis, S3, UniFFI or Kubernetes to the application runtime.

Build meaningful message-state tests and a deterministic simulated-device harness with the unknown-after-radio-submit boundary. Build the Android gateway-mode spike and document the legitimate foreground-service/distribution choice against current Android rules. If real phones are unavailable, complete compilable spike and simulator work, record the exact hardware test procedure and mark the hardware gate unverified. Never substitute emulator/socket results for actual SMS delivery.

For deployment planning, obtain the infrastructure project location from the separately supplied private operator brief. Read that project's AGENTS.md and referenced runbooks before any access. Inspect current inventory/capacity read-only with its approved tooling. Prepare an isolated dedicated-VM deployment proposal; do not modify unrelated services, read secrets into output, reuse broad credentials, or publish home topology in the public repo. This first stage is planning/preflight only, not public deployment. Do not provision paid infrastructure without a concrete deployment budget.

Use the private marketing/preview assets and screens as the visual direction; do not mistake their sample statistics for product evidence. Keep application UI truthful. Sealed-content implementation waits for a reviewed byte-level protocol. Do not invent cryptography or say the gateway is zero knowledge / end-to-end encrypted SMS. Do not implement automatic retry after ambiguous radio submission.

Run appropriate builds/tests and record exact results in docs/implementation-status.md with task IDs, verified evidence, unverified hardware/review dependencies and the next bounded task. Complete independently actionable work before stopping. End with a concise report of what works, what was tested, and the M0 gates still requiring evidence. Do not start M1 until M0's architecture decisions are recorded; do not claim M0 is complete if its hardware gate is unverified.
```

## Continuation prompt

```text
Continue zrotext from docs/implementation-status.md. Read the current stage and its dependencies in docs/IMPLEMENTATION.md, plus the applicable architecture/security/hosting decisions. Implement the next dependency-complete task or small slice, verify it with meaningful tests, update the status record and stop at the stage boundary. Preserve the separately supplied private deployment constraints, truthful delivery semantics, AGPL open-source/self-host parity, and independent cryptographic review gate. Do not expand the roadmap because a new feature seems easy. Report any real-phone, account, review or budget dependency precisely while completing work that does not depend on it.
```

## Context boundaries

Retain the planning package in the project, and put evolving evidence in the status file. No need to repaste the entire original proposal every session. In each session read the active task's relevant docs, not the entire home-infrastructure archive. When implementation decisions change, update the plan/ADR and affected contracts together, with reasons and migration implications.

Human dependencies are real phone access, carrier permissions, purchase/ownership of the domain, production payment account, content-key recovery custody, an independent reviewer, launch jurisdiction, and deployment budget. The agent should request only the specific dependency when needed, not ask permission for ordinary local scaffolding or tests already authorized by implementation.
