# Roadmap

ZROtext is an open-source Android SMS gateway in active development. This page shows where each capability stands and what it depends on. Stages describe progress, not release dates or a promise that every feature is available today. Contributions are welcome through [issues and pull requests](../CONTRIBUTING.md).

<!-- Generated regions come from docs/roadmap.json. Edit that file, then run `python3 scripts/roadmap.py`. -->

<!-- roadmap:overview -->
<p align="center"><img src="assets/roadmap-overview.svg" alt="Roadmap at a glance: 15 capabilities in four tracks. Four are in a restricted pilot, seven are being built, three are in design and one is planned. None has reached general release." width="900"></p>
<!-- /roadmap:overview -->

> [!NOTE]
> **How to read the stages**
> - **Design:** a written design, protocol draft or test vectors exist. Nothing runs in the gateway yet.
> - **Build:** code is merged and tested in CI or local rehearsals. It is not ready for real traffic.
> - **Restricted pilot:** runs end to end only for allowlisted accounts and recipients, using synthetic or controlled tests.
> - **General release:** documented, supported and open to any self-hosted operator. No capability has reached this stage.

## At a glance

<!-- roadmap:summary -->
```mermaid
%%{init: {"themeVariables": {"pie1": "#b6f36a", "pie2": "#6f9b4b", "pie3": "#edbe70", "pie4": "#99a696", "pieSectionTextColor": "#0b0f0c", "pieStrokeColor": "#29332a", "pieOuterStrokeColor": "#29332a"}}}%%
pie showData
    title Capabilities by stage (15 tracked)
    "Restricted pilot" : 4
    "Build" : 7
    "Design" : 3
    "Planned" : 1
```

| Track | General release | Restricted pilot | Build | Design | Planned |
|---|:---:|:---:|:---:|:---:|:---:|
| [Gateway messaging](#gateway-messaging) |  | 4 | 1 |  |  |
| [Self-hosting and integrations](#self-hosting-and-integrations) |  |  | 3 | 1 |  |
| [Privacy and account controls](#privacy-and-account-controls) |  |  | 1 | 1 | 1 |
| [Managed service and resilience](#managed-service-and-resilience) |  |  | 2 | 1 |  |
<!-- /roadmap:summary -->

## Path to general sending

General, non-allowlisted sending is the most important gate on this roadmap. It stays closed until every item on the left is done. The [SMS compliance guide](SMS-COMPLIANCE.md#gate-for-general-sending) has the full reasoning.

<!-- roadmap:gate -->
```mermaid
flowchart LR
    classDef done fill:#b6f36a,stroke:#6f9b4b,color:#0b0f0c
    classDef open fill:#161e17,stroke:#edbe70,color:#f0f3e9,stroke-dasharray:5 4
    classDef gate fill:#0b0f0c,stroke:#b6f36a,color:#f0f3e9,stroke-width:2px

    g0_0["✓ Device enrollment and<br/>authenticated stream"]:::done
    g1_0["✓ Idempotent send with<br/>honest delivery states"]:::done
    g2_0["✓ STOP / START in the<br/>outbound reply window"]:::done
    g3_0["✓ Account-scoped suppression<br/>checked at acceptance"]:::done
    g4_0["○ Opt-out capture beyond<br/>the reply window"]:::open
    g4_1["○ Durable line ID bound<br/>to inbound actions"]:::open
    g4_2["○ Owner review for off-channel<br/>and ambiguous requests"]:::open
    g5_0["○ End-to-end evidence<br/>on real devices"]:::open
    G{{"General send route"}}:::gate

    g0_0 --> g1_0
    g1_0 --> g2_0
    g2_0 --> g3_0
    g3_0 --> g4_0 & g4_1 & g4_2
    g4_0 & g4_1 & g4_2 --> g5_0
    g5_0 --> G
```

✓ marks work done in the restricted pilot; ○ marks work still open.
<!-- /roadmap:gate -->

## How the tracks connect

Arrows show the main dependencies between tracks. Labels include the current stage, so the diagram does not rely on color.

<!-- roadmap:map -->
```mermaid
flowchart LR
    classDef released fill:#e4fbc8,stroke:#6f9b4b,color:#0b0f0c
    classDef pilot fill:#b6f36a,stroke:#6f9b4b,color:#0b0f0c
    classDef build fill:#161e17,stroke:#b6f36a,color:#f0f3e9
    classDef design fill:#161e17,stroke:#edbe70,color:#f0f3e9,stroke-dasharray:5 4
    classDef planned fill:#111712,stroke:#29332a,color:#99a696,stroke-dasharray:2 4

    subgraph t_gateway["Gateway messaging"]
        direction TB
        c_enrollment["Enrollment and device stream<br/>· restricted pilot"]:::pilot
        c_outbound["Outbound send<br/>· restricted pilot"]:::pilot
        c_optout["Opt-out and suppression<br/>· restricted pilot"]:::pilot
        c_inbound["Inbound and webhooks<br/>· restricted pilot"]:::pilot
        c_dashboard["Owner dashboard<br/>· build"]:::build
        c_enrollment --> c_outbound
        c_enrollment --> c_inbound
        c_outbound --> c_optout
        c_inbound --> c_optout
        c_outbound --> c_dashboard
        c_inbound --> c_dashboard
    end

    subgraph t_privacy["Privacy and account controls"]
        direction TB
        c_accounts["Accounts, MFA, API keys<br/>· build"]:::build
        c_sealed["Sealed-content protocol<br/>· design"]:::design
        c_export["Export and deletion<br/>· planned"]:::planned
        c_accounts --> c_export
    end

    subgraph t_selfhost["Self-hosting and integrations"]
        direction TB
        c_compose["Compose deployment<br/>· build"]:::build
        c_releases["Signed releases and SBOMs<br/>· build"]:::build
        c_api["Stable API v1 and SDK<br/>· design"]:::design
        c_diagnostics["Setup diagnostics<br/>· build"]:::build
        c_compose --> c_releases
    end

    subgraph t_managed["Managed service and resilience"]
        direction TB
        c_hosted["Hosted accounts and billing<br/>· build"]:::build
        c_twosite["Two-location routing<br/>· build"]:::build
        c_failover["Automatic failover<br/>· design"]:::design
        c_twosite --> c_failover
    end

    c_optout --> c_api
    c_sealed --> c_api
    c_accounts --> c_api
    c_api --> c_hosted
    c_enrollment --> c_twosite
```
<!-- /roadmap:map -->

<!-- roadmap:tracks -->
## Gateway messaging

Connect a dedicated Android phone and SIM, send and receive SMS through the server, and report outcomes honestly.

| Capability | Stage | Evidence |
|---|---|---|
| Phone + SIM enrollment and device stream | Restricted pilot | [#9](https://github.com/pboachie/zrotext/pull/9), [#24](https://github.com/pboachie/zrotext/pull/24), [#160](https://github.com/pboachie/zrotext/pull/160), [device compatibility](DEVICE-COMPATIBILITY.md) |
| Outbound send with honest delivery states | Restricted pilot | [#17](https://github.com/pboachie/zrotext/pull/17), [#19](https://github.com/pboachie/zrotext/pull/19), [#21](https://github.com/pboachie/zrotext/pull/21) |
| Opt-out handling and recipient suppression | Restricted pilot | [#207](https://github.com/pboachie/zrotext/pull/207), [#210](https://github.com/pboachie/zrotext/pull/210) |
| Inbound capture and signed webhooks | Restricted pilot | [#25](https://github.com/pboachie/zrotext/pull/25), [#29](https://github.com/pboachie/zrotext/pull/29), [#39](https://github.com/pboachie/zrotext/pull/39), [#80](https://github.com/pboachie/zrotext/pull/80) |
| Owner dashboard: device health and history | Build | [#36](https://github.com/pboachie/zrotext/pull/36), [#74](https://github.com/pboachie/zrotext/pull/74), [#76](https://github.com/pboachie/zrotext/pull/76) |

<details>
<summary><b>Phone + SIM enrollment and device stream</b> · restricted pilot</summary>

- [x] One-use pairing with code and key-fingerprint comparison
- [x] P-256 device keys in Android Keystore with challenge-response sign-in
- [x] Authenticated WebSocket stream with heartbeats, fenced session epochs and bounded reconnects
- [x] Opt-in heartbeat resumes after a phone reboot
- [x] Controlled test on one Samsung device and SIM ([compatibility notes](DEVICE-COMPATIBILITY.md))
- [ ] Longer liveness runs across networks, carriers and device models
- [ ] Supported-device guidance

</details>

<details>
<summary><b>Outbound send with honest delivery states</b> · restricted pilot</summary>

- [x] Durable idempotency keys and per-account admission budgets
- [x] One radio operation at a time, with an execution grant bound to device, attempt and recipient
- [x] Ambiguous submissions become `unknown` and are never retried automatically ([state model](ARCHITECTURE.md#message-semantics-and-the-duplicate-send-problem))
- [x] Allowlisted synthetic send route (`/v1/alpha/messages`)
- [ ] Planned public `/v1/messages` route that accepts sealed content
- [ ] Open to any account, after the [path to general sending](#path-to-general-sending) is complete

</details>

<details>
<summary><b>Opt-out handling and recipient suppression</b> · restricted pilot</summary>

- [x] STOP, STOPALL, UNSUBSCRIBE and similar keywords recognized in the outbound reply window
- [x] Likely free-text withdrawals create a conservative block marked for review
- [x] Account-scoped suppression checked when a message is accepted
- [x] Local block on the phone applies immediately, even while offline
- [x] Local line binding and unsolicited opt-outs journaled on the phone ([#210](https://github.com/pboachie/zrotext/pull/210))
- [ ] Authenticated capture beyond the outbound reply window
- [ ] Durable line ID bound to server-side inbound actions
- [ ] Owner workflow for off-channel and ambiguous requests

</details>

<details>
<summary><b>Inbound capture and signed webhooks</b> · restricted pilot</summary>

- [x] Bounded inbound SMS pilot on Android with signed metadata upload
- [x] Durable webhook outbox with HMAC signatures, retries and bounded manual replay
- [x] Webhook signing secrets encrypted at rest, with key rotation ([runbook](WEBHOOK-KEK-ROTATION.md))
- [x] Retention limits for inbound content and delivery history
- [ ] Reliable inbound when senders use RCS ([details](ANDROID-TESTING.md))
- [ ] Sealed inbound content delivered to customer decryptors

</details>

<details>
<summary><b>Owner dashboard: device health and history</b> · build</summary>

- [x] Device pairing and management page
- [x] Authenticated connection lease shown per device
- [x] Message state timeline, inbound activity and webhook history views
- [ ] SIM, queue depth and radio readiness per device
- [ ] Live updates instead of snapshots

</details>

## Self-hosting and integrations

Make ZROtext practical to run, upgrade and build against.

| Capability | Stage | Evidence |
|---|---|---|
| Compose deployment and upgrade guides | Build | [#35](https://github.com/pboachie/zrotext/pull/35), [#105](https://github.com/pboachie/zrotext/pull/105), [#173](https://github.com/pboachie/zrotext/pull/173), [#183](https://github.com/pboachie/zrotext/pull/183) |
| Signed release artifacts and SBOMs | Build | [#86](https://github.com/pboachie/zrotext/pull/86), [#135](https://github.com/pboachie/zrotext/pull/135), [#169](https://github.com/pboachie/zrotext/pull/169), [#197](https://github.com/pboachie/zrotext/pull/197) |
| Stable public API v1 and client SDK | Design | [API outline](ARCHITECTURE.md#planned-api-v1-outline), [test-only sealed reader](../sdk/typescript/README.md) |
| Setup diagnostics and device guidance | Build | [#81](https://github.com/pboachie/zrotext/pull/81), [#189](https://github.com/pboachie/zrotext/pull/189) |

<details>
<summary><b>Compose deployment and upgrade guides</b> · build</summary>

- [x] Complete Compose stack with migrations before API start ([guide](../deploy/compose/README.md))
- [x] Separate migration and restricted runtime database roles
- [x] Verified PostgreSQL TLS and an optional HTTPS edge
- [x] Scripted fresh-install and database restore rehearsals
- [ ] Upgrade guide covering every release
- [ ] Production hardening checklist

</details>

<details>
<summary><b>Signed release artifacts and SBOMs</b> · build</summary>

- [x] Server image built from one source bundle, pinned and scanned
- [x] Release receipts gated on approved identity and SBOMs
- [x] Android release candidate with signing-key custody checks
- [ ] First tagged public release ([process](RELEASING.md))

</details>

<details>
<summary><b>Stable public API v1 and client SDK</b> · design</summary>

- [x] Route outline and sealed send shape ([outline](ARCHITECTURE.md#planned-api-v1-outline))
- [x] Versioned device stream schema aligned with the wire format
- [ ] OpenAPI contract for `/v1/messages`, `/v1/devices`, `/v1/webhooks` and `/v1/usage`
- [ ] TypeScript SDK with local encryption, after the sealed protocol is reviewed

</details>

<details>
<summary><b>Setup diagnostics and device guidance</b> · build</summary>

- [x] Owner enrollment, account setup and mail diagnostics
- [x] SMS and RCS readiness guidance for the gateway phone
- [ ] Accessibility review of owner pages and the Android app
- [ ] Supported-device list backed by repeatable tests

</details>

## Privacy and account controls

Keep message content out of reach of the server, and give owners control of their account and data.

| Capability | Stage | Evidence |
|---|---|---|
| Owner accounts, MFA and scoped API keys | Build | [#43](https://github.com/pboachie/zrotext/pull/43), [#172](https://github.com/pboachie/zrotext/pull/172), [#175](https://github.com/pboachie/zrotext/pull/175), [MFA operations](MFA-OPERATIONS.md) |
| Sealed-content protocol (client-side keys) | Design | [Draft 01](../protocol/drafts/zt-sealed-draft-01.md), [draft 02 proposal](../protocol/drafts/zt-sealed-draft-02-proposal.md), [#159](https://github.com/pboachie/zrotext/pull/159), [#162](https://github.com/pboachie/zrotext/pull/162) |
| Data export and account deletion | Planned | [Data retention](SELF-HOSTING.md#data-retention) covers history pruning only |

<details>
<summary><b>Owner accounts, MFA and scoped API keys</b> · build</summary>

- [x] Verified-email owner registration with closed-by-default policy
- [x] MFA, session revocation and CSRF protection
- [x] API keys with scopes, shown once at creation
- [ ] Team seats beyond one owner
- [ ] Account recovery flows separate from content recovery

</details>

<details>
<summary><b>Sealed-content protocol (client-side keys)</b> · design</summary>

- [x] Draft protocol and validation gates
- [x] TypeScript and Android test vectors, including signed manifests and root rotation
- [x] Test-only envelope parser and Android Keystore boundary
- [ ] External review of the chosen suite
- [ ] Recovery and unlock flows
- [ ] Enabled in the gateway for real messages

</details>

<details>
<summary><b>Data export and account deletion</b> · planned</summary>

- [ ] Owner export of messages, events and settings
- [ ] Account erasure that covers metering and billing records where allowed

</details>

## Managed service and resilience

Offer an operated service built from the same public code, and keep it available across two locations.

| Capability | Stage | Evidence |
|---|---|---|
| Hosted accounts and subscriptions | Build (Stripe test mode only) | [#34](https://github.com/pboachie/zrotext/pull/34), [#44](https://github.com/pboachie/zrotext/pull/44), [#70](https://github.com/pboachie/zrotext/pull/70), [#184](https://github.com/pboachie/zrotext/pull/184) |
| Two-location routing with fenced devices | Build | [#73](https://github.com/pboachie/zrotext/pull/73), [design](MULTI-LOCATION.md) |
| Automatic failover with independent quorum | Design | [Failover design](MULTI-LOCATION.md#automatic-failover-needs-an-independent-decision) |

<details>
<summary><b>Hosted accounts and subscriptions</b> · build, Stripe test mode only</summary>

- [x] Stripe Checkout and Customer Portal in test mode
- [x] Signed event inbox with risk holds for refunds and disputes
- [x] Metered admission for billed pilot tenants
- [ ] Live payments, usage limits and plans
- [ ] Customer support and status communication

</details>

<details>
<summary><b>Two-location routing with fenced devices</b> · build</summary>

- [x] One authoritative database writer with site-aware device leases
- [x] Virtual two-hub fault matrix, including unknown attempts across a hub move
- [x] Local second API instance through the Compose `two-hub` profile
- [ ] Rehearsed manual writer promotion between real sites

</details>

<details>
<summary><b>Automatic failover with independent quorum</b> · design</summary>

- [x] Design requiring an independent quorum member and fencing control
- [ ] Implementation and failure-scenario tests

</details>
<!-- /roadmap:tracks -->

## What has landed

```mermaid
timeline
    title Merged work by theme
    Foundations : Delivery state model and safety contracts : Durable delivery store and locked migrations : Account and device enrollment
    Device link : Authenticated heartbeat and stream : Fenced synthetic send on Android : Samsung hardware test record
    Inbound and webhooks : Signed inbound pilot : Webhook outbox, history and replay : Secret rotation
    Accounts and billing : Owner MFA and API keys : Stripe test-mode billing : Metered pilot admission
    Releases : Attested server image : Android release candidate : Source bundles and SBOMs
    Privacy : Sealed drafts and test vectors : Suppression in the pilot : Local line binding
```

## Where to help

> [!TIP]
> Useful contributions right now:
> - Device test reports from other Android models and carriers. Follow [Android testing](ANDROID-TESTING.md) and keep personal numbers out of reports.
> - Review of the [sealed-content drafts](../protocol/drafts/zt-sealed-draft-02-proposal.md).
> - Accessibility feedback on the owner pages in `web/owner`.
> - Self-hosting feedback from the [Compose guide](../deploy/compose/README.md).
>
> Read [CONTRIBUTING.md](../CONTRIBUTING.md) before opening a pull request.

See the [architecture](ARCHITECTURE.md), [two-location design](MULTI-LOCATION.md) and [security design](SECURITY-DESIGN.md) for technical details. These documents describe a mix of implemented and proposed behavior; inspect the code and release notes for availability.

Stages, checklists and dependencies live in [roadmap.json](roadmap.json). To change them, edit that file and run `python3 scripts/roadmap.py`; it regenerates the graphic, charts and tables on this page and in the README. CI fails if they are out of date.
