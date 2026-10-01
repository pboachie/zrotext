# Roadmap

ZROtext is an open-source Android SMS gateway in active development. This page shows where each capability stands and what it depends on. Stages describe progress, not release dates or a promise that every feature is available today. Contributions are welcome through [issues and pull requests](../CONTRIBUTING.md).

<!-- Generated regions come from docs/roadmap.json. Edit that file, then run `python3 scripts/roadmap.py`. -->

<!-- roadmap:overview -->
<p align="center"><img src="assets/roadmap-overview.svg" alt="Roadmap at a glance: 25 capabilities in five tracks. Four are in a restricted pilot, nine are being built, three are in design and nine are planned. None has reached general release." width="900"></p>
<!-- /roadmap:overview -->

> [!NOTE]
> **How to read the stages**
> - **Planned:** a proposed capability and intended outcomes are recorded; implementation has not started.
> - **Design:** a written design, protocol draft or test vectors exist. Nothing runs in the gateway yet.
> - **Build:** code is merged and tested in CI or local rehearsals. It is not ready for real traffic.
> - **Restricted pilot:** runs end to end only for allowlisted accounts and recipients, using synthetic or controlled tests.
> - **General release:** documented, supported and available for the stated deployment mode. No capability has reached this stage.

## Customer outcomes

The first experiences focus on local service operators and a personal assistant that works in both directions. A dashboard and integrations share one messaging foundation. The [use-case catalog](USE-CASES.md) describes each journey, dependencies and acceptance criteria; the [product implementation plan](PRODUCT-PLAN.md) orders the work.

Priority is delivery order, not availability or a release date. These outcomes are separate from the capability counts below.

<!-- roadmap:usecases -->
| Priority | Experience | Example | Availability |
|---|---|---|---|
| First | [Text receptionist](USE-CASES.md#receptionist) | Gather job details by text, draft a reply, and ask the owner to approve a quote. | Proposed; unavailable |
| First | [Personal AI by SMS](USE-CASES.md#personalai) | Text your assistant a note or reminder; let approved routines communicate with selected contacts. | Proposed; unavailable |
| First | [Agent task notifications and replies](USE-CASES.md#agenttexts) | Receive a task-completion text from your agent, reply with context, and review its proposed next action. | Proposed; unavailable |
| Next | [Repair and project updates](USE-CASES.md#repairs) | Send a repair update and request approval before extra work. | Proposed; unavailable |
| Next | [Cancellation-slot recovery](USE-CASES.md#waitlist) | Offer an open slot in sequence and stop when one booking is confirmed. | Proposed; unavailable |
| Next | [Wedding and event concierge](USE-CASES.md#events) | Send personalized invitations, collect RSVPs, and remind only unanswered guests. | Proposed; unavailable |
| Next | [Volunteer and shift coordination](USE-CASES.md#volunteers) | Fill an open shift by text and stop requests once it is covered. | Proposed; unavailable |
| Later | [Household coordinator](USE-CASES.md#household) | Coordinate pickups, errands and recurring responsibilities through opt-in reminders and replies. | Proposed; unavailable |
| Later | [Community lending desk](USE-CASES.md#lending) | Request equipment by text, confirm availability, and receive return reminders. | Proposed; unavailable |
| Later | [Operational acknowledgment](USE-CASES.md#acknowledgment) | Notify a small team about a maintenance issue and record who will handle it. | Proposed; unavailable |
<!-- /roadmap:usecases -->

## At a glance

<!-- roadmap:summary -->
```mermaid
%%{init: {"themeVariables": {"pie1": "#b6f36a", "pie2": "#6f9b4b", "pie3": "#edbe70", "pie4": "#99a696", "pieSectionTextColor": "#0b0f0c", "pieStrokeColor": "#29332a", "pieOuterStrokeColor": "#29332a"}}}%%
pie showData
    title Capabilities by stage (25 tracked)
    "Restricted pilot" : 4
    "Build" : 9
    "Design" : 3
    "Planned" : 9
```

| Track | General release | Restricted pilot | Build | Design | Planned |
|---|:---:|:---:|:---:|:---:|:---:|
| [Gateway messaging](#gateway-messaging) |  | 4 | 1 |  |  |
| [Self-hosting and integrations](#self-hosting-and-integrations) |  |  | 3 | 1 | 3 |
| [Privacy and account controls](#privacy-and-account-controls) |  |  | 2 | 1 |  |
| [Managed service and resilience](#managed-service-and-resilience) |  |  | 2 | 1 | 2 |
| [Workflows and AI](#workflows-and-ai) |  |  | 1 |  | 4 |
<!-- /roadmap:summary -->

## Path to general sending

General, non-allowlisted sending is the most important gate on this roadmap. It stays closed until every item on the left is done. The [SMS compliance guide](SMS-COMPLIANCE.md#gate-for-general-sending) explains the opt-out requirements; the [product plan](PRODUCT-PLAN.md#messaging-readiness) also requires the sealed messaging runtime and stable API. Internal line-bound opt-out code and the read-only review queue are groundwork, not completion of the remaining gates.

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
    g4_0["○ Production SMS line<br/>activation and SIM binding"]:::open
    g4_1["○ Enable and validate<br/>unsolicited opt-out capture"]:::open
    g4_2["✓ Off-channel holds and<br/>durable review decisions"]:::done
    g5_0["○ Sealed send and inbound<br/>runtime with stable API"]:::open
    g6_0["○ End-to-end evidence<br/>on real devices"]:::open
    G{{"General send route"}}:::gate

    g0_0 --> g1_0
    g1_0 --> g2_0
    g2_0 --> g3_0
    g3_0 --> g4_0 & g4_1 & g4_2
    g4_0 & g4_1 & g4_2 --> g5_0
    g5_0 --> g6_0
    g6_0 --> G
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
        c_export["Export and deletion<br/>· build"]:::build
        c_accounts --> c_export
    end

    subgraph t_selfhost["Self-hosting and integrations"]
        direction TB
        c_compose["Compose deployment<br/>· build"]:::build
        c_releases["Signed releases and SBOMs<br/>· build"]:::build
        c_api["Stable API v1 and SDK<br/>· design"]:::design
        c_diagnostics["Setup diagnostics<br/>· build"]:::build
        c_mcp["MCP messaging tools<br/>· planned"]:::planned
        c_agenttools["Agent adapters and replies<br/>· planned"]:::planned
        c_agentsetup["Guided agent setup<br/>· planned"]:::planned
        c_compose --> c_releases
        c_api --> c_mcp
        c_api --> c_agenttools
        c_diagnostics --> c_agentsetup
        c_compose --> c_agentsetup
        c_mcp --> c_agentsetup
    end

    subgraph t_workflows["Workflows and AI"]
        direction TB
        c_contacts["Contacts and conversations<br/>· build"]:::build
        c_scheduling["Templates and scheduling<br/>· planned"]:::planned
        c_approvals["Approvals and reply tracking<br/>· planned"]:::planned
        c_integrations["Workflow integrations<br/>· planned"]:::planned
        c_assistant["Customer-controlled assistant<br/>· planned"]:::planned
        c_contacts --> c_scheduling
        c_contacts --> c_approvals
        c_approvals --> c_scheduling
        c_approvals --> c_integrations
        c_integrations --> c_assistant
    end

    subgraph t_managed["Managed service and resilience"]
        direction TB
        c_hosted["Hosted accounts and billing<br/>· build"]:::build
        c_twosite["Two-location routing<br/>· build"]:::build
        c_failover["Automatic failover<br/>· design"]:::design
        c_managedai["Optional managed AI<br/>· planned"]:::planned
        c_providers["Provider-based sending<br/>· planned"]:::planned
        c_twosite --> c_failover
        c_hosted --> c_managedai
    end

    c_optout --> c_api
    c_sealed --> c_api
    c_accounts --> c_api
    c_api --> c_hosted
    c_enrollment --> c_twosite
    c_api --> c_contacts
    c_dashboard --> c_contacts
    c_assistant --> c_managedai
    c_export --> c_managedai
    c_api --> c_providers
    c_approvals --> c_providers
    c_integrations --> c_mcp
    c_integrations --> c_agenttools
    c_enrollment --> c_agentsetup
```
<!-- /roadmap:map -->

<!-- roadmap:tracks -->
## Gateway messaging

Connect a dedicated Android phone and SIM, send and receive SMS through the server, and report outcomes honestly.

| Capability | Stage | Evidence |
|---|---|---|
| Phone + SIM enrollment and device stream | Restricted pilot | [#9](https://github.com/pboachie/zrotext/pull/9), [#24](https://github.com/pboachie/zrotext/pull/24), [#160](https://github.com/pboachie/zrotext/pull/160), [#462](https://github.com/pboachie/zrotext/pull/462), [device compatibility](DEVICE-COMPATIBILITY.md) |
| Outbound send with honest delivery states | Restricted pilot | [#17](https://github.com/pboachie/zrotext/pull/17), [#19](https://github.com/pboachie/zrotext/pull/19), [#21](https://github.com/pboachie/zrotext/pull/21) |
| Opt-out handling and recipient suppression | Restricted pilot | [#207](https://github.com/pboachie/zrotext/pull/207), [#210](https://github.com/pboachie/zrotext/pull/210), [line-bound stream](../protocol/v1/line-opt-out-contract.md), [#237](https://github.com/pboachie/zrotext/pull/237), [#242](https://github.com/pboachie/zrotext/pull/242), [#245](https://github.com/pboachie/zrotext/pull/245), [#247](https://github.com/pboachie/zrotext/pull/247) |
| Inbound capture and signed webhooks | Restricted pilot | [#25](https://github.com/pboachie/zrotext/pull/25), [#29](https://github.com/pboachie/zrotext/pull/29), [#39](https://github.com/pboachie/zrotext/pull/39), [#80](https://github.com/pboachie/zrotext/pull/80) |
| Owner dashboard: device health and history | Build | [#36](https://github.com/pboachie/zrotext/pull/36), [#74](https://github.com/pboachie/zrotext/pull/74), [#76](https://github.com/pboachie/zrotext/pull/76), [#237](https://github.com/pboachie/zrotext/pull/237), [#245](https://github.com/pboachie/zrotext/pull/245), [#251](https://github.com/pboachie/zrotext/pull/251), [#255](https://github.com/pboachie/zrotext/pull/255), [concept/state matrix](CONCEPT-IMPLEMENTATION.md)<br/>**Release gate:** Functional restricted-pilot controls exist, but concept fidelity and integrated owner/Android accessibility acceptance remain open (#605/#612). Readiness reports are bounded Android observations and writer counts, not carrier sendability. No design or draft PR advances release maturity. |

<a id="cap-enrollment"></a>
<details>
<summary><b>Phone + SIM enrollment and device stream</b> · restricted pilot</summary>

- [x] One-use pairing with code and key-fingerprint comparison
- [x] P-256 device keys in Android Keystore with challenge-response sign-in
- [x] Authenticated WebSocket stream with heartbeats, fenced session epochs and bounded reconnects
- [x] Opt-in heartbeat resumes after a phone reboot
- [x] Controlled test on one Samsung device and SIM ([compatibility notes](DEVICE-COMPATIBILITY.md))
- [x] Supported-device guidance ([compatibility guidance](DEVICE-COMPATIBILITY.md))
- [ ] Longer liveness runs across networks, carriers and device models

</details>

<a id="cap-outbound"></a>
<details>
<summary><b>Outbound send with honest delivery states</b> · restricted pilot</summary>

- [x] Durable idempotency keys and per-account admission budgets
- [x] One radio operation at a time, with an execution grant bound to device, attempt and recipient
- [x] Ambiguous submissions become `unknown` and are never retried automatically ([state model](ARCHITECTURE.md#message-semantics-and-the-duplicate-send-problem))
- [x] Allowlisted synthetic send route (`/v1/alpha/messages`)
- [ ] Planned public `/v1/messages` route that accepts sealed content
- [ ] Open to any account, after the [path to general sending](#path-to-general-sending) is complete

</details>

<a id="cap-optout"></a>
<details>
<summary><b>Opt-out handling and recipient suppression</b> · restricted pilot</summary>

- [x] STOP, STOPALL, UNSUBSCRIBE and similar keywords recognized in the outbound reply window
- [x] Likely free-text withdrawals create a conservative block marked for review
- [x] Account-scoped suppression checked when a message is accepted
- [x] Local block on the phone applies immediately, even while offline
- [x] Local line binding and unsolicited opt-outs journaled on the phone ([#210](https://github.com/pboachie/zrotext/pull/210))
- [x] Default-off signed line-bound STOP/review stream and durable Android replay identity; production activation remains open
- [x] Owner-only read-only queue for ambiguous SMS holds ([#237](https://github.com/pboachie/zrotext/pull/237))
- [x] Owner-recorded off-channel holds and durable review decisions; a hold or signed opt-out cancels queued sends that have no radio grant ([#242](https://github.com/pboachie/zrotext/pull/242), [#245](https://github.com/pboachie/zrotext/pull/245))
- [x] A signed START releases a hold only when observed more than five minutes after it, tightened by the phone clock reading at upload ([#250](https://github.com/pboachie/zrotext/pull/250), [#253](https://github.com/pboachie/zrotext/pull/253))
- [x] Owner-approved SMS line activation implemented end to end, off by default: browser-held approval key, signed phone declaration and Android install ([#247](https://github.com/pboachie/zrotext/pull/247), [#248](https://github.com/pboachie/zrotext/pull/248), [#251](https://github.com/pboachie/zrotext/pull/251))
- [ ] Validate SMS line activation on physical SIMs, then enable it before unsolicited opt-outs
- [ ] End-to-end opt-out, offline replay and SIM-change evidence on real devices

</details>

<a id="cap-inbound"></a>
<details>
<summary><b>Inbound capture and signed webhooks</b> · restricted pilot</summary>

- [x] Bounded inbound SMS pilot on Android with signed metadata upload
- [x] Durable webhook outbox with HMAC signatures, retries and bounded manual replay
- [x] Webhook signing secrets encrypted at rest, with key rotation ([runbook](WEBHOOK-KEK-ROTATION.md))
- [x] Retention limits for inbound content and delivery history
- [ ] General unsolicited message-content capture and conversation routing beyond the pilot reply window; the line-bound STOP path carries metadata only
- [ ] Reliable inbound when senders use RCS ([details](ANDROID-TESTING.md))
- [ ] Sealed inbound content delivered to customer decryptors

</details>

<a id="cap-dashboard"></a>
<details>
<summary><b>Owner dashboard: device health and history</b> · build</summary>

- [x] Device pairing and management page
- [x] Authenticated connection lease shown per device
- [x] Message state timeline, inbound activity and webhook history views
- [x] Read-only ambiguous opt-out review queue with recipient metadata and event times
- [x] Opt-out hold and review decision forms ([#245](https://github.com/pboachie/zrotext/pull/245))
- [x] SMS lines page: approval key, line list and activation approval ([#251](https://github.com/pboachie/zrotext/pull/251), [#255](https://github.com/pboachie/zrotext/pull/255))
- [x] Device health and recent messages refresh every 15 seconds while the owner page is visible; pagination and active interactions pause their list ([#295](https://github.com/pboachie/zrotext/pull/295))
- [x] Live device and message updates over an owner event stream; the 15-second snapshot refresh stays as the fallback
- [x] SIM, queue depth and radio readiness per device, from Android-reported preconditions and bounded writer counts ([#308](https://github.com/pboachie/zrotext/pull/308), [#317](https://github.com/pboachie/zrotext/pull/317), [#340](https://github.com/pboachie/zrotext/pull/340), [#396](https://github.com/pboachie/zrotext/pull/396))
- [x] Shared responsive owner shell is merged (#683), with fleet-first navigation and separate observer roles
- [x] Fleet overview and selectable bounded device details are merged (#685), preserving live-refresh input and focus
- [x] Authoritative UTC writer summaries are merged (#695), with account/device scope, capped bounds and explicit freshness/unavailability
- [x] Responsive outbound writer activity is merged (#690), with conservative state labels, device links and preserved paging, expansion and focus; no unified inbound feed or decrypted sealed content is implied
- [x] Compact navigation readability and automated rendered candidate checks are merged (#701), including narrow and wide views at 200% text; human acceptance remains open
- [x] The integrated overview places authoritative writer summaries before hardware/details and outbound activity, preserving selected scope, history, pending input and keyboard focus (#605)
- [ ] Complete joint actual-browser/APK visual, state and human accessibility acceptance (#612); merged automated checks do not close this gate

</details>

## Self-hosting and integrations

Make ZROtext practical to run, upgrade and build against.

| Capability | Stage | Evidence |
|---|---|---|
| Compose deployment and upgrade guides | Build | [#35](https://github.com/pboachie/zrotext/pull/35), [#105](https://github.com/pboachie/zrotext/pull/105), [#173](https://github.com/pboachie/zrotext/pull/173), [#183](https://github.com/pboachie/zrotext/pull/183), [#259](https://github.com/pboachie/zrotext/pull/259), [#275](https://github.com/pboachie/zrotext/pull/275)<br/>**Release gate:** The listed deployment and upgrade work is complete for restricted development and pilot use. General production support and deployment acceptance are not established. |
| Signed release artifacts and SBOMs | Build | [#86](https://github.com/pboachie/zrotext/pull/86), [#135](https://github.com/pboachie/zrotext/pull/135), [#169](https://github.com/pboachie/zrotext/pull/169), [#197](https://github.com/pboachie/zrotext/pull/197), [v0.1.6-rc.2](https://github.com/pboachie/zrotext/releases/tag/v0.1.6-rc.2) |
| Stable public API v1 and client SDK | Design | [API outline](ARCHITECTURE.md#planned-api-v1-outline), [sealed SDK preparation](../sdk/typescript/README.md), [#569](https://github.com/pboachie/zrotext/pull/569), [TypeScript SDK #537](https://github.com/pboachie/zrotext/issues/537), [non-UI implementation boundaries](non-ui-implementation.md) |
| Setup diagnostics and device guidance | Build | [#81](https://github.com/pboachie/zrotext/pull/81), [#189](https://github.com/pboachie/zrotext/pull/189), [#268](https://github.com/pboachie/zrotext/pull/268), [#313](https://github.com/pboachie/zrotext/pull/313), [#462](https://github.com/pboachie/zrotext/pull/462), [Android review](ANDROID-ACCESSIBILITY.md) Earlier accessibility review covers the legacy scrolling screen. Merged native Home/Setup/Connection/Tools and guided setup (#603/#604/#648) require their own integrated #612 acceptance; actual assistive-technology validation remains open<br/>**Release gate:** The listed setup diagnostics and device guidance work is complete for restricted pilot use. The compatibility matrix records virtual, host-simulator, and one manual physical record only; no physical device or carrier is proven supported, and the linked physical no-radio and opt-in radio procedures have not been executed on any listed phone. |
| MCP tools for customer-controlled agents | Planned | [agent integration proposal](PRODUCT-PLAN.md#agent-messaging-tools), [#615](https://github.com/pboachie/zrotext/issues/615), [#616](https://github.com/pboachie/zrotext/issues/616) planned work only; issues are acceptance criteria, not runtime or release evidence |
| Agent SDK adapters and reply events | Planned | [agent integration proposal](PRODUCT-PLAN.md#agent-messaging-tools), [#617](https://github.com/pboachie/zrotext/issues/617), [#619](https://github.com/pboachie/zrotext/issues/619) planned work only; issues are acceptance criteria, not runtime or release evidence |
| Guided agent setup and simulator quickstart | Planned | [agent integration proposal](PRODUCT-PLAN.md#agent-messaging-tools), [#618](https://github.com/pboachie/zrotext/issues/618), [#621](https://github.com/pboachie/zrotext/issues/621) planned work only; issues are acceptance criteria, not runtime or release evidence |

<a id="cap-compose"></a>
<details>
<summary><b>Compose deployment and upgrade guides</b> · build</summary>

- [x] Complete Compose stack with migrations before API start ([guide](../deploy/compose/README.md))
- [x] Separate migration and restricted runtime database roles
- [x] Verified PostgreSQL TLS and an optional HTTPS edge
- [x] Scripted fresh-install and database restore rehearsals
- [x] Upgrade guide for moving between source snapshots ([guide](../deploy/compose/UPGRADE.md))
- [x] Production hardening checklist ([checklist](../deploy/compose/README.md#production-hardening-checklist))
- [x] Upgrade notes for tagged restricted candidates ([v0.1.6-rc.2](https://github.com/pboachie/zrotext/releases/tag/v0.1.6-rc.2), [tagged upgrade guide](https://github.com/pboachie/zrotext/blob/v0.1.6-rc.2/deploy/compose/UPGRADE.md))

</details>

<a id="cap-releases"></a>
<details>
<summary><b>Signed release artifacts and SBOMs</b> · build</summary>

- [x] Source and verified server release candidate published; image pinned, scanned and attested ([v0.1.6-rc.1](https://github.com/pboachie/zrotext/releases/tag/v0.1.6-rc.1))
- [x] Release receipts gated on approved identity and SBOMs
- [x] Published restricted rc.2 signed Android candidate, checksums, source identity and runtime SBOM; its candidate receipt records signing-certificate identity
- [ ] Next owner/Android candidate requires integrated concept and accessibility acceptance (#605/#612); no next tag/date is established
- [ ] General-release device, custody and deployment acceptance beyond published restricted candidates ([process](RELEASING.md))

</details>

<a id="cap-api"></a>
<details>
<summary><b>Stable public API v1 and client SDK</b> · design</summary>

- [x] Route outline and sealed send shape ([outline](ARCHITECTURE.md#planned-api-v1-outline))
- [x] Versioned device stream schema aligned with the wire format
- [x] OpenAPI contract distinguishing implemented restricted routes and planned public aliases ([contract](../protocol/v1/openapi/public-v1.json))
- [x] TypeScript production envelope composition and shared vectors; no enabled general send or sealed lifecycle implied ([#569](https://github.com/pboachie/zrotext/pull/569))
- [x] Default-off negotiated grants, device-bound payload fetch and dispatch metadata are merged (#698); Android service routing remains unintegrated
- [ ] Integrate negotiated dispatch into the maintained Android service and complete scoped usage projections (#626/#627/#631); public aliases remain planned
- [ ] Integrated SDK/runtime compatibility after sealed provisioning and key-lifecycle gates

</details>

<a id="cap-diagnostics"></a>
<details>
<summary><b>Setup diagnostics and device guidance</b> · build</summary>

- [x] Owner enrollment, account setup and mail diagnostics
- [x] SMS and RCS readiness guidance for the gateway phone
- [x] Accessibility review of the owner web pages ([review](ACCESSIBILITY-REVIEW.md))
- [x] Accessibility review of the Android app ([review](ANDROID-ACCESSIBILITY.md))
- [x] Supported-device list backed by repeatable tests ([compatibility matrix](DEVICE-COMPATIBILITY.md))
- [x] Native Home/Setup/Connection/Tools and explicit guided setup are merged (#603/#604/#648); navigation does not imply sending authority
- [x] Read-only lifecycle-aware local Home Power observations are merged (#693); unavailable observations remain explicit
- [x] Optional manual Android device-scoped writer-summary reader source uses independent messages:read authority, explicit HTTPS/device configuration and lifecycle cancellation; no credential persistence or local-counter fallback
- [x] Automated landscape/status checks are merged (#701), using actual scrolling and the Compose frame clock to reveal platform-visible status and reachable Pause/disclosure; no spoken TalkBack or physical acceptance is implied
- [ ] Actual TalkBack/Switch Access, keyboard-open masking/focus return, permission and lifecycle traversal, and physical OEM/motion acceptance remain open (#612)
- [ ] Integrated authenticated network and emulator acceptance of the optional Android summary reader (#608/#605); local counters cannot substitute

</details>

<a id="cap-mcp"></a>
<details>
<summary><b>MCP tools for customer-controlled agents</b> · planned</summary>

- [ ] Customer-run stdio server with typed readiness, preview, permitted send, status and cancellation tools
- [ ] Separate read and send grants; enforce recipient scope, approvals, budgets, suppression and revocation outside the model
- [ ] Two-client simulator verification; remote transport requires a separate authorization and deployment decision

</details>

<a id="cap-agenttools"></a>
<details>
<summary><b>Agent SDK adapters and reply events</b> · planned</summary>

- [ ] Python and provider-neutral function adapters over the shared sealed API and tool schemas; reuse the TypeScript SDK in #537
- [ ] Selected-content reply events with signature verification, durable checkpoints and event deduplication
- [ ] Conversation isolation, bounded agent turns and owner review for ambiguous replies

</details>

<a id="cap-agentsetup"></a>
<details>
<summary><b>Guided agent setup and simulator quickstart</b> · planned</summary>

- [ ] One guided setup command and supported client installers with scoped pairing, secret storage and reversible configuration
- [ ] Synthetic first exchange before controlled Android phone and SIM activation; show unavailable readiness gates
- [ ] Measure clean-install steps; preserve fingerprint and permission checks, reconnect diagnostics and revocation

</details>

## Privacy and account controls

Keep message content out of reach of the server, and give owners control of their account and data.

| Capability | Stage | Evidence |
|---|---|---|
| Owner accounts, MFA and scoped API keys | Build | [#43](https://github.com/pboachie/zrotext/pull/43), [#172](https://github.com/pboachie/zrotext/pull/172), [#175](https://github.com/pboachie/zrotext/pull/175), [MFA operations](MFA-OPERATIONS.md), [#240](https://github.com/pboachie/zrotext/pull/240), [#207](https://github.com/pboachie/zrotext/pull/207), [#217](https://github.com/pboachie/zrotext/pull/217), [Recovery tests](../crates/server/src/auth/account/tests.rs) |
| Sealed-content protocol (client-side keys) | Design | [Draft 01](../protocol/drafts/zt-sealed-draft-01.md), [draft 02 proposal](../protocol/drafts/zt-sealed-draft-02-proposal.md), [#159](https://github.com/pboachie/zrotext/pull/159), [#162](https://github.com/pboachie/zrotext/pull/162), [#260](https://github.com/pboachie/zrotext/pull/260), [#464](https://github.com/pboachie/zrotext/pull/464), [#525](https://github.com/pboachie/zrotext/pull/525), [non-UI implementation boundaries](non-ui-implementation.md) |
| Data export and account deletion | Build | [Data retention](SELF-HOSTING.md#data-retention), [#267](https://github.com/pboachie/zrotext/pull/267), [#271](https://github.com/pboachie/zrotext/pull/271), [#320](https://github.com/pboachie/zrotext/pull/320), [#450](https://github.com/pboachie/zrotext/pull/450) retention evidence covers history pruning only |

<a id="cap-accounts"></a>
<details>
<summary><b>Owner accounts, MFA and scoped API keys</b> · build</summary>

- [x] Verified-email owner registration with closed-by-default policy
- [x] MFA, session revocation and CSRF protection
- [x] API keys with scopes, shown once at creation
- [x] MFA-bound SMS approval public-key registration and revocation; end-to-end line activation is implemented default-off ([contract](../protocol/v1/sms-line-activation-contract.md))
- [x] Verified-email and private-operator password recovery revokes sessions, API keys and pending MFA challenges while preserving MFA; authentication only, with production vault/content recovery still pending
- [x] Device-status observer seats: owner-issued, single-use, hashed-token invitations; invitee self-verification and sign-in; read-only device status; irreversible seat removal
- [x] Expiring single-use owner-registration invitation tokens are implemented; closed registration remains the default
- [ ] Selected additional collaboration role boundaries and revocation/export/erasure enforcement (#633)

</details>

<a id="cap-sealed"></a>
<details>
<summary><b>Sealed-content protocol (client-side keys)</b> · design</summary>

- [x] Draft protocol and validation gates
- [x] TypeScript and Android test vectors, including signed manifests and root rotation
- [x] Test-only envelope parser and Android Keystore boundary
- [x] Q1-Q11 decisions recorded with cross-client manifest vectors ([#260](https://github.com/pboachie/zrotext/pull/260))
- [x] Recorded Q1-Q11 decisions re-verified against the evidence each row lists in the [protocol decision log](../protocol/drafts/zt-009-decision-log.md) ([#464](https://github.com/pboachie/zrotext/pull/464)); the Q9 Rust receiver gap it found is closed ([#525](https://github.com/pboachie/zrotext/pull/525))
- [x] Sealed v1 message admission route (`POST /v1/sealed/messages`) mounted behind the default-off `SEALED_ADMISSION_ENABLED` flag; acceptance stores exact envelope bytes and queues toward the bound device, never carrier evidence ([#538](https://github.com/pboachie/zrotext/issues/538))
- [x] Default-off sealed inbound upload and dormant protected conversation consent/read/capture groundwork (#613/#650/#651/#652/#655/#657), not general customer conversation delivery
- [x] Shared cross-client and adversarial vectors are delivered groundwork; runtime downgrade/leakage acceptance remains separately gated
- [ ] Integrated runtime downgrade/leakage acceptance (#632), beyond shared vector groundwork
- [ ] Recovery and unlock flows (first increment recorded as evidence only: offline unlock signing behind a disabled-by-default owner-CLI build feature, no server enablement)
- [ ] Root custody/provisioning, maintained Android provider, negotiated grants and consent-bound customer inbound delivery (#623/#625/#626/#629) before enabling real messages

</details>

<a id="cap-export"></a>
<details>
<summary><b>Data export and account deletion</b> · build</summary>

- [x] Owner takeout of messages with events, devices and the account profile (`GET /v1/owner/export`, no-store)
- [x] Cursor-paginated full-history takeout via `?before=` with tenant-safe 404s
- [x] Owner account erasure in one password-proven transaction with an MFA step-up, covering metering and billing rows and reporting retained sets (`POST /v1/owner/erasure`, fail-closed on schema-protected consent rows and cross-account billing references)
- [ ] Extend export and erasure to future contacts, templates, workflow state and assistant access records

</details>

## Managed service and resilience

Offer an operated service built from the same public code, and keep it available across two locations.

| Capability | Stage | Evidence |
|---|---|---|
| Hosted accounts and subscriptions | Build (Stripe test mode only) | [#34](https://github.com/pboachie/zrotext/pull/34), [#44](https://github.com/pboachie/zrotext/pull/44), [#70](https://github.com/pboachie/zrotext/pull/70), [#184](https://github.com/pboachie/zrotext/pull/184), [#468](https://github.com/pboachie/zrotext/pull/468) |
| Two-location routing with fenced devices | Build | [#73](https://github.com/pboachie/zrotext/pull/73), [design](MULTI-LOCATION.md) |
| Automatic failover with independent quorum | Design | [Failover design](MULTI-LOCATION.md#automatic-failover-needs-an-independent-decision), [Implementation status](MULTI-LOCATION.md#implementation-status-five-increments) |
| Optional managed AI service | Planned | [product proposal](PRODUCT-PLAN.md#managed-ai-and-larger-campaigns), [data-handling proposal](MANAGED-AI.md) proposal only; no runtime implementation |
| Provider-based high-volume sending | Planned | [product proposal](PRODUCT-PLAN.md#managed-ai-and-larger-campaigns), [route evaluation](PROVIDER-ROUTES.md) evaluation only; no route selected and no runtime implementation |

<a id="cap-hosted"></a>
<details>
<summary><b>Hosted accounts and subscriptions</b> · build, Stripe test mode only</summary>

- [x] Stripe Checkout and Customer Portal in test mode
- [x] Signed event inbox with risk holds for refunds and disputes
- [x] Metered admission for billed pilot tenants
- [x] First slice of usage limits and plans: quota-only usage-limit plans with enforced metered limits and honest over-limit responses, disabled by default and without any pricing decision
- [ ] Explicit live-payment isolation and runtime implementation; quota-only limits/plans already exist default-off (#645)
- [ ] Customer support and status communication

</details>

<a id="cap-twosite"></a>
<details>
<summary><b>Two-location routing with fenced devices</b> · build</summary>

- [x] One authoritative database writer with site-aware device leases
- [x] Virtual two-hub fault matrix, including unknown attempts across a hub move
- [x] Local second API instance through the Compose `two-hub` profile
- [ ] Rehearsed manual writer promotion between real sites

</details>

<a id="cap-failover"></a>
<details>
<summary><b>Automatic failover with independent quorum</b> · design</summary>

- [x] Design requiring an independent quorum member and fencing control; five increments recorded as evidence only (pure promotion-decision model with failure-scenario tests, the database executor that applies decisions with a durable journal, the durable consensus store with its observation-source adapter and epoch-anchor interface, the member-side observer that forms safe quorum reports from raw probe outcomes, and the member-side probe-and-report loop that carries those reports into the durable store behind the same default-off flag, all disabled by default)
- [ ] Implementation and failure-scenario tests

</details>

<a id="cap-managedai"></a>
<details>
<summary><b>Optional managed AI service</b> · planned</summary>

- [ ] Explicit opt-in to a separate managed AI service that can read selected content
- [ ] Document provider access, retention, export, deletion, revocation and per-account budgets

</details>

<a id="cap-providers"></a>
<details>
<summary><b>Provider-based high-volume sending</b> · planned</summary>

- [x] Evaluate provider routes, supported regions and sender-number requirements before promising capacity ([evaluation](PROVIDER-ROUTES.md), [#459](https://github.com/pboachie/zrotext/pull/459))
- [ ] Explicit route selection with shared suppression, idempotency and delivery semantics; no automatic resend of unknown phone attempts

</details>

## Workflows and AI

Build useful conversations for local service operators and individuals through the dashboard and integrations. These capabilities are proposed and unavailable; they depend on the general messaging foundation.

| Capability | Stage | Evidence |
|---|---|---|
| Contacts, consent and conversations | Build | [owner contacts API](SELF-HOSTING.md#contacts-and-consent), [product proposal](PRODUCT-PLAN.md#business-inbox) owner API provides account-scoped contacts, encrypted fields, bounded CSV import, purpose-specific consent history and takeout/erasure; workflow sending and conversations remain unavailable |
| Templates and scheduled follow-ups | Planned | [product proposal](PRODUCT-PLAN.md#business-inbox), [Local preview only](TEMPLATE-PREVIEW.md) browser-only personalized text preview; no saved templates, segment estimate or scheduling implementation |
| Approvals and reply tracking | Planned | [product proposal](PRODUCT-PLAN.md#business-inbox), [synthetic demo PR #244](https://github.com/pboachie/zrotext/pull/244), [exact action contract](../protocol/v1/workflow-action-contract.md) exact-action authority/state contract and synthetic conformance vectors; scripted demo in #244; no runtime implementation |
| Workflow connector and integrations | Planned | [product proposal](PRODUCT-PLAN.md#customer-controlled-assistant), [non-UI implementation boundaries](non-ui-implementation.md) product proposal; dormant connector registration/key-lifecycle contract in crates/server/src/sealed_connector_registry (line-scoped read/send grants, independent approval, rotation, revocation, audit) with no runtime route enabled |
| Customer-controlled AI assistant | Planned | [product proposal](PRODUCT-PLAN.md#customer-controlled-assistant) proposal only; no runtime implementation |

<a id="cap-contacts"></a>
<details>
<summary><b>Contacts, consent and conversations</b> · build</summary>

- [x] Account-scoped contacts with duplicate handling, encrypted fields and bounded CSV import
- [x] Append-only per-purpose consent records with coherent transitions, expiry, withdrawal and explicit re-grant
- [x] Owner takeout and account erasure include contacts and consent history
- [ ] Conversation history and eligible-recipient enforcement in future workflow sending
- [ ] Owner-entered job or appointment details and an exceptions inbox, with locally decrypted content

</details>

<a id="cap-scheduling"></a>
<details>
<summary><b>Templates and scheduled follow-ups</b> · planned</summary>

- [ ] Personalized templates, segment preview, recipient-local timing and explicit expiry
- [ ] Paced scheduling with suppression rechecks, cancellation and honest unknown outcomes

</details>

<a id="cap-approvals"></a>
<details>
<summary><b>Approvals and reply tracking</b> · planned</summary>

- [ ] Durable owner decisions tied to the exact recipient and proposed action
- [ ] Reply correlation, human takeover and follow-up cancellation after a response

</details>

<a id="cap-integrations"></a>
<details>
<summary><b>Workflow connector and integrations</b> · planned</summary>

- [ ] Shared services for dashboard actions, SDK tools and signed workflow events
- [ ] Authorized encryption/decryption connector with signature verification and event deduplication
- [ ] An n8n recipe for connecting the shared messaging services; application templates have separate use-case acceptance criteria

</details>

<a id="cap-assistant"></a>
<details>
<summary><b>Customer-controlled AI assistant</b> · planned</summary>

- [ ] Selected conversations decrypted only by an authorized customer-controlled connector
- [ ] Two-way owner conversations and automatic replies within approved routines
- [ ] Escalate commitments and unusual requests; enforce budgets, scope, revocation and human takeover

</details>
<!-- /roadmap:tracks -->

## What has landed

```mermaid
timeline
    title Merged work by theme
    Foundations : Delivery state model and safety contracts : Durable delivery store and locked migrations : Account and device enrollment
    Device link : Authenticated heartbeat and stream : Fenced synthetic send on Android : Samsung hardware test record
    Inbound and webhooks : Signed inbound pilot : Webhook outbox, history and replay : Secret rotation
    Accounts and billing : Owner MFA and API keys : SMS approval-key registration : Stripe test-mode billing : Metered pilot admission
    Releases : Attested server image : Android release candidate : Source bundles and SBOMs
    Privacy : Sealed drafts and test vectors : Suppression in the pilot : Default-off line-bound opt-out stream : Read-only owner review queue
```

## Where to help

> [!TIP]
> Useful contributions right now:
> - Synthetic walkthroughs of the [first customer journeys](USE-CASES.md), especially intake, approval and follow-up. Keep customer data out of public reports.
> - Device test reports from other Android models and carriers. Follow [Android testing](ANDROID-TESTING.md) and keep personal numbers out of reports.
> - Review of the [sealed-content drafts](../protocol/drafts/zt-sealed-draft-02-proposal.md).
> - Accessibility feedback on the owner pages in `web/owner`.
> - Self-hosting feedback from the [Compose guide](../deploy/compose/README.md).
>
> Read [CONTRIBUTING.md](../CONTRIBUTING.md) before opening a pull request.

See the [architecture](ARCHITECTURE.md), [two-location design](MULTI-LOCATION.md) and [security design](SECURITY-DESIGN.md) for technical details. These documents describe a mix of implemented and proposed behavior; inspect the code and release notes for availability.

Stages, checklists, dependencies and use cases live in [roadmap.json](roadmap.json). To change them, edit that file and run `python3 scripts/roadmap.py`; it regenerates the graphic, charts, tables and use-case details on this page, in the catalog and in the README. CI fails if they are out of date or a use case claims availability before its prerequisites.
