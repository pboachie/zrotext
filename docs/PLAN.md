# ZROtext — product and launch plan

Planning baseline: September 22, 2026, America/Los_Angeles. Source checks ran September 22–23 across time zones. This document specifies proposed behavior; it does not certify implemented capabilities.

## 1. The decision

Build an **open-source Android SMS gateway with a paid managed cloud**. The first audience is developers and small operations teams using a dedicated Android phone for opted-in reminders, order updates, internal notifications, and two-way workflows. Customers bring the phone, SIM, mobile plan, and permission to message recipients.

Positioning: **“Your phone. Your number. Your SMS API.”** Supporting message: “Run it yourself, or let us keep it running.” Sell convenience, visible device health, predictable billing, and transparent code. Price is the entry point; dependable operation and support must earn retention.

Use **ZROtext** for the public display name, with a strong ZRO and lighter text. Keep `zrotext` lowercase for the domain, repository, CLI and package identifiers. The domain is proposed and will be purchased by the founder; availability, trademark clearance, social handles, and package names remain launch checks. Do not describe the domain as owned yet.

**Additional founder requirement:** design for two locations and load steering from day one. API/device-hub traffic can run across two independent sites, using one database writer, a standby, health/weight routing and fenced send ownership. See [MULTI-LOCATION.md](MULTI-LOCATION.md). Automatic database failover is a separate operational maturity gate.

## 2. Product value and evidence

ZROtext is an independent product. Its positioning should explain what customers can do, what managed hosting provides, and which capabilities have been verified. Keep competitor names, URLs, comparisons and allegations out of project documents, code, UI, marketing and implementation prompts.

ZROtext's intended benefits:

| Advantage | How a customer sees it | Evidence required before marketing it |
|---|---|---|
| Affordable platform subscription | $5.99 Pro, $19.99 Fleet | Published checkout and cost model |
| Clear delivery semantics | Queued, submitted, delivery confirmed, unknown | Real-phone fault tests; no invented delivery receipts |
| Operable phone fleet | Offline diagnosis, queue age, SIM selection, pacing, pause control | Screen-off, reboot, network-change tests |
| Reviewed sealed content | Message bodies encrypted before reaching relay | Protocol review, cross-client vectors, leakage tests |
| Credible open source | Working Compose quickstart and full application source | Fresh-machine self-host test |

Publish ZROtext's own verified behavior, clear limitations and reproducible evidence. Avoid unsupported superiority claims.

## 3. Business model and licensing

**Founder confirmed: AGPLv3 plus paid hosting.** Recommended SPDX identifier: `AGPL-3.0-only` for server, dashboard, and Android application. SDKs and reusable protocol clients should be Apache-2.0, with a clean dependency boundary that does not embed AGPL implementation code. Have the final license inventory checked before the first public release.

AGPL permits competing hosts; it is not a non-compete clause. It requires relevant source availability under its terms, including its provision for users interacting remotely with modified versions. Do not promise it prevents commercial forks. [AGPLv3 text](https://opensource.org/license/agpl-3.0)

Use a Developer Certificate of Origin sign-off for contributions rather than mandatory copyright assignment. Contributors retain copyright; incoming changes use the relevant component's license. Do not promise future proprietary relicensing that requires rights the project does not hold. Preserve all upstream notices for any reused MIT code. Prefer independent implementation and record provenance for any copied code or fixtures.

Public `zrotext` repository: all gateway behavior, Android client, authenticated dashboard, SDKs, billing implementation, migration code, protocol specs, self-host deployment examples, threat model, test harness, SBOM instructions, audit summaries, and release verification. Private `zrotext-ops` repository: production deployment configuration, secret references, private runbooks, and a separate marketing website/campaign source. Founder-only criteria requested to stay outside repositories remain in a separate operator brief. Include generic build/install scripts necessary for corresponding source in public; a private repository must not hide required application/build material. See [REPOSITORIES.md](REPOSITORIES.md).

Hosted tiers buy operated infrastructure, backups, managed upgrades, longer retention, hosted device limits, and support. All software features remain usable by self-hosters. Self-hosted mode has no vendor account requirement, license-server dependency, or telemetry by default; administrators set their own operational limits. Maintain a conspicuous self-host link, export path, and supported release policy.

Community structure: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue templates for device reports and bugs, discussion templates, contributor quickstart, `good first issue` labels, release notes, and a public roadmap. Merge only with tests appropriate to the change. Protocol, auth, and billing changes need a second human reviewer; recruit one before public paid launch. Private vulnerability reporting must work before the repository opens.

## 4. Proposed plans

USD, monthly, tax excluded. Each account has a monthly outbound allowance **and an equal separate inbound allowance**. “Message” means one logical SMS to/from one recipient, up to six radio segments. Show segment count separately because carriers may bill multipart SMS differently. Document these counting rules consistently in the API, dashboard and checkout.

| | Free | Pro | Fleet |
|---|---:|---:|---:|
| Monthly platform fee | $0 | **$5.99** | **$19.99** |
| Outbound logical SMS/month | 1,000 | 10,000 | 50,000 |
| Separate inbound records/month | 1,000 | 10,000 | 50,000 |
| Active devices | 1 | 5 | 15 |
| Free outbound daily cap, UTC | 100 | No plan daily cap | No plan daily cap |
| Content/recipient history | 7 days | 30 days | 90 days |
| Webhook endpoints | 1 | 3 | 10 |
| Support | Community | Email, best effort | Prioritized email, best effort |
| Seats at launch | 1 | 1 | 1 |

Every tier includes the same cryptography, API, signed webhooks, basic health, and export. Fleet is a device allowance, not team RBAC or a delivery guarantee. No paid “priority routing” that implies carrier priority. Rate, anti-abuse, and hardware limits apply to every plan.

Validate the proposed prices against operating costs, support effort and willingness to pay. Consider annual plans only after a stable paid cohort; proposed later prices $59.99/year and $199.99/year need their own revenue/cash/refund model. Avoid lifetime deals and unlimited promises.

The original 20,000-message Pro and 100,000-message Fleet allowances are deferred. Start with the lower, still useful allowances above; raise them after observing actual support, storage, abuse, and carrier behavior. This preserves room to grow without selling unreliable throughput.

### Metering contract

- One recipient per API request initially; bulk CSV and campaign sending are post-launch. A retry with the same idempotency key and identical request returns the same message without consuming quota again.
- Reserve one outbound unit in the same PostgreSQL transaction as message creation and the outbox job. Refund automatically only for cancellation, expiry, or failure **definitively before radio submission**. Submitted, delivered, carrier-failed-after-submission, and unknown attempts consume the reserved unit once. Expose adjustments in usage history.
- Meter inbound once per device event ID, independently from outbound. At the inbound cap, reject body upload with `INBOUND_LIMIT_REACHED`; keep a bounded, encrypted local backlog up to 7 days/10 MB and show a persistent alert. Resume while capacity exists; never imply missing records were captured. Record sequence gaps and dropped-backlog counts. No automatic charges.
- Quota reset: UTC calendar month for Free, subscription billing period for paid. Daily Free cap UTC. Display exact reset times. Distinguish quota errors from device/recipient safety pacing. At quota exhaustion, outbound returns 429 with a stable code, limit/remaining/reset fields and `Retry-After`; invalid input does not consume units.
- Upgrade entitlement after verified Stripe state, not a checkout redirect. Downgrade at period end; let the owner select retained devices, otherwise retain oldest active devices and pause the remainder with advance notice. Never discard history early just because a plan changes without the documented grace period.
- Failed payment: 7-day grace, then pause new outbound and alert; retain/export existing data until the normal retention boundary. Cancellation schedules the downgrade. Idempotent Stripe handlers reconcile out-of-order events to current subscription state.

## 5. Commercial validation

Measure infrastructure cost, support effort, abuse handling and retention before fixing long-term allowances. Founder financial models and deployment timing are private operating material maintained outside this repository. Product code must not encode revenue-based infrastructure switches. Pricing remains a testable proposal, with security and export available on every tier.

## 6. Scope that can launch

### First real-phone alpha

One account, one phone, single-recipient outbound and inbound SMS, explicit SIM selection, durable queue, idempotency, honest unknown state, phone health, stop/pause, signed webhook, simple dashboard, and self-host Compose. A clearly labeled private transport alpha may use synthetic, operator-readable payloads to validate telephony; it must not make sealed-content claims or onboard normal customer data.

### Paid public launch

Reviewed sealed-content SMS, explicit metadata disclosure, recovery kit and device approval, usable TypeScript SDK, documented REST envelopes, Free/Pro/Fleet entitlements, payment lifecycle, export/deletion, backup restore, signed Android APK, documented supported-phone matrix, transactional notifications, status page, abuse reporting, and actionable onboarding diagnostics.

The cloud is an encrypted relay for bodies in sealed mode. The phone decrypts to submit conventional SMS. The carrier and recipient still see plaintext, as do endpoints and customer integrations. This is **not end-to-end encrypted SMS**. A cloud-delivered browser client remains a trust boundary. Marketing must reflect these limits.

### Later, in this order

1. Python SDK, workflow recipes, local decrypting n8n node/bridge; hosted automation platforms otherwise receive ciphertext.
2. Teams/RBAC, scheduled messages with explicit expiry, safe batch APIs and opt-out workflows.
3. MMS carrier lab and default-SMS app workflow, attachment encryption and limits.
4. OPAQUE evaluation, a common Rust crypto core if it materially reduces interoperability risk, advanced recovery and key transparency.
5. 10,000-socket scale targets, additional regions beyond the required two-location topology, enterprise support and negotiated availability objectives. Two-location support is already in the architecture; automated promotion and strict synchronous durability require later operational gates.

Do not build Kubernetes, NATS, a custom MMS PDU library, full Rust JNI/UniFFI telephony core, 12-month default message history, or a SOC 2 program to get the first useful SMS workflow working.

## 7. Acquisition and activation

Launch page offers “Start free” as primary action, “Self-host” as the visible alternative, and “See Pro” at pricing. Open-source credibility reduces adoption risk; retention and upgrades come from managed value. Conversion surfaces: device #2, history needs, monthly quota, health alerts. Never paywall encryption, recovery, export, or security fixes.

Onboarding: verify email → choose hosted/self-hosted → install signed APK on a dedicated phone → review permissions and gateway access → approve one-use pairing request with matching code → send to a number the owner controls → receive a reply → inspect a webhook → create a narrowly scoped API credential and local encryption configuration. Target under 10 minutes; measure the median rather than claim it early.

Initial pilot: 10–20 developers across at least three phone models and two carrier networks, using dedicated devices and consented test recipients. Founder should personally watch the first ten setups. Ask which failure stopped them, what they currently pay, and whether $5.99 saves meaningful effort. No mass promotional campaign is needed to learn this.

Public rollout: README and self-host guide first, then truthful demo video/screenshots, technical architecture article, one useful integration recipe, founder launch post in relevant communities, and a practical SMS workflow tutorial. All outreach, publication, account creation, and spending are future founder actions; this package does not perform them.

Instrument only privacy-preserving funnel events: registration, device paired, first submitted SMS, first reply, first webhook acknowledgment, day-7 active, upgrade, cancellation reason. Never send message bodies, raw phone numbers, recipient lists, API keys, or ciphertext blobs to product analytics.

Pilot decision criteria: 80% complete pairing without intervention; median first round trip <10 minutes on supported devices; no duplicate sends attributable to retries in the fault suite; ≥5 of 20 active pilots commit to paying; known failures have clear UI recovery. Treat conversion/retention targets as hypotheses with tiny-sample uncertainty. Delay acquisition if phone reliability or support economics fails.

## 8. Operational and release gates

A small initial deployment can run in a dedicated Linux VM with the application and its own PostgreSQL. Use an isolated outbound Cloudflare Tunnel route for the new domain; no public database or PVE management access. See [HOSTING.md](HOSTING.md) for the documented environment, capacity checks, backup requirements, and single-writer cutover. Use automated backups and actually restore them; desired initial RPO ≤1 hour and RTO ≤4 hours must be demonstrated before being advertised. No contractual SLA at launch.

TLS termination, per-tenant authorization, safe logs, outbound-webhook egress restrictions, secret rotation, signing-key custody, backup retention, abuse intake, recipient suppression, refund handling, and rollback are release work. Provide compliance guidance tied to the launch countries and carriers; get applicable consent/marketing rules and carrier contracts reviewed before customer traffic. Owning a SIM does not automatically authorize automated/bulk messaging.

Domain, payment account, real test phones, carrier plans, security-review budget, jurisdiction, and a second reviewer are founder dependencies. They can be resolved during implementation; no production launch should silently assume they exist. Hardware screenshots must come from real tested builds, with personal data removed.

## 9. Schedule and spending decision

Effort estimate: **14–22 engineering weeks for one experienced full-time developer**, plus hardware coordination and external security-review lead time. An agent can accelerate coding but cannot replace carrier/device tests or independent review. At 15 hours/week, equivalent engineering effort is roughly 37–59 calendar weeks. MMS is a separate 4–8+ engineering-week investigation, not a promised release date.

Budget decisions before paid launch: a measured hosting and backup budget; 3–5 usable Android phones and SIM plans (obtain quotes); independent web/API and cryptography reviews (obtain scope-based quotes); legal/business setup and terms review; signing/release infrastructure. Compare actual infrastructure quotes and follow the private operations brief. Do not turn estimates into purchase authorization. Stop or reduce scope if the first two-week phone spike cannot sustain the supported deployment mode.

The executable work breakdown, gates, and first agent prompt are in [IMPLEMENTATION.md](IMPLEMENTATION.md) and [AGENT-HANDOFF.md](AGENT-HANDOFF.md).
