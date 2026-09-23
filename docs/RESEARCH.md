# Research ledger and corrections

Checked September 22–23, 2026. Product facts can change; refresh pricing and platform policies before launch. The founder's attached original plan was read before research. The original name PHOSPHOR and nested-directory instructions are superseded by zrotext in the workspace root.

## Research scope

This ledger retains primary technical references and corrections needed to implement ZROtext. Product positioning describes ZROtext's own capabilities and evidence. No third-party application source was copied into the design preview; future code reuse must preserve applicable license and copyright notices.

## Corrections to the supplied plan

| Original assumption | Revised decision / reason |
|---|---|
| ELv2 branded open source | Founder chose AGPLv3; ELv2 is source available with restrictions |
| Mandatory CLA | DCO recommended; avoid unnecessary rights-assignment friction |
| OPAQUE is RFC 9380 | OPAQUE is RFC 9807; keep it a later reviewed auth project |
| We cannot read messages, by design | Qualify sealed relay, active browser-code trust, plaintext carrier leg and visible metadata |
| Account MEK used like a public/private key | Separate symmetric vault key from account/device/integration asymmetric pairs |
| Per-device wrapping guarantees clean revocation | Future access can be stopped; already delivered ciphertext/keys cannot be recalled |
| Ed25519 always in Keystore/StrongBox | Capability-tested P-256 identity key proposal; StrongBox is optional |
| WebCrypto gives HPKE/OPAQUE without dependencies | Protocol implementations and interoperability review still required |
| API encryption key displayed once by server | Generate private cryptographic credentials locally; public halves only on relay |
| Outbox + dedupe guarantees no double send | Radio boundary remains ambiguous; persist intent, expose unknown, avoid blind retry |
| `UPDATE ... ORDER BY ... LIMIT ... SKIP LOCKED` | Use a locked SELECT CTE and valid UPDATE transaction |
| Redis usage is billing authority | Transactional PostgreSQL reservations/ledger; cache is never financial truth |
| RAM-only from Redis persistence off | Swap, crash dumps, logs and phone retention matter; defer stronger mode |
| Foreground socket + WorkManager is always-on | Test modern Android service limits, Doze and OEM behavior on hardware |
| Default SMS role ensures Play acceptance | Permission policy and real core functionality must be satisfied; review remains separate |
| Rust PDU/UniFFI/MMS before revenue | Kotlin SMS first; carrier lab/MMS and shared Rust core later |
| 12-month content history by default | 7/30/90-day history, clear deletion/backups, lower exposure and cost |
| 1,000 RPS/10,000 phones launch requirement | Pilot-scale measured targets; no synthetic throughput as a carrier guarantee |
| Single-location application only | Founder requires site-aware design, load steering, one writer and fenced send ownership |

## Primary references used for technical decisions

- [Elastic licensing FAQ](https://www.elastic.co/pricing/faq/licensing) and [OSI AGPLv3 text](https://opensource.org/license/agpl-3.0): license terminology and rights. Plan recommendations are engineering/product choices, not a legal opinion on a future distribution.
- [RFC 9807 OPAQUE](https://www.rfc-editor.org/rfc/rfc9807.html), [RFC 9180 HPKE](https://www.rfc-editor.org/rfc/rfc9180.html): protocol references; do not treat this package as expert validation of their integration.
- [Android Keystore](https://developer.android.com/privacy-and-security/keystore), [foreground-service timeouts](https://developer.android.com/develop/background-work/services/fgs/timeout), [periodic work](https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work), [SmsManager](https://developer.android.com/reference/android/telephony/SmsManager), [Play SMS permission policy](https://support.google.com/googleplay/android-developer/answer/10208820): primary sources for the hardware/runtime gate.
- [PostgreSQL SELECT](https://www.postgresql.org/docs/current/sql-select.html) and [standby replication](https://www.postgresql.org/docs/current/warm-standby.html): queue-locking syntax and recovery semantics. [Patroni replication modes](https://patroni.readthedocs.io/en/latest/replication_modes.html) is a candidate operational path, not an installed component.
- [Stripe Payments pricing](https://stripe.com/pricing), [Billing pricing](https://stripe.com/billing/pricing), [webhooks](https://docs.stripe.com/webhooks): US domestic-card scenario and webhook lifecycle design.
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/), [WebSockets](https://developers.cloudflare.com/network/websockets/), [traffic steering](https://developers.cloudflare.com/load-balancing/understand-basics/traffic-steering/): edge behavior; no LB pricing assumed.
- [GPT-6 Sol](https://developers.openai.com/api/docs/models/gpt-6-sol): requested high-reasoning handoff target.

## Local infrastructure sources

Operator-specific infrastructure references and deployment timing are maintained outside this repository. Public documents provide parameterized hosting patterns; no live infrastructure was verified or changed.

## Remaining validation

Actual domain/trademark ownership, app-store acceptance, current toolchain versions, package names, library interoperability, exact legal/country/carrier requirements, provider prices, current PVE capacity, independent backup availability, practical SMS/background behavior, support cost, conversion, load benchmarks, and security review remain implementation/launch work. No evidence in this package establishes those outcomes.
