# Local owner provider disclosure review

`createOwnerProviderDisclosureReview` is an isolated, explicitly opted-in SDK module. It opens an actual selected encrypted owner-facts context locally, displays a copied message alongside the selected unavailable provider declaration, and records a local review as metadata commitments. Every result says `execution: "unavailable"`. It creates no provider action, accepted configuration, storage request, send approval, reader grant, provider Request or attempt identity.

The existing owner context and provider-configuration routers remain unmounted. A normal404 is unavailable. This module does not integrate the normal owner page or change original-reader/routine/custody behavior. Its isolated synthetic browser host does not establish production endpoint availability or complete the owner journey.

## Caller and custody

Supply a connected element in the actual HTTPS owner document, its exact origin, an application-owned authenticated current adapter, current CSRF callback, abort/lifecycle subscriptions, and the existing archive lease. Use the post-enrollment actual binding and manifest. Required options are `enabled`, `origin`, `host`, `binding`, `source`, `configuration`, `archiveLease`, `readCurrent`, `currentCsrf`, `onSetupClose`, `onCustodyClose`, and `signal`. Optional options are `timeoutMs` (1..10000, default10000), `observationMs` (1..1000, default1000), and a native-fetch-compatible `fetchImpl` for isolated tests. Unknown fields and accessors are refused.

`source` contains exactly `scope` and `envelopeDigest`. The scope is the maintained `WorkflowContextScope`, restricted to kind1 owner facts, revision1..128, and the exact current account/device/line/interval/reader/manifest. `configuration` contains `configId`, `configVersion` (1..16) and `recordVersion` (positive safe integer). Configuration IDs and versions select declarations only; they confer no accepted route or policy.

`ArchiveReaderLease02` is a structural exported interface. Its shape is not independently authenticated provenance, and `readCurrent` owner/consent booleans are application observations. A real caller obtains its lease through the maintained `unlockExistingArchive02` flow with independently compared root pin and current archive key. The module invokes the actual `openWorkflowContext` operation inside the key callback, binds copied AAD/envelope to a genuinely verified current manifest, and accepts only its owned completed HPKE result. It ignores the lease's returned value; skipped, premature, duplicate or late callbacks are refused. The host owns the shared lease; closing this module releases its reference without closing the host's custody.

No private key, recovery material, bearer or cookie value is accepted in the options. No helper issues authority or signs a provider action. The actual application remains responsible for genuine bootstrap and custody dependencies.

## Reads and copied decision

The module uses GET only, browser-managed same-origin credentials, matching CSRF header, no-store cache, redirect refusal and bounded streaming. It reads the current context endpoint without a historical revision query and the exact selected provider configuration. The returned envelope header and SHA256 must match the copied selected scope/digest. The declaration must remain draft/unavailable at the exact selected version.

The declaration adapter is exactly `telnyx-sms-v2`. Its closed field order is `adapter`, `organization_id`, `messaging_profile_id`, `sender`, `owner_label`, `intended_region`, `retention_policy_ref`, `eligibility_policy_ref`, `cost_policy_ref`. Optional policy refs are actual null or canonical nonnil UUIDs. They remain unverified declarations. No processing region, retention, eligibility or cost acceptance is inferred.

The detail decoder matches the source-derived maintained `Json(Details)` field order and refuses raw JSON that differs from typed reconstruction, including duplicate or escaped keys and noncanonical numbers. This is a strict output compatibility boundary, not a generic JSON parser. The SDK synthetic raw fixture is source-derived; a separate pure maintained Rust/Axum encoder regression and authenticated handler raw capture establish their own boundaries. A synthetic browser response does not prove the current maintained handler's encoding or authorization.

`prepare(body)` captures one valid UTF8 message of1..4096bytes, reads current selection and opens the source. It returns a frozen empty ticket owned by that exact module instance. `review(ticket)` consumes that ticket once, displays exact copied local facts, message, recipient and declared sender, and waits for the separate **Review locally** decision. The screen states that configuration is unaccepted and sending is unavailable. It uses plain text nodes and refuses changed/hidden/replaced review content. It re-reads source/declaration and current observations after the decision before returning metadata. Same-origin application code controls its page; this local decision is not cryptographic proof of owner display or server approval.

`pending()` returns a defensive bounded metadata identity; `state()` returns a closed phase plus unavailable execution; `close()` is immediate and idempotent. There is one operation per module lifetime, no automatic retry, no second preparation or restart after refusal, and no write/effect operation. A prior unknown context/proposal/attempt must be resolved through its original caller; this module cannot replace its identity or release its liability.

## Commitments

The identity contains account/context IDs and revision, source envelope digest, configuration ID/version/record version, canonical declaration digest, rendered UTF8 body digest, E164 recipient commitment, reader key ID and current manifest generation/version/digest. Integers must be represented exactly; a server version outside JavaScript's safe range is refused.

The local result adds `state: "local_reviewed_unavailable"`, `execution: "unavailable"` and `review_binding_digest`. The latter is SHA256 over `ZT/owner-provider-local-review/v1` followed by NUL, a big-endian uint32 length and the canonical sorted closed identity JSON bytes. Declaration digest uses canonical sorted declaration JSON; body and recipient digests use their exact UTF8 bytes. It contains no provider Request digest, action/routine/policy/usage/attempt or storage-request identity. These hashes can correlate sensitive low-entropy data and are not anonymous.

Metadata is not an authority capability; other code can construct an identical plain object. No consumer in this cut accepts it as send permission or a durable proposal. A future accepted provider operation must independently resolve genuine policy/configuration/source and financial authority and consume a fresh exact disclosure decision.

## Lifetime and limits

One absolute deadline starts before the first observation, decrypt or review. It only shortens, including while a prepared ticket is idle. Conservative request-start observation freshness and actual signed source/manifest/phone/archive/device-signer expiry bound it. Current bootstrap exposes no authenticated session lease; repeated observations and reads are separate checks, not an atomic long-lived owner authority.

The module retains at most one33075byte context envelope, one32768byte opened facts value, one4096byte body, one8192byte detail response and bounded metadata/declaration copies. There are at most two source GETs and two declaration GETs. Close, expiry, abort, pagehide, hidden visibility, setup/custody/lease closure, authority change or read uncertainty wipes owned byte arrays, removes DOM/private declaration references and releases dependency callbacks. Teardown continues after a cleanup exception. It preserves only optional bounded metadata identity. JavaScript/WebCrypto engine copies and strings cannot be reliably zeroized.

Liveness is checked across synchronous CSRF callbacks, awaited current/decrypt/read/digest operations and final publication. Late operations cannot publish a result; rejected promises are observed even if closure wins. No localStorage, sessionStorage, IndexedDB, clipboard, plaintext log or plaintext export is used.

Unit presentation controls use a DOM shim and explicit synthetic owner responses. Positive crypto controls use actual signed manifests, actual archive unlocking and maintained HPKE opening. Chromium checks package/native-fetch/browser-managed cookie behavior and synthetic unavailable404/503 and lifecycle closure. None proves a mounted authenticated server, real account, physical device, carrier, provider call, accepted provider policy or completed application journey.
