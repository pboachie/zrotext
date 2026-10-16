# Isolated reviewer first-root source

This source unit is not mounted by production startup. Its supported scope is
broker login, an isolated typed workspace session, and genuine first-root
enrollment with encrypted custody. It supplies no ordinary session, verified
email, TOTP factor, SMS permission, or full reviewer access. Production
containment and store acceptance require separate qualification.

## Android and browser coordination contract

The fixed same-origin page is `/review/root`. Its frozen coordination object is
`window.ZrotextReviewRoot` with `requestPause(request_id)`,
`pauseStatus(request_id)`, and `resume(request_id)`. The request ID is a fresh
canonical nonzero UUID chosen by the app. The first method returns a boolean;
the second returns null for another ID or the closed object
`{version:1, request_id, state:"waiting"|"paused"}`. Acknowledgement becomes
`paused` only after the page's outstanding request settles, including failure.
New page requests remain refused until exact-ID resume. Navigation destroys
the acknowledgement. The app must check the exact HTTPS origin and fixed page
before and after using it. This is concurrency coordination, never authority,
proof of no effect, or permission to replay an uncertain operation.

`POST /v1/review/session/context` is observational: it sets no cookie and changes
no original expiry or last-use time. Absolute and idle deadlines are the
effective minima of the actual owner, broker, and browser bounds. The response
includes the actual configuration digest and monotonic configuration revision;
an A-to-B-to-A rotation cannot revive an old context. Native code reads this
closed review context from the same app-owned HTTPS cookie jar, independently
of a JavaScript proposal. Root result and custody-export `request_id` values
are fresh read correlations, not authority or prior-completion selectors. The
actual current account and independently selected kit fingerprint select and
verify the genuine receipt/export.

The private locator is retained only in the app-owned HttpOnly cookie
`__Host-ztrw-l-<preparation UUID as 32 lowercase hex digits>`. Its value is a
separate canonical base64url-without-padding selector frame, authenticated under
`zrotext/review/locator-selector/v1` followed by NUL. Its ordered fields are
version u8=1, realm UUID16, database commitment32, origin u16BE byte length plus
ASCII bytes, configuration digest32, monotonic configuration revision u64BE,
authentication-key commitment32, original account/user/preparation/request
UUIDs16 each, generation u64BE, original prepared time u64BE, original private
locator32, and HMAC-SHA25632. UUIDs are raw network-order bytes. It contains
no broker/owner bearer, CSRF, password, session UUID, or authentication event.
Original time must be positive and not future-issued. The selector has no
independent authentication lifetime: current configuration/key identity and
the actual retained association must still match, and it alone grants no access.
It remains after preparation cookies are retired. The cookie is Secure,
Path=/, SameSite=Strict, without Domain. JavaScript receives neither the value
nor a raw-locator endpoint. Under explicit user consent, Kotlin CookieManager
may privately export the closed version-one record containing `version`,
`origin`, `cookie_name`, and `cookie_value` with the independently selected
HTTPS origin, then require exact byte readback before acknowledging
retention. That protected private file is separate from public root material.
No locator, cookie, password, or broker credential crosses JNI or the public
provider. The locator selects context only; future retained-workspace access
still requires genuine root proof. That consumer is unavailable in this unit.

All five advertised first-root capabilities still require actual database
currentness checks. Root-state guidance distinguishes no history, a pending
enrollment, enrolled history, other history, and unavailable. Pending or
historical state never permits replacement Create. The existing native kit
namespace independently prevents overwriting a prior kit.


## Storage, work and failure boundaries

Migration104 and the explicit unmounted router implement these five first-root
capabilities only: bootstrap, root issue, root completion, receipt and custody
export. Retained-workspace root resume and workspace/broker logout reductions
are unavailable. No ordinary production route mounts this router. A separate
real deployment adapter must qualify database, network, HTTPS origin and key
provenance before enabling an isolated service; supplying expected observations
or constructing `ReviewAccess` does not establish containment.

Preparation performs no alias/credential lookup. Login claims the original
preparation and spends durable anonymous route/per-alias budgets in a short
transaction, captures its bounded owned verifier, and releases database clients
before exactly one real Argon2 verification. There is no delivered proven-client
login-budget fallback in this unit. Failed aliases use the fixed valid dummy
verifier. Final allocation compares the current immutable credential and
configuration revision, using original prepared IDs only. A failed or uncertain
final transaction remains UNKNOWN; a missing receipt never proves no effect.
No branch creates a verified email, ordinary session, MFA factor or replacement
workspace to recover lost context.

Currentness locks follow account fence/anchor, existing root authority and
account/user/member parents, marker, preparation, then broker and typed session.
Allocation and cleanup choose write locks before reading rather than upgrading
shared locks. Real database time is checked again after writes. Review checkout
and transactions pin `search_path` to `pg_catalog` only; review SQL references
its installation tables explicitly. Runtime roles have SELECT and exact wrapper
EXECUTE privileges, with direct relation/column writes and internal helper
execution denied and repaired on provisioner reruns.

Original browser/session caps, five-minute preparation, seven-day result/action
retention and one-hour cleanup slack are source resource defaults, not approved
hosted retention or store policy. `prune_once` handles at most one disposition
per transaction, preserving lock order. Expiry cleanup removes finite evidence
or expired sessions, never the persistent workspace or private locator. Ordinary
unverified-signup age cleanup excludes actual review workspace users in the
same installation. Account/user/member erasure cascades remove associated
review identities, including the locator. Physical locator retention until
erasure does not guarantee use after configuration/key rotation.

The generic HTTP fixtures execute actual numbered PostgreSQL migrations with
separate ordinary LOGIN roles and genuine password/root/custody cryptography.
Their in-process HTTPS origin is synthetic: this is not external TLS, Android
CookieManager/SAF, device, SMS, production isolation or Google Play acceptance.
The browser page reports only the supported first-root scope; its synchronization
ACK and retained private selector never grant backend authority.
