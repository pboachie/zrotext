# Original-browser registration intent

The original browser can verify a newly created pending account with its mailed
code during a fixed fifteen-minute setup window. Verification then returns to
explicit sign-in. The existing password-bound verification and resend routes
remain available and unchanged. Deployment requires migration 107 and its
complete numbered predecessor train.

## Browser flow and HTTP contract

The owner submits email and password once to `POST /v1/auth/register`, retaining
its existing `{ "email": "owner@example.test", "password": "your-password" }` request and opaque empty
202 response. Every opaque admitted, declined or colliding registration response
sets the same two short-lived cookie shapes. A successful new pending account
and its original-browser intent are created in one transaction. A decline or
collision receives independent random decoy values, never an intent for the
existing account. There is no intent-validity GET or account-existence response.

`__Host-zrotext_registration_intent` contains 256 random bits with an intent
prefix. It is Secure, HttpOnly, SameSite=Strict, Path=/, with a maximum age of
900 seconds. `__Host-zrotext_registration_csrf` is a separately generated
256-bit proof with the same Secure, Strict, Path=/ and maximum-age attributes;
JavaScript can read only this proof. The database stores domain-separated
digests of both. It binds the proof to this particular intent. Neither value
contains a user, account, email, password, mailed code or session credential.

Two new body-carrying routes require exact configured Origin, the intent
cookie, and a matching proof cookie plus `x-zrotext-registration-csrf` header.
Stateless header validation precedes body extraction. Both use no-store
responses and closed JSON DTOs:

| Route | Body | Successful result |
| --- | --- | --- |
| `POST /v1/auth/registration-intent/verify` | `{ "token": "your-token" }` | Empty 204; no session, CSRF or intent cookies written |
| `POST /v1/auth/registration-intent/resend` | `{}` | Opaque empty 202, including invalid, declined and throttled intents |

A readable proof cookie allows the page to offer code-only verification; it
does not prove an account or valid intent exists. No secret enters URLs, web
storage, page snapshots, logs or analytics. Password fields are cleared after
submission. Another browser, an expired intent, or an explicitly chosen fallback
uses the existing password-bound routes. The existing password-protected email
verification rule is not relaxed for the recipient of somebody else's signup.

Successful code verification leads to explicit Sign in, where password-manager
support and the existing MFA flow remain available. The new route never creates
or replaces an ordinary auth session or CSRF cookie. It refuses to consume proof
when a valid session is already present, and checks current MFA policy without
creating a new MFA challenge protocol. The page checks the ordinary session
endpoint after verification or an uncertain registration/verification reply; a session created in another tab is
preserved and shown as an existing signed-in account, never treated as evidence
about this registration. Otherwise the page offers ordinary sign-in or the
existing password-bound verification fallback.

The consumed intent stays one-use on the server. Verification does not send a
late cookie-clearing response, because that could overwrite a newer registration
intent created in another tab. Cookies expire at their original short lifetime;
their continued presence is not evidence of unconsumed authority. No browser
password, session credential, intent token or approval is saved in web storage.

## Stored binding and transaction rules

Migration `107_registration_browser_intents.sql` adds one narrow pending-owner
table. Its binding includes account, user, normalized email, exact password
version binding, current verification-generation UUID, independent intent and
CSRF digests, creation/absolute-expiry timestamps, attempt count and consumed
timestamp. The password binding is a domain-separated digest of the exact
current password hash; it does not duplicate the password verifier. Foreign keys
retain account/user ownership and cascade cleanup when the pending owner is
removed. This is authentication metadata, with no message or root-key authority.

The table has an immutable, nonnull `account_id`; there is no deployment-wide
or unbound row. Its invoker trigger fixes its search path and checks the
verification generation in the same installation schema. The stock runtime
provisioner revokes direct helper execution, including after reprovisioning.
The table is excluded from account exports because it contains authentication
proof and password-version bindings. Complete owner erasure deletes and reports
its account-scoped rows before deleting verification parents or memberships;
another account's pending proof is preserved. Parent verification cleanup and
membership removal also cascade its rows. The fifteen-minute limit expires
authority; it does not claim immediate storage deletion. These classifications
do not modify the separately reviewed profile03 candidate inventory or enable
that profile.

Expiry is fixed at creation plus 15 minutes. Resend, refresh, failure and page
departure cannot extend it or reset the verification-attempt budget. Verification
and resend hold account, user, membership and intent locks in a specified order,
then recheck live membership, enabled account, unverified pending window, exact
email/password binding, current generation and absolute expiry using current
database time. Token consumption, intent consumption and email verification commit together,
at most once. No session is issued by this transaction. A concurrent account,
membership, password or email change cannot pass an earlier unlocked check.

Intent resend preserves its absolute expiry and attempt budget. It retires old
verification tokens and queued/leased mail, creates a fresh generation and mail
job, and updates only that intent's generation in the same transaction. Existing
per-user resend spacing and daily bounds still apply. A duplicate signup that
cancels the original generation invalidates the intent as well. Invalid/decoy
resends remain indistinguishable and never mail another pending owner.

Verification has a durable per-intent attempt bound and public-route budgets.
Only the combined live mailed code and matching intent may use the verified
budget lane; possessing an opaque registration cookie alone must not reveal
whether registration succeeded. Resend declines and budget refusals share the
same opaque 202. Malformed Origin or cookie/header proof fails before database
work. Missing, expired, changed, consumed and decoy authorities never mint a
session or disclose an account-existence signal.

## Source ownership and qualification

Implementation belongs in new `auth/registration_intent` and
`http_auth/registration_intent` modules and focused tests. `auth/mod.rs` receives
only the module declaration and a narrow optional insertion hook inside the
existing registration transaction. `http_auth/mod.rs` receives only module,
router and registration-response integration. Existing verification/resend
handlers remain unchanged. Hosted controller/forms consume the new routes and
retain explicit password fallback. Runtime-role grants and new-table
classification must be additive and reviewed with their current owners.

This change deliberately stacks on the compact owner workspace. Migrations
100 through 104 belong to the separate reviewed account/review train; pairing
resume uses 105 and hosted billing uses 106. This change reserves 107 and must
qualify against the complete frozen predecessor stack. It must not edit,
replace, renumber or weaken those migrations or their guards.

Required tests cover genuine registration and one-use verification, the foreign
registration/mail-recipient threat, other-browser password fallback, opaque
collision/decline cookies, password/email/membership/account/MFA changes, fixed
expiry and resend generation replacement, wrong-code budgets, Origin/CSRF
failure before body/database work, two-tab consumption races, existing-session
replacement refusal, the absence of auth/CSRF cookie writes and lost-reply/session recovery. Rendered tests use the
served forms and enforce real cookie/header contracts. Database and runtime-role
qualification are separate from synthetic browser fixtures; no provider,
deployment or live configuration operation is authorized by this document.
