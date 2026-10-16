# Authoritative setup observations

Apply migration `105_device_pairing_bindings.sql` after the complete preceding
numbered migration chain before running these endpoints.

`GET /v1/account/setup` requires the current owner session and its matching
CSRF header. Responses are `no-store`; observers, expired/revoked sessions,
disabled accounts and standby observations are refused. Account, user,
membership and session rows remain share locked while observations are read,
and the session deadline is checked again before returning.

The version 1 object contains `schema_version`, `account_id`, `session_id`,
`observed_at_ms`, `sms_line_activation_available`, `pairings`,
`line_activations`, `devices`, and `truncated`. Each array is bounded to 50
records; `truncated` means more records exist and the UI must not interpret an
omission as an absence. Existing paginated device and line endpoints remain
available for account-wide administration. No token, nonce, private key,
signature or checkout URL is restored from this endpoint or browser storage.

Pairing observations include the public ID, name, timestamps and current
status. Only an unexpired proof-verified pairing awaiting explicit owner
approval includes the comparison code and fingerprint. The owner must still
compare those exact values independently with the phone before approval.
Approved phone records preserve the public source pairing ID after normal
pairing pruning. This recovery locator is immutable and never a bearer secret.

Phone observations include the current key fingerprint, revoked flag and
`line_activation_version` (1, 2 or null). A version is reported only from the
current authenticated writer/site/deployment lease. `setup_line_id` and
`setup_opening_id` are deterministic public locators for the default SMS line
and the next current-session opening, eliminating manual UUID entry and
letting tabs converge. An existing unfinished ceremony uses its returned
opening ID; a fresh opening is never inferred while an outcome is unresolved.
These identifiers confer no authority and are accepted only through the
existing authenticated, locked v2 activation protocol.

Line observations include public line, challenge, opening and device IDs,
decimal-string generation, expiry, `same_session` and current stored status.
Clients reload the existing v2 view before signing; observation metadata is not
an approval transcript or evidence of current SIM readiness. An original owner
session change or phone connection epoch change requires a fresh declaration
for the affected step. Account, subscription and enrolled phone remain valid.
An approved line receipt means approval was recorded; local SIM currentness,
installation, delivery readiness and carrier tests retain their separate gates.

The existing disabled SMS activation flag remains authoritative. With it off,
the endpoint returns no line ceremonies and no actionable capability version.
It does not enable the flag or bypass ownership, enrollment, billing or dispatch
checks.

# Configured TEST plan metadata

When existing TEST hosted sessions are explicitly enabled, startup validates
the single configured Stripe TEST price with a bounded, timeout-limited,
redirect-free provider read. Only an active, fixed, licensed recurring TEST
price matching the configured ID can create the private verified catalog
capability. Amount, currency and recurrence come from that response; allowance
and device cap come from the matching configured TEST quota mapping. There are
no default commercial prices or plans. Invalid or unavailable metadata fails
startup for this explicitly enabled TEST session adapter.

`GET /v1/billing/plan` returns the verified startup snapshot with exact fields
`schema_version`, `mode` (`test`), `currency`, `unit_amount`, `interval`,
`interval_count`, `outbound_limit`, `device_cap`. The last two may be null when
no quota mapping exists. This route creates no customer, subscription or
entitlement. Checkout continues to accept no browser-selected price, account,
customer or return URL.

`GET /v1/service/availability` is mounted in the runtime. TEST checkout is
advertised only with that verified catalog and its actual mounted adapter.
Registration visibility continues to require the configured ready verification
dispatcher and explicit registration policy. Self hosting advertises disabled
billing. This legacy TEST capability cannot prove or substitute for a LIVE
hosted namespace gate. LIVE payment transport remains a separate implementation
and deployment acceptance gate.
