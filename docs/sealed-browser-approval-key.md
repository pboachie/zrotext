# Retained sealed browser approval key

The source helper `SealedApprovalKeyStore` retains the exact nonextractable
P-256 sealed line approval key through IndexedDB structured cloning. It uses a
separate database and purpose from ordinary SMS approval and account root custody.
The existing sealed line setup exposes this as a separate, unchecked local-retention choice. Session-only setup remains available. This mount does not add profile03 election or change the original line protocol.

An embedding must obtain explicit browser-local retention consent for a genuinely
new sealed registration. `create(scope, {retain: true, newRegistration: true})`
commits its first key atomically, then reads it back and proves possession against
the public point before returning. No server registration action may precede this
completion. A second creator cannot overwrite the winner. The store keeps at most
128 records, with no eviction or automatic replacement.

The immutable scope contains the canonical HTTPS origin, account, original user,
device, line and independently compared root fingerprint. Session IDs are omitted
so the same authenticated user can reuse the original key after signing in again.
This does not remove server authentication, current membership or MFA checks.

To reuse a key, independently verify its original sealed registration, then call
`load(scope, originalApprovalFingerprint)`. Missing, corrupt, cross-scope,
extractable or substituted keys refuse. Never turn a failed load into `create`.
If creation's outcome is interrupted, explicitly reconcile `metadata(scope)` and
the original registration. Public metadata is not server authority. Loss of the
browser database requires the application's explicit existing-key recovery or a
separately approved new registration; this helper cannot reconstruct a lost key.

A lease's `withKey` callback is trusted application code and can use the existing
key. The embedding must bind the exact registration/election transcript and verify
current authorization before and after asynchronous operations. A local key or
signature is not proof of database acceptance, current owner status, reader
availability or SMS permission. Closing the store, changing origin or aborting its
lifetime suppresses late results. Closing releases live key references but retains
the committed record. Passwords, authenticator factors, private exported bytes and
message content are never stored here.

Source tests exercise actual structured-clone persistence, public-point
possession, concurrent creation, abort after request success, corruption,
cross-scope substitution, closure during work and the capacity bound. Browser
platform persistence, server integration and a physical phone remain separate
qualification requirements.
