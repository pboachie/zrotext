# Explicit root custody setup

`ROOT_CUSTODY_ENABLED` defaults to `false`. An operator may expose the existing
`/v1/auth/sealed-root/challenge` and `/v1/auth/sealed-root` ceremony only after
applying its schema, configuring the account routes and matching
`MFA_ENCRYPTION_KEY_B64` on every account-serving instance. Missing account/cipher configuration fails startup; this switch does not
perform a custody-schema readiness check. `MFA_RECOVERY_ONLY=true` omits the cipher and cannot
be combined with this opt-in. Forward the same setting to both Compose apps.
This switch does not enable conversation capture or SMS dispatch.

The owner must explicitly create or select an existing supported custody bundle,
perform the recovery check, and independently compare its account/origin-bound
fingerprint. The existing offline owner tool supports `init`, `restore-check`
and, in its explicit `unlock` build, signing an enrollment challenge. It does
not yet expose the additional custody-transcript signature required by the
HTTP completion route; that signing bridge remains an integration gap. Key
creation must be initiated by the owner; operators must not generate owner keys
or fabricate comparison evidence. Retain the recovery material outside the
service. A login or device pairing is not this trust decision.

The authenticated owner submits the public root pin, encrypted backup and public
card with the independently compared fingerprint to the challenge route. Completion requires signatures over that exact returned challenge and
custody transcript from the verified existing root, followed by the ceremony with the current session,
same-origin CSRF proof and MFA code. Handlers continue to enforce account,
origin, root generation, challenge expiry and one-use completion. Never send
root private keys, recovery tokens or plaintext backups to the service.

Only then can separately approved phone/archive readers and their signed
manifest establish conversation authority. The conversation SDK mount already
exists: its separate `CONVERSATION_ENABLED`, validated WSS origin and verified
SDK asset directory must be configured. Browser setup still requires the exact
independently accepted root/manifest checkpoint. Phone content-transfer consent,
browser approval, completed activation and exact reply confirmation are further
requirements. Exposing root custody alone does not complete these steps.

The operator flag is implemented; a single ordinary-user setup journey that
assembles initial reader authority is a separate integration requirement. Do
not describe root enrollment or conversation readiness as completed merely
because these routes are reachable. Simulator credentials do not establish
production custody or carrier delivery.
