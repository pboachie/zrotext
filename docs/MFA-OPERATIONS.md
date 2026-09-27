# Owner MFA deployment and recovery

Owner TOTP enrollment is disabled by default. `MFA_ENROLLMENT_ENABLED=true`
requires `MFA_ENCRYPTION_KEY_B64`, an independently generated 32-byte key
encoded as base64. Store the key in the operator secret store and backups, and
give every account-serving site the same value. Never log or place it in the
repository. The auth token pepper is separate and must also remain stable;
recovery-code verifiers depend on it.

To introduce MFA, first apply the numbered database migrations. Deploy binaries
that understand MFA and the key to every account-serving site while enrollment
stays off. Drain and remove every older binary before setting
`MFA_ENROLLMENT_ENABLED=true` on the new sites. An older binary can issue a
password-only session for an MFA-enabled owner, so do not enable enrollment
during a mixed-version rollout. Verify that each site starts and reaches
`/readyz` before opening enrollment.

At startup, each account-serving site checks every enabled owner secret against
its configured key. A missing or mismatched key prevents startup when enabled
owners exist. With no enabled owners, an unset key is accepted only while
enrollment remains off. Keep the key available across restarts and restores.

If the encryption key is unavailable, set `MFA_RECOVERY_ONLY=true` and keep
`MFA_ENROLLMENT_ENABLED=false` on the affected site. This explicit mode ignores
the TOTP key: an owner can complete login with an unused recovery code and can
disable MFA with their password and another unused recovery code. TOTP and
enrollment are unavailable. This mode does not recover accounts that have also
lost their recovery codes or auth pepper. Once a valid key is restored, turn
recovery-only mode off and restart; the startup check must pass before normal
service resumes. Plan key rotation as a separate migration, not an ad hoc
replacement of `MFA_ENCRYPTION_KEY_B64`.

## Factor failure budgets

Each MFA owner has two independent budgets of five rejected factors (a wrong
TOTP or recovery code) per 15 minutes. When a budget is spent, requests it
guards get 429 until its window ends, even with a correct code.

- The **sign-in budget** is stored on the owner's MFA row and guards only the
  second step of sign-in. Anyone holding the owner's password can spend it, so
  a successful sign-in factor clears it. Each sign-in challenge also allows at
  most five attempts, and the challenge token has its own request budget.
- The **step-up budget** is stored in the shared auth abuse counters, keyed by
  the owner, and guards factors presented from a signed-in session: password
  change, revoking other sessions, confirming or disabling MFA, and owner
  step-ups such as SMS-line approval key changes. Only a live owner session can
  spend it.

Sign-in failures therefore cannot stop a signed-in owner from changing the
password, revoking sessions or disabling MFA. They can still delay a new
sign-in for up to 15 minutes; an owner who suspects the password is known
should change it from an existing session. Neither budget is reset by an
operator password reset.
