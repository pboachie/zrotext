# Exact creator-session recovery

`DELETE /v1/auth/sessions/{session_id}` uses the existing authenticated member
mutation boundary: session cookie, exact configured HTTPS Origin, double-submit
CSRF, current unlocked membership and account. The existing revocation library
restricts the target to that account and authenticated user. A different user's
or account's target has no effect. The response is idempotent `204`, which does
not reveal whether a foreign target exists. There is no request body or bulk
revocation option. The exchange schema/vector validates only shape; it cannot
prove authentication, ownership, revocation or current grant authority.

Workflow grants remain bound to their issuing session. Revoking that session
invalidates its grants without changing grant scope or making another session
its creator. Guided recovery records only nonsecret account/user/session IDs
before issuance, requires those account/user IDs to match the fresh login, and
keeps the intent on an unknown response. Only a confirmed response permits
custody/receipt cleanup. A later explicit idempotent recovery can resolve a lost
response. Setup does not automatically issue another grant.
