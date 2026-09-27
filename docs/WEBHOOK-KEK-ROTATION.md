# Webhook endpoint KEK rotation

This procedure changes the operational key that encrypts webhook endpoint
signing secrets in PostgreSQL. It does **not** rotate the signing secret shared
with a receiver. Keep the old and new KEKs, database URL, backups, and exact
site inventory in private operator storage outside the repositories.

The application accepts an active `WEBHOOK_KEK_VERSION`/`WEBHOOK_KEK_B64` pair
and an optional `WEBHOOK_KEK_SECONDARY_VERSION`/
`WEBHOOK_KEK_SECONDARY_B64` pair. Versions must be distinct positive integers;
both keys must be different 32-byte values encoded in standard base64. New
endpoints and owner signing-secret rotations always use the active key. A
stored endpoint can be read with either configured version. Unknown versions
and failed authentication cannot send a webhook or enable an endpoint.
Migration 015 records a keyed commitment for each version. Startup rejects a
site whose bytes disagree with an already registered version, even when no
endpoints exist. This commitment check is the fail-closed startup gate and
must pass on both sites during each stage.

Startup does not open every stored endpoint secret, so one damaged or
foreign row cannot stop the whole server. After startup, each site runs a
read-only background sweep that opens every stored endpoint secret and logs
the endpoint ID of each one it cannot open (at most 100) as
`webhook_endpoint_key_unreadable endpoint_id=...`, followed by a
`webhook_endpoint_key_audit checked=... unreadable=... listed=...` summary.
The lines contain no ciphertext, secret, or key material; a clean sweep logs
nothing. The sweep changes no rows. Deliveries for an unreadable endpoint are
deferred as described below and are not lost; the endpoint cannot be enabled
until it opens. Repair the key ring (for example, restore a secondary key that
was removed too early) and restart, or have the owner rotate that endpoint's
signing secret, which disables it and retires its queued deliveries.
The `--check` preflight below remains the fail-closed decrypt check: run it
before removing any key.

## Coordinated two-site change

1. Take and verify an encrypted database backup. Generate a fresh KEK and a
   previously unused version in private operator storage. Preserve the old KEK
   until the final step.
2. Deploy both sites with the **old key active** and **new key secondary**.
   Confirm both sites have replaced their prior processes. This prepares every
   site to read ciphertext that a newer process may write.
3. Deploy both sites with the **new key active** and **old key secondary**.
   Confirm every old-active process has drained. Endpoint creation and owner
   signing-secret rotation now write the new version.
4. Run `zrotext-webhook-kek-rewrap --check` with `DATABASE_URL` and the same
   active/secondary key variables. The check is read-only and requires both
   versions to have been registered by application startup. It validates the
   key commitments and decrypts every stored endpoint, then reports the count
   requiring rewrap. If any endpoint cannot be opened it fails and prints the
   IDs of up to 100 such endpoints (no secrets). Run `--apply` only after this
   succeeds. The command holds
   one advisory lock, rewraps at most 100 rows per transaction, and reports
   completion without logging processed rows or key material. An unknown
   version or unauthentic ciphertext stops the run without changing its
   current batch. It never sends webhooks.
5. Run `--check` again and require zero remaining rows. Inspect the database
   and app health on both sites. Retain the old secondary key until all
   old-active processes and in-flight leases have drained; then remove the
   secondary pair from both sites. Verify endpoint enable and a controlled
   synthetic delivery during a separate authorized test.

Each endpoint row is locked while its ciphertext is replaced, so owner
signing-secret rotation and rewrap serialize on that row. The endpoint's
signing secret stays the same; a queued delivery loads the current endpoint
row when it gets a lease. An already loaded in-flight payload may still use
the old ciphertext during rollout, so both versions must remain readable on
all sites until the drain is complete. If a site cannot read the active
version, leave delivery disabled there and restore the staged key ring before
resuming it. A later key-open failure defers the delivery for five minutes
without using a send attempt; `webhook_deliveries.key_failure_count` records
repeated failures for operator repair. Do not delete the old KEK based solely
on the CLI count.
