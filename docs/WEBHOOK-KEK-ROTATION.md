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
   active/secondary key variables. Then run `--apply`. The command holds one
   advisory lock, rewraps at most 100 rows per transaction, and reports only
   counts and the new version. An unknown version or unauthentic ciphertext
   stops the run without changing its current batch. It never sends webhooks.
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
resuming it. Do not delete the old KEK based solely on the CLI count.
