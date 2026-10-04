<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Android candidate sealed stream execution

Ordinary service startup continues to offer only device status protocols. The
candidate path requires a process-only `SealedExecutionMount` installation with
`enabled=true`, an existing payload key, and independently owner-provisioned
manifest/request authority. No preference, intent extra, bootstrap input, or
cold-start recovery installs this lease. Owner provisioning and physical-device
acceptance remain separate work; this path is not a release activation.

When explicitly installed, the ordinary authenticated service offers sealed
dispatch v2. Its fresh nonce time sample binds the already authenticated account,
device, connection epoch, deployment epoch, and per-socket session identity.
The phone uses elapsed time and a conservative network upper bound, never its
wall clock. A later sample with a shorter round trip retains the earlier
conservative bound; it cannot restore lifetime to an expired operation. A sample
below the prior server-send time plus elapsed time still refuses as rollback. Samples expire after 60 seconds, replies take at most two seconds,
and refreshes neither renew the five-minute readiness window nor an execution
grant. Reboot, stale sessions, rollback, identity changes, and unavailable samples
refuse execution. A finite sample budget requires a new authenticated socket.

The phone signs the complete immutable grant with its existing hardware enrollment
key and fetches its exact ciphertext from the same HTTPS origin. There is no
bearer credential, redirect, cookie, cache, fallback, or automatic wire retry.
Known foreign grant headers refuse before retrieval or signing. The existing
executor binds the ciphertext digest, current device reader, selected line/card,
owner manifest/request, and expiry, then records its permanent preparation replay
fence before hardware decryption.

Prepared plaintext enters the shared durable intent, exact writer acknowledgment,
selected-card/suppression checks, and one-use Room radio-start CAS. Current local
authority is checked again after waits and before consumption and invocation.
Socket teardown fences future consumption. Prepared buffers close on every path;
Android string APIs still create transient copies that cannot be reliably wiped.
An acknowledgment or platform call is not carrier delivery. Lost acknowledgment,
crash, expiry, withdrawal, permission/key loss, or an ambiguous platform result
never triggers a retry. Retained preparation rows also prevent the ordinary alpha
event pump from resending a sealed intent after restart.

JVM fixtures replace hardware custody and the platform driver; they do not send
SMS and do not prove hardware or carrier behavior. A physical-device run requires
separate explicit opt-in on a controlled device.

The internal existing-key custody scope keeps one payload lifecycle record access
and its file lock through the operation and a final fresh key/public-identity
reload. It checks the pinned key ID, public point and observed security level,
then expires on every exit. Its facade exposes only copied public metadata and
local revalidation, with no private handle or decryption operation. Nested
key-store entry refuses before a device monitor is acquired; scope use from
another thread or after completion refuses. Enrollment and revocation continue
to use the ordinary device-to-record lock order.

This scope is a local custody observation. It does not check owner, manifest,
consent, capture or execution authority, release plaintext, select an HPKE
profile, or install a receiver provider. AndroidKeyStore agreement still
requires API 31 or later; the application's API 28 floor is unchanged. Provider
integration and physical key-custody acceptance remain separate gates.
