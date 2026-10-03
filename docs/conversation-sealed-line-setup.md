# Sealed line setup startup

`SEALED_LINE_SETUP_ENABLED` is an independent server opt-in, defaulting to
`false`. Both Compose server services forward the flag with that default.
It does not enable carrier dispatch or grant content-transfer authority.

Enabling it requires `CONVERSATION_ENABLED`, the existing authenticated root
custody opt-in, an available MFA cipher, and startup outside MFA recovery-only
mode. The conversation SDK package and WSS origin remain mandatory. Missing
account routes or any prerequisite fails startup rather than mounting a
partially configured setup surface.

The explicit setup router validates the complete installed registration and
activation-exchange schema before returning. Schema installation is performed
by the ordinary migrator, never by a request handler or retention worker.

The opt-in reserves one additional worker-class database slot. Configurations
that exceed the shared worker budget fail startup. The bounded retention lane
uses the process drain flag and notification; it preserves immutable receipts
and removes only expired public challenge state. Disabled setup neither mounts
its routes nor starts this retention lane.

Root enrollment, line registration, owner activation and phone installation
acknowledgment are distinct decisions. None replaces separate phone and browser
content consent, current reader authority, or exact confirmed-send authorization.

The enabled authenticated device socket carries separate `sealed_line_challenge`,
`sealed_line_proof`, `sealed_line_proof_ack`, `sealed_line_activated`,
`sealed_line_installed`, and `sealed_line_install_ack` frames. Every frame binds
the current connection epoch. The phone proof uses the SEALED line domain and
requires Android API 31 or later and one explicitly selected active subscription;
the SMS line proof domain and its lower API floor cannot substitute for it.
The public device-stream schema includes synthetic examples of these frames.
Runtime checks additionally enforce integer representation bounds and verify
canonical signatures, current account and
device authority, expiry, and the exact signed statement and signature digests.

Sending an activation acknowledgment does not retire it. The socket repeats it
until the phone confirms the exact installed receipt. The phone requires an
independent local line approval, installation in its durable binding journal,
and successful storage of the exact public signed provenance before sending
that confirmation. Missing provenance, storage failure, cancellation, changed
SIM or signing identity, stale session, and expired proof fail closed. Restart
requires fresh local approval and authentication; receipt recovery grants no
body-transfer consent, content readiness, or send permission.

The draft schema uses provisional migrations `086_sealed_line_key_registration.sql`
and `087_sealed_line_activation_exchanges.sql`, in that order. Final numbering
belongs to the coordinator before merge. These files do not enable setup or
carrier dispatch; request handlers never install a schema.
