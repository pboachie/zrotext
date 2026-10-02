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
