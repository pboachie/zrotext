# Protocol v1 contracts

The [device stream JSON Schema](device-stream.schema.json) defines the exact tagged JSON frames sent by the phone and hub on `/v1/device-stream`. Its examples are checked against the Rust wire types and validated against the schema in CI. [device-stream.md](device-stream.md) explains the authenticated handshake; [synthetic-alpha-stream.md](synthetic-alpha-stream.md) explains the opt-in send extension. The former `execution-grant.schema.json` and `message-event.schema.json` described obsolete metadata shapes and have been replaced by the stream schema. A customer-decryptable sealed-body format is still proposed and is not defined here.

The authenticated socket determines the device identity for `radio_event`; that frame carries `connection_epoch`, message ID and attempt ID, while a `synthetic_grant` also carries device ID and deployment epoch. The phone journals a `submitting` intent before calling the Android radio API. On restart without conclusive callback evidence, it reports `crash_without_callback`; neither hub may issue a replacement grant automatically. A later callback can reconcile the state. A manual resend gets a new message ID and warns of possible duplication.

`recipient_digest` binds the grant to the approved E.164 recipient. The `synthetic_grant` frame also sends the plaintext `recipient_e164` number and fixed test `body` to the phone.

[inbound-foundation.md](inbound-foundation.md) defines the signed inbound storage and outbox contract. Optional inbound frames and webhook delivery have separate configuration and contracts.

[sealed-inbound-prerequisites.md](sealed-inbound-prerequisites.md) records the separate event identity and default-closed line-binding storage foundation for future sealed inbound content. It exposes no sealed-content route.

[line-activation-contract.md](line-activation-contract.md) defines an internal, challenge-bound, dual-signature generation transition. It is not wired to a transport or a trusted owner-key bootstrap.

[vectors/ztse-draft-01.json](vectors/ztse-draft-01.json) contains public synthetic
bytes for the unapproved sealed-content draft. The TypeScript reader and test
instructions are in [sdk/typescript/README.md](../../sdk/typescript/README.md).
