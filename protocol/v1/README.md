# Protocol v1 contracts

The JSON Schemas pin metadata fields and event names for the simulator. [device-stream.md](device-stream.md) records the authenticated phone-to-hub handshake. Other contracts in this directory describe execution grants and inbound metadata. A customer-decryptable sealed-body format is still proposed and is not defined by these schemas.

Every event carries stable client message ID, attempt ID, device ID, session epoch, and deployment epoch. The phone journals a `submitting` intent before calling the Android radio API. On restart without conclusive callback evidence, it reports `unknown`; neither hub may issue a replacement grant automatically. A later callback can reconcile the state. A manual resend gets a new message ID and warns of possible duplication.

`recipient_digest` is a binding field, not an assertion that recipients are anonymous to the server. The eventual API still needs recipient metadata to route SMS and enforce suppression.

[inbound-foundation.md](inbound-foundation.md) defines the signed inbound storage and outbox contract. Optional inbound frames and webhook delivery have separate configuration and contracts.
