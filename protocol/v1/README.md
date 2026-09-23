# Protocol v1 contracts

The JSON Schemas pin metadata fields and event names for the simulator. [device-stream.md](device-stream.md) records the implemented M1 authenticated heartbeat handshake. It carries no message commands or radio events. The schemas still do not define wire encoding of grants, signed event format, or sealed body format. The server does not expose message endpoints yet. M2 specifies encrypted content only after review.

Every event carries stable client message ID, attempt ID, device ID, session epoch, and deployment epoch. The phone journals a `submitting` intent before calling the Android radio API. On restart without conclusive callback evidence, it reports `unknown`; neither hub may issue a replacement grant automatically. A later callback can reconcile the state. A manual resend gets a new message ID and warns of possible duplication.

`recipient_digest` is a binding field, not an assertion that recipients are anonymous to the server. The eventual API still needs recipient metadata to route SMS and enforce suppression.

[inbound-foundation.md](inbound-foundation.md) defines the disabled-by-default
ZT-008 signed storage and outbox contract. It is not an enabled inbound wire
frame or webhook sender.
