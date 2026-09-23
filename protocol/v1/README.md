# Protocol v1 M0 contracts

These JSON Schemas pin metadata fields and event names for the simulator. They do not define an authenticated device protocol, wire encoding of grants, signed event format, or sealed body format. The server does not expose message endpoints yet. M1 must add authentication, durable writer transactions, replay checks, and conformance vectors before using these objects on a network. M2 specifies encrypted content only after review.

Every event carries stable client message ID, attempt ID, device ID, session epoch, and deployment epoch. The phone journals a `submitting` intent before calling the Android radio API. On restart without conclusive callback evidence, it reports `unknown`; neither hub may issue a replacement grant automatically. A later callback can reconcile the state. A manual resend gets a new message ID and warns of possible duplication.

`recipient_digest` is a binding field, not an assertion that recipients are anonymous to the server. The eventual API still needs recipient metadata to route SMS and enforce suppression.
