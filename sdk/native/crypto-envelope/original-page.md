# Candidate authenticated original page discovery

The Java `OriginalCurrentClient.page`, C# `PageAsync` and Ruby `page` methods
perform one bounded HTTPS page request. They return immutable captured event
metadata and a next cursor only after the existing current proof verifier has
authenticated the enrolled scope and signed manifest history and durably
advanced the checkpoint. These are experimental source companions. Package
publication and installed-consumer qualification are separate gates.

Each request accepts a limit from 1 through 32 and an optional captured cursor
with a canonical nonzero UUID and positive safe-integer acceptance timestamp.
Invalid inputs refuse before HTTP. The response has a closed shape, at most the
requested number of events, unique event IDs, bounded unique active-request IDs
and one of the three maintained dispositions. Events must follow the exact
server ordering: acceptance time followed by UUID bytes, strictly after the
requested cursor and previous row. A full page must return its final row as the
next cursor; a shorter page must return null. No automatic prefetch or pagination
loop is performed.

Discovery metadata is not a verified ciphertext, read permission, consumption
receipt, STOP authority or permission to propose a workflow action. An
application must invoke the appropriate independently guarded operation for
effects. Client exclusivity, callback reentry refusal, durable local comparison
floors and persistence poisoning are shared with `original-current.md`.
Authentication failures expose no server response or credentials. The trusted
private checkpoint still has no hostile whole-file rollback protection.

Run `original-page-run.py --language java|csharp|ruby --fixture <fixture-checkout>
--producer <producer-checkout>` after building the producer TypeScript package.
The exact clean signed TLS fixture pin is
`e3ed703a2c5eb0f72fc4138fade0859637dff3d5`; its maintained producer pin is
`72124e1a3ff28e782f870eeddbdc33cacf8ca3b4`. The shared 47 cases cover empty/full
pages, exclusive equal-time UUID cursors, malformed metadata, duplicate IDs,
incorrect next cursors, signed proof rejection and local clock rollback.

The ordering and full-page next-cursor checks additionally enforce the public
server's `original_reply/page.rs` contract. The maintained TypeScript client
validates metadata shape and uniqueness but does not itself enforce every one
of these ordering checks. This stricter response acceptance is deliberate.
The dedicated workflow uses Windows/Linux software execution. No protected-key
operation, live service, server configuration or credential issuance is involved.
