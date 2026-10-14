# Reviewed template authoring

Java `OwnerTemplate.Authoring`, C# `OwnerTemplate.Authoring`, and Ruby
`OwnerTemplate::Authoring` own one immutable local draft lifetime and a concrete
persistence client. Construction is dormant. `prepare` validates and copies
canonical template content, independently rereads the host draft epoch/revision
and current owner/session authority, consumes an exact local review decision,
seals with the selected public recipient, and prepares one ciphertext ticket.
Only true accepts the draft review. Preparation performs no HTTP.

The host supplies `DraftState` containing positive epoch/revision and a live
custody lease flag. That flag is an application fact, not proof of protected
provider qualification: public-key sealing does not need a private recipient.
The host must invalidate on input, navigation, owner, or custody changes. Current
callbacks must supply independently verified manifests and live permission;
immutable signed history alone is insufficient.

The returned ticket belongs to `author.client`/`author.Client`. The caller must
explicitly commit through that client. Existing sticky uncertainty, exact retry,
GET reconciliation, and no-read-acknowledgment semantics remain in force. A
second prepare refuses without destroying the first ticket. Admission precedes
one-shot state inspection; a losing authoring operation preserves another
caller's reviewed or unknown record, including preparation while local review
is blocked. Error cleanup only closes an exact owned record or an empty idle
client. Explicit lifecycle close still closes the whole owned client.

The original authoring deadline caps the successfully prepared ticket and its
client's future operations. A close timer also ends the lifetime, but operation
checks enforce expiry even when that timer is delayed. No new operation renews
the authoring lifetime. Owned canonical and ciphertext working buffers are
cleared; immutable template/preview strings cannot guarantee physical erasure.

`template-authoring-run.py` compiles isolated consumers and uses a pinned shared
synthetic TLS suite and maintained TypeScript authoring oracle. Successful
explicit commits are independently decrypted by maintained TypeScript. Tests
cover review refusal, draft/session/current changes, concurrency, retained
foreign records, deadline expiry and no automatic POST. These source checks do
not establish installed package acceptance, live owner integration, protected
custody qualification, or complete legacy SDK parity.
