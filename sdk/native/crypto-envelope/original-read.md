# Candidate verified original HTTPS reads

The Java, C# and Ruby original current clients now combine the bounded HTTPS
transport, accepted-history checkpoint and selected original reader. These APIs
are experimental source companions. They do not publish packages or establish
service availability, consume permission, workflow authorization or perpetual
read authority.

`readSoftware` / `ReadSoftwareAsync` / `read_software` accepts an explicitly
exportable native key. Java `readWithRecipient` and Ruby `read_with_recipient`
accept trusted application adapters (including the qualified native protected
recipient); C# `ReadProtectedAsync` accepts its concrete protected recipient.
Generic adapters make no custody claim. Callers own key lifetime and trusted
clock/credential inputs.

The operation captures the requested event and selects an independently retained
baseline within the 32-manifest service window. Zero chooses the oldest eligible
retained version; an explicit unknown baseline refuses before HTTP. The closed
response must match the event, scope and authenticated manifest proof. Cached
overlap must retain the signed unsigned-manifest identity, and new history cannot
end behind the current checkpoint. Signed acceptance timestamps use the narrow
original-grant 30-second allowance described in `original-current.md`; local
comparison floors remain monotone and durable.

After durable proof acceptance, the reader verifies the historical manifest,
activation, dual signed selection and exact ciphertext routing/wrap set. Native
HPKE and AEAD produce plaintext only within the reader's guarded operation. A
second real HTTPS current request, signature verification and durable acceptance
run after AEAD and before plaintext returns. Revocation, expiry, scope changes,
checkpoint conflict, transport failure and cancellation refuse. The result binds
the plaintext to the event, ciphertext SHA-256, requested accepted baseline and
final transient authority snapshot. It is not a consumption receipt.

Only one operation may run per client, including callbacks; clock callback
reentry refuses before another request. Failed persistence poisons the client.
The checkpoint remains a trusted private-path, checksummed journal, without
hostile whole-file rollback resistance. Java/C# immutable plaintext strings and
runtime/crypto internals cannot promise erasure. Ruby clears its owned mutable
plaintext on failure before transfer. C#'s native reader callback synchronously
waits for the final asynchronous request; its internal awaits avoid context
capture and preserve the cancellation token.

## Repeatable acceptance

`original-read-run.py --language java|csharp|ruby --fixture <read-fixture-checkout>
--producer <producer-checkout>` builds native consumers and executes 33 genuine
signed TLS read cases. The exact clean fixture pin is
`d127e5c86f3b17db371acc608eedcf6419264ba7`; the maintained TypeScript producer pin
is `72124e1a3ff28e782f870eeddbdc33cacf8ca3b4`. Build the producer with its locked
TypeScript dependencies first. Java uses the pinned Gson dependencies from the
HTTP runner; C#/Ruby use platform JSON/HTTP. CI exercises software acceptance on
Windows and Linux, and makes no hardware claim.

On a supported Windows protected-provider host, add `--hardware`. Java also
requires `--jna <JNA-5.17.0.jar>` with the checked dependency hash. Four controls
cover protected positive opening, final proof rejection, authenticated ciphertext
mutation and an injected fixture-setup failure. Each child records its exact
owned alias before creation, supplies only its public point to the independent
producer, refuses a supplied selected scalar, and deletes only its created key.
Deletion must refuse reopen; the private receipt is replaced with a durable
deleted marker. Harness exceptions close stdin and allow native cleanup before
bounded termination. No preexisting keys, provider settings or live service
credentials are used.

Page discovery, consume/status recovery and installed-package qualification of
these new read APIs remain separate tracked work. Existing current-proof and
checkpoint APIs retain their prior contracts.
