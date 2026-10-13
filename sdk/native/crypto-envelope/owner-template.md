# Candidate managed cold owner templates

Java 17, .NET 8 and Ruby 3.3 provide an explicit opt-in `OwnerTemplate`
client alongside the existing encrypted-template primitive. Construction sends
no request. The application supplies independently authenticated owner-session
cookie and CSRF values for the exact HTTPS origin, plus trusted current owner
binding and a verified profile-02 manifest. These are separate inputs; a signed
manifest alone does not establish an owner session or consent.

The captured binding includes account, device, line, interval, owner session,
binding generation, peer and both reader identities. Every operation requires
live owner authority and consent, an active phone key, and the role-2 reader with
workflow-context permission. Three current checks surround fetching, scope
validation and publication. Current root/enrollment, manifest version/digest,
comparison time, key expiry and caller-declared freshness bound the operation.
Session changes, closed clients and late callbacks cannot publish a snapshot.

A cold snapshot contains copied opaque ciphertext and its encrypted digest.
It does **not** authenticate the AEAD body, expose plaintext, acknowledge a save,
match a pending request, or authorize sending. Explicit opening remains in
`EncryptedTemplate`. Within one client, a lower revision or different bytes at
the same revision refuse. These are in-memory observations, not a durable
checkpoint or rollback-resistant store.

Only one GET is attempted per call. Redirects, automatic retries, proxy
environment variables and response cookie persistence are disabled. Java and
C# use a single TLS connection and explicit bounded HTTP/1.1 framing; Ruby uses
`Net::HTTP` with retries disabled. TLS hostname and chain verification remain
enabled; an optional additional trust bundle is an explicit application input.
Cookie and CSRF values are redacted from session display and failure messages.
No original-reply or workflow-output bearer credential participates here.

The default operation budget is 10 seconds; the caller may select 1–10000 ms.
At most eight workers are admitted. Closing or timing out settles the foreground
call but cannot terminate arbitrary trusted application callbacks: their worker
slots remain occupied until those callbacks actually finish. Reentrant reads on
the same instance refuse while it is busy. Applications must keep callbacks
bounded and avoid blocking their own authorization dependencies.

`TemplateStore.SaveRequest` is a pure helper that captures one request identity,
expected revision, exact encrypted bytes and required headers. Its receipt
validator requires exactly canonical `{"revision":N}` bytes, matching the
maintained owner client's stricter receipt check. This is stronger than the loose
low-level receipt JSON parser. The helper performs no save, acknowledgement,
reconciliation or retry; those state-machine APIs remain a separate slice.

## Reproduce source acceptance

Build the maintained TypeScript producer in clean checkout
`26e876da9f34372d9cf26511993cf633971e0037` with `npm ci --ignore-scripts`
and `npm run build` in `sdk/typescript`. Supply the clean shared runner checkout
`312e1e0ddfeee21a8af6f75d8c268c7e8346838f`:

```sh
python sdk/native/crypto-envelope/owner-template-run.py --language java --fixture FIXTURE --producer PRODUCER
python sdk/native/crypto-envelope/owner-template-run.py --language csharp --fixture FIXTURE --producer PRODUCER
python sdk/native/crypto-envelope/owner-template-run.py --language ruby --fixture FIXTURE --producer PRODUCER
```

Each runtime exercises 76 actual loopback TLS controls and 36 comparisons with
the maintained client, plus pure request/receipt checks and four admission and
close/recovery controls. Java/C# additionally exercise ten framing cases; Ruby
exercises chunked and orderly EOF framing through its standard library. Shared
controls include dropped connections with exactly one request, changed sessions,
late current callbacks, body deadlines, contradictory heads and opaque-body
semantics. Synthetic certificates and private fixture material stay in temporary
directories; no live owner session, database or provider is used.

The Java/C# test orchestration explicitly gives post-handshake body and callback
cases 1000 ms, with callbacks held for longer than that budget, an exact one-HTTP
assertion and a bounded no-result deadline. The separate 100 ms pre-dispatch
refusal stays unchanged. Ruby uses the shared 100 ms profile. This separates cold
TLS startup from the phase under test and does not change runtime defaults.
Source acceptance is not installed-package, hosted-CI or production approval.
