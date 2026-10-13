# Candidate original-grant HTTP transport

Java `OriginalHttp`, C# `OriginalHttp`, and Ruby `ZrotextCandidate::OriginalHTTP`
provide a bounded wire transport for original-grant `current`, `page`, `read`,
`status`, and owner-review-only `consume`. This is experimental companion source,
not yet part of the installed native packages. The transport returns explicitly
**untrusted JSON**. It does not verify grant proofs, commit accepted history,
authorize plaintext, or establish full original-reply client compatibility.

The application configures a literal HTTPS origin and a total deadline of 1 to
10,000 milliseconds. Paths other than `/`, user information, whitespace, query
parameters and fragments are refused before network access. Each call takes a
canonical original-grant credential and a closed request description. No output
credential, owner credential, arbitrary RPC name or automatic descriptor is
accepted. Consume always sends `descriptor: null`; the caller retains its request
identity and must reconcile an uncertain outcome separately.

TLS uses platform trust and hostname verification. Independently trusted PEM CA
roots may be added by the application; a certificate returned by the service is
not a trust configuration. The transport bypasses environment proxies, cookies
and automatic redirects, uses HTTP/1.1, and performs no application retry. Ruby
disables Net::HTTP retries; Java and C# additionally refuse a second publication
of the request body. Java refuses the global setting that enables all-method
HTTP retries. Caller cancellation/deadline after a consume attempt cannot prove
that the server did not execute it.

The deadline covers streaming response receipt, with at most 524,288 bytes,
strict UTF-8, bounded JSON nesting, and an exact `kind`/`result` envelope matching
the requested method. Top-level duplicate or extra fields, malformed JSON,
non-JSON content types and non-success HTTP responses are refused. Nested result
content still requires a separate canonical proof verifier. Errors contain no
response body, credential, transport exception or URL. Failures after attempting
consume report `unknown`; invalid input before dispatch reports `unavailable`.

Java requires Gson 2.14.0 for its strict streaming JSON parser; no reflection-based
object binding is used. The source runner verifies exact Maven Central JAR
hashes for Gson and its Error Prone annotations dependency. C# and Ruby use their
standard JSON and HTTP libraries.

## Acceptance

Run `original-http-run.py --language java|csharp|ruby --fixture CHECKOUT`, where
`CHECKOUT` is the clean shared native transport fixture commit
`78a3900ed1fea531c3fbe894696ee19805e0f1c9`. Java needs a JDK supporting release 17,
C# needs .NET 8, and Ruby uses 3.3.9. The Python fixture requires cryptography.
Use `--ruby PATH` to select a portable interpreter.

The same 45 local TLS controls exercise each compiled/interpreted companion:
all five closed methods, authentication confinement, ignored proxy configuration,
untrusted TLS roots, invalid input before dispatch, one observed request on
connection loss, redirects, wrong response identity, malformed/duplicate/extra
JSON, invalid UTF-8, oversize/truncated bodies and a slow streaming deadline.
The fixture creates ephemeral keys and credentials only in temporary storage.
Two additional controls use a trusted CA with an incorrect server hostname and
require refusal before any application request for current and consume.
A third control requires empty user information in an origin to fail preflight,
including for consume, without classifying it as an attempted operation.
These are synthetic transport checks, not a live service or registry release
qualification. Proof verification and checkpoint integration remain separate.
