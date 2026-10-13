# Candidate original-grant HTTPS transport

Rust `original_http::OriginalHttp` and Go `OriginalHTTP` make one direct HTTPS
POST to `/v1/reply-events`. They accept a fresh canonical original-reader grant
per call, a positive accepted manifest version, and a closed request shape.
Supported methods are current, page, read, status, and owner-review consumption
with a null proposal descriptor. They never accept an owner credential or attach
an output workflow credential. Proposal consumption requires a later native
workflow-validation integration and is unavailable here.

The returned `UntrustedWire`/`OriginalWire` is raw **untrusted JSON**. HTTP success
does not authenticate a proof, authorize a reader, validate consumption identity,
or advance an accepted-history checkpoint. This transport must not release
plaintext or drive effects until a verified client performs those steps.

Origins are ASCII HTTPS authorities with an optional single trailing slash;
userinfo, other paths, query, fragment, whitespace and backslash refuse. TLS uses
normal certificate and hostname verification (TLS 1.2 minimum). Optional extra CA
PEM must come from independent application trust configuration. There is no
insecure TLS option. Environment proxies, redirects, cookies, connection reuse
and automatic request retries are disabled. All requests are POST; the Go body
has no replay callback. Rust explicitly disables the reqwest retry policy.

The configured timeout is 1–10000 milliseconds and includes response-body reads.
Rust sets the timeout on the request itself so the underlying asynchronous body
retains a total deadline, in addition to blocking operation bounds. Go uses both
the request context and HTTP client deadline. Requests are bounded to 4096 bytes;
responses to 524288 bytes. Non-success status, truncated/oversized/invalid UTF-8
or JSON, duplicate/extra top-level fields, or mismatched result kind refuse.
The inner result remains untrusted and requires its own closed-schema validation.

Pre-dispatch shape/credential failures return only `unavailable`. A dispatched
consumption whose response fails returns only `unknown`, including connection or
TLS failure where delivery cannot be established. Callers must reconcile the
same consumption ID with status; there is no implicit replay. Other transport
failures return `unavailable`. Neither error exposes a URL, token, response body,
nor an underlying library error. Grant/header memory follows the HTTP libraries'
ordinary lifetime; this API does not claim guaranteed secret-memory erasure.

Go requires 1.26.9 for this candidate's existing SQLite dependency; Rust requires
1.97.1. Rust adds the public reqwest 0.13.5 dependency already used by the server
for TLS and request deadlines, and promotes the existing JSON/base64 test
dependencies to runtime. It uses no Tungsten runtime or private dependency feed.
Rust is a blocking API: call it from a blocking thread, not inside an asynchronous
runtime. The transport is stateless with respect to grant authority; the verified
client must serialize its own checkpoint and consumption operations.

`test-original-http.py --binary <native probe>` creates disposable local TLS
certificates and synthetic credentials under a temporary directory. It checks
all five methods, raw request fields/auth, ignored environment proxy, single
attempts, unknown consumption outcomes, redirects, invalid/truncated responses,
slow streaming body deadlines, and zero requests for invalid inputs/untrusted
TLS. These are synthetic transport tests, not deployed grant/provenance evidence,
and not installed-package acceptance of this new capability.
Managed native runtimes may use `--command-file <trusted-local-json-argv>` instead
of `--binary`; this executes an explicit argument array without a shell. The
command file must be trusted test configuration, never HTTP response data.
