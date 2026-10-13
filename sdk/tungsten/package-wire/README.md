# Installed native archive wire contracts

`package-native.py` builds `go-main.go` against its clean ordinary module feed
after removing the SDK/runtime staging sources, then runs `test_wire.py` against
that executable. No source replacement, editable install, or private checkout
dependency is used. Run through `package-artifacts.py --target go`; this directory
is a test consumer, not part of the published SDK archive. The Rust target builds
`rust-main.rs` against its ordinary candidate registry, using its freshly resolved
consumer lockfile and no Cargo patches or path dependencies. Both targets run the
same behavioral cases; neither harness is included in SDK archives.

The base harness and eight cases come from the reviewed native wire conformance
change (#1138). Additional cases exercise planned aliases, disabled sealed gates,
invalid JSON, and timeout during body settlement. Inputs and responses are
synthetic. Planned calls and invalid authorization must make no request; uncertain
mutations preserve the caller key and make exactly one request.

The known same-origin read redirect defect remains tracked by Tungsten #65. The
mutation and cross-origin redirect checks do not establish that missing policy.
Native sealed cryptography, public registry installation and device acceptance
remain independent gates.

## Managed installed pagination

`package-artifacts.py --target java` (or `csharp`, `ruby`) builds and installs
ordinary SDK/runtime archives, removes source staging, and runs `managed.py`
against the compiled or installed probes in this directory. The twenty-five
checks include six typed owner-message pagination cases. Each language's public
resource iterator must preserve decoded message IDs, the returned cursor and
owner cookie/CSRF credentials across requests; a caller-supplied initial cursor
must reach the first request. An application page limit must not prefetch an
extra request. A second-page rate refusal or malformed item must yield a terminal
error without retry, and missing authentication must send nothing.

Error cases continue iterating after the yielded error so the test verifies the
iterator itself terminates. A four-result harness ceiling and subprocess timeout
bound a broken iterator; neither is considered successful termination. These are
synthetic HTTP contracts, not production session-authority checks. Same-origin
read redirects remain unqualified under Tungsten #65.
