# Installed Go archive wire contracts

`package-native.py` builds `go-main.go` against its clean ordinary module feed
after removing the SDK/runtime staging sources, then runs `test_wire.py` against
that executable. No source replacement, editable install, or private checkout
dependency is used. Run through `package-artifacts.py --target go`; this directory
is a test consumer, not part of the published SDK archive.

The base harness and eight cases come from the reviewed native wire conformance
change (#1138). Additional cases exercise planned aliases, disabled sealed gates,
invalid JSON, and timeout during body settlement. Inputs and responses are
synthetic. Planned calls and invalid authorization must make no request; uncertain
mutations preserve the caller key and make exactly one request.

The known same-origin read redirect defect remains tracked by Tungsten #65. The
mutation and cross-origin redirect checks do not establish that missing policy.
Native sealed cryptography, public registry installation and device acceptance
remain independent gates.
