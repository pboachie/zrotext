# Candidate offline owner recovery tool

`zrotext-owner` is a Windows-only, source-built candidate for creating an
**unregistered generation-one** encrypted root backup and checking recovery in
a new process. It does not enroll a root, sign requests, rotate an enrolled root,
contact a server, install software or establish an authenticated distribution.
Do not treat a passing recovery check as server or phone approval.

## Supported environment

Use a trusted build and an interactive local Windows console as a non-elevated
user. Standard input, output and error must all be console handles; redirects,
pipes, changed handles, queued input and unsupported session states are refused.
The process must not impersonate another token. These checks do not establish
physical presence or absence of recording. Other programs running as the same
user, terminal hosts, administrators, SYSTEM and drivers remain trusted.

Storage is the fixed `zrotext-root-bundles` child of the current user's existing
Windows LocalAppData known folder. The supported path is ASCII, absolute and on
fixed local NTFS, with no reparse points, network paths or fallback directories.
The tool obtains this location from Windows, not an environment setting or the
current directory. Unsupported locations fail closed.

## Create and independently check recovery

Commands accept public arguments only, in the exact order below. Account IDs
must use canonical lowercase UUID spelling; origins must be canonical HTTPS
origins. Obtain the intended account and origin independently before starting.

```text
zrotext-owner init --account UUID --origin HTTPS_ORIGIN
zrotext-owner restore-check --account UUID --origin HTTPS_ORIGIN --bundle PUBLIC_ID
```

`init` displays the intended account, origin and generation, and requires exact
`CREATE` consent before generating a root and independent recovery secret from
fallible system randomness. It seals and publishes an immutable encrypted backup
and public card, then displays the public bundle ID and full lowercase fingerprint.
Keep account, origin, bundle ID and fingerprint with your separate recovery kit.

Only a confirmed publication permits the next prompt. Exact `REVEAL` consent in
the retained console session displays the recovery token once. The token is
visible to the terminal host and may remain in scrollback. The tool does not
copy it to the clipboard, a log or a file, and never displays the root scalar.
Capture the complete token privately. Creation is **recovery-unverified**.

Run `restore-check` as a separate invocation. Enter the full fingerprint from
the independent kit before the stored card is accepted, then enter the recovery
token without echo. The tool verifies the backup ID, public context and card,
authenticates/decrypts the backup, and rederives the public root for comparison.
Secret material is dropped before the public success message. There is no
durable ready marker, cached unlock or restored plaintext file. Any future
enrollment must restore and check again immediately before signing.

## Failure and durability limits

Cancellation, bad input, randomness failures and unsupported environments fail
closed. Publication failures and ambiguous rename outcomes never permit token
reveal. Encrypted/public pending artifacts may remain; they are not overwritten
or automatically deleted. When an unrevealed recovery secret is lost, that
orphan is unrecoverable. A new `init` uses fresh material and a fresh ID.

A partial reveal or failed terminal cleanup is an error. There is no automatic
second reveal. If the complete kit was captured, a fresh recovery check can
establish recoverability; the failed creation itself does not establish it.
Wrong context, token, fingerprint or corrupted files cannot produce recovery
success. Recovery checks open existing stores without creating directories.

Flushes, handle checks and rename do not prove durability after power loss.
A successful check now does not prove future availability or an independent
backup copy. Secure erasure, malicious same-user software protection and
authenticated release provenance are not claimed. Repeated creation does not
rotate or replace an existing enrolled root.

## Automated verification

Native tests use hidden, exclusively owned child consoles, unique temporary
directories and deterministic synthetic root/recovery fixtures supplied through
test-only dependencies. Creation and restore run in distinct processes. No secret
argument/environment interface or production seed/path override exists. Eligibility
checks remain active in tests; an ineligible runner fails rather than skipping.
An elevated test parent must obtain its existing, genuinely non-elevated linked
token and launch the hidden child with that token. Missing token or launch
privileges fail the test; there is no credential, privilege-enabling or policy
bypass fallback. This launcher is compiled only for tests.
The production `init` command is not executed with real owner material by tests.
