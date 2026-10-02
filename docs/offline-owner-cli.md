# Candidate offline owner recovery tool

`zrotext-owner` is a Windows-only, source-built candidate for creating an
**unregistered generation-one** encrypted root backup and checking recovery in
a new process. The default build does not enroll a root, sign requests,
rotate an enrolled root, contact a server, install software or establish an
authenticated distribution. The only exception is the **disabled-by-default**
`unlock` candidate below, which adds offline one-challenge possession signing
and nothing else. Do not treat a passing recovery check as server or phone
approval.

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

## Candidate unlock command (disabled by default)

The `unlock` command is the first slice of owner recovery/unlock. It is **not
in the default build**: `cargo build -p zrotext-owner` produces a binary
without it, `--help` does not list it, and the default native suite asserts
the command word is refused. A maintainer must deliberately build with
`cargo build -p zrotext-owner --features unlock`. No released artifact,
workflow or server route enables it, and the dormant server ceremony still has
no HTTP route. The Windows CI lints and tests the feature build separately so
the candidate cannot rot silently.

```text
zrotext-owner unlock --account UUID --origin HTTPS_ORIGIN --bundle PUBLIC_ID --challenge FILE
```

The `--challenge` file is public data: the exact `RootEnrollment01` bytes
(152–663 bytes) a future server ceremony would display. Obtain it through a
channel you independently trust; this tool cannot authenticate its origin.
The path must be an ASCII absolute drive path of at most 260 bytes, and the
read is size-bounded before parsing.

`unlock` performs the same verified recovery as `restore-check` — fingerprint
from your independent kit, stored bundle and public card, then the recovery
token without echo, authenticated backup opening and public pin comparison —
with one addition. **Before any secret is requested**, the challenge's
account, origin and root fingerprint are bound to the independently supplied
identity and to the local clock's validity window, and the challenge ID and
expiry are displayed. The generation line is honest about being offline: the
tool prints `Generation: unknown offline`, because only the hub records the
active generation. Consent is exact: typing `UNLOCK` proceeds; typing
`decline-UNLOCK` ends the ceremony cleanly with nothing signed, no token
requested and no state changed; anything else fails closed. After exact
`UNLOCK` consent, the token is read, the
backup is opened and compared, and the challenge transcript is signed once
with the recovered root as canonical low-s `r || s` (64 bytes). The root and
recovery secret are dropped before the fixed public `Signature:` line is
displayed for transcription. The challenge file is read from an absolute
drive path only: drive-relative, UNC, device and reparse-point paths are
refused before any read.

Threat and failure cases considered:

- **Confused deputy.** A challenge for any other account, origin or root is
  refused before the recovery token is requested; the tool never signs an
  identity it was not independently told to expect. User, session and
  challenge identities are inside the signed transcript and remain
  server-side obligations; a phished owner could still be social-engineered
  into signing a challenge for their own genuine root, which enrolls nothing
  the server does not independently authorize.
- **Clock.** An incorrect local clock refuses to sign (fail closed), and
  expiry is rechecked after interactive token entry.
- **Custody.** The recovered root exists only in process memory on a
  general-purpose Windows machine. No TPM, secure element or other
  hardware-backed key custody is involved or claimed; memory hygiene is
  best-effort zeroization. The bundle store's discretionary ACL boundary is
  the only at-rest protection and excludes administrators, SYSTEM and other
  same-user code only by policy, not by hardware isolation.
- **No state.** No durable unlock marker, cached key or restored plaintext
  file is written; every future use requires the full kit again. The
  signature and challenge are public data; the token is never displayed,
  logged or written.
- **Failures.** Cancellation, wrong context, wrong fingerprint, wrong token,
  malformed or expired challenges, oversized challenge files and unsupported
  environments fail closed with a fixed diagnostic and no signature.

## Candidate custody signing (disabled by default)

The explicit `unlock` feature also provides a separate offline operation:

```text
zrotext-owner custody-sign --account UUID --origin HTTPS_ORIGIN --bundle PUBLIC_ID --challenge FILE
```

Supply account, origin, bundle ID and fingerprint from your independent recovery
kit. The command reads the existing local encrypted bundle and a bounded public
enrollment challenge once, verifies their identity and card/backup digest binding,
and displays the bundle ID, both public artifact digests, challenge ID and expiry.
Type exactly `CUSTODY` to authorize this encrypted publication, or `DECLINE` to
end without requesting recovery material. `UNLOCK` does not authorize custody.

Only after consent does the eligible secure console request the recovery token.
Authenticated recovery and root-pin comparison are required. A fresh clock check
after secret entry rejects expiry before either signature is produced. The
immutable review binds the exact unsigned enrollment bytes, SHA256 of the stored
encrypted backup, SHA256 of its public card, and independently compared root
fingerprint under the existing `ZTSE/root-custody/v1` domain with a trailing NUL.

The two public console lines, `Enrollment signature:` and `Custody signature:`,
contain distinct canonical 64-byte low-s signatures. Use them only with that
reviewed challenge and those exact encrypted/public artifacts. The command
contacts no server, enrolls nothing, creates no output file or durable unlock
marker, and leaves recovery readiness unchanged. The root and recovery secret
are dropped before output. A console/output failure may leave a partial public
signature display; no completed publication is thereby established. All ordinary
unlock environment, context, token, clock and memory-hygiene limits apply.

Fixture tests verify the server's exact transcript encoding, signature-domain
separation, immutable review, wrong root/context/bundle, malformed or oversized
input and expiry. Hidden limited-token console tests exercise success, pre-secret
context rejection, decline, wrong token and expiry during token entry, checking
that rejected operations emit neither signature and do not modify the bundle.

## Automated verification

Native tests use hidden, exclusively owned child consoles, unique temporary
directories and deterministic synthetic root/recovery fixtures supplied through
test-only dependencies. Creation and restore run in distinct processes. No secret
argument/environment interface or production seed/path override exists. Eligibility
checks remain active in tests; an ineligible runner fails rather than skipping.
Hidden native test children never run with administrator rights. A
non-elevated test parent launches them directly. An elevated parent first
confirms that production eligibility rejects it, then uses its existing limited
linked token (UAC) when Windows provides one. Otherwise it derives a
UAC-equivalent reduced-rights token of the same account in the same session:
BUILTIN\Administrators deny-only, administrator privileges removed, Medium
integrity and a standard default DACL so the child can open itself to start
its console host. Before launch the token must be non-elevated, primary, at or below
Medium integrity, without Administrators enabled and without administrator
privileges, and every child checks its own token the same way first. Launch
refusal fails the test; there is no credential, privilege-enabling or policy
bypass fallback. This launcher is compiled only for tests.

The GitHub-hosted Windows runner is elevated and has no linked token, so the
terminal and owner suites run there through the reduced-rights launcher and
must report exact counts with zero failed or ignored tests. A second,
feature-enabled owner suite (`--features unlock`, five tests) runs the same
way and exercises the unlock stages — successful signature display and
codec-level verification of the transcribed public signature, an unbound
challenge refused before the token prompt, and a wrong token producing no
signature — while the default four-test suite keeps asserting the command
word is refused. The bundle suite
runs separately as an explicitly provisioned disposable standard user. That
fixture compiles the bundle test executable first, gives the user only an
immutable hash-checked copy and a private temporary directory, and requires the
exact suite count with zero ignored tests. Its script refuses workstation and
self-hosted environments. Passwords stay in secure/unmanaged buffers, never
arguments, files or environment values. Only the new logon SID's temporary
desktop permissions are removed; unrelated permissions are preserved.
Process-tree, account, optional profile and owned-directory cleanup must
succeed. Forced VM termination may prevent cleanup; the disposable VM is the
final containment boundary. Neither path changes UAC, machine policy,
repository permissions or production eligibility checks.The production `init` command is not executed with real owner material by tests.
