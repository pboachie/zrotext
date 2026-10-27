# Android authenticated profile03 setup composition

The foreground **Connect for encrypted messaging** action mounts the additive
profile03 consumer alongside the actual complete-v2 line consumer on Android13+.
It is user intent to connect, not a root, reader, line, owner or SMS permission.
Reboot resume remains heartbeat-only. Existing02 wire bytes and default protocol
offers remain unchanged. Missing or unsupported authority refuses without another
provider, plaintext path, key enrollment or history reset.

This is source integration under [#1054](https://github.com/pboachie/zrotext/issues/1054).
Source mounting does not establish hosted transaction, integrated maintained-provider,
no-radio device, reconnect or carrier acceptance. The corresponding server and owner
transport implementations require their own checks before this path can operate.

## Genuine initial setup

Pairing remains the original device identity. The phone requires an actual newly
reviewed sealed-v2 selected-SIM installation, independently compared account root
and explicitly enrolled nonexportable reader. A socket frame cannot create these.
Initial manifest import is an explicit action in phone enrollment, independent of
conversation consent. It uses the current authenticated03 nonce/time sample and
the already compared root, actual selected device/line and existing key points.
The complete root-signed02 chain is preflighted before a single atomic old-or-final
root-store write. Interrupted import retains the old compared-root state and can
retry the same full chain. Exact completed replay does not renew acceptance.
The initial import cannot advance existing accepted history or create a second root.

The strict full election challenge includes the exact E500 core, root-signed03
successor, actual immutable reserved new-binding UUID and complete original02
projection. The new UUID is absent from E500; it must come from the authenticated
durable server reservation and match the separately retained phone mapping.
Before signing, the phone independently compares its root/history, selected
hardware reader and enrollment signer, original registration and activation
signatures, genuine current complete-SIM permit, current socket/deployment and
trusted time. It commits the permanent reservation before hardware signing and
commits the exact outgoing raw64 proof before returning it to the socket.

Transport loss never retires or re-signs that row. A saved exact signed proof may
be re-emitted only while its same original live ceremony remains valid. Reserved,
retired, conflicting or expired openings cannot create another signature. Remote
acceptance remains unknown until the exact authenticated accepted evidence is read.

An explicitly opened replacement for an expired never-accepted ceremony requires
the server's complete immutable `closed_unaccepted` chain. Android independently
checks every original02 scope and exact locally retained predecessor, then commits
the chain and higher fresh reservation together before signing. Missing history,
accepted predecessors or unresolved radio effects refuse. This separate
[unaccepted-election recovery](../protocol/drafts/profile03-unaccepted-recovery.md)
preserves old signatures and permanent02 fallback fences; a timeout cannot resolve
an unknown outcome. The initial challenge also requires the empty array.

## Original evidence and current authority

`Profile03OriginalBindingProof` decodes the existing canonical registration
evidence and separate canonical activation evidence. It verifies the original
RootLineRegister root/approval signatures and both exact sealed-v2 statements and
received DER signatures. Original canonical high-s DER remains valid and is hashed
verbatim. It reconstructs the original binding identity, including registration
and both approval/confirmation digests, then compares the exact E500 commitment.
Digests cannot replace a missing original signature or receipt.

Later reload matches the existing local signed/installed Room record before using
an authenticated server election timestamp. The phone retains its own independently
verified02 checkpoint; the server's original02 acceptance timestamp is a separate
checkpoint over the exact same retained bytes and position. Both must precede the
accepted election. Expired02 is history at those original times; current03 roles,
device/owner leases and message deadlines use actual authenticated now. No
downloaded root or timestamp repairs missing local history.

Nonce-bound current installation uses a distinct closed device selection with
`kind: device_selection03` and `selection_expires_ms`. It omits live owner IDs and
owner-session digest. This can publish Ready03 only after the exact original
signed local ceremony is installed atomically; it describes reader availability.
It cannot supply per-message send permission. The exact fetch sidecar has its
separate closed full permission projection and signed reviewed intent, including
the original admitted owner/session, selected peer/readers and segment ceiling.
Device selection fields cannot be coerced into that message permission parser.

The nonce metadata sample binds the actual configured site/instance, device lease,
deployment and line-version2 consumer. Replies are closed before projection,
nonce/replay/rate bounded and require round trip at most two seconds. Current
selection reads are bounded and never reserve, re-sign or renew an election.
Not-yet-accepted replies preserve the signed row; unsupported/expired replies
pause reads and retain recovery history.

## Protocol origin and socket routing

The actual configured secure WebSocket supplies two separately checked origin
names for the same host and port. `Profile03Origins` binds those names when the
shipping connection is constructed. It rejects another scheme, user information,
fragment or inconsistent host/port normalization. A default secure port becomes
an omitted port in the canonical HTTPS origin and explicit port443 in the existing
WSS routing identity. The origin mapping is public configuration metadata; it
grants no authentication, reader, SIM or message permission.

| Retained or received value | Required domain |
| --- | --- |
| Signed registration, E500 election, refresh496 and reviewed-intent origin | SHA256 of the canonical HTTPS origin |
| `Profile03ElectionRecord.originHash` and `SelectionRefresh03Record.originHash` | The original signed HTTPS digest |
| Authenticated session, original v2 activation and preparation routing | Existing `EvidenceIdentity` WSS host and explicit port hash |
| Typed passive-history original origin pin | Original WSS routing hash |

Original-proof comparison derives the matching routing name from the independently
configured protocol origin and compares the existing v2 record without changing it.
Election setup, accepted-current reads, retained manifest history, fresh same-phone
review and the radio context check each domain explicitly. The same-phone review
captures its mapping, actor, connection/deployment epochs and clock from one current
publication. A clock read checks that original publication again after any wait;
withdrawal or a replacement connection cannot supply its time to an old observation.

There is no migration or relabeling of existing origin fields, wire bytes, signatures
or attempt history. Missing or inconsistent provenance refuses. These source checks
and their JVM regression cases require combined compilation and execution; they do
not establish hardware custody, hosted current permission or carrier delivery.

## Message path and recovery limits

Explicit root/reader enrollment uses separate full validation and a
[callback-scoped storage guard](android-enrollment-storage.md); no Room or
framework read runs under its protected root-storage monitor.

The enrolled device-authentication/E500/fetch signer is independent of manifest
role04, which authorizes inbound event signing. Setup, history comparison and
payload-reader availability check role01 and independently verify the original
registered enrollment key; they accept a distinct or absent role04 record.
Message-direction signer gates remain separate: outbound requires role05, and
the existing inbound02 consumer still requires its exact role04 point in actual
local signer custody. Availability does not grant that inbound capability.

The ordinary raw03 grant path independently checks local current selection before
the exact signed HTTPS fetch. It verifies the sidecar's original proofs, same
existing nonexportable keys and current complete-SIM permit, then composes the
[journaled preparation](android-profile03-preparation.md) with the maintained Wolf
recipient. The existing durable intent, authenticated writer ACK, suppression and
one-use radio-start CAS remain required. Unknown effects cannot retry.

The original complete-v2 permit is process-only and is withdrawn on connection or
process loss. Saved observation tokens are historical declarations, not current
OS continuity. Same-phone reconnect needs the distinct fresh phone/owner review
and selected-binding acknowledgment implemented by the
[separate same-phone review](android-same-phone-selection-review.md). Its source
still requires integrated no-radio server/database/provider qualification before
repeatable hosted messaging can be claimed. New-phone replacement remains
the separate proposed operation in [#1469](https://github.com/pboachie/zrotext/issues/1469).
This source does not restore an old monitor, relabel a binding generation or
claim repeatable reviewer access from first-session preparation.
