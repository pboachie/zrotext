# Same-phone selected-SIM refresh03 candidate

This additive operation retains the original sealed v2 activation, original
registered owner approval key, accepted profile03 election, binding UUID and
generation. It does not replace a phone, reset an attempt, renew an old message or
reinterpret any existing v2/E500/Grant03/Fetch03 bytes. Source implementation and
vectors do not establish deployment or carrier readiness.

It supports the same enrolled phone and retained subscription index only. A
matching subscription index does not prove the same physical SIM. The phone
captures a genuinely fresh complete Android 13+ observation and explicitly shows
the selected subscription, kind and complete count for confirmation. Sending is
withdrawn at review entry. Closing or leaving the app invalidates pending work.
Original evidence and unknown outcomes remain in the journal.

The authenticated owner opens and approves the operation with separate current
password/MFA checks. The original registered **SEALED** approval key signs; the
root, ordinary SMS, device and reader keys cannot substitute. Current actors come
from actual authenticated sessions, never copied identifiers or proof booleans.

## Fixed public proofs

`L(domain, payload)` is ASCII domain, one NUL, u32BE payload length, payload.
All u64 values below are positive and at most the maximum signed 64-bit value.
Every UUID and digest is nonzero. Reserved bytes must be zero.

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 8 | `ZTSR 01 03 03 00` |
| 8 | 80 | account, device, line, refresh challenge, current binding UUIDs |
| 88 | 32 | binding generation, vault generation, current manifest version, actual selection epoch |
| 120 | 32 | original election commitment |
| 152 | 32 | original election bundle SHA-256 |
| 184 | 32 | selected reader key ID |
| 216 | 32 | enrolled device signing key ID |
| 248 | 32 | original SEALED owner approval key ID |
| 280 | 32 | independently retained root fingerprint |
| 312 | 32 | current manifest semantic digest |
| 344 | 32 | actual canonical device-session digest |
| 376 | 32 | actual canonical owner-session digest |
| 408 | 32 | canonical configured HTTPS origin SHA-256 |
| 440 | 32 | fresh challenge nonce |
| 472 | 8 | issued time in milliseconds |
| 480 | 8 | exclusive expiry in milliseconds |
| 488 | 8 | reserved zero |

Lifetime is at most 300000 milliseconds. Observation is the exact existing
121-byte complete-set v2 observation, with actual new issuer tokens. Its selected
subscription must match the retained original local and original signed server
activation. New tokens cannot be rewritten into historical tokens.

The device signs `L("ZTSE/line/payload-profile/selection-refresh/device/v1",
core496 || observation121)`. The owner signs
`L("ZTSE/line/payload-profile/selection-refresh/owner/v1", core496 ||
observation121 || SHA256(exact_device_signature64))`. Bundle745 is core,
observation, device64, owner64, in that order. New signatures are strict raw64
low-S. Received original v2 canonical DER, including valid high-S, is preserved.

Installed ACK signs
`L("ZTSE/line/payload-profile/selection-refresh/installed/v1", refreshUUID16 ||
SHA256(bundle745) || actualDeviceSessionDigest32)`, an 80-byte payload.

## Device transport and journal

The additive profile03 socket carries these closed objects. Version is `v:1`.
Epoch is a JSON integer. Historical timestamps use canonical positive decimal
strings. Binary fields use canonical unpadded base64url.

| Type | Other exact fields |
| --- | --- |
| `payload_profile_selection_challenge03` | `refresh_id,core,evidence,closed_unaccepted` |
| `payload_profile_selection_proof03` | `connection_epoch,refresh_id,observation,device_signature` |
| `payload_profile_selection_approved03` | `refresh_id,bundle,accepted_ms` |
| `payload_profile_selection_installed03` | `connection_epoch,refresh_id,bundle_sha256,device_signature` |
| `payload_profile_selection_install_ack03` | `connection_epoch,refresh_id,bundle_sha256,installed_ms` |

Evidence has exactly `root_pin,prior_manifest02,prior_accepted_ms,
accepted_manifest03,accepted_ms,bundle,device_signing_point,owner_approval_point,
registration_evidence,activation_evidence`. It is a historical authenticated read
before physical availability, not a Ready or message permission claim. The phone
verifies all original registration/v2/election/manifest signatures, exact retained
root and predecessor history, installed identity and existing hardware before
signing. A downloaded checkpoint cannot repair missing local history.

Room schema16 stores separate permanent refresh records. Transitions are
reserved → signed → accepted → ack_reserved → ack_signed → installed.
Reservation precedes device signing; separate acceptance and ACK reservation
precede installed signing. Exact retries preserve original signatures and times.
Every released signature remains an unknown-outcome fence after retirement.
An unresolved radio effect refuses a refresh. No cold load reconstructs a lease.

Only an exact actual-socket installation ACK received within the original window
can publish the genuine fresh opaque issuer lease. After successful installation,
the approval times are historical; actual current device, reader, root, manifest
and observation still independently bound availability. At most one accepted
refresh is supported per binding/current device connection. A later observation
requires an explicit new connection and fresh phone/owner approval.

Device selection projections require a closed `physical_selection` union:
`{kind:"original_v2"}` for genuine original live issuer continuity, or
`{kind:"owner_refresh03",refresh_id,bundle,accepted_ms,installed_ms}` for the
actual accepted and acknowledged separate receipt. The phone also requires its
matching local installed record and opaque live lease. Full message permission
projections retain their separate existing owner/session fields. Server admission,
grant and fetch must retain the exact physical receipt/device session; old messages
cannot migrate to a new selection. Prepared plaintext and radio submission also
retain the exact original opaque permit object and refuse its replacement.

`protocol/v1/profile03-selection-refresh.schema.json` describes these additive
frames. `vectors/sealed-profile03-selection-refresh-01.json` contains independently
generated real synthetic P-256 signatures. It asserts grammar/signature parity,
not operating-system truth, hardware custody or database acceptance.

## Explicit interrupted-refresh recovery

Every owner challenge/status response and phone challenge requires an initially
empty or at most sixteen-member `closed_unaccepted` array. Each closed member is
`{opening_id,refresh_id,core,closed_unaccepted_ms,superseded_by_refresh_id}`.
UUIDs are canonical and nonzero; core is exact canonical unpadded base64url496;
closure time is a positive canonical decimal string. The entire ancestor chain
is ordered by strictly increasing issued time. Each closure equals its immediate
successor's exact issued time, at or after the original expiry, and the last
member targets the new live refresh. Binding, election, manifest, keys, selection
epoch and full device lease/origin remain identical. Original owner-session
digest and nonce may vary with the genuinely new opening.

Only an explicit owner opening with fresh password/MFA may atomically close
expired never-approved rows and reserve a replacement. Status, timeout and
unavailable replies never close them. Server acceptance of a closed predecessor
must remain impossible even on clock regression. Android verifies the complete
chain under the actual current socket and full original proof/custody checks;
every known signed predecessor matches exact original core. Unknown intermediate
entries remain history without invented local observations or signatures.

A different owner challenge only queues a candidate on the phone. Signing also
requires a genuinely new foreground complete-SIM confirmation after all closed
predecessors' expiry, with a distinct consent ID. Android commits its closure
chain and fresh reservation together in schema18 before signing. Accepted rows
cannot be closed, and late approval/install/signing on closed rows refuses.
Any ever-signed observation permanently fences original physical fallback for
that full connection. At most sixteen reservations are retained per binding/full
lease; histories are not deleted to evade that bound. A new actual connection
still needs fresh explicit physical approval and cannot translate old messages.
