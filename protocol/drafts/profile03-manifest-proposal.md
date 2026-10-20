<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Offline profile03 browser-signer manifest proposal

This public packet requests one existing-root manifest signature for browser
signer enrollment, same-key renewal or explicit lost-key replacement. It grants
no owner session, server installation, phone, content interval or SMS permission.
Secret signing requires the separate offline `unlock` feature.

`ZTMU01` is closed binary, at most20,480 bytes. Integers are big-endian; positive
counters and times fit signed64-bit storage. UUIDs and commitments are nonzero.
Variable fields have unsigned16-bit byte lengths. Trailing bytes, credentials,
private keys, content and unknown operations are refused.

| Field, in order | Width |
|---|---|
| `ZTMU` followed by version byte1 | 5 |
| Operation: enroll1, renew2, replace3 | 1 |
| Account, device, line UUIDs | 16 each |
| Canonical HTTPS origin, ASCII, at most512 bytes | u16 + bytes |
| Existing root fingerprint | 32 |
| Independently retained predecessor version | u64 |
| Predecessor unsigned semantic SHA-256 | 32 |
| Original accepted checkpoint milliseconds | u64 |
| Independently selected phone reader key ID | 32 |
| Explicitly compared browser P-256 point and role05 key ID | 65 + 32 |
| New manifest issued and expiry milliseconds | u64 each |
| Original signed predecessor03, at most9,753 bytes | u16 + bytes |
| Exact unsigned successor03, at most9,689 bytes | u16 + bytes |

Select the existing root card, account/origin/root identity, retained high-water
and compared browser point independently. Copying downloaded fields into expected
inputs supplies no provenance. Review verifies the predecessor signature at its
original accepted checkpoint, even after expiry, and keeps comparison monotonic.
Signing requires an issue time no later than now, less than five minutes old,
and a positive new manifest window of at most24 hours.

Shared readonly policy preserves the complete historical record set, root,
account, selected phone/line and strict next-version linkage. Enrollment adds one
distinct role05 key. Renewal preserves the same active browser point. Replacement
revokes only the selected old browser record and adds the explicitly compared
new key; revoked records remain exact. Existing active key windows may extend
within the new expiry, without shortening or changing roles, subjects, points,
scopes or original validity starts. The console displays every changed retained
record's expiry/state. Capacity exhaustion preserves history and refuses.

The offline custodian consumes a typed reviewed proposal, rechecks the actual
clock and recovered existing root, and signs only `ZTSE/manifest/v3`. Output is
create-new public data. The browser checks exact expected unsigned bytes and the
root signature before separate possession signing or authenticated installation.
Old admitted messages and intervals retain their original manifests.

`sealed-profile03-manifest-proposal-01.json` encodes the signed three-edge public
history in `sealed-profile03-manifest-install-01.json`. These synthetic vectors
qualify codec interoperability, not database acceptance, root custody, current
permission or shipping UI. The TypeScript builder requires the genuine historical
manifest token verified at the independently retained original accepted time.
