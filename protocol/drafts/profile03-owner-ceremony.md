# Explicit profile03 owner ceremony

This is an implementation candidate, not a production capability declaration.
The separate owner and enrolled-socket library routers implement original02
bootstrap, durable reservation recovery, device signature retention and final
owner acceptance. Existing startup paths do not mount either router. Current03
installation, message admission, execution grants and signed fetch remain
separate integration work. The serial110 schema must be installed with its
closed ordinary-runtime ACL verifier; missing, partial and elevated callers
refuse rather than taking a legacy alternative.

The owner base is `/v1/account/sealed/payload-profile`. All methods are POST,
with byte-exact `application/json`, configured HTTPS Origin, the existing
ordinary session and CSRF cookies, and `x-zrotext-csrf`. API bearers are refused.
Request objects are closed, reject positional arrays and escaped duplicate
members, and are bounded to96KiB with a five-second body deadline. Responses
are no-store. UUIDs are canonical nonzero lowercase hyphenated strings;
binary values are canonical unpadded base64url. Owner response times/counters
are decimal strings within signed-storage range.

| Path | Closed request fields |
| --- | --- |
| `/bootstrap` | `v:1,line_id` |
| `/challenges` | `v:1,opening_id,line_id,successor_manifest03,password,factor` |
| `/challenges/status` | `v:1,opening_id,line_id` |
| `/challenges/proof` | `v:1,opening_id,challenge_id` |
| `/elections` | `v:1,opening_id,challenge_id,successor_manifest03,bundle,password,factor` |

The bootstrap candidate contains actual current owner/session, enrolled lease,
selected original binding/reader and exact original root, manifest,
registration and activation evidence. It is not browser trust: an independent
paired-root/signing-fingerprint and cryptographic verifier remain mandatory.
The current enrollment signer is derived from the actual enrolled signing point;
a role4 conversation signer is a different authority and is not a substitute.

An opening UUID must be persisted by the browser before its first request.
One request-admission transaction authenticates the actual owner and commits
the management debit before password work or an untrusted body stream. A
separate transition transaction authenticates again, consumes a genuine fresh
password/factor and keeps that opaque proof in the same transaction as the
transition. Failure budgets commit on rejected credentials; transition refusals
roll back factor consumption and every effect write. A reservation's consumed
factor is never a fresh acceptance factor.

The server allocates independent CSPRNG challenge/binding UUIDs and a nonce.
The generation is the actual locked issued highwater plus one, not the current
binding plus one. The narrow reserve routine atomically retains E500, exact
signed successor, original02 checkpoint and mapping while burning that highwater.
The old binding/profile stays02 until acceptance. Lifetime is at most300000ms,
capped by actual held factor/session, manifest keys and current device lease.

A challenge response is exactly
`{v,opening_id,challenge_id,new_binding_id,core,successor_manifest03,issued_ms,expires_ms,status,closed_unaccepted}`.
Status is `reserved` or `accepted`. Exact opening/line/successor recovery returns
the retained response with200, without consuming a new factor or extending any
deadline. A new reservation uses201; changed bytes conflict409. Proof read
returns `{v,opening_id,challenge_id,device_signature}`; absent proof404,
closed/expired proof410. A response lost in transit never causes automatic
allocation, signing or retry.

`closed_unaccepted` is an array of at most16 closed objects
`{opening_id,challenge_id,new_binding_id,core,closed_unaccepted_ms,superseded_by_challenge_id}`.
Entries preserve the linked predecessor chain in ascending burned generation.
Only an explicit fresh opening, under exclusive current02/epoch0/unchanged
binding fences and a distinct genuine factor, may irreversibly close an expired
never-accepted predecessor and bind it to the higher reservation in the same
transaction. Status and exact retry never close or allocate. All prior core,
signature, highwater and deadline bytes remain. Closed challenges can never be
accepted, including after primary-clock regression. The phone retains its
ever-signed02 fallback fence and compares exact retained local rows and the
complete chain before explicitly signing a higher03 challenge. Timeout,
elapsed local time and an absent response are not nonacceptance proofs.

The enrolled stream has the additive exact subprotocol
`zrotext-device-status-v2+sealed-dispatch-v3`. It selects status2 and complete
line-activation2; existing protocol tokens and02 frames are unchanged. A03
selection never enters the legacy sealed grant branch. The new library router
requires independently configured matching HTTPS/WSS authority. It remains
absent from ordinary startup, and does not yet advertise execution readiness.

Closed incoming frames are:

- `{v:1,type:"payload_profile_session03_request",connection_epoch,challenge}`.
- `{v:1,type:"payload_profile_proof03",challenge_id,device_signature}`.

The session reply is exactly
`{v:1,type:"payload_profile_session03",challenge,account_id,device_id,connection_epoch,deployment_epoch,session_id,server_time_ms,site_id,instance_id,line_activation_version:2}`.
These metadata epochs/time retain the existing numeric socket grammar. The
actual current enrolled lease, deployment and primary clock are read after
waits; socket-local nonce samples are bounded to64 and five-second spacing.
This is identity/time only, never line approval, readiness or a lease renewal.

The server challenge is exactly
`{v:1,type:"payload_profile_challenge03",challenge_id,new_binding_id,core,successor_manifest03,original,closed_unaccepted}`.
`original` is the independently selected original02 candidate and all raw proofs,
available before the device signs. The phone must verify its own retained
root/pairing/hardware selection and exact current nonce-bound session. E500
does not include the new binding UUID; the immutable reservation mapping and
phone journal bind it before releasing a signature. Device proof uses the
existing strict lowS raw64 election domain. It does not approve a SIM or elect
the account, and there is no permission-bearing device-proof ACK.

Acceptance compares exact E500, original retained device signature, successor
bytes and a separately verified original SEALED approval signature, after
rechecking the genuine fresh owner factor and exact current records. Its narrow
routine couples immutable accepted evidence, new03 binding, current line,
same-root03 authority and one epoch advance. Deferred bounds reject a late
commit; the old-epoch witness is never relabeled as a new one. Original v2
activation/installed history remains byte-for-byte retained. Exact historical
bundle retry returns the original receipt with200, not new current permission;
a new acceptance returns201. Changed proof bytes conflict even when another
valid signature could authenticate the same semantic statement.

The acceptance receipt is exactly
`{v:1,opening_id,challenge_id,binding_id,binding_generation,election_digest,bundle_sha256,accepted_ms,selection_epoch}`.
Cryptographic acceptance and delivery are distinct. This candidate supplies no
plaintext, software hardware substitute, SMS attempt or permission to dispatch.
