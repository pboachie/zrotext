<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Reviewed profile03 queue admission

The optional server library accepts the exact signed reviewed intent and sealed
outbound envelope only while the original owner session, complete accepted
manifest ancestry, installed conversation consent, selected physical receipt,
full device lease and mutable integration mappings remain current. A selected
UUID, valid signature or downloaded projection alone supplies none of those
permissions. Browser role5 is independently selected by the signed manifest;
the original SEALED approval key and phone role4 are separate authorities.

The reviewed intent authenticates the immutable SMS segment ceiling. The
additive queue input requires a ceiling from one through six and uses the
distinct `sealed_profile03` transport and envelope profile. Existing profile02
and alpha queue behavior stays unchanged. A missing ceiling has no typed03
queue representation and cannot become a dispatcher default.

Original reviewed capture, the actual message ciphertext, dispatch job and
genuine outbound quota reservation commit in the same transaction. The server
uses the established billing account admission and reservation policy, including
hosted protected triggers and payment-risk/reconciliation/invoice guards. A
self-hosted account needs a finite configured outbound quota; an operator quota
is supported without requiring a hosted paid subscription. An unconfigured
account refuses rather than queueing without a reserve. Customer locking uses
the actual customer row before the account row upgrade; advisory participation
does not substitute for that tuple ordering.

The original short review window bounds initial admission. It does not renew
current owner permission or become a later grant deadline. The server repeats
actual current records, signatures, physical/mapping deadlines and the original
review after SQL waits. The installed consent time cannot follow admission.
An exact retry returns only the original receipt, with no new queue row, job,
quota reserve, time or attempt. Changed intent, signature or envelope conflicts.

Ciphertext has one source in the actual message. When existing retention permits
content erasure, the reviewed intent, signature and peer are redacted together;
immutable hashes and replay identity remain. A historical receipt cannot restore
erased content, grant a fetch, renew consent or recreate an execution attempt.

The closed POST routes are `/v1/owner/conversation/send03` with
`{v:1,envelope,reviewed_intent,reviewed_signature}` and its `/status` route with
`{v:1,message_id,interval_id,envelope_sha256,reviewed_intent_sha256,reviewed_signature_sha256}`.
Binary values use canonical unpadded base64url. Existing canonical UUID,
same-origin cookie and `x-zrotext-csrf`, management budget, finite JSON/time and
static error rules apply. First admission returns201; exact history/status200.
The receipt includes original message/interval IDs, admission/expiry times,
selection epoch, exact proof hashes and authenticated ceiling.

This is explicit library composition absent from main startup. Its synthetic
ordinary-runtime tests exercise server signatures and queue/billing behavior;
they do not establish browser private-key custody, HPKE decryption, actual
device hardware, carrier submission, grant/fetch acceptance, deployment or
release readiness. The distinct one-use03 grant and execution paths require
their own qualified integration before any queued message can dispatch.
