# Profile03 browser message recovery candidate

The ordinary owner conversation page composes messages only after verifying the
original request, phone approval and installation signatures against a fresh
conversation context. The active display flag alone cannot authorize a send.
The retained role05 key must match that original signed statement.

Review preserves the exact text and an explicit maximum of one to six SMS
segments. Text, prepared crypto handles, current permission and approval remain
in memory. Editing, canceling, Stop, expiry, session/CSRF changes, hidden pages
and page exit withdraw that approval. Confirm consumes it synchronously.

Before each effect the browser commits an immutable original record in IndexedDB:

1. Save the exact unsigned encrypted envelope and `envelope_sign_reserved`
   before invoking its signature.
2. Retain the completed envelope, then the exact V2 reviewed intent and
   `intent_sign_reserved` before invoking the separate review signature.
3. Retain both signatures, then `submit_reserved` before the transport POST.
4. Retain an exact validated acceptance receipt without claiming carrier delivery.

Compare-and-set uses one real read/write transaction, committed completion and
readback. A competing tab cannot advance a stale predecessor. The original
message, interval, owner session, ciphertext, signatures and receipt cannot be
replaced. Closed records never reopen. Records contain no plaintext message,
content key, private signing key, password or authenticator value.

A reload can inspect history and passively check the original submitted packet.
It cannot reconstruct a private crypto proof, signing permission or submit
approval from a saved phase. Unavailable, expired or not-found responses do not
reset the attempt. One unresolved submission fences another submission for the
same retained original-user/conversation scope, including across browser tabs;
only retaining its exact acceptance receipt clears that pending index.

History is paged at sixteen records per read and has no lifetime attempt count.
Earlier sign-ins of the same original user may reconcile the exact packet;
another user cannot adopt it. Local records do not provide rollback resistance,
remote current-state authority, a delivery grant, phone approval or SMS evidence.
Server admission and the phone still perform their independent checks and
segmentation. No live SMS, deployment, signing or release promotion is implied
by the browser fixtures or this source candidate.
