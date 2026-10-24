# Profile03 unsigned composition boundary

The SDK adds `prepareSealedOutboundEnvelope03`,
`preparedOutboundEnvelopeSnapshot03` and `completeSealedOutboundEnvelope03`
for #1630. The original convenience composer and exact envelope03/type1 body,
HPKE, signature and recipient wire contracts remain available unchanged.

Preparation validates the genuine manifest/election and explicit current input,
selected keys/routing, strict UTF8 body and whole-message bounds before drawing
fresh material. It encrypts and wraps without invoking the role5 signing key. Its
private local handle exposes owned copies of only the exact unsigned ciphertext,
signature transcript, unsigned digest and authorized signer public point. No
plaintext, CEK, ephemeral private key or signing key is projected. Temporary text
and secret byte buffers are cleared best effort; engine/crypto copies can remain.

The adapter must durably retain that exact public ciphertext and burn its
one-use signing phase before invoking the actual retained key. Completion accepts
the same private handle, the already produced strict low-S raw64 signature and
the comparison clock. It rechecks original captured selection/key/whole-message
lifetime bounds and verifies the exact signature before returning the completed
envelope. It performs no signing, randomness, encryption or retry itself.

The handle is a component proof, not a one-use authorization or current DB read.
It cannot be restored from a JSON or ciphertext snapshot after restart. Repeated
passive inspection/completion of the same already signed bytes grants no right
to invoke a key again. The maintained adapter must preserve burned phases and
completed exact packets, reconcile UNKNOWN without re-signing or re-encryption,
and independently enforce original installed consent, same owner/session,
current physical/full lease/mappings, retained key custody and explicit review.
Actual browser persistence, transport, maintained receiver and radio execution
remain separate integration work; this component mounts none of them.
