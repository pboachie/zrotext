# Original activation capture and historical reader

The registered complete SEALED-v2 activation transaction captures the exact
original device and owner statements and received DER signatures before its
first activation mutation when the additive receipt schema is installed. It
reverifies the original RootLineRegister signatures and identity, both actual
activation signatures and the complete actual challenge tuple. The narrow SQL
capture function supplies the immutable binding UUID and historical acceptance
checkpoint; it does not authenticate signatures or supply fresh owner authority.

Capture and activation share one transaction. The current original pending
proof, owner and registered scope are checked again after capture may wait, and
the original registration deadline and primary-clock floor are checked before
commit. The schema's deferred completion constraint requires the actual approved
pending state, consumed challenge, activated registration and active binding.
Installation acknowledgement remains a later transaction. A refused activation
cannot leave a separately committed receipt or binding allocation.

The complete original statements retain the already consumed historical nonce.
Pending nonces remain private; installation still clears the pending copy.
Historical bytes cannot authorize another activation or restore current access.
Account/registration erasure follows the additive schema's existing lifecycle
cascades. No original signature, timestamp or missing statement is reconstructed
from its digest, and already approved legacy history is never backfilled.

The optional schema probe preserves actual pre-installation v2 applications and
isolated fixtures. Partial, changed or unsupported receipt installations refuse.
Ordinary SMS and unregistered legacy activation do not gain SEALED originals or
an invented profile03 upgrade path.

`sealed_payload_election03::activation_records` reads the actual immutable
mapping and originals with a trusted application database connection and
configured canonical origin. It reuses the original registration reader's
authority/account fences, checks every retained identity and stored digest,
reverifies both original signature sets, and returns the existing canonical
activation evidence and old-binding commitment. The actual original activation
observation lease remains separate from both the earlier registration lease and
a later live device lease. A caller-supplied reader ID is a lookup expectation,
not proof of its selected manifest role or installed hardware custody.

Returned records are historical evidence only. Current owner authentication,
root/manifest/reader selection, installed complete-v2 continuity, current device
lease, accepted election and effect fences remain independent. A retained
historical object does not become present permission after sign-out, revocation
or transaction end. No profile03 HTTP route, capability advertisement, grant,
fetch, provider operation or message send is enabled by this change.

The focused database tests use the stock runtime ACL-reset block with generated
ordinary roles, full public migrations, genuine account/MFA/root/device and
registered-v2 ceremonies. Their device lease and Android observation are
synthetic; these tests do not establish a real socket, physical SIM, hardware
reader, Android interoperability or release readiness. Compilation and executed
qualification must be reported separately from source review.
