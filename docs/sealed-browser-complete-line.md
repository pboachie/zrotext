# Browser complete-set sealed line setup

The ordinary sealed line controller exposes a separate unchecked Android13+
complete-set choice. It uses the existing registered `challenges-v2`, `view`
and `approve` routes, the current ordinary owner session and CSRF, the existing
offline-root-approved line registration, and the exact paired signing point.
Its custody may be session-only or explicitly retained in the browser. Changing
the selected protocol or any frozen identity closes the active ceremony.

The controller verifies the exact255-byte SEALED-v2 device statement, complete
121-byte observation and genuine paired P-256 signature. It reconstructs the
existing314-byte owner statement with the hash of the original received canonical
DER, including high-S signatures without rewriting them. Account, device, line,
challenge and generation must match the independent current selection. Android
API, subscription count, selected subscription, kind, tokens, port/slot and
observer epoch must satisfy the existing complete-set codec. A declaration
can include multiple active SIMs. Compare the selected SIM on the phone; its
signed opaque observations are not independent proof of physical SIM identity.

The view's separate observation and owner-statement bytes must match the
independently verified signed statement. Only then can the user explicitly
approve with the original sealed approval key. Current session, original
registration expiry and captured protocol/scope are rechecked around waits.
The original challenge deadline is retained; status reads never renew it.

An uncertain approval is observed through the same challenge and cannot be
automatically re-signed or resent. A committed activation is displayed separately
from durable phone installation acknowledgment. The activated view must retain
the exact original observed bytes/signature before installation can be shown.
Unsupported or malformed v2 responses refuse without selecting a legacy route.
Every existing v1 codec and route remains unchanged.

This is setup source integration. It does not mount server composition gates,
capture originals on a pre-receipt server, elect profile03, authorize content,
provide a maintained reader, or send SMS. Those capabilities require their
separate current authorization, durable evidence and integrated qualification.
