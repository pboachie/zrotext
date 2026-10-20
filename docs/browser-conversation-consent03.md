# Browser conversation consent crypto

The separate SDK module `conversation-interval03` verifies public ZTCA03
statements. It is an unmounted prerequisite for browser content consent. It
does not activate conversations or change existing profile02 APIs.

The statement carries nine identities, eight positive signed-storage-range
counters and times, thirteen commitments, the exact disclosure, an E.164 peer
and up to six explicit connector/read-grant/key mappings. Its length is
`692 + peer_bytes + 64 * reader_count`. Mappings are strictly ordered by key
identity and have independently unique connector and grant identities.

The trusted caller supplies its actual accepted election, independently
verified current manifest and current authority from the authenticated adapter.
It also supplies the original actual owner identity/session, configured HTTPS
origin, full device-session and physical-selection commitments, current grant
mappings, owner deadline and checked service time. The module checks genuine
proof handles and both inbound and outbound manifest policies. Matching public
fields cannot establish those adapter facts, current connector nonrevocation,
private-key custody or a physical connection.

Before signing, `checkConversationStatement03` checks the unsigned statement
against that captured context. The browser must separately match its durable
opening/receipt and show the exact phone, peer, reader list, disclosure and
deadline for explicit consent. `conversationRequestTranscript03` only frames
the exact received bytes; it does not validate or authorize them by itself.

`verifyConversationReceipts03` checks the separate role05 request, role04 phone
approval and role04 install signatures, with strict low-S raw P-256 signatures.
Approval binds the hash of the original request signature; install also binds
the original approval hash. Original times must be ordered and within the
original setup window. Missing earlier phases refuse later receipts.

Historical receipt checks may run after setup expiry while the installed
interval and actual present authority remain valid. They do not extend any
original time or turn an expired permission into a new one. A returned statement
is owned public crypto metadata, never a durable install ACK, restored key or
local interval handle, reader Ready state, or authorization for a message.

## Checked owner context and exact recovery transport

The separate `OwnerManifestHistoryClient03.conversationContext` read requires
complete original history and the exact retained unsigned reservation. It uses
a fresh request UUID and the fixed authenticated owner context endpoint. It
verifies the same complete current selection as the existing current method,
with independently held physical/session facts, actual original owner deadline
and the exact current registry reader projection. Original independent UI
peer/key/mapping choices are checked separately from the unsigned statement.
Both reply comparison times and permission deadlines must match. The actual
owner deadline can outlast the short current physical lease; it never extends
that lease. Current key, registry, owner, interval and permission bounds are
checked through the final cryptographic wait before returning metadata.

`OwnerConversationIntervalClient03` provides explicit reservation, request,
passive status and Stop calls at fixed same-origin paths. Before each mutation,
its callback must commit the exact public recovery record. A request record
contains the original statement and role05 signature; password and fresh factor
are passed only to that explicit request in memory. The callback never receives
those credentials. No method retries, creates a key or signs another original.

An interrupted first reservation may have no interval UUID yet. The distinct
opening-status read resolves its retained opening UUID without reserving again.
Fresh same-user sign-in may observe the original public receipt but cannot adopt
its old session as new consent. Requests retain the original actual session.
An uncertain commit503, malformed success, post-admission session withdrawal or
lost response remains UNKNOWN. A definite refusal requires the closed known
typed error body. Neither outcome erases a saved opening or original signature.

These modules remain unmounted SDK prerequisites. Actual browser durable
storage/controller, disclosure and fresh-factor UI, foreground phone consent,
durable install correlation and integrated server/device execution remain
separate requirements before enabling messaging. A phase label or downloaded
receipt is public metadata and cannot restore local custody or send permission.
