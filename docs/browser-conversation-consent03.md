# Browser conversation consent crypto

The separate SDK module `conversation-interval03` verifies public ZTCA03
statements. The explicit browser consent controller uses it with retained
role05 custody and the checked ordinary-owner transport. Existing profile02
APIs are unchanged; server feature mounting remains a separate decision.

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

## Browser continuation and interruption

The conversation page fills archive and selected-phone signer choices from its
complete root-verified public manifest. This discovery supplies no physical
lease or content permission. The owner chooses the exact peer and any additional
readers, a bounded duration and the displayed disclosure. The controller checks
those choices independently against the newly reserved statement and genuine
current context before using the existing nonexportable role05 key. It never
creates a missing key. Password and fresh factor clear from the page before the
explicit request call and never enter durable recovery.

Two IndexedDB stores atomically retain the current opening and all prior public
attempts. Closed records contain no private key, factors or message body. Exact
compare-and-set and committed readback precede mutation HTTP; stale tabs,
aborted commits and late operations cannot overwrite an original signed request.
Original signatures and submitted markers cannot reset. An uncertain first
response is reconciled by its original opening; an unsent saved command can be
explicitly resumed without a new UUID. A submitted request never repeats on
reload. The user checks its original status before any explicit continuation.
History has no software lifetime-count cap: explicit scoped pages return at
most32 records with an original-opening cursor. Appending another request does
not delete earlier attempts or block an unrelated peer after a global row count.

Fresh same-user sign-in observes old-session history without adopting it. A new
opening requires explicit action after an actual terminal service response. A
proven never-submitted, unsigned, receipt-free command can also be replaced
explicitly after the genuine anchored parent clock proves its expiry. Its exact
old record stays retained; an expired submitted/UNKNOWN command never receives
this exception, and an already expired unsent command is not sent again. Parent
conservative elapsed time and actual primary comparison have separate monotone
floors; neither can lower the conservative local expiry clock.
Stop withdraws local approval immediately, including
during signing, and aborts pending transport before its separate original Stop
call. Late crypto cannot publish a new signed request. If the original interval
identity or session is unavailable, the page asks for reconciliation rather than
claiming service-side Stop succeeded. Leaving, hiding, CSRF/session/selection
change, parent checkpoint withdrawal, clock regression or timeout closes the
local operation without deleting its history.

All three independent request/phone/install signatures and actual current
context are checked before showing verified active consent. That display loses
current permission at its original deadline. It remains public consent evidence,
not a phone-local durable handle, Ready state or permission for a message. The
existing composer is not unlocked by this controller. Integrated server/browser/
foreground phone, durable install correlation and message execution still need
qualification before enabling messaging.
