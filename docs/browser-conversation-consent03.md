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

Current browser transport, original-request persistence, fresh-factor handling,
foreground phone consent, actual durable install correlation and integrated
server/device execution remain separate requirements before mounting this path.
