# Owner consent context and interrupted openings

The optional conversation03 library router adds two distinct authenticated
reads. Main startup does not mount it. Both use the existing cookie, Origin,
CSRF and independent read budget, bounded JSON and static refusal handling.
Neither read signs, allocates, renews, activates or sends a message.

After an unsigned reservation, POST
`/v1/owner/conversation/interval03/context` accepts the closed object
`{v:1,request_id,opening_id,interval_id}`. The original user and session must
still be current. The server holds the exact original interval, current owner,
root and complete manifest ancestry, full device lease, physical receipt and
actual mutable integration mappings in one transaction. It rechecks the
original statement/signatures, phase and deadlines after waits.

The closed response is
`{v:1,kind:"owner_conversation_context03",request_id,opening_id,interval_id,statement_sha256,selection,owner_session_expires_ms,physical_selection_digest,compared_ms,permission_expires_ms,readers}`.
`selection` retains the complete `owner_manifest_selection03` grammar. Both
comparison times and permission bounds are equal across that same held read.
The actual original owner-session deadline is separate from the shorter live
phone permission. Selected connector/read-grant rows retain their exact keys,
both-direction scope and lifetimes. A signed interval's end must fit the owner,
manifest, key and mapping lifetimes; current physical availability is a separate
requirement, never reconstructed from an unsigned statement.

If the initial reservation response was lost, POST
`/v1/owner/conversation/interval03/openings/status` accepts only
`{v:1,opening_id}`. It returns the same original public receipt for the same
original user, including after genuine fresh sign-in. It exposes no selection
or new permission. Fresh sign-in cannot adopt the old interval session, and
terminal history cannot become actionable through a context read. Existing
`/status` and current parsers are unchanged.

Clients retain their independently chosen opening, peer, keys and mappings,
match the fresh request nonce and exact statement, and verify the complete
current cryptographic evidence and local custody before signing. A context
response is neither phone consent nor an installed physical handle. Transport
uncertainty retains the original opening rather than automatically allocating
or signing another one. UUIDs are canonical and nonzero; binary values use
unpadded base64url and times use positive canonical decimal strings.
