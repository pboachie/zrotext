# Experimental scoped agent authority

This is a default-off library prerequisite for customer-controlled agents.
Production routing, general sending, line activation and the approved sealed
cryptography release remain separately gated. It does not establish trust from
an SMS, a model instruction or a caller-supplied approval flag.

An authenticated owner selects one existing connector, device, line, binding
generation and attested self-notification recipient. Grant creation requires
the current password and, when enabled, MFA, with the existing session, origin
and CSRF checks. The recipient is stored as an account-specific keyed digest.
Changing the scope requires a new owner-authorized grant. A grant lasts at most
one day and permits at most 100 distinct messages and three consumed turns.
The four operations are independent:

| Permission | Dedicated operation |
| --- | --- |
| Metadata | Read the seven safe message metadata fields in the selected scope |
| Content | Fetch the exact outbound ciphertext for the selected current reader |
| Draft | Validate a signed proposed action without queueing or consuming a budget |
| Send | Admit an exact signed action already approved by the authenticated owner |

Grant-linked API credentials are rejected by ordinary API authentication even
after revocation. They cannot acquire ordinary account access by falling back
to another route. Metadata and content reads require agent-origin provenance
and the selected account, device, line, binding generation and recipient; they
do not require the caller to possess send permission. Content additionally
requires the current selected reader's manifest authority and envelope wrap.
The server returns ciphertext and does not decrypt it. Inbound reading is not
provided by this prerequisite.

Owner grant management uses `/v1/auth/agent-grants`, with grant-specific
`/revoke`, `/takeover` and `/approvals` operations. Creation returns the API
credential once. Listing exposes the selected reader, independent permissions,
expiry, withdrawal state and reserved budgets, without returning credentials.
Owner mutations recheck the current session after their final writes; expiry
rolls back the complete grant, approval, withdrawal or takeover. Inventory
rechecks current owner authority before releasing its page.
Listing returns at most 100 grants with explicit `truncated` and `next_cursor`
fields; `before` continues that account's history. Owner takeout includes the
same bounded `agent_grants` page, continued with `agent_before`. A cursor outside
the account returns 404. Account erasure includes grant, approval and action
records in its deletion plan; existing immutable line and sealed trust-history
blockers still make erasure fail closed with nothing deleted.
Model-provider content access is refused; it is not inferred from permission
to read ciphertext.

The sealed library exposes these dedicated paths when explicitly enabled:

- `GET /v1/sealed/agent/messages/{message_id}`
- `GET /v1/sealed/agent/messages/{message_id}/content`
- `POST /v1/sealed/agent/actions/{action_id}/draft`
- `POST /v1/sealed/agent/actions/{action_id}/messages`

POST bodies are the existing signed candidate envelope. Draft timing uses the
canonical `x-zrotext-not-before-ms` header. Sending uses the timing recorded by
the authenticated owner's approval. Action approval binds the account, grant,
action and message identities, device, line, binding generation, recipient,
unsigned envelope digest, not-before time and expiry. Editing any bound field
requires another authenticated approval. An identical admission replay keeps
the existing message identity and does not consume another message or turn.
Existing owner-origin queued work cannot be adopted as agent work.
Distinct admitted actions permanently consume this grant's message and turn
limits. Cancelling a message can refund its delivery quota without replenishing
agent authority or permitting a retry to create another effect.
The self-notification pilot has an immutable one-segment ceiling. The caller
cannot widen it; the gateway must still validate the decrypted segment count.
The server does not infer that count from ciphertext.

Admission serializes grant budgets and checks current account, connector,
manifest, line and suppression authority. Durable agent provenance remains
attached to the queued message. Independent database guards recheck that
authority before creating attempts, fences, durable radio intent or entering
claimed/submitting states. Grant withdrawal and takeover serialize against
those decisions; elapsed time is checked again after waiting for authority.
Grant issuance, device envelope fetch and the final durable-intent commit also
recheck agent authority after their last potential write or lock wait.
Revocation stops future authorization and cannot retract an already committed
radio intent, erase ciphertext previously fetched by a reader or remove copies
retained by a customer application. Historical delivery evidence remains
recordable after withdrawal.

Received SMS content remains untrusted input. It cannot grant permissions,
approve actions, widen recipients or impersonate the owner. No plaintext,
private signing/decryption keys or provider credentials belong in agent logs.
Physical-device and carrier delivery remain separate release verification.
