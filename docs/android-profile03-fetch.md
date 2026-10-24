# Android current message permission for signed fetch

The full-history profile03 execution path consumes the distinct closed
`message_manifest_permission03` projection. Existing first-only, earlier
full-history message and device selection parsers retain their exact field sets.
An old, device-only or capture projection cannot be rewritten into this kind.
No runtime gate is enabled by this source change.

The existing25-field grant,362-byte device-signature transcript and closed fetch
request remain unchanged. Before Room, framework or hardware lookup after the
response, the consumer requires request kind `fetch`, the actual grant attempt
UUID and SHA256 of that exact independently prepared transcript. Both current
and interval permission deadlines must equal the unchanged grant expiry, and
both use the same primary comparison time. A shorter or longer deadline refuses.
The server must actually revalidate every current bound through that end; a
matching received digest or deadline does not establish server provenance.

The current projection requires the complete original ten evidence fields,
separate current signed manifest and ancestry prefix, original actual owner
identity/session, full current device lease and an explicit closed physical
selection. The existing verifier independently checks retained original signed
election history, compared root/02 checkpoint, original registration/activation,
actual existing nonexportable reader relation and complete installed ancestry
with its genuine current socket readback. It does not install a higher tip from
fetch JSON. Missing local history or readback refuses.

Physical `original_v2` additionally requires the same original installed local
issuer/connection and no ever-signed refresh history for that connection.
`owner_refresh03` must exactly match the retained installed refresh, all original
proofs/times, actual full lease and current opaque issuer. Its historical manifest
is independently verified through the installed ancestry. Neither subscription
equality nor a public refresh bundle reconstructs a physical permit.

Every preparation and effect recheck uses the distinct consumer. It still requires
the actual active RAM interval and exact durable local original statement, three
signatures and receipt times. The original reviewed admission must occur after
installation; current owner, manifest/key, peer, mapping, full lease, physical and
grant predicates are checked at actual now. The one-use preparation/radio journal
and maintained nonexportable recipient guards remain mandatory. A queued message's
original lifetime may outlast a short current lease; it is not backdated or renewed
to make a fetch succeed. Stop, withdrawal or expired authority refuses effects.

The new JVM cases exercise public correlation, every signed-transcript input,
closed kinds/fields/physical union, exact grant coverage, current comparison,
duplicate-name and malformed-byte refusal with genuine synthetic interval proofs.
Their public candidate projection deliberately lacks installed ancestry and cannot
establish authenticated service records, private custody or an actual install ACK.
Integrated server/SQL, Android/native/provider and no-radio device qualification
remain separate from source review or synthetic component tests. Inbound capture
uses a separate future permission/intent/receipt contract.
