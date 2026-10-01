# Dormant owner host and phone proposal adapters

These adapters require explicit host composition. They do not mount ordinary
production routes, provision keys, or supply an owner root trust anchor.

The owner router exposes same-origin POST endpoints with existing owner-cookie
authentication and CSRF admission before body extraction. Bearer authority is
refused. Responses are `no-store`; request bodies are bounded to 20 KiB and reject
unknown fields. Binary JSON fields use canonical standard padded base64. Account,
owner session, site, instance, epochs and server time come from authenticated
server state, never the request body.

* `/v1/owner/conversation/activation` accepts `consent` and `next_manifest`.
  Consent contains `device_id`, `line_id`, `binding_generation`, `peer`,
  `disclosure_version` and affirmative `content_transfer_confirmed`. The existing
  activation transaction verifies the signed successor and selected line. A 200
  response contains the canonical original statement with content type
  `application/vnd.zrotext.conversation-statement.v1`. It leaves phone consent
  pending; transport success does not enable capture.
* `/v1/owner/conversation/enrollment` accepts `device_id`, `line_id`,
  `binding_generation`, `peer`, `phone_reader`, `archive_reader`, `signer`,
  `public_point`, `predecessor` and `signed_successor`. IDs/digest are 32 bytes,
  the uncompressed P-256 point is 65 bytes and the signed manifest is 364–9,751
  bytes. Existing enrollment checks predecessor CAS and the exact signed role
  changes. Success is 204; clients must verify the successor before using it.
* `/v1/owner/conversation/bootstrap` accepts only `device_id`, `line_id`,
  `binding_generation` and `peer`. It checks current owner, device, line, keys and
  manifest authority, including durable time rollback protection, without changing
  consent, intervals, trust or the manifest high-water mark.

Bootstrap JSON contains `v:1`, `trust_candidate:true`, `owner_session_live:true`,
`consent_live`, `account_id`, `session_id`, selected device/line/peer,
`binding_generation`, `phase`, nullable `interval_id`, `server_now_ms`, `root_pin`,
`root_fingerprint`, `current_manifest`, `manifest_digest`, `manifest_version`,
`trust_generation`, and the `phone_reader`, `archive_reader`, `phone_signer` public
`_id`/`_point` pairs. Integer generations, versions and milliseconds are decimal
strings in this response. Binary values use canonical standard base64. Phases are
`unprepared`, `pending`, `install_pending` or `active`.

The entire projection is an **untrusted candidate**. A downloaded public root is
not a trust anchor. Clients must independently compare an existing root pin and
verify signed manifest history, exact account and durable high-water/time bounds.
No private key, message content or credential appears in the projection.

## Authenticated binary proposal bundle

Kinds 16 and 17 reuse the exact 118-byte authenticated channel header defined in
`conversation-adapters.md`, including nonzero challenge and the existing phone
session/account/device/connection/deployment/origin binding.

| Kind | Body after header | Exact bounds |
|---|---|---|
| 16: retrieve pending proposal | Nonzero interval UUID (16 bytes) | Exactly 134 bytes total |
| 17: immutable proposal bundle | u16 BE original length, canonical original statement, u16 BE manifest length, exact stored signed activation manifest | Original 380–1,024 bytes; manifest 364–9,751 bytes; total at most 10,897 bytes |

Receivers require strict EOF; lengths cannot identify external data or paths. The
reply echoes the authenticated request challenge. Both payloads are the immutable
bytes saved for that interval, including after approved installation or renewal.
They are never reconstructed or replaced with an unrelated current manifest.

Retrieval permits only `pending` and `install_pending`, exact original placement,
current device/line roles and live initiating owner session. Pending retrieval
verifies the saved successor against the current predecessor and selected reader
and phone signer. Installed-pending retrieval requires current authority to equal
that exact saved successor. Fresh authority, roles, origin, phone lease and expiry
are checked after blocking operations. Missing or foreign selectors are forbidden;
withdrawn and active intervals are not reopened by this endpoint.

The phone must verify the manifest using its independently accepted root, chain,
high-water and time checks, then require the canonical unsigned manifest semantic
SHA-256 digest (excluding its 64-byte signature), version, trust generation
and account to equal the original statement before accepting it. Receiving the
bundle grants no consent or capture admission. Existing affirmative phone approval
and installation remain mandatory.
