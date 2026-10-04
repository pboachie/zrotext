// SPDX-License-Identifier: AGPL-3.0-only
// Test-only independent conformance model. No SDK producer or authority.
function rawParse(raw) {
    if (Buffer.byteLength(raw) > 4096)
        throw Error('wire size');
    const result = JSON.parse(raw);
    validate(result);
    // The original bounded bytes are retained. Generic parsing alone proves no
    // duplicate refusal; exact re-encoding rejects duplicate/escaped aliases,
    // exponent/fraction/-0/whitespace forms even if JSON.parse normalizes them.
    if (raw !== canonical(result))
        throw Error('noncanonical original wire');
    return result;
}
function proposalParse(raw) {
    if (Buffer.byteLength(raw) > 8192)
        throw Error('outer wire size');
    const body = fields(JSON.parse(raw), ['descriptor', 'request_id']);
    uuid(body.request_id);
    validate(body.descriptor);
    if (Buffer.byteLength(canonical(body.descriptor)) > 4096)
        throw Error('descriptor size');
    // Whole retained original bytes prove nested encoding. Generic object parsing
    // alone would lose duplicate/spelling/padding evidence.
    if (raw !== canonical(body))
        throw Error('noncanonical whole original wire');
    return body.descriptor;
}
function nested(raw) {
    return '{"descriptor":' + raw + ',"request_id":"00000000-0000-0000-0000-000000000001"}';
}
const record = (v) => {
    if (!v || typeof v !== 'object' || Array.isArray(v))
        throw Error('object');
    return v;
};
const fields = (v, names) => {
    const r = record(v);
    if (Object.keys(r).sort().join('\0') !== [...names].sort().join('\0'))
        throw Error('fields');
    return r;
};
const literal = (v, wanted) => { if (v !== wanted)
    throw Error('literal'); };
const integer = (v, low = 1, high = Number.MAX_SAFE_INTEGER) => {
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < low || v > high)
        throw Error('range');
};
const uuid = (v) => {
    if (typeof v !== 'string' || !/^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v))
        throw Error('uuid');
};
const digest = (v, nonzero = false) => {
    if (typeof v !== 'string' || !/^[0-9a-f]{64}$/.test(v) || (nonzero && /^0+$/.test(v)))
        throw Error('digest');
};
const text = (v, max) => {
    if (typeof v !== 'string' || !/^[!-~]+$/.test(v) || v.length > max)
        throw Error('text');
};
function validate(v) {
    const t = fields(v, ['profile', 'action', 'route', 'reader', 'disclosure']);
    literal(t.profile, 'workflow-action-02');
    const a = fields(t.action, ['account_id', 'action_id', 'revision', 'line_id', 'recipient_id', 'purpose_id', 'content_ref', 'content_digest', 'content_version', 'not_before', 'expires_at', 'timezone', 'window_id', 'routine_id', 'authority_generation', 'commitment']);
    for (const name of ['account_id', 'action_id', 'line_id', 'recipient_id', 'content_ref', 'routine_id'])
        uuid(a[name]);
    if (!['00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000003'].includes(a.purpose_id))
        throw Error('purpose');
    integer(a.revision, 1, 128);
    integer(a.content_version, 1, 128);
    integer(a.authority_generation);
    digest(a.content_digest);
    integer(a.not_before, 0, 9007199254740);
    integer(a.expires_at, 1, 9007199254740);
    if (a.not_before >= a.expires_at)
        throw Error('time order');
    text(a.timezone, 64);
    if (a.timezone === 'unknown')
        throw Error('unknown zone');
    text(a.window_id, 128);
    if (!['informational', 'sensitive'].includes(a.commitment))
        throw Error('commitment');
    const r = fields(t.route, ['kind', 'adapter', 'route_id', 'route_version', 'organization_id', 'messaging_profile_id', 'sender_config_id', 'sender_config_version', 'route_fingerprint', 'eligibility_policy_id', 'eligibility_policy_version', 'eligibility_digest', 'exposure_route_policy_id', 'exposure_policy_version']);
    literal(r.kind, 'provider');
    literal(r.adapter, 'telnyx-sms-v2');
    for (const name of ['route_id', 'organization_id', 'messaging_profile_id', 'sender_config_id', 'eligibility_policy_id', 'exposure_route_policy_id'])
        uuid(r[name]);
    for (const name of ['route_version', 'sender_config_version', 'eligibility_policy_version', 'exposure_policy_version'])
        integer(r[name]);
    digest(r.route_fingerprint);
    digest(r.eligibility_digest);
    const reader = record(t.reader);
    const common = ['kind', 'role', 'key_id', 'trust_generation', 'manifest_version', 'manifest_digest'];
    if (reader.kind === 'owner_local') {
        fields(reader, common);
        literal(reader.role, 2);
    }
    else if (reader.kind === 'customer_selected') {
        fields(reader, [...common, 'grant_id', 'grant_version']);
        literal(reader.role, 3);
        uuid(reader.grant_id);
        integer(reader.grant_version);
    }
    else
        throw Error('reader kind');
    digest(reader.key_id, true);
    digest(reader.manifest_digest, true);
    integer(reader.trust_generation);
    integer(reader.manifest_version);
    const d = fields(t.disclosure, ['mode', 'recipient_commitment', 'request_digest']);
    literal(d.mode, 'provider_plaintext');
    digest(d.recipient_commitment, true);
    digest(d.request_digest);
}
function canonical(v) {
    if (v && typeof v === 'object')
        return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
    return JSON.stringify(v).replace(/\x7f/g, '\\u007f');
}
export { rawParse, proposalParse, canonical, nested };
