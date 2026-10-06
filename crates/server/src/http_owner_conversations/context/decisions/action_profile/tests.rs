// SPDX-License-Identifier: AGPL-3.0-only
use super::super::{
    model::{self, Phase},
    store,
};
use super::*;
use serde_json::{Value, json};
use sha2::Digest;

// Literal independently computed Python specimens, not codec-produced output.
pub(crate) const OWNER: &str = r#"{"action":{"account_id":"00000000-0000-0000-0000-000000000001","action_id":"00000000-0000-0000-0000-00000000000a","authority_generation":1,"commitment":"sensitive","content_digest":"abababababababababababababababababababababababababababababababab","content_ref":"00000000-0000-0000-0000-00000000000d","content_version":1,"expires_at":2000000300,"line_id":"00000000-0000-0000-0000-00000000000b","not_before":2000000000,"purpose_id":"00000000-0000-0000-0000-000000000001","recipient_id":"00000000-0000-0000-0000-00000000000c","revision":1,"routine_id":"00000000-0000-0000-0000-00000000000e","timezone":"UTC","window_id":"fixture-window"},"disclosure":{"mode":"provider_plaintext","recipient_commitment":"5afca772560f2d440678bd819ec6dc0c726714a19e96fc2cdb05c38d154cbaa7","request_digest":"0075fec7caed9bb7f6ed3570f6c41bdf8007da81e7e8af7bd2cb6218363e8efb"},"profile":"workflow-action-02","reader":{"key_id":"0101010101010101010101010101010101010101010101010101010101010101","kind":"owner_local","manifest_digest":"0202020202020202020202020202020202020202020202020202020202020202","manifest_version":1,"role":2,"trust_generation":1},"route":{"adapter":"telnyx-sms-v2","eligibility_digest":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","eligibility_policy_id":"00000000-0000-0000-0000-000000000016","eligibility_policy_version":1,"exposure_policy_version":1,"exposure_route_policy_id":"00000000-0000-0000-0000-000000000017","kind":"provider","messaging_profile_id":"00000000-0000-0000-0000-000000000003","organization_id":"00000000-0000-0000-0000-000000000002","route_fingerprint":"2ce6fbb7810f27d51d5906c9a1b16833dd224c339c3b12099d8607447c98bfc0","route_id":"00000000-0000-0000-0000-000000000014","route_version":1,"sender_config_id":"00000000-0000-0000-0000-000000000015","sender_config_version":1}}"#;
const CUSTOMER: &str = r#"{"action":{"account_id":"00000000-0000-0000-0000-000000000001","action_id":"00000000-0000-0000-0000-00000000000a","authority_generation":1,"commitment":"sensitive","content_digest":"abababababababababababababababababababababababababababababababab","content_ref":"00000000-0000-0000-0000-00000000000d","content_version":1,"expires_at":2000000300,"line_id":"00000000-0000-0000-0000-00000000000b","not_before":2000000000,"purpose_id":"00000000-0000-0000-0000-000000000001","recipient_id":"00000000-0000-0000-0000-00000000000c","revision":1,"routine_id":"00000000-0000-0000-0000-00000000000e","timezone":"UTC","window_id":"fixture-window"},"disclosure":{"mode":"provider_plaintext","recipient_commitment":"5afca772560f2d440678bd819ec6dc0c726714a19e96fc2cdb05c38d154cbaa7","request_digest":"0075fec7caed9bb7f6ed3570f6c41bdf8007da81e7e8af7bd2cb6218363e8efb"},"profile":"workflow-action-02","reader":{"grant_id":"00000000-0000-0000-0000-00000000001e","grant_version":1,"key_id":"0101010101010101010101010101010101010101010101010101010101010101","kind":"customer_selected","manifest_digest":"0202020202020202020202020202020202020202020202020202020202020202","manifest_version":1,"role":3,"trust_generation":1},"route":{"adapter":"telnyx-sms-v2","eligibility_digest":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","eligibility_policy_id":"00000000-0000-0000-0000-000000000016","eligibility_policy_version":1,"exposure_policy_version":1,"exposure_route_policy_id":"00000000-0000-0000-0000-000000000017","kind":"provider","messaging_profile_id":"00000000-0000-0000-0000-000000000003","organization_id":"00000000-0000-0000-0000-000000000002","route_fingerprint":"2ce6fbb7810f27d51d5906c9a1b16833dd224c339c3b12099d8607447c98bfc0","route_id":"00000000-0000-0000-0000-000000000014","route_version":1,"sender_config_id":"00000000-0000-0000-0000-000000000015","sender_config_version":1}}"#;
pub(crate) fn fixture() -> Value {
    serde_json::from_str(OWNER).unwrap()
}
pub(crate) fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn literal_whole_provider_digest_and_both_readers_remain_complete() {
    for (raw, expected) in [
        (
            OWNER,
            "0a5b3363d9d9ff8ea8dcb0a1b1eebe137a895abf0821e6b6e3635946136e4ade",
        ),
        (
            CUSTOMER,
            "ec1674beda783aad0b18c2449b8ef3a274a99f4bd0ef6b30d72f260f296fd183",
        ),
    ] {
        let d = ProviderAction::parse(raw.as_bytes()).unwrap();
        assert_eq!(d.canonical(), raw.as_bytes());
        assert_eq!(
            super::super::descriptor::hex(&d.key().unwrap().binding_digest),
            expected
        );
        let nested: Value = serde_json::from_slice(&d.canonical()).unwrap();
        let nested_hash: [u8; 32] = sha2::Sha256::digest(bytes(&nested["action"])).into();
        assert_ne!(d.key().unwrap().binding_digest, nested_hash);
    }
}
#[test]
fn each_complete_route_reader_disclosure_and_action_binding_changes_identity() {
    let d = ProviderAction::parse(OWNER.as_bytes()).unwrap();
    for (section, field, value) in [
        (
            "route",
            "route_id",
            json!("00000000-0000-0000-0000-000000000077"),
        ),
        ("route", "route_version", json!(2)),
        (
            "route",
            "organization_id",
            json!("00000000-0000-0000-0000-000000000077"),
        ),
        (
            "route",
            "messaging_profile_id",
            json!("00000000-0000-0000-0000-000000000077"),
        ),
        (
            "route",
            "sender_config_id",
            json!("00000000-0000-0000-0000-000000000077"),
        ),
        ("route", "sender_config_version", json!(2)),
        ("route", "route_fingerprint", json!("77".repeat(32))),
        (
            "route",
            "eligibility_policy_id",
            json!("00000000-0000-0000-0000-000000000077"),
        ),
        ("route", "eligibility_policy_version", json!(2)),
        ("route", "eligibility_digest", json!("77".repeat(32))),
        (
            "route",
            "exposure_route_policy_id",
            json!("00000000-0000-0000-0000-000000000077"),
        ),
        ("route", "exposure_policy_version", json!(2)),
        ("reader", "key_id", json!("77".repeat(32))),
        ("reader", "trust_generation", json!(2)),
        ("reader", "manifest_version", json!(2)),
        ("reader", "manifest_digest", json!("77".repeat(32))),
        ("disclosure", "recipient_commitment", json!("77".repeat(32))),
        ("disclosure", "request_digest", json!("77".repeat(32))),
        ("action", "window_id", json!("different-window")),
        ("action", "content_digest", json!("77".repeat(32))),
    ] {
        let mut changed = fixture();
        changed[section][field] = value;
        let next = ProviderAction::parse(&bytes(&changed)).unwrap();
        assert_ne!(
            next.key().unwrap().binding_digest,
            d.key().unwrap().binding_digest,
            "{section}.{field}"
        );
    }
}
#[test]
fn original_wire_duplicates_aliases_numeric_spelling_order_and_caps_refuse() {
    let bad = [
        OWNER.replacen(
            "\"profile\":",
            "\"profile\":\"workflow-action-02\",\"profile\":",
            1,
        ),
        OWNER.replace("\"profile\"", &format!("\"profi{}u006ce\"", char::from(92))),
        OWNER.replace("\"revision\":1", "\"revision\":1.0"),
        format!(" {OWNER}"),
        format!("{OWNER}\n"),
        "[]".into(),
    ];
    for raw in bad {
        assert!(ProviderAction::parse(raw.as_bytes()).is_err());
    }
    assert!(ProviderAction::parse(&vec![b' '; 4097]).is_err());
    let request = format!(
        "{{\"descriptor\":{OWNER},\"request_id\":\"00000000-0000-0000-0000-000000000064\"}}"
    );
    let (id, d) = ProviderAction::proposal(request.as_bytes()).unwrap();
    assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000064");
    assert_eq!(d.canonical(), OWNER.as_bytes());
    assert!(
        ProviderAction::proposal(request.replace("request_id", "request\\u005fid").as_bytes())
            .is_err()
    );
    assert!(ProviderAction::proposal(&vec![b' '; 8193]).is_err());
}
#[test]
fn internal_edit_invalidates_whole_changes_but_refuses_revision_only_and_lineage_changes() {
    let old = ProviderAction::parse(OWNER.as_bytes()).unwrap();
    for (part, field, value) in [
        ("route", "route_version", json!(2)),
        ("reader", "manifest_version", json!(2)),
        ("disclosure", "request_digest", json!("77".repeat(32))),
    ] {
        let mut v = fixture();
        v["action"]["revision"] = json!(2);
        v[part][field] = value;
        let next = ProviderAction::parse(&bytes(&v)).unwrap();
        assert!(model::edit_provider(&old, &next, Phase::Proposed).is_ok());
        assert!(model::edit_provider(&old, &next, Phase::Approved).is_ok());
        for phase in [
            Phase::Cancelled,
            Phase::Unknown,
            Phase::Dispatching,
            Phase::Succeeded,
        ] {
            assert!(model::edit_provider(&old, &next, phase).is_err());
        }
    }
    let mut revision = fixture();
    revision["action"]["revision"] = json!(2);
    assert!(
        model::edit_provider(
            &old,
            &ProviderAction::parse(&bytes(&revision)).unwrap(),
            Phase::Proposed
        )
        .is_err()
    );
    for field in ["account_id", "action_id", "content_ref", "routine_id"] {
        let mut v = revision.clone();
        v["action"][field] = json!("00000000-0000-0000-0000-000000000077");
        v["route"]["route_version"] = json!(2);
        assert!(
            model::edit_provider(
                &old,
                &ProviderAction::parse(&bytes(&v)).unwrap(),
                Phase::Proposed
            )
            .is_err()
        );
    }
}
#[test]
fn stored_provider_profile_cannot_be_loaded_as_phone_or_under_projected_key() {
    let d = ProviderAction::parse(OWNER.as_bytes()).unwrap();
    let key = d.key().unwrap();
    assert!(
        StoredProfile::parse(OWNER.as_bytes(), key)
            .unwrap()
            .phone()
            .is_err()
    );
    let mut wrong = key;
    wrong.binding_digest = [0; 32];
    assert!(StoredProfile::parse(OWNER.as_bytes(), wrong).is_err());
    let mut value = fixture();
    value["profile"] = json!("workflow-action-01");
    assert!(ProviderAction::parse(&bytes(&value)).is_err());
}
#[test]
fn provider_replay_binds_owner_request_whole_previous_key_cas_and_complete_next() {
    let owner = Uuid::from_u128(1);
    let request = Uuid::from_u128(100);
    let d = ProviderAction::parse(OWNER.as_bytes()).unwrap();
    let key = d.key().unwrap();
    let full = d.canonical();
    let args = (key, 1, full.clone());
    assert_eq!(
        super::super::descriptor::hex(
            &store::provider_request_digest(1, owner, request, &full).unwrap()
        ),
        "f5d90033876f14f4af6d3d61eee78abbe960de700cdb2e3ff91e95c0a000ab1e"
    );
    let expected = store::provider_request_digest(3, owner, request, &args).unwrap();
    assert_eq!(
        expected,
        store::provider_request_digest(3, owner, request, &args).unwrap()
    );
    assert_ne!(
        expected,
        store::provider_request_digest(3, Uuid::from_u128(2), request, &args).unwrap()
    );
    assert_ne!(
        expected,
        store::provider_request_digest(3, owner, Uuid::from_u128(101), &args).unwrap()
    );
    assert_ne!(
        expected,
        store::provider_request_digest(3, owner, request, &(key, 2, full.clone())).unwrap()
    );
    let mut wrong = key;
    wrong.binding_digest = [0; 32];
    assert_ne!(
        expected,
        store::provider_request_digest(3, owner, request, &(wrong, 1, full.clone())).unwrap()
    );
    let mut value = fixture();
    value["route"]["route_version"] = json!(2);
    assert_ne!(
        expected,
        store::provider_request_digest(3, owner, request, &(key, 1, bytes(&value))).unwrap()
    );
    assert_ne!(expected, store::request_digest(3, &args).unwrap());
}
