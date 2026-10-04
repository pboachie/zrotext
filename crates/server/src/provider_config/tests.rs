// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::json;

mod database;

fn declaration() -> Declaration {
    serde_json::from_value(json!({
        "adapter":"telnyx-sms-v2",
        "organization_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "messaging_profile_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "sender":"+15550100001","owner_label":"Example","intended_region":"unverified",
        "retention_policy_ref":null,"eligibility_policy_ref":null,"cost_policy_ref":null
    }))
    .unwrap()
}
#[test]
fn typed_declarations_refuse_alias_duplicates_unknown_fields_and_noncanonical_ids() {
    let d = declaration();
    let bytes = d.bytes().unwrap();
    let raw = String::from_utf8(bytes).unwrap();
    assert!(
        serde_json::from_str::<Declaration>(&raw.replacen("{", "{\"sender\":\"other\",", 1))
            .is_err()
    );
    assert!(
        serde_json::from_str::<Declaration>(&raw.replacen("{", r#"{"sen\u0064er":"other","#, 1))
            .is_err()
    );
    assert!(
        serde_json::from_str::<Declaration>(&raw.replacen("{", "{\"enabled\":true,", 1)).is_err()
    );
    for bad in [
        "00000000-0000-0000-0000-000000000000",
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n",
    ] {
        let mut changed = d.clone();
        changed.organization_id = bad.into();
        assert!(changed.bytes().is_err());
    }
    for bad in [
        "label\n",
        "label\r",
        "label\u{2028}",
        "label\u{2029}",
        "",
        "two words",
    ] {
        let mut changed = d.clone();
        changed.owner_label = bad.into();
        assert!(changed.bytes().is_err());
    }
    let mut maximal = d;
    maximal.owner_label = "L".repeat(64);
    assert!(maximal.bytes().is_ok());
    maximal.owner_label.push('L');
    assert!(maximal.bytes().is_err());
}
#[test]
fn declaration_bytes_and_request_identity_bind_every_private_field_without_authority() {
    let d = declaration();
    let bytes = d.bytes().unwrap();
    let mut changed = d.clone();
    changed.sender = "+15550100002".into();
    assert_ne!(
        model::digest(&bytes),
        model::digest(&changed.bytes().unwrap())
    );
    let a = uuid::Uuid::new_v4();
    let c = uuid::Uuid::new_v4();
    let hash = model::request_digest(a, c, "create", 0, Some(&bytes)).unwrap();
    for other in [
        model::request_digest(a, c, "revise", 1, Some(&bytes)).unwrap(),
        model::request_digest(a, c, "withdraw", 1, None).unwrap(),
        model::request_digest(uuid::Uuid::new_v4(), c, "create", 0, Some(&bytes)).unwrap(),
    ] {
        assert_ne!(hash, other);
    }
}
