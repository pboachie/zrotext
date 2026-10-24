// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
#[test]
fn configured_origins_refuse_whitespace_instead_of_relying_on_url_normalization() {
    for origin in [
        " wss://example.test",
        "wss://example.test ",
        "\twss://example.test",
        "wss://exam\nple.test",
        "wss://example.test\r",
        "\u{a0}wss://example.test",
    ] {
        assert!(protection_origin_digest(origin).is_err());
        assert!(conversation_origin_check(origin).is_err());
    }
}
fn ids() -> [String; 3] {
    [
        Uuid::from_u128(1).to_string(),
        Uuid::from_u128(2).to_string(),
        Uuid::from_u128(3).to_string(),
    ]
}
fn request() -> serde_json::Value {
    let [setup, opening, command] = ids();
    serde_json::json!({"v":1,"type":"protection_origin_proof_open","connection_epoch":1,"setup_id":setup,"opening_id":opening,"command_id":command,"proof_request_id":Uuid::from_u128(4),"association":URL_SAFE_NO_PAD.encode([7;329]),"aes_probe":URL_SAFE_NO_PAD.encode([8;120]),"previous_attempt_id":null,"previous_core_sha256":null,"previous_bundle_sha256":null})
}
#[test]
fn routing_is_not_authority_and_full_fields_reject_missing_nulls_or_duplicate_aliases() {
    let value = request();
    let encoded = value.to_string();
    assert!(parse(&encoded).unwrap().is_some());
    let body: Attempt = serde_json::from_str(&encoded).unwrap();
    assert_eq!(nullable_id(&body.previous_attempt_id).unwrap(), None);
    assert!(nullable_hash(&body.previous_core_sha256).unwrap().is_none());
    let mut missing = value.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("previous_bundle_sha256");
    assert!(serde_json::from_str::<Attempt>(&missing.to_string()).is_err());
    let duplicate = encoded.replacen("{", "{\"v\":1,", 1);
    assert!(serde_json::from_str::<Attempt>(&duplicate).is_err());
    let escaped_key = format!("{{\"{}u0076\":1,", char::from(92));
    let escaped = encoded.replacen("{", &escaped_key, 1);
    assert!(serde_json::from_str::<Attempt>(&escaped).is_err());
    let mut extra = value.clone();
    extra["owner_permission"] = serde_json::json!(true);
    assert!(serde_json::from_str::<Attempt>(&extra.to_string()).is_err());
    assert!(serde_json::from_str::<Attempt>("[]").is_err());
    assert!(parse(r#"{"type":"conversation_ready"}"#).unwrap().is_none());
    assert!(parse(&format!("{} ", encoded.repeat(5))).is_err());
    assert!(binary::<32>(&URL_SAFE_NO_PAD.encode([1; 31])).is_err());
    assert!(binary::<32>(&(URL_SAFE_NO_PAD.encode([1; 32]) + "=")).is_err());
    assert!(id("00000000-0000-0000-0000-000000000000").is_err());
}
#[test]
fn every_new_control_shape_fits_the_existing_ordinary_four_kib_cap() {
    let id = Uuid::from_u128(1).to_string();
    let hash = URL_SAFE_NO_PAD.encode([1; 32]);
    let maximum = i64::MAX.to_string();
    let opening = serde_json::json!({"account_id":id,"device_id":id,"source_pairing_id":id,"origin_digest":hash,"enrolled_point":URL_SAFE_NO_PAD.encode([4;65]),"enrolled_key_id":hash,"opening_nonce":hash,"created_ms":maximum,"pairing_created_ms":maximum,"pairing_claimed_ms":maximum,"pairing_approved_ms":maximum,"pairing_expires_ms":maximum});
    let predecessor = serde_json::json!({"proof_request_id":id,"attempt_id":id,"core_sha256":hash,"bundle_sha256":hash,"closed_ms":maximum});
    let challenge = serde_json::json!({"proof_request_id":id,"attempt_id":id,"core":URL_SAFE_NO_PAD.encode([1;393]),"nonce":hash,"closed_predecessor":predecessor});
    let receipt = serde_json::json!({"association_sha256":hash,"core_sha256":hash,"bundle_sha256":hash,"accepted_ms":maximum});
    let status = serde_json::json!({"v":1,"type":"protection_origin_status","connection_epoch":i64::MAX,"request_id":id,"setup_id":id,"opening_id":id,"command_id":id,"proof_request_id":id,"status":"accepted","opening":opening,"challenge":challenge,"receipt":receipt});
    assert!(status.to_string().len() < MAX_FRAME_BYTES);
    let attempt = request();
    assert!(attempt.to_string().len() < MAX_FRAME_BYTES);
    let proof = serde_json::json!({"v":1,"type":"protection_origin_proof","connection_epoch":i64::MAX,"setup_id":id,"opening_id":id,"command_id":id,"proof_request_id":id,"attempt_id":id,"bundle":URL_SAFE_NO_PAD.encode([1;521])});
    assert!(proof.to_string().len() < MAX_FRAME_BYTES);
    assert_eq!(socket_frame_limit(false), MAX_FRAME_BYTES);
    // These width/encoding fixtures establish bounded canonical wire sizes,
    // not valid points/signatures or a provider/current permission.
}
