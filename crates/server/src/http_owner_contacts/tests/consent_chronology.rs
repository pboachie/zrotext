// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn consent_transitions_cannot_precede_the_latest_effective_event() {
    let owned = fixture(true).await;
    let response = owned
        .send(post_json(
            "/v1/owner/contacts",
            &owned.owner,
            &json!({"recipient_e164": "+15550100009"}),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let id = body(response).await["contact_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("/v1/owner/contacts/{id}/consents");
    let now = test_now_ms();
    let event = |action, effective| {
        json!({"purpose": "transactional", "action": action,
        "source": "off_channel_record", "effective_at_ms": effective})
    };
    let cases = [
        ("grant", now - 1_000, StatusCode::OK, "granted"),
        ("withdraw", now - 2_000, StatusCode::CONFLICT, "granted"),
        ("withdraw", now - 500, StatusCode::OK, "withdrawn"),
        ("grant", now - 750, StatusCode::CONFLICT, "withdrawn"),
        ("grant", now - 100, StatusCode::OK, "granted"),
    ];
    let mut records = 0;
    for (action, effective, status, state) in cases {
        let response = owned
            .send(post_json(&path, &owned.owner, &event(action, effective)))
            .await;
        assert_eq!(response.status(), status, "{action} at {effective}");
        if status == StatusCode::OK {
            records += 1;
        }
        let response = owned
            .send(get(&format!("/v1/owner/contacts/{id}"), &owned.owner))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let detail = body(response).await;
        assert_eq!(
            states_by_purpose(&detail["consents"])["transactional"]["status"],
            state
        );
        assert_eq!(detail["consent_history"].as_array().unwrap().len(), records);
    }
    owned.drop_schema().await;
}
