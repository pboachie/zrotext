// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::collections::HashSet;

async fn page(app: &axum::Router, token: &str, path: &str) -> serde_json::Value {
    let response = app.clone().oneshot(get_request(token, path)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn device_pages_preserve_all_bindings_and_count_distinct_devices() {
    let (case, token) = resource_case("devices:read").await;
    let f = &case.fixture;
    let mut lines = HashSet::from([f.line.to_string()]);
    for _ in 0..26 {
        let line = Uuid::new_v4();
        f.db.execute(
            "INSERT INTO phone_lines(id,account_id) VALUES($1,$2)",
            &[&line, &f.account],
        )
        .await
        .unwrap();
        f.db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,purpose) VALUES($1,$2,$3,1,'sealed')", &[&f.account, &line, &f.device]).await.unwrap();
        lines.insert(line.to_string());
    }
    let app = router(case.state());
    let single = page(&app, &token, "/devices").await;
    assert_eq!(single["devices"].as_array().unwrap().len(), 1);
    assert!(
        single["next_cursor"].is_null(),
        "bindings are not extra devices"
    );
    let listed: HashSet<_> = single["devices"][0]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line["line_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(listed, lines, "a device's bindings must never be truncated");
    let detail = page(&app, &token, &format!("/devices/{}", f.device)).await;
    assert_eq!(detail["lines"].as_array().unwrap().len(), lines.len());

    let mut expected = HashSet::from([f.device.to_string()]);
    for offset in 1i32..=25 {
        let device = Uuid::new_v4();
        f.db.execute("INSERT INTO devices(id,account_id,display_name,created_at) SELECT $1,$2,'synthetic',created_at-make_interval(secs => $3::int) FROM devices WHERE id=$4", &[&device, &f.account, &offset, &f.device]).await.unwrap();
        f.db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device, &f.account, &vec![4u8;65], &vec![1u8;32]]).await.unwrap();
        expected.insert(device.to_string());
    }
    let first = page(&app, &token, "/devices").await;
    assert_eq!(first["devices"].as_array().unwrap().len(), 25);
    assert_eq!(
        first["devices"][0]["lines"].as_array().unwrap().len(),
        lines.len()
    );
    let cursor = first["next_cursor"].as_str().unwrap();
    let second = page(&app, &token, &format!("/devices?before={cursor}")).await;
    assert_eq!(second["devices"].as_array().unwrap().len(), 1);
    assert!(second["next_cursor"].is_null());
    let ids: Vec<_> = first["devices"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["devices"].as_array().unwrap())
        .map(|device| device["device_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), expected.len());
    assert_eq!(ids.into_iter().collect::<HashSet<_>>(), expected);
    case.fixture.cleanup().await;
}
