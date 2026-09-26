// SPDX-License-Identifier: AGPL-3.0-only
use super::tests::{apply_migrations, json_response, request};
use super::*;
use crate::auth::{login, register, verify_email};
use axum::http::Method;
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use rand::rng;
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn owner_queue_counts_are_bounded_tenant_scoped_and_preserve_writer_states() {
    let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
    let (mut db, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("owner_queue_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    apply_migrations(&db).await;
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let mut owners = Vec::new();
    for label in ["queue-a", "queue-b"] {
        let email = format!("{label}@example.test");
        let password = format!("synthetic-{}", Uuid::new_v4());
        let signup = register(&mut db, &hasher, &email, &password).await.unwrap();
        verify_email(&mut db, &hasher, &signup.verification_token)
            .await
            .unwrap();
        let session = login(&db, &hasher, &email, &password).await.unwrap();
        let device = Uuid::new_v4();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Synthetic gateway')",
            &[&device, &signup.account_id],
        )
        .await
        .unwrap();
        let signing = SigningKey::generate_from_rng(&mut rng());
        let key = signing.verifying_key().to_sec1_point(false);
        let fingerprint = rand::random::<[u8; 32]>();
        db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device, &signup.account_id, &key.as_bytes(), &&fingerprint[..]]).await.unwrap();
        owners.push((signup.account_id, device, session));
    }
    let sep = if base.contains('?') { '&' } else { '?' };
    let app = router(EnrollmentHttpState::new(
        format!("{base}{sep}options=-csearch_path%3D{schema}"),
        hasher,
        Arc::new(EnrollmentHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap()),
        "https://test.example".into(),
    ));
    let (account, device, session) = &owners[0];
    let get = || {
        request(
            Method::GET,
            "/devices",
            json!({}),
            Some((&session.token, &session.csrf_token)),
        )
    };
    let empty = json_response(app.clone().oneshot(get()).await.unwrap()).await;
    assert_eq!(empty["devices"][0]["pending_messages"], 0);
    assert_eq!(empty["devices"][0]["in_flight_messages"], 0);
    for (tenant, phone, _) in &owners {
        for state in [
            "accepted",
            "queued",
            "claimed",
            "submitting",
            "submitted",
            "delivered",
            "delivery_unknown",
            "unknown",
            "failed",
            "cancelled",
            "expired",
        ] {
            db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),$4,now()-interval '1 hour')", &[&Uuid::new_v4(), tenant, phone, &state]).await.unwrap();
        }
    }
    let response = app.clone().oneshot(get()).await.unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let page = json_response(response).await;
    let status = &page["devices"][0];
    assert_eq!(page["devices"].as_array().unwrap().len(), 1);
    assert_eq!(status["pending_messages"], 3);
    assert_eq!(status["in_flight_messages"], 2);
    assert_eq!(status["active_socket_lease"], false);
    assert!(
        status["status_observed_at_ms"].as_i64().unwrap()
            >= empty["devices"][0]["status_observed_at_ms"]
                .as_i64()
                .unwrap()
    );
    for private in [
        "recipient_e164",
        "transport_payload",
        "sim_id",
        "sms_ready",
        "radio_ready",
    ] {
        assert!(status.get(private).is_none());
    }
    // A large final history must not make these active-state probes scan it.
    db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) SELECT md5('history-'||g)::uuid,$1,$2,'+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),'delivered',now() FROM generate_series(1,10000) g", &[account, device]).await.unwrap();
    db.batch_execute("ANALYZE messages; ANALYZE devices")
        .await
        .unwrap();
    let plan = db
        .query(
            &format!(
                "EXPLAIN (ANALYZE, BUFFERS) {}",
                enrollment::OWNER_DEVICE_STATUS_QUERY
            ),
            &[account, &None::<Uuid>, &51_i64, &1_000_i64],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(plan.contains("messages_device_state"), "{plan}");
    assert!(!plan.contains("Seq Scan on messages"), "{plan}");
    // The two categories are capped independently; final/uncertain states do
    // not contribute. A revoked device retains its observed state counts.
    db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) SELECT md5('in-flight-'||g)::uuid,$1,$2,'+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),'submitted',now() FROM generate_series(1,1005) g", &[account, device]).await.unwrap();
    db.execute("UPDATE devices SET revoked_at=now() WHERE id=$1", &[device])
        .await
        .unwrap();
    let capped = json_response(app.clone().oneshot(get()).await.unwrap()).await;
    assert_eq!(capped["devices"][0]["pending_messages"], 3);
    assert_eq!(capped["devices"][0]["in_flight_messages"], 1_000);
    assert_eq!(capped["devices"][0]["revoked"], true);
    db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) SELECT md5('pending-'||g)::uuid,$1,$2,'+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),'queued',now() FROM generate_series(1,1005) g", &[account, device]).await.unwrap();
    let both_capped = json_response(app.clone().oneshot(get()).await.unwrap()).await;
    assert_eq!(both_capped["devices"][0]["pending_messages"], 1_000);
    assert_eq!(both_capped["devices"][0]["in_flight_messages"], 1_000);
    db.batch_execute("ANALYZE messages").await.unwrap();
    let capped_plan = db
        .query(
            &format!(
                "EXPLAIN (ANALYZE, BUFFERS) {}",
                enrollment::OWNER_DEVICE_STATUS_QUERY
            ),
            &[account, &None::<Uuid>, &51_i64, &1_000_i64],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        capped_plan.contains("messages_device_state"),
        "{capped_plan}"
    );
    assert!(
        !capped_plan.contains("Seq Scan on messages"),
        "{capped_plan}"
    );
    assert_eq!(
        capped_plan
            .lines()
            .filter(|line| line.contains("Limit") && line.contains("rows=1000 loops=1"))
            .count(),
        2,
        "{capped_plan}"
    );
    let other = &owners[1].2;
    let page = json_response(
        app.clone()
            .oneshot(request(
                Method::GET,
                "/devices",
                json!({}),
                Some((&other.token, &other.csrf_token)),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(page["devices"][0]["pending_messages"], 3);
    assert_eq!(page["devices"][0]["in_flight_messages"], 2);
    db.execute(
        "UPDATE sessions SET revoked_at=now() WHERE account_id=$1",
        &[account],
    )
    .await
    .unwrap();
    assert_eq!(
        app.oneshot(get()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}
