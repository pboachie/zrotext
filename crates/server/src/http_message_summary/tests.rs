// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::TokenHasher;
use crate::auth::{ApiKeyLifetime, SessionCredentials, login, register, verify_email};
use axum::body::to_bytes;
use axum::{body::Body, http::Request};
use serde_json::Value;
use tokio_postgres::NoTls;
use tower::ServiceExt;

const METADATA_MIGRATION: &str =
    include_str!("../../../../deploy/compose/migrations/070_message_summary_metadata.sql");
const QUEUE_INDEX: &str = "CREATE INDEX messages_summary_queue ON messages(account_id,state,created_at) WHERE state IN ('accepted','queued','claimed','submitting','submitted')";

struct Fixture {
    db: Client,
    schema: String,
    hasher: Arc<TokenHasher>,
    url: String,
    account: Uuid,
    other_account: Uuid,
    first: Uuid,
    second: Uuid,
    foreign: Uuid,
    session: SessionCredentials,
}

impl Fixture {
    async fn new() -> Self {
        let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
        let schema = format!("summary_{}", Uuid::new_v4().simple());
        let (admin, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        crate::auth::test_schema::apply_without_summary(&db).await;
        db.batch_execute(QUEUE_INDEX).await.unwrap();
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(29)).unwrap());
        let mut accounts = Vec::new();
        for (label, password) in [
            ("summary-a@example.test", crate::test_keys::password(29)),
            ("summary-b@example.test", crate::test_keys::password(30)),
        ] {
            let signup = register(&mut db, &hasher, label, &password).await.unwrap();
            verify_email(&mut db, &hasher, &signup.verification_token)
                .await
                .unwrap();
            accounts.push((
                signup.account_id,
                login(&db, &hasher, label, &password).await.unwrap(),
            ));
        }
        let mut accounts = accounts.into_iter();
        let (account, session) = accounts
            .next()
            .unwrap_or_else(|| panic!("primary summary fixture account is missing"));
        let (other_account, _) = accounts
            .next()
            .unwrap_or_else(|| panic!("foreign summary fixture account is missing"));
        assert!(
            accounts.next().is_none(),
            "unexpected summary fixture account"
        );
        let (first, second, foreign) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        db.execute("INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Synthetic Alpha'),($3,$2,'Synthetic Beta'),($4,$5,'Synthetic Foreign')",
            &[&first, &account, &second, &foreign, &other_account]).await.unwrap();
        Self {
            db,
            schema,
            hasher,
            url,
            account,
            other_account,
            first,
            second,
            foreign,
            session,
        }
    }

    async fn install(&mut self) {
        let tx = self.db.transaction().await.unwrap();
        tx.batch_execute(METADATA_MIGRATION).await.unwrap();
        tx.commit().await.unwrap();
    }

    fn app(&self) -> Router {
        router(OwnerMessagesState {
            database_url: self.url.clone(),
            auth_hasher: self.hasher.clone(),
            canonical_origin: "https://example.test".into(),
        })
    }

    async fn message(&self, account: Uuid, device: Uuid, state: &str) -> Uuid {
        let id = Uuid::new_v4();
        // Non-routable synthetic digits satisfy only the storage-format constraint.
        self.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+1'||repeat('0',10),$4,'synthetic_alpha',$5,$4,$6,now()+interval '1 hour')",
            &[&id, &account, &device, &vec![1_u8;32], &b"synthetic".as_slice(), &state]).await.unwrap();
        id
    }

    async fn event(
        &self,
        account: Uuid,
        message: Uuid,
        evidence: &str,
        resulting: &str,
        received: f64,
    ) {
        self.db.execute("INSERT INTO message_events(id,account_id,message_id,evidence_code,event_digest,observed_at,received_at,resulting_state) VALUES($1,$2,$3,$4,$5,to_timestamp($6::double precision/1000),to_timestamp($6::double precision/1000),$7)",
            &[&Uuid::new_v4(), &account, &message, &evidence, &vec![2_u8;32], &received, &resulting]).await.unwrap();
    }

    async fn at(&self, account: Uuid, device: Option<Uuid>, observed: f64) -> tokio_postgres::Row {
        let sql = summary_sql(device.is_some()).replace(
            "statement_timestamp()",
            "to_timestamp($4::double precision/1000)",
        );
        self.db
            .query_one(&sql, &[&account, &device, &(COUNT_BOUND + 1), &observed])
            .await
            .unwrap()
    }

    async fn cleanup(self) {
        self.db
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

fn owner_request(path: &str, session: &SessionCredentials) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(
            header::COOKIE,
            format!(
                "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                session.token, session.csrf_token
            ),
        )
        .header("x-zrotext-csrf", &session.csrf_token)
        .body(Body::empty())
        .unwrap()
}

async fn json(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn first_complete_callback_is_counted_once_across_midnight_and_uncertain_outcomes() {
    let mut f = Fixture::new().await;
    let old = f.message(f.account, f.first, "delivered").await;
    let start = 946_684_800_000_f64;
    f.event(f.account, old, "sent_callback_ok", "submitted", start - 1.0)
        .await;
    f.event(f.account, old, "sent_callback_ok", "submitted", start + 1.0)
        .await;
    f.install().await;
    assert_eq!(f.at(f.account, None, start + 1.0).await.get::<_, i64>(3), 0);
    let partial = f.message(f.account, f.first, "submitting").await;
    f.event(
        f.account,
        partial,
        "sent_callback_ok",
        "submitting",
        start + 2.0,
    )
    .await;
    let failed = f.message(f.account, f.first, "failed").await;
    f.event(
        f.account,
        failed,
        "sent_callback_failed",
        "failed",
        start + 2.0,
    )
    .await;
    let uncertain = f.message(f.account, f.first, "unknown").await;
    f.event(
        f.account,
        uncertain,
        "sent_callback_ok",
        "unknown",
        start + 2.0,
    )
    .await;
    assert_eq!(
        f.at(f.account, Some(f.first), start + 3.0)
            .await
            .get::<_, i64>(3),
        0
    );
    f.event(
        f.account,
        partial,
        "sent_callback_ok",
        "submitted",
        start + 3.0,
    )
    .await;
    f.event(
        f.account,
        partial,
        "sent_callback_ok",
        "submitted",
        start + 86_400_001.0,
    )
    .await;
    f.event(
        f.account,
        partial,
        "callback_conflict",
        "unknown",
        start + 4.0,
    )
    .await;
    assert_eq!(
        f.at(f.account, Some(f.first), start + 5.0)
            .await
            .get::<_, i64>(3),
        1
    );
    assert_eq!(
        f.at(f.account, Some(f.first), start + 86_400_001.0)
            .await
            .get::<_, i64>(3),
        0
    );
    f.db.batch_execute("SET TIME ZONE 'America/New_York'")
        .await
        .unwrap();
    for date in ["2026-03-08 23:59:59+00", "2026-11-01 23:59:59+00"] {
        let at: f64 =
            f.db.query_one(
                "SELECT (extract(epoch FROM $1::text::timestamptz)*1000)::double precision",
                &[&date],
            )
            .await
            .unwrap()
            .get(0);
        let row = f.at(f.account, None, at).await;
        assert_eq!(row.get::<_, i64>(2) - row.get::<_, i64>(1), 86_400_000);
        assert!(row.get::<_, i64>(0) < row.get::<_, i64>(2));
        let end = row.get::<_, i64>(2);
        assert_eq!(
            f.at(f.account, None, end as f64 - 0.1)
                .await
                .get::<_, i64>(0),
            end - 1
        );
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn summaries_enforce_owner_csrf_device_binding_and_account_isolation() {
    let mut f = Fixture::new().await;
    assert_eq!(
        f.app()
            .oneshot(owner_request("/v1/owner/message-summary", &f.session))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    f.install().await;
    for (account, device, state) in [
        (f.account, f.first, "queued"),
        (f.account, f.second, "claimed"),
        (f.account, f.first, "submitting"),
        (f.other_account, f.foreign, "queued"),
    ] {
        f.message(account, device, state).await;
    }
    let foreign_submission = f.message(f.other_account, f.foreign, "submitted").await;
    f.event(
        f.other_account,
        foreign_submission,
        "sent_callback_ok",
        "submitted",
        946_684_800_001.0,
    )
    .await;
    assert_eq!(
        f.at(f.account, None, 946_684_800_002.0)
            .await
            .get::<_, i64>(3),
        0
    );
    assert_eq!(
        f.at(f.other_account, Some(f.foreign), 946_684_800_002.0)
            .await
            .get::<_, i64>(3),
        1
    );
    let response = f
        .app()
        .oneshot(owner_request("/v1/owner/message-summary", &f.session))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = json(response).await;
    assert_eq!(body["pending"]["value"], 2);
    assert_eq!(body["in_flight"]["value"], 1);
    assert_eq!(body["submitted_today"]["value"], 0);
    assert!(!body.to_string().contains("recipient"));
    assert!(!body.to_string().contains("synthetic"));
    let selected = json(
        f.app()
            .oneshot(owner_request(
                &format!("/v1/owner/message-summary?device_id={}", f.first),
                &f.session,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(selected["pending"]["value"], 1);
    assert_eq!(
        f.app()
            .oneshot(owner_request(
                &format!("/v1/owner/message-summary?device_id={}", f.foreign),
                &f.session
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let principal = auth::authenticate_session(&f.db, &f.hasher, &f.session.token)
        .await
        .unwrap();
    let key = auth::create_api_key(
        &mut f.db,
        &f.hasher,
        &principal,
        &[Scope::MessagesRead],
        Some(f.first),
        ApiKeyLifetime::Days(30),
    )
    .await
    .unwrap();
    for (device, expected) in [
        (Some(f.first), StatusCode::OK),
        (Some(f.second), StatusCode::FORBIDDEN),
        (Some(f.foreign), StatusCode::FORBIDDEN),
        (None, StatusCode::BAD_REQUEST),
    ] {
        let path = device.map_or_else(
            || "/v1/message-summary".into(),
            |id| format!("/v1/message-summary?device_id={id}"),
        );
        let request = Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {}", key.token))
            .body(Body::empty())
            .unwrap();
        assert_eq!(f.app().oneshot(request).await.unwrap().status(), expected);
    }
    let send_only = auth::create_api_key(
        &mut f.db,
        &f.hasher,
        &principal,
        &[Scope::MessagesSend],
        Some(f.first),
        ApiKeyLifetime::Days(30),
    )
    .await
    .unwrap();
    let request = Request::builder()
        .uri(format!("/v1/message-summary?device_id={}", f.first))
        .header(header::AUTHORIZATION, format!("Bearer {}", send_only.token))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        f.app().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    f.db.execute(
        "WITH removed AS (DELETE FROM memberships WHERE account_id=$1 RETURNING account_id,user_id) INSERT INTO memberships(account_id,user_id,role) SELECT account_id,user_id,'observer' FROM removed",
        &[&f.account],
    )
    .await
    .unwrap();
    assert_eq!(
        f.app()
            .oneshot(owner_request("/v1/owner/message-summary", &f.session))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn indexed_probes_cap_counts_and_refuse_missing_or_disabled_metadata() {
    let mut f = Fixture::new().await;
    f.install().await;
    f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) SELECT gen_random_uuid(),$1,$2,'+1'||repeat('0',10),$3,'synthetic_alpha',$4,$3,'queued',now()+interval '1 hour' FROM generate_series(1,1001)",
        &[&f.account,&f.first,&vec![1_u8;32],&b"synthetic".as_slice()]).await.unwrap();
    f.db.execute("INSERT INTO message_submission_receipts(message_id,account_id,device_id,first_submitted_at) SELECT id,account_id,device_id,statement_timestamp() FROM messages WHERE account_id=$1", &[&f.account]).await.unwrap();
    let summary = json(
        f.app()
            .oneshot(owner_request("/v1/owner/message-summary", &f.session))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(summary["pending"]["value"], COUNT_BOUND);
    assert_eq!(summary["pending"]["capped"], true);
    assert_eq!(summary["submitted_today"]["capped"], true);
    assert_eq!(summary["in_flight"]["value"], 0);
    // Unrelated tenants and terminal history must not make a bounded probe scan
    // the account/device's entire history. Exercise the planner, not SQL text.
    for (account, device, state) in [
        (f.other_account, f.foreign, "queued"),
        (f.account, f.second, "delivered"),
    ] {
        f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) SELECT gen_random_uuid(),$1,$2,'+1'||repeat('0',10),$3,'synthetic_alpha',$4,$3,$5,now()+interval '1 hour' FROM generate_series(1,20000)", &[&account,&device,&vec![1_u8;32],&b"synthetic".as_slice(),&state]).await.unwrap();
    }
    f.db.batch_execute("ANALYZE messages; ANALYZE message_submission_receipts")
        .await
        .unwrap();
    for device in [None, Some(f.first)] {
        let statement = format!(
            "EXPLAIN (ANALYZE, FORMAT JSON) {}",
            summary_sql(device.is_some())
        );
        // PostgreSQL's EXPLAIN output is JSON; cast its row through text via the
        // simple protocol to avoid adding a driver feature solely for tests.
        let statement = statement
            .replace("$1", &format!("'{}'::uuid", f.account))
            .replace(
                "$2",
                &device.map_or("NULL::uuid".into(), |id| format!("'{id}'::uuid")),
            )
            .replace("$3", "1001");
        let rows = f.db.simple_query(&statement).await.unwrap();
        let text = rows
            .iter()
            .find_map(|row| match row {
                tokio_postgres::SimpleQueryMessage::Row(row) => row.get(0),
                _ => None,
            })
            .unwrap();
        let plan: Value = serde_json::from_str(text).unwrap();
        assert_bounded_plan(&plan);
    }
    f.db.batch_execute(
        "ALTER TABLE message_events DISABLE TRIGGER message_summary_capture_submission",
    )
    .await
    .unwrap();
    assert_eq!(
        f.app()
            .oneshot(owner_request("/v1/owner/message-summary", &f.session))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    f.db.batch_execute("ALTER TABLE message_events ENABLE TRIGGER message_summary_capture_submission; DROP INDEX message_submission_receipts_account_day").await.unwrap();
    assert_eq!(
        f.app()
            .oneshot(owner_request("/v1/owner/message-summary", &f.session))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    f.cleanup().await;
}

fn assert_bounded_plan(value: &Value) {
    match value {
        Value::Object(node) => {
            if node.get("Relation Name").and_then(Value::as_str) == Some("messages") {
                assert_ne!(
                    node.get("Node Type").and_then(Value::as_str),
                    Some("Seq Scan"),
                    "{node:?}"
                );
            }
            if node.get("Node Type").and_then(Value::as_str) == Some("Limit") {
                // PostgreSQL 18 reports EXPLAIN row counts as fractional numbers.
                let rows = node["Actual Rows"]
                    .as_f64()
                    .expect("a measured Limit must report a numeric row count");
                assert!(
                    rows.is_finite() && (0.0..=1001.0).contains(&rows),
                    "a summary probe exceeded its row bound"
                );
            }
            for child in node.values() {
                assert_bounded_plan(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                assert_bounded_plan(child);
            }
        }
        _ => {}
    }
}

#[test]
fn bounded_plans_accept_integer_and_fractional_explain_counts() {
    for rows in ["0", "1001", "0.00", "1000.50", "1001.00"] {
        let plan: Value =
            serde_json::from_str(&format!(r#"{{"Node Type":"Limit","Actual Rows":{rows}}}"#))
                .unwrap();
        assert_bounded_plan(&plan);
    }
}

#[test]
fn bounded_plans_reject_excessive_negative_and_missing_counts() {
    for rows in ["1001.01", "1002", "-0.01", "null", "\"1001\""] {
        let plan: Value =
            serde_json::from_str(&format!(r#"{{"Node Type":"Limit","Actual Rows":{rows}}}"#))
                .unwrap();
        assert!(std::panic::catch_unwind(|| assert_bounded_plan(&plan)).is_err());
    }
}

#[test]
fn a_real_zero_and_exact_bound_are_distinct_from_a_capped_lower_bound() {
    assert_eq!(
        Count::from_probe(0),
        Count {
            value: 0,
            capped: false
        }
    );
    assert_eq!(
        Count::from_probe(COUNT_BOUND),
        Count {
            value: COUNT_BOUND,
            capped: false
        }
    );
    assert_eq!(
        Count::from_probe(COUNT_BOUND + 1),
        Count {
            value: COUNT_BOUND,
            capped: true
        }
    );
}

#[test]
fn bearer_rejects_ambiguous_or_malformed_authorization() {
    let mut headers = HeaderMap::new();
    assert_eq!(bearer(&headers), None);
    headers.insert(header::AUTHORIZATION, "Bearer synthetic".parse().unwrap());
    assert_eq!(bearer(&headers), Some("synthetic"));
    headers.append(header::AUTHORIZATION, "Bearer other".parse().unwrap());
    assert_eq!(bearer(&headers), None);
    headers.clear();
    headers.insert(header::AUTHORIZATION, "Bearer extra value".parse().unwrap());
    assert_eq!(bearer(&headers), None);
}

#[tokio::test]
async fn unauthenticated_summary_reads_and_unknown_queries_fail_before_database_admission() {
    let app = router(OwnerMessagesState {
        database_url: "unavailable".into(),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(27)).unwrap()),
        canonical_origin: "https://example.test".into(),
    });
    for (path, expected) in [
        ("/v1/owner/message-summary", StatusCode::UNAUTHORIZED),
        ("/v1/message-summary", StatusCode::UNAUTHORIZED),
        (
            "/v1/owner/message-summary?timezone=local",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/owner/message-summary")
                .header(
                    header::COOKIE,
                    "__Host-zrotext_session=synthetic; __Host-zrotext_csrf=synthetic",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
