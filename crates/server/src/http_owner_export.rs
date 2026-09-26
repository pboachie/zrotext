// SPDX-License-Identifier: AGPL-3.0-only
//! Owner data export: one takeout document with the account profile,
//! devices, messages and per-message events. Unlike the pilot timeline
//! this carries the recipient and transport payload, so responses are
//! always no-store and never cached.

use crate::{auth::TokenHasher, http_auth::require_owner};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc, time::SystemTime};
#[cfg(test)]
use tokio_postgres::NoTls;
use uuid::Uuid;

// A takeout stays a bounded single response; a full-history export can
// paginate on top of this later.
const EXPORT_MESSAGE_LIMIT: usize = 500;

#[derive(Clone)]
pub struct OwnerExportState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
}

pub fn router(state: OwnerExportState) -> Router {
    Router::new()
        .route("/v1/owner/export", get(export_account))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Serialize)]
struct AccountView {
    account_id: Uuid,
    email: String,
    email_verified: bool,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct DeviceView {
    device_id: Uuid,
    display_name: String,
    created_at_ms: i64,
    revoked_at_ms: Option<i64>,
}

#[derive(Serialize)]
struct MessageEventView {
    evidence_code: String,
    resulting_state: String,
    received_at_ms: i64,
    segment_index: Option<i32>,
    segment_count: Option<i32>,
}

#[derive(Serialize)]
struct MessageView {
    message_id: Uuid,
    device_id: Uuid,
    recipient_e164: String,
    transport_mode: String,
    transport_payload: String,
    state: String,
    created_at_ms: i64,
    updated_at_ms: i64,
    expires_at_ms: i64,
    events: Vec<MessageEventView>,
}

#[derive(Serialize)]
struct ExportView {
    generated_at_ms: i64,
    account: AccountView,
    devices: Vec<DeviceView>,
    messages: Vec<MessageView>,
    messages_truncated: bool,
}

async fn export_account(
    State(state): State<Arc<OwnerExportState>>,
    headers: HeaderMap,
) -> Response {
    let Ok(client) = crate::runtime_db::connect(&state.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let account_id = principal.tenant.account_id();
    let account = match client
        .query_opt(
            "SELECT a.id,u.email,(u.email_verified_at IS NOT NULL), \
             (extract(epoch FROM a.created_at)*1000)::bigint \
             FROM accounts a JOIN memberships m ON m.account_id=a.id \
             JOIN users u ON u.id=m.user_id WHERE a.id=$1",
            &[&account_id],
        )
        .await
    {
        Ok(Some(row)) => AccountView {
            account_id: row.get(0),
            email: row.get(1),
            email_verified: row.get(2),
            created_at_ms: row.get(3),
        },
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let device_rows = match client
        .query(
            "SELECT id,display_name,(extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM revoked_at)*1000)::bigint \
             FROM devices WHERE account_id=$1 ORDER BY created_at,id",
            &[&account_id],
        )
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|row| DeviceView {
                device_id: row.get(0),
                display_name: row.get(1),
                created_at_ms: row.get(2),
                revoked_at_ms: row.get(3),
            })
            .collect::<Vec<_>>(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let message_rows = match client
        .query(
            "SELECT id,device_id,recipient_e164,transport_mode, \
             convert_from(transport_payload,'UTF8'),state, \
             (extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM updated_at)*1000)::bigint, \
             (extract(epoch FROM expires_at)*1000)::bigint \
             FROM messages WHERE account_id=$1 \
             ORDER BY created_at DESC,id DESC LIMIT $2",
            &[&account_id, &(EXPORT_MESSAGE_LIMIT as i64 + 1)],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let messages_truncated = message_rows.len() > EXPORT_MESSAGE_LIMIT;
    let mut messages = message_rows
        .into_iter()
        .take(EXPORT_MESSAGE_LIMIT)
        .map(|row| MessageView {
            message_id: row.get(0),
            device_id: row.get(1),
            recipient_e164: row.get(2),
            transport_mode: row.get(3),
            transport_payload: row.get(4),
            state: row.get(5),
            created_at_ms: row.get(6),
            updated_at_ms: row.get(7),
            expires_at_ms: row.get(8),
            events: Vec::new(),
        })
        .collect::<Vec<_>>();
    let ids: Vec<Uuid> = messages.iter().map(|message| message.message_id).collect();
    if !ids.is_empty() {
        let events = match client
            .query(
                "SELECT selected.id,e.evidence_code,e.resulting_state, \
                 (extract(epoch FROM e.received_at)*1000)::bigint, \
                 e.segment_index,e.segment_count \
                 FROM unnest($2::uuid[]) AS selected(id) \
                 JOIN message_events e \
                 ON e.account_id=$1 AND e.message_id=selected.id \
                 ORDER BY e.received_at,e.id",
                &[&account_id, &ids],
            )
            .await
        {
            Ok(rows) => rows,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        let positions: HashMap<Uuid, usize> = ids
            .iter()
            .enumerate()
            .map(|(index, id)| (*id, index))
            .collect();
        for row in events {
            let id: Uuid = row.get(0);
            let Some(&index) = positions.get(&id) else {
                continue;
            };
            messages[index].events.push(MessageEventView {
                evidence_code: row.get(1),
                resulting_state: row.get(2),
                received_at_ms: row.get(3),
                segment_index: row.get(4),
                segment_count: row.get(5),
            });
        }
    }
    Json(ExportView {
        generated_at_ms: SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or_default(),
        account,
        devices: device_rows,
        messages,
        messages_truncated,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{login, register, verify_email};
    use axum::{
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::Value;
    use tower::ServiceExt;

    fn get(path: &str, token: Option<&str>) -> Request<Body> {
        let mut request = Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header(header::COOKIE, format!("__Host-zrotext_session={token}"));
        }
        request.body(Body::empty()).unwrap()
    }

    async fn body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn export_is_tenant_bound_and_carries_owner_content() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("owner_export_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        ] {
            db.batch_execute(migration).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(19)).unwrap());
        let a = register(
            &mut db,
            &hasher,
            "export-a@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let b = register(
            &mut db,
            &hasher,
            "export-b@example.test",
            &crate::test_keys::password(2),
        )
        .await
        .unwrap();
        verify_email(&mut db, &hasher, &a.verification_token)
            .await
            .unwrap();
        verify_email(&mut db, &hasher, &b.verification_token)
            .await
            .unwrap();
        let session_a = login(
            &db,
            &hasher,
            "export-a@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let session_b = login(
            &db,
            &hasher,
            "export-b@example.test",
            &crate::test_keys::password(2),
        )
        .await
        .unwrap();
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Exporter'),($3,$4,'Other')",
            &[&device_a, &a.account_id, &device_b, &b.account_id],
        )
        .await
        .unwrap();
        let mut a_ids = Vec::new();
        for index in 0..2 {
            let id = Uuid::new_v4();
            a_ids.push(id);
            db.execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,$7,now()+interval '1 hour')",
                &[&id, &a.account_id, &device_a, &vec![1_u8; 32],
                    &format!("EXPORT_BODY_A_{index}").as_bytes().to_vec(), &vec![2_u8; 32],
                    &if index == 0 { "delivered" } else { "queued" }],
            )
            .await
            .unwrap();
        }
        let b_id = Uuid::new_v4();
        db.execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
             VALUES($1,$2,$3,'+15557654321',$4,'synthetic_alpha',$5,$6,'queued',now()+interval '1 hour')",
            &[&b_id, &b.account_id, &device_b, &vec![3_u8; 32],
                &b"EXPORT_BODY_B_NEVER_LEAK".as_slice(), &vec![4_u8; 32]],
        )
        .await
        .unwrap();
        let attempt = Uuid::new_v4();
        db.execute(
            "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
             VALUES($1,$2,$3,$4,1,1,1,'submitted')",
            &[&attempt, &a.account_id, &a_ids[0], &device_a],
        )
        .await
        .unwrap();
        for (evidence, state) in [
            ("sent_callback_ok", "submitted"),
            ("delivery_callback_ok", "delivered"),
        ] {
            db.execute(
                "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code,event_digest,observed_at,resulting_state,segment_index,segment_count) \
                 VALUES($1,$2,$3,$4,$5,$6,now(),$7,0,1)",
                &[&Uuid::new_v4(), &a.account_id, &a_ids[0], &attempt,
                    &evidence, &vec![5_u8; 32], &state],
            )
            .await
            .unwrap();
        }
        let app = router(OwnerExportState {
            database_url,
            auth_hasher: hasher,
            canonical_origin: "https://test.example".to_owned(),
        });
        let anonymous = app
            .clone()
            .oneshot(get("/v1/owner/export", None))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .clone()
            .oneshot(get("/v1/owner/export", Some(&session_a.token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let raw = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let takeout: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(takeout["account"]["account_id"], a.account_id.to_string());
        assert_eq!(takeout["account"]["email"], "export-a@example.test");
        assert_eq!(takeout["account"]["email_verified"], true);
        assert_eq!(takeout["devices"].as_array().unwrap().len(), 1);
        assert_eq!(takeout["devices"][0]["device_id"], device_a.to_string());
        assert_eq!(takeout["devices"][0]["display_name"], "Exporter");
        assert_eq!(takeout["messages_truncated"], false);
        let messages = takeout["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert!(String::from_utf8_lossy(&raw).contains("EXPORT_BODY_A_0"));
        assert!(String::from_utf8_lossy(&raw).contains("EXPORT_BODY_A_1"));
        assert!(!String::from_utf8_lossy(&raw).contains("EXPORT_BODY_B_NEVER_LEAK"));
        assert!(!String::from_utf8_lossy(&raw).contains("+15557654321"));
        let delivered = messages
            .iter()
            .find(|item| item["message_id"] == a_ids[0].to_string())
            .unwrap();
        assert_eq!(delivered["state"], "delivered");
        assert_eq!(delivered["recipient_e164"], "+15551234567");
        assert_eq!(delivered["transport_mode"], "synthetic_alpha");
        assert_eq!(delivered["transport_payload"], "EXPORT_BODY_A_0");
        let events = delivered["events"].as_array().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["evidence_code"], "sent_callback_ok");
        assert_eq!(events[0]["resulting_state"], "submitted");
        assert_eq!(events[1]["evidence_code"], "delivery_callback_ok");
        assert_eq!(events[1]["resulting_state"], "delivered");
        assert_eq!(events[0]["segment_count"], 1);
        let queued = messages
            .iter()
            .find(|item| item["message_id"] == a_ids[1].to_string())
            .unwrap();
        assert_eq!(queued["state"], "queued");
        assert_eq!(
            queued["events"].as_array().unwrap().len(),
            0,
            "message without events exports an empty event list"
        );
        let foreign = app
            .clone()
            .oneshot(get("/v1/owner/export", Some(&session_b.token)))
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::OK);
        let foreign = body(foreign).await;
        assert_eq!(foreign["account"]["email"], "export-b@example.test");
        let foreign_messages = foreign["messages"].as_array().unwrap();
        assert_eq!(foreign_messages.len(), 1);
        assert_eq!(foreign_messages[0]["message_id"], b_id.to_string());
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
