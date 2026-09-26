// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-only synthetic pilot timeline. The response contains writer metadata,
//! never the recipient, transport payload, or device-side inbound content.

use crate::{auth::TokenHasher, http_auth::require_owner};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::SystemTime};
#[cfg(test)]
use tokio_postgres::NoTls;
use uuid::Uuid;

const PAGE_SIZE: usize = 20;
const MAX_EVENTS_PER_MESSAGE: usize = 32;

#[derive(Clone)]
pub struct OwnerMessagesState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
}

pub fn router(state: OwnerMessagesState) -> Router {
    Router::new()
        .route("/v1/owner/messages", get(list_messages))
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct TimelineEvent {
    evidence: String,
    resulting_state: String,
    received_at_ms: i64,
    segment_index: Option<i32>,
    segment_count: Option<i32>,
}

#[derive(Serialize)]
struct MessageView {
    message_id: Uuid,
    device_id: Uuid,
    state: String,
    created_at_ms: i64,
    updated_at_ms: i64,
    events: Vec<TimelineEvent>,
    events_truncated: bool,
}

#[derive(Serialize)]
struct ListResponse {
    messages: Vec<MessageView>,
    next_cursor: Option<Uuid>,
}

async fn list_messages(
    State(state): State<Arc<OwnerMessagesState>>,
    Query(query): Query<ListQuery>,
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
    let before_point: Option<(SystemTime, Uuid)> = if let Some(before) = query.before {
        match client
            .query_opt(
                "SELECT created_at FROM messages WHERE account_id=$1 AND id=$2",
                &[&account_id, &before],
            )
            .await
        {
            Ok(Some(row)) => Some((row.get(0), before)),
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };
    let before_at = before_point.map(|point| point.0);
    let before_id = before_point.map(|point| point.1);
    let rows = match client
        .query(
            "SELECT id,device_id,state, \
             (extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM updated_at)*1000)::bigint \
             FROM messages WHERE account_id=$1 AND \
             ($2::timestamptz IS NULL OR (created_at,id)<($2,$3::uuid)) \
             ORDER BY created_at DESC,id DESC LIMIT 21",
            &[&account_id, &before_at, &before_id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let has_more = rows.len() > PAGE_SIZE;
    let mut messages: Vec<MessageView> = rows
        .into_iter()
        .take(PAGE_SIZE)
        .map(|row| MessageView {
            message_id: row.get(0),
            device_id: row.get(1),
            state: row.get(2),
            created_at_ms: row.get(3),
            updated_at_ms: row.get(4),
            events: Vec::new(),
            events_truncated: false,
        })
        .collect();
    let ids: Vec<Uuid> = messages.iter().map(|message| message.message_id).collect();
    if !ids.is_empty() {
        let events = match client
            .query(
                "SELECT selected.id,e.evidence_code,e.resulting_state, \
                 (extract(epoch FROM e.received_at)*1000)::bigint, \
                 e.segment_index,e.segment_count FROM unnest($2::uuid[]) AS selected(id) \
                 JOIN LATERAL (SELECT id,evidence_code,resulting_state,received_at, \
                     segment_index,segment_count FROM message_events \
                     WHERE account_id=$1 AND message_id=selected.id \
                     ORDER BY received_at DESC,id DESC LIMIT 33) e ON true \
                 ORDER BY selected.id,e.received_at,e.id",
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
            let message = &mut messages[index];
            message.events.push(TimelineEvent {
                evidence: row.get(1),
                resulting_state: row.get(2),
                received_at_ms: row.get(3),
                segment_index: row.get(4),
                segment_count: row.get(5),
            });
            if message.events.len() > MAX_EVENTS_PER_MESSAGE {
                message.events.remove(0);
                message.events_truncated = true;
            }
        }
    }
    let next_cursor = if has_more {
        messages.last().map(|message| message.message_id)
    } else {
        None
    };
    Json(ListResponse {
        messages,
        next_cursor,
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
        serde_json::from_slice(&to_bytes(response.into_body(), 256 * 1024).await.unwrap()).unwrap()
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn timeline_is_tenant_bound_paginated_and_contains_only_writer_metadata() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("owner_timeline_test_{}", Uuid::new_v4().simple());
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
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(11)).unwrap());
        let a = register(
            &mut db,
            &hasher,
            "timeline-a@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let b = register(
            &mut db,
            &hasher,
            "timeline-b@example.test",
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
            "timeline-a@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let session_b = login(
            &db,
            &hasher,
            "timeline-b@example.test",
            &crate::test_keys::password(2),
        )
        .await
        .unwrap();
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'A'),($3,$4,'B')",
            &[&device_a, &a.account_id, &device_b, &b.account_id],
        )
        .await
        .unwrap();
        let mut a_ids = Vec::new();
        for index in 0..21 {
            let id = Uuid::new_v4();
            a_ids.push(id);
            db.execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,$7,now()+interval '1 hour')",
                &[&id, &a.account_id, &device_a, &vec![1_u8; 32],
                    &b"PRIVATE_BODY_NEVER_EXPOSE".as_slice(), &vec![2_u8; 32],
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
                &b"FOREIGN_BODY_NEVER_EXPOSE".as_slice(), &vec![4_u8; 32]],
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
        let app = router(OwnerMessagesState {
            database_url,
            auth_hasher: hasher,
            canonical_origin: "https://test.example".to_owned(),
        });
        let anonymous = app
            .clone()
            .oneshot(get("/v1/owner/messages", None))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        let first = app
            .clone()
            .oneshot(get("/v1/owner/messages", Some(&session_a.token)))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.headers()[header::CACHE_CONTROL], "no-store");
        let first = body(first).await;
        assert_eq!(first["messages"].as_array().unwrap().len(), 20);
        let cursor = first["next_cursor"].as_str().unwrap();
        let second = body(
            app.clone()
                .oneshot(get(
                    &format!("/v1/owner/messages?before={cursor}"),
                    Some(&session_a.token),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(second["messages"].as_array().unwrap().len(), 1);
        assert!(second["next_cursor"].is_null());
        let combined: Vec<Value> = first["messages"]
            .as_array()
            .unwrap()
            .iter()
            .chain(second["messages"].as_array().unwrap().iter())
            .cloned()
            .collect();
        let ids: Vec<&str> = combined
            .iter()
            .map(|item| item["message_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 21);
        assert!(
            a_ids
                .iter()
                .all(|id| ids.contains(&id.to_string().as_str()))
        );
        let delivered = combined
            .iter()
            .find(|item| item["message_id"] == a_ids[0].to_string())
            .unwrap();
        assert_eq!(delivered["state"], "delivered");
        assert_eq!(delivered["events"].as_array().unwrap().len(), 2);
        assert_eq!(delivered["events"][0]["evidence"], "sent_callback_ok");
        assert_eq!(delivered["events"][1]["evidence"], "delivery_callback_ok");
        let text = serde_json::to_string(&combined).unwrap();
        assert!(!text.contains("+1555"));
        assert!(!text.contains("PRIVATE_BODY_NEVER_EXPOSE"));
        assert!(!text.contains("FOREIGN_BODY_NEVER_EXPOSE"));
        let foreign_cursor = app
            .clone()
            .oneshot(get(
                &format!("/v1/owner/messages?before={b_id}"),
                Some(&session_a.token),
            ))
            .await
            .unwrap();
        assert_eq!(foreign_cursor.status(), StatusCode::NOT_FOUND);
        let b_page = body(
            app.oneshot(get("/v1/owner/messages", Some(&session_b.token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(b_page["messages"].as_array().unwrap().len(), 1);
        assert_eq!(b_page["messages"][0]["message_id"], b_id.to_string());
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
