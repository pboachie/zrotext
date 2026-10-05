// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use super::super::{ExceptionInput, exception, resolve, tests::Case, write};
use crate::http_owner_conversations::activation::tests::capture;
use axum::{Json, body::to_bytes, response::IntoResponse};

const ACCOUNT: Uuid = Uuid::from_u128(1);
const CONTEXT: Uuid = Uuid::from_u128(2);
const TIME: &str = "9999-12-31T23:59:59.999999Z";
const FIELDS: [&str; 13] = [
    "account_id", "context_id", "id", "context_revision", "source_kind", "source_id",
    "reason", "request_digest", "revision", "state", "resolution_request_id",
    "resolved_at", "created_at",
];

fn record() -> ExceptionRecord {
    ExceptionRecord {
        account_id: ACCOUNT,
        context_id: CONTEXT,
        id: Uuid::from_u128(3),
        context_revision: 128,
        source_kind: 1,
        source_id: Uuid::from_u128(4),
        reason: 5,
        request_digest: (0u8..32).collect(),
        revision: 2,
        state: "resolved".into(),
        resolution_request_id: Some(Uuid::from_u128(5)),
        resolved_at: Some(TIME.into()),
        created_at: TIME.into(),
    }
}

fn assert_shape(page: &Value, account: Uuid, context: Uuid) {
    let object = page.as_object().unwrap();
    assert_eq!(object.len(), 4);
    for key in ["account_id", "context_id", "items", "next_cursor"] {
        assert!(object.contains_key(key));
    }
    assert_eq!(page["account_id"], account.to_string());
    assert_eq!(page["context_id"], context.to_string());
    for item in page["items"].as_array().unwrap() {
        let row = item.as_object().unwrap();
        assert_eq!(row.len(), 13);
        for key in FIELDS {
            assert!(row.contains_key(key));
        }
        assert_eq!(item["account_id"], account.to_string());
        assert_eq!(item["context_id"], context.to_string());
        assert!(canonical_timestamp(item["created_at"].as_str().unwrap()));
        assert_eq!(item["request_digest"].as_str().unwrap().len(), 66);
    }
}

async fn response_bytes(page: ExceptionsPage) -> Vec<u8> {
    let expected = serde_json::to_vec(&page).unwrap();
    let response = Json(page).into_response();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    let actual = to_bytes(response.into_body(), 65_536).await.unwrap().to_vec();
    assert_eq!(actual, expected);
    actual
}

#[tokio::test]
async fn closed_empty_and_twenty_row_json_responses_bind_scope_and_fit_stream_budget() {
    let empty = response_bytes(ExceptionsPage {
        account_id: ACCOUNT,
        context_id: CONTEXT,
        items: Vec::new(),
        next_cursor: None,
    }).await;
    let value: Value = serde_json::from_slice(&empty).unwrap();
    assert_shape(&value, ACCOUNT, CONTEXT);
    assert_eq!(value["items"], serde_json::json!([]));
    assert!(value["next_cursor"].is_null());

    let items = (1..=20).map(|index| {
        let mut row = record();
        row.id = Uuid::from_u128(index);
        row.request_digest = vec![255; 32];
        row.into_wire(ACCOUNT, CONTEXT).unwrap()
    }).collect();
    let bytes = response_bytes(ExceptionsPage {
        account_id: ACCOUNT,
        context_id: CONTEXT,
        items,
        next_cursor: Some(Uuid::from_u128(20)),
    }).await;
    // An executed Rust/Axum byte assertion when this test runs; no static arithmetic proxy.
    assert!(bytes.len() <= 65_536);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_shape(&value, ACCOUNT, CONTEXT);
    assert_eq!(value["items"].as_array().unwrap().len(), 20);
    assert_eq!(value["items"][0]["request_digest"], format!("\\x{}", "ff".repeat(32)));
}

#[test]
fn typed_records_accept_only_the_five_pairs_and_exact_pending_or_resolved_states() {
    for (kind, reason) in [(1, 1), (1, 5), (2, 2), (2, 3), (2, 4)] {
        for revision in [1, 128] {
            let mut row = record();
            row.source_kind = kind;
            row.reason = reason;
            row.context_revision = revision;
            let value = serde_json::to_value(row.into_wire(ACCOUNT, CONTEXT).unwrap()).unwrap();
            assert_eq!(value["request_digest"], "\\x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        }
    }
    let mut pending = record();
    pending.revision = 1;
    pending.state = "pending".into();
    pending.resolution_request_id = None;
    pending.resolved_at = None;
    let value = serde_json::to_value(pending.into_wire(ACCOUNT, CONTEXT).unwrap()).unwrap();
    assert!(value["resolution_request_id"].is_null());
    assert!(value["resolved_at"].is_null());
}

#[test]
fn unsupported_identity_range_digest_kind_reason_and_state_refuse_serialization() {
    for case in 0..23 {
        let mut row = record();
        match case {
            0 => row.account_id = Uuid::nil(),
            1 => row.context_id = Uuid::nil(),
            2 => row.id = Uuid::nil(),
            3 => row.source_id = Uuid::nil(),
            4 => row.account_id = Uuid::from_u128(99),
            5 => row.context_id = Uuid::from_u128(99),
            6 => row.context_revision = 0,
            7 => row.context_revision = 129,
            8 => row.source_kind = 0,
            9 => row.source_kind = 3,
            10 => row.reason = 0,
            11 => row.reason = 6,
            12 => row.reason = 2,
            13 => row.source_kind = 2,
            14 => row.request_digest.clear(),
            15 => row.request_digest.push(0),
            16 => row.revision = 3,
            17 => row.state = "pending".into(),
            18 => row.state = "other".into(),
            19 => row.resolution_request_id = None,
            20 => row.resolution_request_id = Some(Uuid::nil()),
            21 => row.resolved_at = None,
            _ => row.created_at = "infinity".into(),
        }
        assert!(matches!(row.into_wire(ACCOUNT, CONTEXT), Err(ConversationError::Unavailable)), "case {case}");
    }
    for (request, time) in [(None, Some(TIME.into())), (Some(Uuid::from_u128(5)), None)] {
        let mut row = record();
        row.revision = 1;
        row.state = "pending".into();
        row.resolution_request_id = request;
        row.resolved_at = time;
        assert!(row.into_wire(ACCOUNT, CONTEXT).is_err());
    }
    for kind in 1..=2 {
        for reason in 1..=5 {
            let mut row = record();
            row.source_kind = kind;
            row.reason = reason;
            assert_eq!(row.into_wire(ACCOUNT, CONTEXT).is_ok(), matches!((kind, reason), (1, 1 | 5) | (2, 2..=4)));
        }
    }
}

#[test]
fn canonical_timestamps_require_finite_four_digit_utc_calendar_values() {
    for time in ["0001-01-01T00:00:00.000000Z", "2000-02-29T23:59:59.123456Z", TIME] {
        assert!(canonical_timestamp(time));
    }
    for time in [
        "", "infinity", "-infinity", "0000-01-01T00:00:00.000000Z",
        "10000-01-01T00:00:00.000000Z", "1900-02-29T00:00:00.000000Z",
        "2001-02-29T00:00:00.000000Z", "2000-00-01T00:00:00.000000Z",
        "2000-13-01T00:00:00.000000Z", "2000-01-00T00:00:00.000000Z",
        "2000-04-31T00:00:00.000000Z", "2000-01-01T24:00:00.000000Z",
        "2000-01-01T00:60:00.000000Z", "2000-01-01T00:00:60.000000Z",
        "2000-01-01T00:00:00.00000Z", "2000-01-01T00:00:00.000000+00:00",
        "2000-01-01 00:00:00.000000Z", "2000-01-01T00:00:00.00000é",
    ] {
        assert!(!canonical_timestamp(time), "{time}");
        let mut row = record();
        row.resolved_at = Some(time.into());
        assert!(row.into_wire(ACCOUNT, CONTEXT).is_err());
    }
}

// The existing Case is SYNTHETIC: its owner/session/manifest/conversation metadata
// exercises actual PostgreSQL authorization, not onboarding or genuine HPKE opening.
async fn context() -> Case {
    let c = Case::new().await;
    write(&mut c.f.connect().await, &c.owner, Uuid::new_v4(), 0, &c.bytes()).await.unwrap();
    c
}

async fn queue(c: &Case, before: Option<Uuid>) -> Result<ExceptionsPage, ConversationError> {
    exceptions(&mut c.f.connect().await, &c.owner, c.h.context, before).await
}

// Direct SQL wire-edge fixture, deliberately separate from public exception provenance.
// It does not manufacture a sealed message effect, grant, approval or inbound provenance.
async fn seed(c: &Case, id: Uuid, kind: i16, reason: i16, created: &str, resolved: Option<&str>) {
    let revision = if resolved.is_some() { 2i64 } else { 1i64 };
    let state = if resolved.is_some() { "resolved" } else { "pending" };
    let request = resolved.map(|_| Uuid::new_v4());
    c.f.db.execute(
        "INSERT INTO workflow_exceptions(account_id,context_id,id,context_revision,source_kind,source_id,reason,request_digest,revision,state,resolution_request_id,resolved_at,created_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11::text::timestamptz,$12::text::timestamptz)",
        &[&c.f.account, &c.h.context, &id, &kind, &Uuid::new_v4(), &reason, &vec![255u8; 32], &revision, &state, &request, &resolved, &created],
    ).await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn authorized_empty_context_is_bound_and_foreign_or_revoked_reads_refuse() {
    let c = context().await;
    let page = queue(&c, None).await.unwrap();
    let bytes = response_bytes(page).await;
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_shape(&value, c.f.account, c.h.context);
    assert_eq!(value["items"], serde_json::json!([]));
    assert!(value["next_cursor"].is_null());
    assert!(exceptions(&mut c.f.connect().await, &c.owner, Uuid::new_v4(), None).await.is_err());
    let foreign = context().await;
    assert!(exceptions(&mut c.f.connect().await, &foreign.owner, c.h.context, None).await.is_err());
    foreign.cleanup().await;
    c.f.db.execute("UPDATE sessions SET revoked_at=clock_timestamp() WHERE account_id=$1", &[&c.f.account]).await.unwrap();
    assert!(matches!(queue(&c, None).await, Err(ConversationError::Forbidden)));
    c.cleanup().await;
}

async fn message(c: &Case, state: &str, peer: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut payload = vec![88u8; 426];
    payload[..6].copy_from_slice(b"ZTSE\x02\x01");
    // Synthetic terminal metadata only. Migration071 still refuses ungranted unknown effects.
    c.f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at,sealed_line_id,sealed_binding_generation,sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id) VALUES($1,$2,$3,$4,$5,'sealed_candidate02',$6,$5,$7,clock_timestamp()+interval '1 hour',$8,1,$9,$10,$11,$12)",
        &[&id, &c.f.account, &c.f.device, &peer, &vec![1u8; 32], &Some(payload), &state, &c.f.line, &c.h.trust_generation, &c.h.manifest_version, &c.h.manifest_digest.as_slice(), &c.s.signer.as_slice()]).await.unwrap();
    id
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn public_exception_producers_and_resolution_keep_provenance_replay_and_closed_rows() {
    let c = context().await;
    let event = Uuid::new_v4();
    capture(&c.f, &c.s, event, 1, b"+12").await.unwrap();
    let base = ExceptionInput {
        context_id: c.h.context,
        context_revision: 1,
        source_kind: 1,
        source_id: event,
        reason: 1,
    };
    let mut produced = Vec::new();
    for reason in [1, 5] {
        let input = ExceptionInput { reason, ..base };
        let id = exception(&mut c.f.connect().await, &c.owner, input).await.unwrap();
        assert_eq!(exception(&mut c.f.connect().await, &c.owner, input).await.unwrap(), id);
        produced.push((id, input));
    }
    for (state, reason) in [("expired", 3), ("cancelled", 4)] {
        let source_id = message(&c, state, "+12").await;
        let input = ExceptionInput { source_kind: 2, source_id, reason, ..base };
        let id = exception(&mut c.f.connect().await, &c.owner, input).await.unwrap();
        produced.push((id, input));
        assert!(exception(&mut c.f.connect().await, &c.owner, ExceptionInput { reason: 2, ..input }).await.is_err());
    }
    let wrong_peer = message(&c, "cancelled", "+13").await;
    for input in [
        ExceptionInput { source_id: Uuid::new_v4(), ..base },
        ExceptionInput { context_revision: 2, ..base },
        ExceptionInput { source_kind: 2, source_id: wrong_peer, reason: 4, ..base },
    ] {
        assert!(exception(&mut c.f.connect().await, &c.owner, input).await.is_err());
    }
    let first = queue(&c, None).await.unwrap();
    let value = serde_json::to_value(&first).unwrap();
    assert_shape(&value, c.f.account, c.h.context);
    assert_eq!(first.items.len(), 4);
    for (id, input) in &produced {
        let row = first.items.iter().find(|row| row.id == *id).unwrap();
        assert_eq!((row.source_kind, row.reason, row.source_id), (input.source_kind, input.reason, input.source_id));
        let expected: String = input.digest(c.f.account).unwrap().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(row.request_digest, format!("\\x{expected}"));
        assert_eq!((row.revision, row.state.as_str()), (1, "pending"));
        assert!(row.resolution_request_id.is_none() && row.resolved_at.is_none());
    }
    let id = produced[0].0;
    let request = Uuid::new_v4();
    assert_eq!(resolve(&mut c.f.connect().await, &c.owner, id, request, 1).await.unwrap(), 2);
    assert_eq!(resolve(&mut c.f.connect().await, &c.owner, id, request, 1).await.unwrap(), 2);
    assert!(resolve(&mut c.f.connect().await, &c.owner, id, Uuid::new_v4(), 1).await.is_err());
    assert_eq!(exception(&mut c.f.connect().await, &c.owner, produced[0].1).await.unwrap(), id);
    let page = queue(&c, None).await.unwrap();
    let row = page.items.iter().find(|row| row.id == id).unwrap();
    assert_eq!((row.revision, row.state.as_str(), row.resolution_request_id), (2, "resolved", Some(request)));
    assert!(row.resolved_at.as_deref().is_some_and(canonical_timestamp));
    let before: i64 = c.f.db.query_one("SELECT count(*) FROM workflow_context_audit", &[]).await.unwrap().get(0);
    let _ = response_bytes(page).await;
    queue(&c, None).await.unwrap();
    let after: i64 = c.f.db.query_one("SELECT count(*) FROM workflow_context_audit", &[]).await.unwrap().get(0);
    assert_eq!(before, after);
    assert_eq!(c.f.db.query_one("SELECT count(*) FROM workflow_exceptions", &[]).await.unwrap().get::<_, i64>(0), 4);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn populated_queue_refuses_expired_session_manifest_line_and_scrubbed_context() {
    for refusal in 0..4 {
        let c = context().await;
        seed(&c, Uuid::from_u128(1), 1, 1, TIME, None).await;
        match refusal {
            0 => {
                c.f.db.execute("UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE account_id=$1", &[&c.f.account]).await.unwrap();
            }
            1 => {
                c.f.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1", &[&c.f.account]).await.unwrap();
            }
            2 => {
                c.f.db.execute("UPDATE device_line_bindings SET state='revoked' WHERE account_id=$1", &[&c.f.account]).await.unwrap();
            }
            _ => {
                c.f.db.execute("UPDATE workflow_context_versions SET envelope=NULL WHERE account_id=$1", &[&c.f.account]).await.unwrap();
            }
        }
        assert!(queue(&c, None).await.is_err(), "refusal {refusal}");
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn direct_sql_twenty_one_rows_continue_ascending_and_foreign_cursors_refuse() {
    let c = context().await;
    let ids: Vec<_> = (1..=21).map(Uuid::from_u128).collect();
    for id in &ids {
        seed(&c, *id, 1, 1, TIME, None).await;
    }
    let page = queue(&c, None).await.unwrap();
    assert_eq!(page.items.iter().map(|row| row.id).collect::<Vec<_>>(), ids[..20]);
    assert_eq!(page.next_cursor, Some(ids[19]));
    let last = queue(&c, page.next_cursor).await.unwrap();
    assert_eq!(last.items.iter().map(|row| row.id).collect::<Vec<_>>(), ids[20..]);
    assert!(last.next_cursor.is_none());
    let end = queue(&c, Some(ids[20])).await.unwrap();
    assert!(end.items.is_empty() && end.next_cursor.is_none());
    assert!(queue(&c, Some(Uuid::from_u128(99))).await.is_err());
    let mut h = c.h.clone();
    h.context = Uuid::new_v4();
    write(&mut c.f.connect().await, &c.owner, Uuid::new_v4(), 0, &Case::envelope(&h, 88)).await.unwrap();
    let other_context_cursor = Uuid::from_u128(30);
    c.f.db.execute("INSERT INTO workflow_exceptions(account_id,context_id,id,context_revision,source_kind,source_id,reason,request_digest) VALUES($1,$2,$3,1,1,$4,1,$5)", &[&c.f.account, &h.context, &other_context_cursor, &Uuid::new_v4(), &vec![1u8; 32]]).await.unwrap();
    assert!(queue(&c, Some(other_context_cursor)).await.is_err());
    let foreign = context().await;
    let foreign_cursor = Uuid::from_u128(31);
    seed(&foreign, foreign_cursor, 1, 1, TIME, None).await;
    // Direct SQL copies of independently prepared synthetic FK parents put a real
    // foreign-account cursor in this SAME table. No authentication is manufactured.
    let schema = foreign.f.schema.replace('"', "\"\"");
    let mut client = c.f.connect().await;
    let tx = client.transaction().await.unwrap();
    for table in [
        "accounts", "users", "memberships", "sessions", "devices", "phone_lines",
        "device_line_bindings", "conversation_intervals", "workflow_contexts",
        "workflow_context_versions", "workflow_exceptions",
    ] {
        tx.batch_execute(&format!("INSERT INTO {table} SELECT * FROM \"{schema}\".{table}")).await.unwrap();
    }
    tx.commit().await.unwrap();
    assert_eq!(c.f.db.query_one("SELECT account_id FROM workflow_exceptions WHERE id=$1", &[&foreign_cursor]).await.unwrap().get::<_, Uuid>(0), foreign.f.account);
    assert!(queue(&c, Some(foreign_cursor)).await.is_err());
    foreign.cleanup().await;
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn direct_sql_timestamp_and_digest_edges_ignore_postgres_output_settings() {
    let c = context().await;
    for (index, (kind, reason)) in [(1, 1), (1, 5), (2, 2), (2, 3), (2, 4)].into_iter().enumerate() {
        seed(&c, Uuid::from_u128(index as u128 + 1), kind, reason, "0001-01-01T00:00:00.000001Z", Some(TIME)).await;
    }
    seed(&c, Uuid::from_u128(6), 1, 1, "2000-01-01T00:30:00.123456+01:00", None).await;
    let baseline = serde_json::to_vec(&queue(&c, None).await.unwrap()).unwrap();
    for settings in [
        "SET bytea_output='escape'; SET DateStyle='SQL, DMY'; SET TimeZone='Pacific/Honolulu'",
        "SET bytea_output='hex'; SET DateStyle='German, DMY'; SET TimeZone='Asia/Kathmandu'",
    ] {
        let mut client = c.f.connect().await;
        client.batch_execute(settings).await.unwrap();
        let page = exceptions(&mut client, &c.owner, c.h.context, None).await.unwrap();
        assert_eq!(serde_json::to_vec(&page).unwrap(), baseline);
        assert_eq!(page.items[0].created_at, "0001-01-01T00:00:00.000001Z");
        assert_eq!(page.items[0].resolved_at.as_deref(), Some(TIME));
        assert_eq!(page.items[5].created_at, "1999-12-31T23:30:00.123456Z");
        let bytes = response_bytes(page).await;
        assert_shape(&serde_json::from_slice(&bytes).unwrap(), c.f.account, c.h.context);
    }
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn direct_sql_unsupported_timestamps_nil_ids_and_kind_pairs_refuse_entire_page() {
    let c = context().await;
    for id in 1..=20 {
        seed(&c, Uuid::from_u128(id), 1, 1, TIME, None).await;
    }
    // Put each refusal at the lookahead, after twenty supported rows.
    for (created, resolved) in [
        ("infinity", None), ("-infinity", None), ("10000-01-01T00:00:00Z", None),
        ("0001-01-01 BC", None), (TIME, Some("infinity")),
        (TIME, Some("-infinity")), (TIME, Some("10000-01-01T00:00:00Z")),
        (TIME, Some("0001-01-01 BC")),
    ] {
        let id = Uuid::from_u128(21);
        seed(&c, id, 1, 1, created, resolved).await;
        assert!(matches!(queue(&c, None).await, Err(ConversationError::Unavailable)));
        c.f.db.execute("DELETE FROM workflow_exceptions WHERE id=$1", &[&id]).await.unwrap();
    }
    for (id, kind, reason) in [(Uuid::nil(), 1, 1), (Uuid::from_u128(21), 1, 2), (Uuid::from_u128(21), 2, 5)] {
        seed(&c, id, kind, reason, TIME, None).await;
        assert!(matches!(queue(&c, None).await, Err(ConversationError::Unavailable)));
        c.f.db.execute("DELETE FROM workflow_exceptions WHERE id=$1", &[&id]).await.unwrap();
    }
    // Migration permits nil source/request UUIDs; the wire projection refuses them.
    for resolved in [false, true] {
        c.f.db.execute("INSERT INTO workflow_exceptions(account_id,context_id,id,context_revision,source_kind,source_id,reason,request_digest,revision,state,resolution_request_id,resolved_at) VALUES($1,$2,$3,1,1,$4,1,$5,$6,$7,$8,$9::text::timestamptz)",
            &[&c.f.account, &c.h.context, &Uuid::from_u128(21), &if resolved { Uuid::new_v4() } else { Uuid::nil() }, &vec![1u8; 32], &if resolved { 2i64 } else { 1i64 }, &if resolved { "resolved" } else { "pending" }, &if resolved { Some(Uuid::nil()) } else { None }, &if resolved { Some(TIME) } else { None }]).await.unwrap();
        assert!(matches!(queue(&c, None).await, Err(ConversationError::Unavailable)));
        c.f.db.execute("DELETE FROM workflow_exceptions WHERE id=$1", &[&Uuid::from_u128(21)]).await.unwrap();
    }
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn direct_sql_worst_twenty_resolved_revision_rows_fit_actual_json_budget_and_cap_stays_thirty_two() {
    let c = context().await;
    // Establish all immutable revisions through the existing public writer.
    for revision in 2..=128 {
        let mut h = c.h.clone();
        h.revision = revision;
        assert_eq!(write(&mut c.f.connect().await, &c.owner, Uuid::new_v4(), revision - 1, &Case::envelope(&h, 88)).await.unwrap(), revision);
    }
    for id in 1..=32 {
        c.f.db.execute("INSERT INTO workflow_exceptions(account_id,context_id,id,context_revision,source_kind,source_id,reason,request_digest,revision,state,resolution_request_id,resolved_at,created_at) VALUES($1,$2,$3,128,2,$4,4,$5,2,'resolved',$6,$7::text::timestamptz,$7::text::timestamptz)",
            &[&c.f.account, &c.h.context, &Uuid::from_u128(id), &Uuid::new_v4(), &vec![255u8; 32], &Uuid::new_v4(), &TIME]).await.unwrap();
    }
    let page = queue(&c, None).await.unwrap();
    assert_eq!(page.items.len(), 20);
    assert_eq!(page.next_cursor, Some(Uuid::from_u128(20)));
    assert!(page.items.iter().all(|r| r.context_revision == 128 && r.created_at == TIME && r.resolved_at.as_deref() == Some(TIME)));
    let bytes = response_bytes(page).await;
    assert!(bytes.len() <= 65_536);
    assert_shape(&serde_json::from_slice(&bytes).unwrap(), c.f.account, c.h.context);
    let event = Uuid::new_v4();
    capture(&c.f, &c.s, event, 1, b"+12").await.unwrap();
    let input = ExceptionInput { context_id: c.h.context, context_revision: 128, source_kind: 1, source_id: event, reason: 1 };
    assert!(matches!(exception(&mut c.f.connect().await, &c.owner, input).await, Err(ConversationError::Conflict)));
    assert_eq!(c.f.db.query_one("SELECT count(*) FROM workflow_exceptions", &[]).await.unwrap().get::<_, i64>(0), 32);
    c.cleanup().await;
}
