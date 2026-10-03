// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::context::tests::Case;
fn header(c: &Case) -> wire::Header {
    wire::Header {
        account: c.h.account,
        device: c.h.device,
        line: c.h.line,
        interval: c.h.interval,
        template: c.h.context,
        binding_generation: c.h.binding_generation,
        revision: 1,
        expires_ms: c.h.expires_ms,
        trust_generation: c.h.trust_generation,
        manifest_version: c.h.manifest_version,
        peer_digest: c.h.peer_digest,
        reader: c.h.reader,
        manifest_digest: c.h.manifest_digest,
    }
}
fn envelope(h: &wire::Header, value: u8) -> Vec<u8> {
    let mut b = h.aad().unwrap();
    b.extend(
        p256::SecretKey::from_slice(&[1; 32])
            .unwrap()
            .public_key()
            .to_sec1_bytes(),
    );
    b.extend(33u32.to_be_bytes());
    b.extend([value; 33]);
    b
}
#[test]
fn dedicated_template_wire_rejects_context_plaintext_and_unbounded_inputs() {
    assert_ne!(
        wire::INFO,
        crate::http_owner_conversations::context::wire::INFO
    );
    assert!(wire::parse(b"synthetic template plaintext").is_err());
    assert!(wire::parse(&vec![0; wire::MAX_ENVELOPE + 1]).is_err());
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn templates_cas_replay_digest_and_reader_scope_are_durable() {
    let c = Case::new().await;
    let h = header(&c);
    let bytes = envelope(&h, 88);
    let req = Uuid::new_v4();
    assert_eq!(
        write(&mut c.f.connect().await, &c.owner, req, 0, &bytes)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        write(&mut c.f.connect().await, &c.owner, req, 0, &bytes)
            .await
            .unwrap(),
        1
    );
    assert!(
        write(
            &mut c.f.connect().await,
            &c.owner,
            req,
            0,
            &envelope(&h, 89)
        )
        .await
        .is_err()
    );
    assert_eq!(
        read(&mut c.f.connect().await, &c.owner, h.template, None)
            .await
            .unwrap(),
        bytes
    );
    assert!(wire::parse(&c.bytes()).is_err());
    let mut next = h.clone();
    next.revision = 2;
    let a = envelope(&next, 90);
    let b = envelope(&next, 91);
    let mut ca = c.f.connect().await;
    let mut cb = c.f.connect().await;
    let (a, b) = tokio::join!(
        write(&mut ca, &c.owner, Uuid::new_v4(), 1, &a),
        write(&mut cb, &c.owner, Uuid::new_v4(), 1, &b)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let page = list(&mut c.f.connect().await, &c.owner, h.interval, None)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].revision, 2);
    assert_eq!(
        read(&mut c.f.connect().await, &c.owner, h.template, Some(1))
            .await
            .unwrap(),
        bytes
    );
    let mut wrong = h.clone();
    wrong.template = Uuid::new_v4();
    wrong.reader = [9; 32];
    assert!(
        write(
            &mut c.f.connect().await,
            &c.owner,
            Uuid::new_v4(),
            0,
            &envelope(&wrong, 88)
        )
        .await
        .is_err()
    );
    c.f.db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.owner.session_id],
        )
        .await
        .unwrap();
    assert!(
        read(&mut c.f.connect().await, &c.owner, h.template, None)
            .await
            .is_err()
    );
    assert!(
        write(&mut c.f.connect().await, &c.owner, req, 0, &bytes)
            .await
            .is_err()
    );
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn template_withdrawal_retention_export_and_account_erase_preserve_no_rehydration() {
    let c = Case::new().await;
    let h = header(&c);
    let bytes = envelope(&h, 88);
    let req = Uuid::new_v4();
    write(&mut c.f.connect().await, &c.owner, req, 0, &bytes)
        .await
        .unwrap();
    let takeout = lifecycle::export(&mut c.f.connect().await, &c.owner, [None, None])
        .await
        .unwrap();
    assert_eq!(takeout.templates.items.len(), 1);
    assert_eq!(takeout.versions.items.len(), 1);
    assert!(
        takeout.versions.items[0]["envelope_hex"]
            .as_str()
            .unwrap()
            .starts_with("5a545754")
    );
    c.f.db.execute("UPDATE conversation_intervals SET phase='withdrawn',statement=NULL,closed_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&h.account,&h.interval]).await.unwrap();
    assert_eq!(
        lifecycle::prune(&mut c.f.connect().await, 1).await.unwrap(),
        1
    );
    assert_eq!(
        lifecycle::prune(&mut c.f.connect().await, 1).await.unwrap(),
        0
    );
    assert!(
        read(&mut c.f.connect().await, &c.owner, h.template, None)
            .await
            .is_err()
    );
    assert!(
        write(&mut c.f.connect().await, &c.owner, req, 0, &bytes)
            .await
            .is_err()
    );
    assert!(
        c.f.db
            .execute(
                "UPDATE encrypted_template_versions SET envelope=$1 WHERE account_id=$2",
                &[&bytes, &h.account]
            )
            .await
            .is_err()
    );
    let mut db = c.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let erased = lifecycle::erase(&tx, h.account).await.unwrap();
    assert!(erased.iter().all(|(_, n)| *n == 1));
    tx.commit().await.unwrap();
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn template_account_identity_cap_and_takeout_pages_are_real_and_atomic() {
    let c = Case::new().await;
    let mut h = header(&c);
    let bytes = envelope(&h, 88);
    write(
        &mut c.f.connect().await,
        &c.owner,
        Uuid::new_v4(),
        0,
        &bytes,
    )
    .await
    .unwrap();
    // Exact scoped opaque fixtures exercise storage capacity, never HPKE proof.
    let mut db = c.f.connect().await;
    let tx = db.transaction().await.unwrap();
    for _ in 1..256 {
        h.template = Uuid::new_v4();
        let bytes = envelope(&h, 88);
        let digest = Sha256::digest(&bytes).to_vec();
        tx.execute("INSERT INTO encrypted_templates SELECT account_id,$2,interval_id,device_id,line_id,binding_generation,peer_digest,reader_key_id,trust_generation,revision,expires_at_ms,purged_at,created_at FROM encrypted_templates WHERE account_id=$1 LIMIT 1",&[&h.account,&h.template]).await.unwrap();
        tx.execute("INSERT INTO encrypted_template_versions(account_id,template_id,id,revision,expires_at_ms,request_id,request_digest,envelope) VALUES($1,$2,$3,1,$4,$5,$6,$7)",&[&h.account,&h.template,&Uuid::new_v4(),&h.expires_ms,&Uuid::new_v4(),&digest,&bytes]).await.unwrap();
    }
    tx.commit().await.unwrap();
    drop(db);
    h.template = Uuid::new_v4();
    assert!(
        write(
            &mut c.f.connect().await,
            &c.owner,
            Uuid::new_v4(),
            0,
            &envelope(&h, 88)
        )
        .await
        .is_err()
    );
    let first = lifecycle::export(&mut c.f.connect().await, &c.owner, [None, None])
        .await
        .unwrap();
    assert_eq!(first.templates.items.len(), 20);
    assert!(first.templates.next_cursor.is_some());
    let second = lifecycle::export(
        &mut c.f.connect().await,
        &c.owner,
        [first.templates.next_cursor, first.versions.next_cursor],
    )
    .await
    .unwrap();
    assert_eq!(second.templates.items.len(), 20);
    assert_ne!(
        first.templates.items[0]["id"],
        second.templates.items[0]["id"]
    );
    let page = list(&mut c.f.connect().await, &c.owner, h.interval, None)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 20);
    assert!(page.next_cursor.is_some());
    assert_eq!(
        c.f.db
            .query_one("SELECT count(*) FROM encrypted_templates", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        256
    );
    assert_eq!(
        c.f.db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn template_live_manifest_revocation_refuses_reads_empty_lists_and_exact_replays() {
    let c = Case::new().await;
    let h = header(&c);
    let bytes = envelope(&h, 88);
    let req = Uuid::new_v4();
    write(&mut c.f.connect().await, &c.owner, req, 0, &bytes)
        .await
        .unwrap();
    c.f.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",&[&h.account]).await.unwrap();
    assert!(
        read(&mut c.f.connect().await, &c.owner, h.template, None)
            .await
            .is_err()
    );
    assert!(
        list(&mut c.f.connect().await, &c.owner, h.interval, None)
            .await
            .is_err()
    );
    assert!(
        write(&mut c.f.connect().await, &c.owner, req, 0, &bytes)
            .await
            .is_err()
    );
    let takeout = lifecycle::export(&mut c.f.connect().await, &c.owner, [None, None])
        .await
        .unwrap();
    assert_eq!(takeout.versions.items.len(), 1);
    c.cleanup().await;
}
#[test]
fn template_header_matches_shared_normative_vector() {
    let h = wire::Header {
        account: Uuid::from_u128(1),
        device: Uuid::from_u128(2),
        line: Uuid::from_u128(3),
        interval: Uuid::from_u128(4),
        template: Uuid::from_u128(5),
        binding_generation: 1,
        revision: 1,
        expires_ms: 1_893_500_000_000,
        trust_generation: 1,
        manifest_version: 1,
        peer_digest: Sha256::digest(b"+12").into(),
        reader: [2; 32],
        manifest_digest: [3; 32],
    };
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/encrypted-template-01.json"
    ))
    .unwrap();
    let aad = h.aad().unwrap();
    assert_eq!(
        aad.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        v["aad_hex"].as_str().unwrap()
    );
    assert_eq!(
        [wire::INFO, aad.as_slice()]
            .concat()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        v["hpke_info_hex"].as_str().unwrap()
    );
}

async fn insert_opaque_version(tx: &Transaction<'_>, h: &wire::Header, bytes: &[u8]) {
    let digest = Sha256::digest(bytes).to_vec();
    tx.execute("INSERT INTO encrypted_template_versions(account_id,template_id,id,revision,expires_at_ms,request_id,request_digest,envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&h.account,&h.template,&Uuid::new_v4(),&h.revision,&h.expires_ms,&Uuid::new_v4(),&digest,&bytes]).await.unwrap();
}
async fn insert_head(tx: &Transaction<'_>, h: &wire::Header) {
    tx.execute("INSERT INTO encrypted_templates(account_id,id,interval_id,device_id,line_id,binding_generation,peer_digest,reader_key_id,trust_generation,revision,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",&[&h.account,&h.template,&h.interval,&h.device,&h.line,&h.binding_generation,&h.peer_digest.as_slice(),&h.reader.as_slice(),&h.trust_generation,&h.revision,&h.expires_ms]).await.unwrap();
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expired_template_revision_is_scrubbed_while_current_version_stays_readable() {
    let c = Case::new().await;
    let mut old = header(&c);
    old.expires_ms = 1;
    let mut current = old.clone();
    current.revision = 2;
    current.expires_ms = c.h.expires_ms;
    let mut db = c.f.connect().await;
    let tx = db.transaction().await.unwrap();
    insert_head(&tx, &current).await;
    insert_opaque_version(&tx, &old, &envelope(&old, 88)).await;
    let current_bytes = envelope(&current, 89);
    insert_opaque_version(&tx, &current, &current_bytes).await;
    tx.commit().await.unwrap();
    assert_eq!(
        lifecycle::prune(&mut c.f.connect().await, 1).await.unwrap(),
        1
    );
    assert_eq!(
        lifecycle::prune(&mut c.f.connect().await, 1).await.unwrap(),
        0
    );
    assert!(
        read(&mut c.f.connect().await, &c.owner, old.template, Some(1))
            .await
            .is_err()
    );
    assert_eq!(
        read(&mut c.f.connect().await, &c.owner, current.template, None)
            .await
            .unwrap(),
        current_bytes
    );
    let row=c.f.db.query_one("SELECT (SELECT envelope IS NULL FROM encrypted_template_versions WHERE revision=1),purged_at IS NULL FROM encrypted_templates",&[]).await.unwrap();
    assert!(row.get::<_, bool>(0));
    assert!(row.get::<_, bool>(1));
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn template_encrypted_byte_budget_rolls_back_new_head_and_version() {
    let c = Case::new().await;
    let base = header(&c);
    let mut db = c.f.connect().await;
    let tx = db.transaction().await.unwrap();
    for count in [128, 125] {
        let mut h = base.clone();
        h.template = Uuid::new_v4();
        h.revision = count;
        insert_head(&tx, &h).await;
        for revision in 1..=count {
            h.revision = revision;
            let mut bytes = h.aad().unwrap();
            bytes.extend(
                p256::SecretKey::from_slice(&[1; 32])
                    .unwrap()
                    .public_key()
                    .to_sec1_bytes(),
            );
            bytes.extend(32784u32.to_be_bytes());
            bytes.extend(vec![88; 32784]);
            insert_opaque_version(&tx, &h, &bytes).await;
        }
    }
    tx.commit().await.unwrap();
    let mut candidate = base.clone();
    candidate.template = Uuid::new_v4();
    let mut bytes = candidate.aad().unwrap();
    bytes.extend(
        p256::SecretKey::from_slice(&[1; 32])
            .unwrap()
            .public_key()
            .to_sec1_bytes(),
    );
    bytes.extend(32784u32.to_be_bytes());
    bytes.extend(vec![89; 32784]);
    assert!(
        write(
            &mut c.f.connect().await,
            &c.owner,
            Uuid::new_v4(),
            0,
            &bytes
        )
        .await
        .is_err()
    );
    let row=c.f.db.query_one("SELECT (SELECT count(*) FROM encrypted_templates),(SELECT count(*) FROM encrypted_template_versions),(SELECT coalesce(sum(octet_length(envelope)),0)::bigint FROM encrypted_template_versions)",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 2);
    assert_eq!(row.get::<_, i64>(1), 253);
    assert!(row.get::<_, i64>(2) < ACCOUNT_BYTES);
    c.cleanup().await;
}

#[tokio::test]
async fn dormant_template_router_and_bearer_refusal_do_not_touch_database() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;
    let state = crate::http_owner_conversations::OwnerConversationsState {
        database_url: String::new(),
        canonical_origin: "https://gateway.invalid".into(),
        auth_hasher: Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap()),
    };
    let response = http::router(state.clone(), false)
        .oneshot(
            Request::builder()
                .uri("/v1/owner/workflow/templates")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = http::router(state, true)
        .oneshot(
            Request::builder()
                .uri(
                    "/v1/owner/workflow/templates?interval_id=00000000-0000-0000-0000-000000000004",
                )
                .header("authorization", "Bearer synthetic-untrusted")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["cache-control"], "no-store");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn template_http_save_read_and_revocation_use_real_owner_cookie_and_csrf() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};
    use std::sync::Arc;
    use tower::ServiceExt;
    let c = Case::new().await;
    let h = header(&c);
    let bytes = envelope(&h, 88);
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let hash = |domain: &[u8], value: &str| {
        let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
        mac.update(domain);
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    c.f.db
        .execute(
            "UPDATE sessions SET token_hash=$1,csrf_hash=$2 WHERE id=$3",
            &[
                &hash(b"session-v1\0", &token),
                &hash(b"csrf-v1\0", &csrf),
                &c.owner.session_id,
            ],
        )
        .await
        .unwrap();
    let sep = if c.f.url.contains('?') { '&' } else { '?' };
    let state = crate::http_owner_conversations::OwnerConversationsState {
        database_url: format!("{}{sep}options=-csearch_path%3D{}", c.f.url, c.f.schema),
        canonical_origin: "https://test.example".into(),
        auth_hasher: Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap()),
    };
    let cookie = format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}");
    let request = || {
        Request::post("/v1/owner/workflow/templates")
            .header(
                "content-type",
                "application/vnd.zrotext.workflow-template.v1",
            )
            .header("origin", "https://test.example")
            .header("cookie", &cookie)
            .header("x-zrotext-csrf", &csrf)
            .header("idempotency-key", Uuid::new_v4().to_string())
            .header("x-zrotext-template-revision", "0")
            .body(Body::from(bytes.clone()))
            .unwrap()
    };
    let saved = http::router(state.clone(), true)
        .oneshot(request())
        .await
        .unwrap();
    assert_eq!(saved.status(), StatusCode::OK);
    assert_eq!(saved.headers()["cache-control"], "no-store");
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(saved.into_body(), 128).await.unwrap()).unwrap();
    assert_eq!(value["revision"], 1);
    let read_request = || {
        Request::get(format!("/v1/owner/workflow/templates/{}", h.template))
            .header("cookie", &cookie)
            .header("x-zrotext-csrf", &csrf)
            .body(Body::empty())
            .unwrap()
    };
    let response = http::router(state.clone(), true)
        .oneshot(read_request())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), wire::MAX_ENVELOPE)
            .await
            .unwrap()
            .as_ref(),
        bytes
    );
    let denied = http::router(state.clone(), true)
        .oneshot(
            Request::get(format!("/v1/owner/workflow/templates/{}", h.template))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    c.f.db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.owner.session_id],
        )
        .await
        .unwrap();
    let denied = http::router(state, true)
        .oneshot(read_request())
        .await
        .unwrap();
    assert!(!denied.status().is_success());
    c.cleanup().await;
}
