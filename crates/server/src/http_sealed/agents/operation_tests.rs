// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth,
    sealed_outbound::{self, tests::TestCase},
};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac, digest::KeyInit};
use p256::ecdsa::{Signature, signature::Signer};
use serde_json::Value;
use sha2::Sha256;
use tower::ServiceExt;

struct Case {
    base: TestCase,
    token: String,
    grant: Uuid,
    reader: [u8; 32],
    connector: Uuid,
    router: Router,
}
impl Case {
    async fn new(permissions: [bool; 4]) -> Self {
        let (base, connector, reader) = TestCase::with_agent_connector().await;
        let (token, grant) = issue(&base, connector, reader, permissions, "+12").await;
        let separator = if base.url.contains('?') { '&' } else { '?' };
        let url = format!(
            "{}{separator}options=-csearch_path%3D{}",
            base.url, base.schema
        );
        let state = SealedHttpState::new(
            url,
            Arc::new(auth::TokenHasher::new(crate::test_keys::key(76)).unwrap()),
            "manifest-test".into(),
            1,
            false,
        )
        .unwrap()
        .with_agent_authority_enabled();
        let router = super::super::router(state);
        Self {
            base,
            token,
            grant,
            reader,
            connector,
            router,
        }
    }
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        timing: Option<&str>,
    ) -> Response {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", self.token));
        if method == "POST" {
            request = request.header("content-type", super::super::SEALED_CONTENT_TYPE);
        }
        if let Some(timing) = timing {
            request = request.header("x-zrotext-not-before-ms", timing);
        }
        self.router
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }
    async fn effects(&self) -> (i64, i64, i64, i32, i32) {
        let row=self.base.db.query_one("SELECT (SELECT count(*) FROM messages WHERE account_id=$1),(SELECT count(*) FROM agent_authority_actions WHERE account_id=$1),(SELECT count(*) FROM agent_authority_approvals WHERE account_id=$1),messages_reserved,turns_consumed FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2",&[&self.base.account,&self.grant]).await.unwrap();
        (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
    }
    async fn envelope(&self, id: Uuid, selected_reader: bool) -> Vec<u8> {
        let mut bytes = self.base.envelope(id).await;
        if selected_reader {
            let end = bytes.len() - 64;
            bytes.truncate(end);
            bytes[200] += 1;
            bytes.push(3);
            bytes.extend(self.reader);
            bytes.extend(
                self.base
                    .root
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes(),
            );
            bytes.extend([9; 48]);
            bytes.extend([0; 64]);
            sign(&self.base, &mut bytes);
        }
        bytes
    }
    /// Real Send-only admission creates provenance, independently of this
    /// owner's separate read-only grant; no owner message is adopted.
    async fn historical(&self, id: Uuid, bytes: &[u8]) {
        let (token, grant) = issue(
            &self.base,
            self.connector,
            self.reader,
            [false, false, false, true],
            "+12",
        )
        .await;
        let mut db = self.base.connect().await;
        let tx = db.transaction().await.unwrap();
        let now: i64 = tx
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let action = store::validate_owner_action(
            &tx,
            &self.base.hasher,
            self.base.account,
            grant,
            Uuid::new_v4(),
            bytes,
            now,
        )
        .await
        .unwrap();
        assert_eq!(action.message, id);
        tx.execute("INSERT INTO agent_authority_approvals(account_id,action_id,grant_id,message_id,device_id,line_id,binding_generation,recipient_digest,unsigned_digest,action_digest,not_before_ms,expires_ms,approved_by_user,approved_session,approved_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,floor(extract(epoch FROM clock_timestamp())*1000)::bigint)",&[&action.account,&action.action,&action.grant,&action.message,&action.device,&action.line,&action.binding_generation,&action.recipient.as_slice(),&action.unsigned_envelope.as_slice(),&action.digest().as_slice(),&action.not_before_ms,&action.expires_ms,&self.base.user,&Uuid::new_v4()]).await.unwrap();
        tx.commit().await.unwrap();
        let principal = agent_grants::authenticate_agent(&db, &self.base.hasher, &token)
            .await
            .unwrap();
        assert!(
            sealed_outbound::admit_agent_candidate02(
                &mut db,
                &principal,
                &self.base.hasher,
                self.base.writer(),
                bytes,
                action.action
            )
            .await
            .unwrap()
            .created
        );
        for path in [
            format!("/agent/messages/{id}"),
            format!("/agent/messages/{id}/content"),
        ] {
            let request = Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                self.router.clone().oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
    }
    async fn ordinary(&self, bytes: &[u8]) {
        let mut db = self.base.connect().await;
        sealed_outbound::admit_candidate02(
            &mut db,
            &self.base.principal,
            &self.base.hasher,
            self.base.writer(),
            bytes,
        )
        .await
        .unwrap();
    }
}
fn sign(base: &TestCase, bytes: &mut [u8]) {
    let end = bytes.len() - 64;
    let signature: Signature = base.event_signer.sign(
        &[
            b"ZTSE/sign/v2\0".as_slice(),
            &(end as u32).to_be_bytes(),
            &bytes[..end],
        ]
        .concat(),
    );
    bytes[end..].copy_from_slice(&signature.normalize_s().to_bytes());
}

#[test]
fn draft_timing_is_canonical_and_cannot_be_duplicated() {
    for invalid in ["", "0", "01", "+1", "-1", " 1", "1 ", "9223372036854775808"] {
        let mut headers = HeaderMap::new();
        headers.insert("x-zrotext-not-before-ms", invalid.parse().unwrap());
        assert!(not_before(&headers).is_err());
    }
    let mut headers = HeaderMap::new();
    headers.insert("x-zrotext-not-before-ms", "1".parse().unwrap());
    assert_eq!(not_before(&headers).unwrap(), 1);
    headers.append("x-zrotext-not-before-ms", "2".parse().unwrap());
    assert!(not_before(&headers).is_err());
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated signed fixture"]
async fn draft_only_permission_validates_exact_action_without_queue_approval_or_send() {
    let case = Case::new([false, false, true, false]).await;
    let action = Uuid::new_v4();
    let message = Uuid::new_v4();
    let bytes = case.envelope(message, false).await;
    let now: i64 = case
        .base
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let timing = now.to_string();
    let path = format!("/agent/actions/{action}/draft");
    let response = case.call("POST", &path, bytes.clone(), Some(&timing)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["approved"], false);
    assert_eq!(body["queued"], false);
    assert_eq!(
        STANDARD
            .decode(body["action_digest_b64"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(case.effects().await, (0, 0, 0, 0, 0));
    for route in [
        format!("/agent/messages/{message}"),
        format!("/agent/messages/{message}/content"),
    ] {
        assert_eq!(
            case.call("GET", &route, vec![], None).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        case.call(
            "POST",
            &format!("/agent/actions/{action}/messages"),
            bytes.clone(),
            None
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        case.call("POST", &path, bytes.clone(), Some("01"))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let foreign = TestCase::with_agent_connector().await.0;
    let foreign_bytes = foreign.envelope(Uuid::new_v4()).await;
    assert_eq!(
        case.call("POST", &path, foreign_bytes, Some(&timing))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    foreign.cleanup().await;
    let mut inbound = bytes.clone();
    inbound[5] = 2;
    assert_eq!(
        case.call("POST", &path, inbound, Some(&timing))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut edited = bytes.clone();
    edited[165] = b'3';
    sign(&case.base, &mut edited);
    assert_eq!(
        case.call("POST", &path, edited, Some(&timing))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let agent = agent_grants::authenticate_agent(&case.base.db, &case.base.hasher, &case.token)
        .await
        .unwrap();
    case.base
        .db
        .execute(
            "UPDATE agent_authority_grants SET revoked_ms=1 WHERE grant_id=$1",
            &[&case.grant],
        )
        .await
        .unwrap();
    let mut db = case.base.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(
        store::validate_agent_draft(&tx, &case.base.hasher, &agent, action, &bytes, now)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        case.call("POST", &path, bytes, Some(&timing))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(case.effects().await, (0, 0, 0, 0, 0));
    case.base.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated signed fixture"]
async fn metadata_only_returns_exact_lifecycle_for_own_ledger_without_content_or_draft() {
    let case = Case::new([true, false, false, false]).await;
    let id = Uuid::new_v4();
    let bytes = case.envelope(id, false).await;
    case.historical(id, &bytes).await;
    let before = case.effects().await;
    let response = case
        .call("GET", &format!("/agent/messages/{id}"), vec![], None)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    let keys = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            "message_id",
            "device_id",
            "state",
            "state_version",
            "created_at_ms",
            "updated_at_ms",
            "expires_at_ms"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        case.call(
            "GET",
            &format!("/agent/messages/{id}/content"),
            vec![],
            None
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        case.call(
            "POST",
            &format!("/agent/actions/{}/draft", Uuid::new_v4()),
            bytes.clone(),
            Some("1")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let ordinary = Uuid::new_v4();
    let bytes = case.envelope(ordinary, false).await;
    case.ordinary(&bytes).await;
    assert_eq!(
        case.call("GET", &format!("/agent/messages/{ordinary}"), vec![], None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let (other_peer, _) = issue(
        &case.base,
        case.connector,
        case.reader,
        [true, false, false, false],
        "+13",
    )
    .await;
    let request = Request::builder()
        .uri(format!("/agent/messages/{id}"))
        .header("authorization", format!("Bearer {other_peer}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        case.router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    let foreign = Case::new([false, false, false, true]).await;
    let foreign_id = Uuid::new_v4();
    let foreign_bytes = foreign.envelope(foreign_id, false).await;
    foreign.historical(foreign_id, &foreign_bytes).await;
    assert_eq!(
        case.call(
            "GET",
            &format!("/agent/messages/{foreign_id}"),
            vec![],
            None
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    foreign.base.cleanup().await;
    assert_eq!(
        case.effects().await,
        (before.0 + 1, before.1, before.2, before.3, before.4)
    );
    case.base.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated signed fixture"]
async fn content_only_requires_exact_current_selected_reader_wrap_and_never_grants_metadata_or_draft()
 {
    let case = Case::new([false, true, false, false]).await;
    let id = Uuid::new_v4();
    let bytes = case.envelope(id, true).await;
    case.historical(id, &bytes).await;
    let before = case.effects().await;
    let response = case
        .call(
            "GET",
            &format!("/agent/messages/{id}/content"),
            vec![],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        super::super::SEALED_CONTENT_TYPE
    );
    assert_eq!(
        to_bytes(response.into_body(), 40_000)
            .await
            .unwrap()
            .as_ref(),
        bytes
    );
    assert_eq!(
        case.call("GET", &format!("/agent/messages/{id}"), vec![], None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        case.call(
            "POST",
            &format!("/agent/actions/{}/draft", Uuid::new_v4()),
            bytes.clone(),
            Some("1")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let missing = Uuid::new_v4();
    let envelope = case.envelope(missing, false).await;
    case.historical(missing, &envelope).await;
    assert_eq!(
        case.call(
            "GET",
            &format!("/agent/messages/{missing}/content"),
            vec![],
            None
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let (other_peer, _) = issue(
        &case.base,
        case.connector,
        case.reader,
        [false, true, false, false],
        "+13",
    )
    .await;
    let request = Request::builder()
        .uri(format!("/agent/messages/{id}/content"))
        .header("authorization", format!("Bearer {other_peer}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        case.router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    case.base
        .db
        .execute(
            "UPDATE connector_keys SET retired_ms=1 WHERE account_id=$1 AND key_id=$2",
            &[&case.base.account, &case.reader.as_slice()],
        )
        .await
        .unwrap();
    assert_eq!(
        case.call(
            "GET",
            &format!("/agent/messages/{id}/content"),
            vec![],
            None
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        case.effects().await,
        (before.0 + 1, before.1 + 1, before.2 + 1, before.3, before.4)
    );
    case.base.cleanup().await;
}

async fn issue(
    base: &TestCase,
    connector: Uuid,
    reader: [u8; 32],
    permissions: [bool; 4],
    peer: &str,
) -> (String, Uuid) {
    let key = Uuid::new_v4();
    let grant = Uuid::new_v4();
    let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(76)).unwrap();
    mac.update(b"api-key-v1\0");
    mac.update(token.as_bytes());
    let hash = mac.finalize().into_bytes();
    let now: i64 = base
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    base.db.execute("INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id,expires_at) VALUES($1,$2,$3,$4,$5,ARRAY['messages:send','messages:read'],$6,to_timestamp($7::bigint::double precision/1000))",&[&key,&base.account,&base.user,&&token[4..16],&hash.as_slice(),&base.device,&(now+100_000)]).await.unwrap();
    let recipient = base.hasher.agent_recipient_digest(base.account, peer);
    base.db.execute("INSERT INTO agent_authority_grants(account_id,grant_id,api_key_id,connector_id,connector_key_id,signer_key_id,device_id,line_id,binding_generation,recipient_digest,metadata_allowed,content_allowed,draft_allowed,send_allowed,reader_identity,owner_self_notification,created_by_user,created_session,created_ms,expires_ms,message_limit,turn_limit) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$10,$11,$12,$13,$4,true,$14,$15,$16,$17,3,3)",&[&base.account,&grant,&key,&connector,&reader.as_slice(),&base.signer.as_slice(),&base.device,&base.line,&recipient.as_slice(),&permissions[0],&permissions[1],&permissions[2],&permissions[3],&base.user,&Uuid::new_v4(),&now,&(now+100_000)]).await.unwrap();
    (token, grant)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated signed fixture"]
async fn draft_expiry_is_rechecked_after_the_final_identity_query_stalls() {
    let case = Case::new([false, false, true, false]).await;
    let principal = agent_grants::authenticate_agent(&case.base.db, &case.base.hasher, &case.token)
        .await
        .unwrap();
    let mut bytes = case.envelope(Uuid::new_v4(), false).await;
    let now: i64 = case
        .base
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    bytes[146..154].copy_from_slice(&(now as u64).to_be_bytes());
    bytes[154..162].copy_from_slice(&((now + 5000) as u64).to_be_bytes());
    sign(&case.base, &mut bytes);
    // Retain the actual constrained table and its FKs. A test-only view injects
    // a storage stall into the second identity lookup, after initial crypto
    // validation; it never changes or bypasses an authority guard.
    case.base.db.batch_execute("ALTER TABLE api_keys RENAME TO draft_test_api_keys; CREATE SEQUENCE draft_identity_reads; CREATE FUNCTION draft_identity_delay() RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$ BEGIN IF nextval('draft_identity_reads')=2 THEN PERFORM pg_sleep(6); END IF; RETURN true; END; $$; CREATE VIEW api_keys AS SELECT * FROM draft_test_api_keys WHERE draft_identity_delay()").await.unwrap();
    let mut db = case.base.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(matches!(
        store::validate_agent_draft(
            &tx,
            &case.base.hasher,
            &principal,
            Uuid::new_v4(),
            &bytes,
            now
        )
        .await,
        Err(store::StoreError::Denied)
    ));
    tx.rollback().await.unwrap();
    let reads: i64 = case
        .base
        .db
        .query_one("SELECT last_value FROM draft_identity_reads", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        reads, 2,
        "the regression must reach the delayed final identity check"
    );
    assert_eq!(case.effects().await, (0, 0, 0, 0, 0));
    case.base.cleanup().await;
}
