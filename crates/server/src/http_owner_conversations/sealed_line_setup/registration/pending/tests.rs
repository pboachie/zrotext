// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::{self, mfa},
    http_owner_conversations::{OwnerConversationsState, sealed_line_setup::SetupState},
    sealed_manifest_store::tests::Fixture,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use std::sync::Arc;

const ORIGIN: &str = "https://owner.example.test";

struct Owner {
    f: Fixture,
    principal: SessionPrincipal,
    hasher: Arc<TokenHasher>,
    cipher: Arc<mfa::MfaCipher>,
    root: SigningKey,
    pin: [u8; 94],
    token: String,
    csrf: String,
    email: String,
    password: String,
    recovery: Vec<String>,
}
struct Case {
    owner: Owner,
    device: Uuid,
    line: Uuid,
    paired: SigningKey,
    approval: SigningKey,
}
impl Case {
    async fn new() -> Self {
        let f = Fixture::without_authority().await;
        // Canonical auth prerequisites precede genuine enrollment. No session,
        // MFA secret or recovery-factor row is manufactured by this fixture.
        for sql in [
            include_str!(
                "../../../../../../../deploy/compose/migrations/053_observer_seat_invitations.sql"
            ),
            include_str!(
                "../../../../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"
            ),
            include_str!(
                "../../../../../../../deploy/compose/migrations/086_sealed_line_key_registration.sql"
            ),
            include_str!(
                "../../../../../../../deploy/compose/migrations/087_sealed_line_activation_exchanges.sql"
            ),
        ] {
            f.db.batch_execute(sql).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(93)).unwrap());
        let cipher = Arc::new(mfa::MfaCipher::new(crate::test_keys::key(92)).unwrap());
        let email = format!("pending-owner-{}@example.test", Uuid::new_v4());
        let password = Uuid::new_v4().to_string();
        let mut db = f.connect().await;
        let signup = auth::register(&mut db, &hasher, &email, &password)
            .await
            .unwrap();
        assert!(
            auth::verify_email_with_password(
                &mut db,
                &hasher,
                &signup.verification_token,
                &password
            )
            .await
            .unwrap()
        );
        let credentials = auth::login(&db, &hasher, &email, &password)
            .await
            .unwrap();
        let principal = auth::authenticate_session(&db, &hasher, &credentials.token)
            .await
            .unwrap();
        let enrollment = mfa::begin_enrollment(&mut db, &cipher, &principal, &password)
            .await
            .unwrap();
        let code = totp_rs::Builder::new()
            .with_secret(totp_rs::Secret::try_from_base32(&enrollment.secret_base32).unwrap())
            .build()
            .unwrap()
            .generate_current()
            .to_string();
        let recovery = mfa::confirm_enrollment(&mut db, &cipher, &hasher, &principal, &code)
            .await
            .unwrap()
            .codes;
        let principal = auth::authenticate_session(&db, &hasher, &credentials.token)
            .await
            .unwrap();
        let account = principal.tenant.account_id();
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let pin: [u8; 94] = [
            b"ZTRP\x02".as_slice(),
            account.as_bytes(),
            &1u64.to_be_bytes(),
            root.verifying_key().to_sec1_point(false).as_bytes(),
        ]
        .concat()
        .try_into()
        .unwrap();
        let fingerprint = zrotext_root_material::sealed_root_enrollment::root_fingerprint(
            &pin,
            account.as_bytes(),
        )
        .unwrap();
        // Synthetic extant independently pinned root and enrolled phone, not
        // a claim that this fixture performs production genesis or pairing.
        db.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)", &[&account, &pin.as_slice(), &fingerprint.as_slice(), &vec![0u8;32]]).await.unwrap();
        let device = Uuid::new_v4();
        let line = Uuid::new_v4();
        let paired = SigningKey::generate_from_rng(&mut rand::rng());
        let approval = SigningKey::generate_from_rng(&mut rand::rng());
        let point = paired
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let fp = Sha256::digest(&point).to_vec();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
            &[&device, &account],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device,&account,&point,&fp]).await.unwrap();
        db.execute("INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,deployment_epoch,lease_until) VALUES($1,$2,'manifest-test','fixture',1,1,clock_timestamp()+interval '10 minutes')", &[&device,&account]).await.unwrap();
        Self {
            owner: Owner {
                f,
                principal,
                hasher,
                cipher,
                root,
                pin,
                token: credentials.token,
                csrf: credentials.csrf_token,
                email,
                password,
                recovery,
            },
            device,
            line,
            paired,
            approval,
        }
    }
    async fn issue(&self, generation: i64) -> Statement {
        super::super::issue(
            &mut self.owner.f.connect().await,
            &self.owner.principal,
            ORIGIN,
            super::super::Selection {
                device: self.device,
                line: self.line,
                generation,
                root_fingerprint: zrotext_root_material::sealed_root_enrollment::root_fingerprint(
                    &self.owner.pin,
                    self.owner.principal.tenant.account_id().as_bytes(),
                )
                .unwrap(),
                paired_fingerprint: Sha256::digest(
                    self.paired.verifying_key().to_sec1_point(false).as_bytes(),
                )
                .into(),
                approval_point: self
                    .approval
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                connection_epoch: 1,
                deployment_epoch: 1,
                site_id: "manifest-test".into(),
                instance_id: "fixture".into(),
            },
        )
        .await
        .unwrap()
    }
    async fn successor(&self) -> (auth::SessionCredentials, SessionPrincipal) {
        let mut db = self.owner.f.connect().await;
        assert!(matches!(
            auth::login(&db, &self.owner.hasher, &self.owner.email, &self.owner.password).await,
            Err(auth::AuthError::MfaRequired { .. })
        ));
        let p = &self.owner.principal;
        let challenge = mfa::begin_login_challenge(
            &db,
            &self.owner.hasher,
            p.tenant.account_id(),
            p.user_id,
            &self.owner.password,
        )
        .await
        .unwrap();
        let credentials = mfa::complete_login(
            &mut db,
            Some(&self.owner.cipher),
            &self.owner.hasher,
            &challenge,
            &self.owner.recovery[1],
        )
        .await
        .unwrap();
        let principal = auth::authenticate_session(&db, &self.owner.hasher, &credentials.token)
            .await
            .unwrap();
        assert_eq!(principal.tenant.account_id(), p.tenant.account_id());
        assert_eq!(principal.user_id, p.user_id);
        assert_ne!(principal.session_id, p.session_id);
        (credentials, principal)
    }
    fn signatures(&self, statement: &Statement) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let bytes = codec::encode(statement).unwrap();
        let root: Signature = self.owner.root.sign(&bytes);
        let approval: Signature = self.approval.sign(&bytes);
        (
            bytes,
            root.normalize_s().to_bytes().to_vec(),
            approval.normalize_s().to_bytes().to_vec(),
        )
    }
    fn state(&self) -> SetupState {
        let sep = if self.owner.f.url.contains('?') {
            '&'
        } else {
            '?'
        };
        SetupState {
            owner: OwnerConversationsState {
                database_url: format!(
                    "{}{sep}options=-csearch_path%3D{}",
                    self.owner.f.url, self.owner.f.schema
                ),
                auth_hasher: self.owner.hasher.clone(),
                canonical_origin: ORIGIN.into(),
            },
            mfa_cipher: self.owner.cipher.clone(),
        }
    }
    async fn cleanup(self) {
        self.owner.f.cleanup().await;
    }
}

fn keys(value: &serde_json::Value, expected: &[&str]) {
    use std::collections::BTreeSet;
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected.iter().copied().collect()
    );
}
fn envelope(value: &serde_json::Value, c: &Case, statement: &Statement) {
    keys(
        value,
        &[
            "v",
            "kind",
            "account_id",
            "user_id",
            "session_id",
            "origin",
            "root_fingerprint_hex",
            "proposal_sha256_hex",
            "proposal_b64",
            "expected_context",
            "server_now_ms",
            "expires_ms",
        ],
    );
    assert_eq!(value["v"].as_u64(), Some(1));
    assert_eq!(value["kind"].as_u64(), Some(1));
    for name in [
        "account_id",
        "user_id",
        "session_id",
        "origin",
        "root_fingerprint_hex",
        "proposal_sha256_hex",
        "proposal_b64",
        "server_now_ms",
        "expires_ms",
    ] {
        assert!(value[name].is_string(), "{name} must be a string");
    }
    assert_eq!(
        value["account_id"],
        c.owner.principal.tenant.account_id().to_string()
    );
    assert_eq!(value["user_id"], c.owner.principal.user_id.to_string());
    assert_eq!(
        value["session_id"],
        c.owner.principal.session_id.to_string()
    );
    assert_eq!(value["origin"], ORIGIN);
    assert_eq!(
        value["root_fingerprint_hex"],
        hex(statement.root_fingerprint())
    );
    let bytes = codec::encode(statement).unwrap();
    assert_eq!(
        STANDARD
            .decode(value["proposal_b64"].as_str().unwrap())
            .unwrap(),
        bytes
    );
    assert_eq!(value["proposal_sha256_hex"], hex(&Sha256::digest(&bytes)));
    keys(&value["expected_context"], &["root_pin", "scope"]);
    assert_eq!(value["expected_context"]["root_pin"], hex(&c.owner.pin));
    let s = statement.scope();
    let account = c.owner.principal.tenant.account_id();
    let scope = &value["expected_context"]["scope"];
    keys(
        scope,
        &[
            "account",
            "user",
            "owner_session",
            "device",
            "line",
            "next_generation",
            "challenge",
            "nonce",
            "issued_ms",
            "expires_ms",
            "approval_fingerprint",
            "paired_signing_fingerprint",
            "connection_epoch",
            "deployment_epoch",
            "site_id",
            "instance_id",
            "origin",
        ],
    );
    for (name, bytes) in [
        ("account", account.as_bytes().as_slice()),
        ("user", c.owner.principal.user_id.as_bytes()),
        ("owner_session", c.owner.principal.session_id.as_bytes()),
        ("device", c.device.as_bytes()),
        ("line", c.line.as_bytes()),
        ("challenge", s.challenge.as_slice()),
        ("nonce", s.nonce.as_slice()),
        ("approval_fingerprint", s.approval_fingerprint.as_slice()),
        (
            "paired_signing_fingerprint",
            s.paired_signing_fingerprint.as_slice(),
        ),
    ] {
        assert_eq!(scope[name], hex(bytes));
    }
    for (name, number) in [
        ("next_generation", 1),
        ("issued_ms", s.issued_ms),
        ("expires_ms", s.expires_ms),
        ("connection_epoch", 1),
        ("deployment_epoch", 1),
    ] {
        assert_eq!(scope[name].as_u64(), Some(number));
    }
    assert_eq!(scope["site_id"], "manifest-test");
    assert_eq!(scope["instance_id"], "fixture");
    assert_eq!(scope["origin"], ORIGIN);
    let now: u64 = value["server_now_ms"].as_str().unwrap().parse().unwrap();
    assert_eq!(value["server_now_ms"], now.to_string());
    assert!(s.issued_ms <= now && now < s.expires_ms);
    assert_eq!(value["expires_ms"], s.expires_ms.to_string());
}
async fn stored(c: &Case) -> (Uuid, Vec<u8>, i64, i64, Option<i64>) {
    let row = c.owner.f.db.query_one("SELECT challenge_id,transcript,issued_ms,expires_ms,completed_ms FROM sealed_line_key_challenges WHERE account_id=$1", &[&c.owner.principal.tenant.account_id()]).await.unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable pending line context"]
async fn pending_context_returns_original_bytes_and_fences_changed_or_consumed_authority() {
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let id = Uuid::from_bytes(statement.scope().challenge);
    let original = stored(&c).await;
    let value = context(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        id,
        ORIGIN,
    )
    .await
    .unwrap()
    .unwrap();
    envelope(&value, &c, &statement);
    assert_eq!(stored(&c).await, original);
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            Uuid::nil(),
            ORIGIN
        )
        .await
        .is_err()
    );
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            Uuid::new_v4(),
            ORIGIN
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(stored(&c).await, original);
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            "https://other.example.test"
        )
        .await
        .is_err()
    );
    let sid = c.owner.principal.session_id;
    let mut changed = c.owner.principal.clone();
    changed.session_id = Uuid::new_v4();
    assert!(
        context(&mut c.owner.f.connect().await, &changed, id, ORIGIN)
            .await
            .is_err()
    );
    assert_eq!(c.owner.principal.session_id, sid);
    c.owner.f.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second' WHERE device_id=$1",&[&c.device]).await.unwrap();
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            ORIGIN
        )
        .await
        .is_err()
    );
    c.owner.f.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()+interval '10 minutes' WHERE device_id=$1",&[&c.device]).await.unwrap();
    c.owner
        .f
        .db
        .execute(
            "UPDATE sealed_line_key_challenges SET expires_ms=issued_ms+1 WHERE challenge_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            ORIGIN
        )
        .await
        .is_err()
    );
    c.owner
        .f
        .db
        .execute(
            "UPDATE sealed_line_key_challenges SET expires_ms=$2 WHERE challenge_id=$1",
            &[&id, &(statement.scope().expires_ms as i64)],
        )
        .await
        .unwrap();
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            ORIGIN
        )
        .await
        .unwrap()
        .is_some()
    );
    c.owner
        .f
        .db
        .execute(
            "UPDATE sealed_line_key_challenges SET completed_ms=issued_ms WHERE challenge_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            ORIGIN
        )
        .await
        .unwrap()
        .is_none()
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable pending line context"]
async fn pending_context_rejects_coherent_expired_transcript_and_changed_phone_epoch_or_key() {
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let id = Uuid::from_bytes(statement.scope().challenge);
    c.owner
        .f
        .db
        .execute(
            "UPDATE device_sessions SET connection_epoch=connection_epoch+1 WHERE device_id=$1",
            &[&c.device],
        )
        .await
        .unwrap();
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            ORIGIN
        )
        .await
        .is_err()
    );
    c.owner
        .f
        .db
        .execute(
            "UPDATE device_sessions SET connection_epoch=connection_epoch-1 WHERE device_id=$1",
            &[&c.device],
        )
        .await
        .unwrap();
    let key = c
        .owner
        .f
        .db
        .query_one(
            "SELECT fingerprint FROM device_keys WHERE device_id=$1",
            &[&c.device],
        )
        .await
        .unwrap()
        .get::<_, Vec<u8>>(0);
    c.owner
        .f
        .db
        .execute(
            "UPDATE device_keys SET fingerprint=$2 WHERE device_id=$1",
            &[&c.device, &vec![77u8; 32]],
        )
        .await
        .unwrap();
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            ORIGIN
        )
        .await
        .is_err()
    );
    c.owner
        .f
        .db
        .execute(
            "UPDATE device_keys SET fingerprint=$2 WHERE device_id=$1",
            &[&c.device, &key],
        )
        .await
        .unwrap();
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            ORIGIN
        )
        .await
        .unwrap()
        .is_some()
    );
    // Persist a codec-valid transcript and matching row whose deadline is truly past.
    let mut scope = statement.scope().clone();
    let utc: i64 = c
        .owner
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    scope.issued_ms = (utc - 2000) as u64;
    scope.expires_ms = (utc - 1000) as u64;
    let expired = Statement::new(
        scope,
        *statement.root_pin(),
        *statement.root_fingerprint(),
        *statement.approval_point(),
    )
    .unwrap();
    let bytes = codec::encode(&expired).unwrap();
    c.owner.f.db.execute("UPDATE sealed_line_key_challenges SET transcript=$2,issued_ms=$3,expires_ms=$4 WHERE challenge_id=$1", &[&id,&bytes,&(expired.scope().issued_ms as i64),&(expired.scope().expires_ms as i64)]).await.unwrap();
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            ORIGIN
        )
        .await
        .is_err()
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable pending line context"]
async fn pending_context_cannot_transfer_original_proposal_to_valid_successor_session() {
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let id = Uuid::from_bytes(statement.scope().challenge);
    let (_, principal) = c.successor().await;
    assert!(
        context(&mut c.owner.f.connect().await, &principal, id, ORIGIN)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        context(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            id,
            ORIGIN
        )
        .await
        .unwrap()
        .is_some()
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable pending line HTTP status"]
async fn status_http_returns_pending_original_bytes_then_completed_receipt_without_pending() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let id = Uuid::from_bytes(statement.scope().challenge);
    let path = format!("/v1/owner/conversation/sealed-line/owner-key/{id}/status");
    let original = stored(&c).await;
    let request = |origin: &str, csrf: &str| {
        Request::post(&path)
            .header("origin", origin)
            .header("content-type", "application/json")
            .header(
                "cookie",
                format!(
                    "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                    c.owner.token, c.owner.csrf
                ),
            )
            .header("x-zrotext-csrf", csrf)
            .body(Body::from(
                serde_json::json!({"expected_session_id":c.owner.principal.session_id}).to_string(),
            ))
            .unwrap()
    };
    for (origin, csrf) in [
        ("https://other.example.test", c.owner.csrf.as_str()),
        (ORIGIN, "wrong"),
    ] {
        let response = crate::http_owner_conversations::sealed_line_setup::router(c.state())
            .oneshot(request(origin, csrf))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    for (body, status) in [
        (
            serde_json::json!({"expected_session_id":Uuid::new_v4()}),
            StatusCode::FORBIDDEN,
        ),
        (
            serde_json::json!({"expected_session_id":Uuid::nil()}),
            StatusCode::FORBIDDEN,
        ),
        (
            serde_json::json!({"expected_session_id":c.owner.principal.session_id,"account_id":c.owner.principal.tenant.account_id()}),
            StatusCode::BAD_REQUEST,
        ),
        (
            serde_json::json!({"expected_session_id":null}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut req = request(ORIGIN, &c.owner.csrf);
        *req.body_mut() = Body::from(body.to_string());
        let response = crate::http_owner_conversations::sealed_line_setup::router(c.state())
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap())
                .unwrap_or(serde_json::Value::Null);
        assert!(value.get("pending").is_none());
        assert_eq!(stored(&c).await, original);
    }
    let response = crate::http_owner_conversations::sealed_line_setup::router(c.state())
        .oneshot(request(ORIGIN, &c.owner.csrf))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    keys(&value, &["receipt", "pending"]);
    assert!(value["receipt"].is_null());
    envelope(&value["pending"], &c, &statement);
    assert_eq!(stored(&c).await, original);
    assert_eq!(
        value["pending"]["proposal_b64"],
        STANDARD.encode(codec::encode(&statement).unwrap())
    );
    // A genuine current successor cookie cannot inherit original-session proposal authority.
    let (credentials, principal) = c.successor().await;
    let response = crate::http_owner_conversations::sealed_line_setup::router(c.state())
        .oneshot(
            Request::post(&path)
                .header("origin", ORIGIN)
                .header("content-type", "application/json")
                .header(
                    "cookie",
                    format!(
                        "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                        credentials.token, credentials.csrf_token
                    ),
                )
                .header("x-zrotext-csrf", &credentials.csrf_token)
                .body(Body::from(
                    serde_json::json!({"expected_session_id":principal.session_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    keys(&value, &["receipt", "pending"]);
    assert!(value["receipt"].is_null());
    assert!(value["pending"].is_null());
    assert_eq!(stored(&c).await, original);
    let (bytes, root, approval) = c.signatures(&statement);
    let factor = &c.owner.recovery[0];
    super::super::complete(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        ORIGIN,
        &c.owner.hasher,
        &c.owner.cipher,
        id,
        super::super::Completion {
            unsigned: &bytes,
            root_signature: &root,
            approval_signature: &approval,
            factor,
        },
    )
    .await
    .unwrap();
    let response = crate::http_owner_conversations::sealed_line_setup::router(c.state())
        .oneshot(request(ORIGIN, &c.owner.csrf))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    keys(&value, &["receipt", "pending"]);
    assert_eq!(value["receipt"]["registration_id"], id.to_string());
    assert_eq!(
        value["receipt"]["unsigned_statement"],
        STANDARD.encode(&bytes)
    );
    assert!(value["pending"].is_null());
    assert!(stored(&c).await.4.is_some());
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable pending line revocation"]
async fn pending_context_refuses_revoked_original_session_or_root() {
    for sql in [
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",
    ] {
        let c = Case::new().await;
        let statement = c.issue(1).await;
        let id = Uuid::from_bytes(statement.scope().challenge);
        let original = stored(&c).await;
        let target = if sql.starts_with("UPDATE sessions") {
            c.owner.principal.session_id
        } else {
            c.owner.principal.tenant.account_id()
        };
        assert_eq!(c.owner.f.db.execute(sql, &[&target]).await.unwrap(), 1);
        assert!(
            context(
                &mut c.owner.f.connect().await,
                &c.owner.principal,
                id,
                ORIGIN
            )
            .await
            .is_err()
        );
        assert_eq!(stored(&c).await, original);
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable pending line lock wait"]
async fn pending_context_refuses_phone_lease_lost_during_observed_database_wait() {
    use std::time::Duration;
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let id = Uuid::from_bytes(statement.scope().challenge);
    let original = stored(&c).await;
    let mut locker = c.owner.f.connect().await;
    let tx = locker.transaction().await.unwrap();
    tx.query_one(
        "SELECT device_id FROM device_sessions WHERE device_id=$1 FOR UPDATE",
        &[&c.device],
    )
    .await
    .unwrap();
    {
        let mut blocked = c.owner.f.connect().await;
        let pid: i32 = blocked
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let pending = context(&mut blocked, &c.owner.principal, id, ORIGIN);
        tokio::pin!(pending);
        let barrier = async {
            loop {
                if c.owner
                    .f
                    .db
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)",
                        &[&pid],
                    )
                    .await
                    .unwrap()
                    .get::<_, bool>(0)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::select! {
            result = &mut pending => panic!("inspection ended before its observed database wait: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(2), barrier) => assert!(result.is_ok(), "inspection never reached the held phone row"),
        }
        // Actual authority loss while the operation is blocked, not a timing sleep
        // or an enlarged lease. PostgreSQL must recheck before publishing bytes.
        tx.execute("UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second' WHERE device_id=$1", &[&c.device]).await.unwrap();
        tx.commit().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut pending)
                .await
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(stored(&c).await, original);
    c.cleanup().await;
}
