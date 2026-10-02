// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{inbound::InboundSession, sealed_root_ceremony::tests::Owner};
use axum::{body::Body, http::Request};
use hmac::{Hmac, Mac, digest::KeyInit};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
pub(crate) const ORIGIN: &str = "https://owner.example.test";
pub(crate) struct Case {
    pub owner: Owner,
    pub device: Uuid,
    pub line: Uuid,
    pub paired: SigningKey,
    pub approval: SigningKey,
}
fn token_hash(domain: &[u8], text: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&crate::test_keys::key(93)).unwrap();
    mac.update(domain);
    mac.update(&[0]);
    mac.update(text.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
impl Case {
    pub(crate) async fn new() -> Self {
        Self::build(true).await
    }
    /// A fresh owner/paired-device fixture for the real root enrollment path.
    /// Never insert then erase authority: insertion also reserves its permanent
    /// enrollment ledger, and that history must remain protected.
    pub(crate) async fn without_root() -> Self {
        Self::build(false).await
    }
    async fn build(install_root: bool) -> Self {
        let mut owner = Owner::new().await;
        let account = owner.principal.tenant.account_id();
        let device = Uuid::new_v4();
        let line = Uuid::new_v4();
        let paired = SigningKey::generate_from_rng(&mut rand::rng());
        let approval = SigningKey::generate_from_rng(&mut rand::rng());
        owner
            .f
            .db
            .batch_execute(include_str!("registration.sql"))
            .await
            .unwrap();
        owner
            .f
            .db
            .batch_execute(include_str!("schema.sql"))
            .await
            .unwrap();
        // Synthetic existing independently pinned v0 authority and real paired role.
        let rootfp = zrotext_root_material::sealed_root_enrollment::root_fingerprint(
            &owner.pin,
            account.as_bytes(),
        )
        .unwrap();
        if install_root {
            owner.f.db.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)",&[&account,&owner.pin.as_slice(),&rootfp.as_slice(),&vec![0u8;32]]).await.unwrap();
        }
        owner
            .f
            .db
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
                &[&device, &account],
            )
            .await
            .unwrap();
        let point = paired
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let fp = Sha256::digest(&point).to_vec();
        owner.f.db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",&[&device,&account,&point,&fp]).await.unwrap();
        owner.f.db.execute("INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,deployment_epoch,lease_until) VALUES($1,$2,'manifest-test','fixture',1,1,clock_timestamp()+interval '10 minutes')",&[&device,&account]).await.unwrap();
        // Known fixture pepper supplies multiple independent one-use recovery factors.
        owner.hasher = TokenHasher::new(crate::test_keys::key(93)).unwrap();
        owner
            .f
            .db
            .execute(
                "UPDATE sessions SET token_hash=$2,csrf_hash=$3 WHERE id=$1",
                &[
                    &owner.principal.session_id,
                    &token_hash(b"session-v1", &owner.token),
                    &token_hash(b"csrf-v1", &owner.csrf),
                ],
            )
            .await
            .unwrap();
        owner.principal =
            crate::auth::authenticate_session(&owner.f.db, &owner.hasher, &owner.token)
                .await
                .unwrap();
        Self {
            owner,
            device,
            line,
            paired,
            approval,
        }
    }
    pub(crate) fn session(&self) -> InboundSession<'_> {
        InboundSession {
            account_id: self.owner.principal.tenant.account_id(),
            device_id: self.device,
            site_id: "manifest-test",
            instance_id: "fixture",
            connection_epoch: 1,
            deployment_epoch: 1,
        }
    }
    pub(crate) fn selection(&self, generation: i64) -> registration::Selection {
        registration::Selection {
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
        }
    }
    pub(crate) async fn issue(
        &self,
        generation: i64,
    ) -> zrotext_root_material::line_key_registration::Statement {
        registration::issue(
            &mut self.owner.f.connect().await,
            &self.owner.principal,
            ORIGIN,
            self.selection(generation),
        )
        .await
        .unwrap()
    }
    pub(crate) async fn factor(&self) -> String {
        let code = format!(
            "zrc_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
        );
        let p = &self.owner.principal;
        let hash = token_hash(
            b"mfa-recovery-v1",
            &format!("{}:{}:{code}", p.tenant.account_id(), p.user_id),
        );
        self.owner.f.db.execute("INSERT INTO owner_mfa_recovery_codes(account_id,user_id,code_hash) VALUES($1,$2,$3)",&[&p.tenant.account_id(),&p.user_id,&hash]).await.unwrap();
        code
    }
    pub(crate) fn signatures(
        &self,
        statement: &zrotext_root_material::line_key_registration::Statement,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let bytes = zrotext_root_material::line_key_registration::encode(statement).unwrap();
        let root: Signature = self.owner.root.sign(&bytes);
        let approval: Signature = self.approval.sign(&bytes);
        (
            bytes,
            root.normalize_s().to_bytes().to_vec(),
            approval.normalize_s().to_bytes().to_vec(),
        )
    }
    pub(crate) async fn register(&self, generation: i64) -> Uuid {
        let statement = self.issue(generation).await;
        let id = Uuid::from_bytes(statement.scope().challenge);
        let (bytes, root, approval) = self.signatures(&statement);
        let factor = self.factor().await;
        registration::complete(
            &mut self.owner.f.connect().await,
            &self.owner.principal,
            ORIGIN,
            &self.owner.hasher,
            &self.owner.cipher,
            id,
            registration::Completion {
                unsigned: &bytes,
                root_signature: &root,
                approval_signature: &approval,
                factor: &factor,
            },
        )
        .await
        .unwrap();
        id
    }
    pub(crate) async fn cleanup(self) {
        self.owner.f.cleanup().await
    }
    pub(crate) fn state(&self) -> SetupState {
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
                auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(93)).unwrap()),
                canonical_origin: ORIGIN.into(),
            },
            mfa_cipher: Arc::new(MfaCipher::new(crate::test_keys::key(92)).unwrap()),
        }
    }
}
#[test]
fn setup_bounds_canonical_fields_and_never_accepts_caller_account() {
    for v in ["01", "0", "-1", "9223372036854775808", "1 "] {
        assert!(number(v).is_err());
    }
    assert_eq!(number("1").unwrap(), 1);
    for v in ["YQ", "YR==", "YQ==\n", "YQ==="] {
        assert!(decode::<1>(v).is_err());
    }
    assert_eq!(decode::<1>("YQ==").unwrap(), [97]);
    assert!(serde_json::from_value::<Bootstrap>(serde_json::json!({"expected_session_id":Uuid::new_v4(),"device_id":Uuid::new_v4(),"line_id":Uuid::new_v4(),"account_id":Uuid::new_v4()})).is_err());
}
#[tokio::test]
async fn setup_routes_require_explicit_mount_and_authenticate_before_body() {
    let owner = OwnerConversationsState {
        database_url: "invalid".into(),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(93)).unwrap()),
        canonical_origin: ORIGIN.into(),
    };
    for path in [
        "/v1/owner/conversation/sealed-line/bootstrap",
        "/v1/owner/conversation/sealed-line/owner-key/challenge",
    ] {
        assert_eq!(
            super::super::owner_host::router(owner.clone())
                .oneshot(Request::post(path).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let app = router(SetupState {
            owner: owner.clone(),
            mfa_cipher: Arc::new(MfaCipher::new(crate::test_keys::key(92)).unwrap()),
        });
        let body = Body::from_stream(futures_util::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.oneshot(Request::post(path).body(body).unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn setup_csrf_and_origin_fail_before_body_without_persistent_writes() {
    let c = Case::new().await;
    for (origin, csrf) in [
        ("https://other.example", c.owner.csrf.as_str()),
        (ORIGIN, "ztc_wrong"),
    ] {
        let body = Body::from_stream(futures_util::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            router(c.state()).oneshot(
                Request::post("/v1/owner/conversation/sealed-line/owner-key/challenge")
                    .header("origin", origin)
                    .header(
                        "cookie",
                        format!(
                            "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                            c.owner.token, c.owner.csrf
                        ),
                    )
                    .header("x-zrotext-csrf", csrf)
                    .body(body)
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(
        c.owner
            .f
            .db
            .query_one("SELECT count(*) FROM sealed_line_key_challenges", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn registration_requires_root_and_new_key_possession_exact_session_and_one_use_factor() {
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let id = Uuid::from_bytes(statement.scope().challenge);
    let (bytes, root, approval) = c.signatures(&statement);
    let factor = c.factor().await;
    for which in 0..4 {
        let mut r = root.clone();
        let mut a = approval.clone();
        let mut p = c.owner.principal.clone();
        if which == 0 {
            r[0] ^= 1;
        }
        if which == 1 {
            a[0] ^= 1;
        }
        if which == 2 {
            p.session_id = Uuid::new_v4();
        }
        if which == 3 {
            p.user_id = Uuid::new_v4();
        }
        assert!(
            registration::complete(
                &mut c.owner.f.connect().await,
                &p,
                ORIGIN,
                &c.owner.hasher,
                &c.owner.cipher,
                id,
                registration::Completion {
                    unsigned: &bytes,
                    root_signature: &r,
                    approval_signature: &a,
                    factor: &factor
                }
            )
            .await
            .is_err()
        );
    }
    registration::complete(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        ORIGIN,
        &c.owner.hasher,
        &c.owner.cipher,
        id,
        registration::Completion {
            unsigned: &bytes,
            root_signature: &root,
            approval_signature: &approval,
            factor: &factor,
        },
    )
    .await
    .unwrap();
    assert!(
        registration::complete(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            ORIGIN,
            &c.owner.hasher,
            &c.owner.cipher,
            id,
            registration::Completion {
                unsigned: &bytes,
                root_signature: &root,
                approval_signature: &approval,
                factor: &factor
            }
        )
        .await
        .is_err()
    );
    let receipt = registration::receipt(&mut c.owner.f.connect().await, &c.owner.principal, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt["unsigned_statement"], B.encode(bytes));
    assert!(receipt["assigned_challenge_id"].is_null());
    assert_eq!(
        c.owner
            .f
            .db
            .query_one(
                "SELECT count(*) FROM line_owner_approval_keys WHERE account_id=$1",
                &[&c.owner.principal.tenant.account_id()]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn registration_rejects_same_device_uuid_changed_key_and_removed_owner_membership() {
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let id = Uuid::from_bytes(statement.scope().challenge);
    let (bytes, root, approval) = c.signatures(&statement);
    let factor = c.factor().await;
    let replacement = SigningKey::generate_from_rng(&mut rand::rng());
    let point = replacement
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    c.owner
        .f
        .db
        .execute(
            "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
            &[&c.device, &point, &Sha256::digest(&point).to_vec()],
        )
        .await
        .unwrap();
    assert!(
        registration::complete(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            ORIGIN,
            &c.owner.hasher,
            &c.owner.cipher,
            id,
            registration::Completion {
                unsigned: &bytes,
                root_signature: &root,
                approval_signature: &approval,
                factor: &factor
            }
        )
        .await
        .is_err()
    );
    c.owner
        .f
        .db
        .execute(
            "DELETE FROM memberships WHERE account_id=$1",
            &[&c.owner.principal.tenant.account_id()],
        )
        .await
        .unwrap();
    assert!(
        registration::bootstrap(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            c.device,
            c.line
        )
        .await
        .is_err()
    );
    assert_eq!(
        c.owner
            .f
            .db
            .query_one("SELECT count(*) FROM sealed_line_key_receipts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn registration_rechecks_owner_expiry_after_root_lock_wait_and_creates_no_key() {
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let id = Uuid::from_bytes(statement.scope().challenge);
    let (bytes, root, approval) = c.signatures(&statement);
    let factor = c.factor().await;
    c.owner.f.db.execute("UPDATE sessions SET expires_at=clock_timestamp()+interval '150 milliseconds' WHERE id=$1",&[&c.owner.principal.session_id]).await.unwrap();
    let mut blocker = c.owner.f.connect().await;
    let held = blocker.transaction().await.unwrap();
    held.query_one(
        "SELECT root_pin FROM sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
        &[&c.owner.principal.tenant.account_id()],
    )
    .await
    .unwrap();
    let mut db = c.owner.f.connect().await;
    let p = c.owner.principal.clone();
    let hasher = TokenHasher::new(crate::test_keys::key(93)).unwrap();
    {
        let cipher = &c.owner.cipher;
        let pending = registration::complete(
            &mut db,
            &p,
            ORIGIN,
            &hasher,
            cipher,
            id,
            registration::Completion {
                unsigned: &bytes,
                root_signature: &root,
                approval_signature: &approval,
                factor: &factor,
            },
        );
        tokio::pin!(pending);
        tokio::select! {result=&mut pending=>panic!("completion ended before lock release: {result:?}"),_=tokio::time::sleep(std::time::Duration::from_millis(220))=>{}}
        held.commit().await.unwrap();
        assert!(pending.await.is_err());
    }
    assert_eq!(
        c.owner
            .f
            .db
            .query_one("SELECT count(*) FROM sealed_line_key_receipts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    drop(blocker);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn registration_rejects_wrong_comparison_alias_scope_and_frozen_lease_without_writes() {
    let c = Case::new().await;
    for which in 0..6 {
        let mut selection = c.selection(1);
        match which {
            0 => selection.root_fingerprint[0] ^= 1,
            1 => selection.paired_fingerprint[0] ^= 1,
            2 => selection.generation = 2,
            3 => selection.connection_epoch = 2,
            4 => {
                selection.approval_point = c
                    .paired
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap()
            }
            _ => {
                selection.approval_point = c
                    .owner
                    .root
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap()
            }
        }
        assert!(
            registration::issue(
                &mut c.owner.f.connect().await,
                &c.owner.principal,
                ORIGIN,
                selection
            )
            .await
            .is_err()
        );
    }
    assert_eq!(
        c.owner
            .f
            .db
            .query_one("SELECT count(*) FROM sealed_line_key_challenges", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.owner
            .f
            .db
            .query_one(
                "SELECT count(*) FROM phone_lines WHERE account_id=$1",
                &[&c.owner.principal.tenant.account_id()]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    // An independently trusted, unscoped live key must survive both issue and completion.
    let pending = c.issue(1).await;
    let unrelated = SigningKey::generate_from_rng(&mut rand::rng());
    let point = unrelated
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    let fingerprint: [u8; 32] = Sha256::digest(&point).into();
    c.owner.f.db.execute("INSERT INTO line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) VALUES($1,$2,$3)", &[&c.owner.principal.tenant.account_id(), &fingerprint.as_slice(), &point]).await.unwrap();
    let (bytes, root, approval) = c.signatures(&pending);
    let factor = c.factor().await;
    assert!(
        registration::complete(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            ORIGIN,
            &c.owner.hasher,
            &c.owner.cipher,
            Uuid::from_bytes(pending.scope().challenge),
            registration::Completion {
                unsigned: &bytes,
                root_signature: &root,
                approval_signature: &approval,
                factor: &factor
            }
        )
        .await
        .is_err()
    );
    assert!(
        registration::issue(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            ORIGIN,
            c.selection(1)
        )
        .await
        .is_err()
    );
    let retained=c.owner.f.db.query_one("SELECT revoked_at IS NULL FROM line_owner_approval_keys WHERE account_id=$1 AND fingerprint=$2", &[&c.owner.principal.tenant.account_id(), &fingerprint.as_slice()]).await.unwrap();
    assert!(retained.get::<_, bool>(0));
    assert_eq!(
        c.owner
            .f
            .db
            .query_one("SELECT count(*) FROM sealed_line_key_receipts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn registration_retry_history_is_bounded_and_replaced_keys_remain_tombstones() {
    let mut c = Case::new().await;
    for _ in 0..16 {
        c.approval = SigningKey::generate_from_rng(&mut rand::rng());
        c.register(1).await;
    }
    c.approval = SigningKey::generate_from_rng(&mut rand::rng());
    assert!(
        registration::issue(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            ORIGIN,
            c.selection(1)
        )
        .await
        .is_err()
    );
    let r=c.owner.f.db.query_one("SELECT count(*),count(*) FILTER(WHERE retired_ms IS NULL) FROM sealed_line_key_receipts",&[]).await.unwrap();
    assert_eq!(r.get::<_, i64>(0), 16);
    assert_eq!(r.get::<_, i64>(1), 1);
    let keys=c.owner.f.db.query_one("SELECT count(*),count(*) FILTER(WHERE revoked_at IS NULL) FROM line_owner_approval_keys WHERE account_id=$1",&[&c.owner.principal.tenant.account_id()]).await.unwrap();
    assert_eq!(keys.get::<_, i64>(0), 16);
    assert_eq!(keys.get::<_, i64>(1), 1);
    assert_eq!(
        c.owner
            .f
            .db
            .query_one("SELECT count(*) FROM sealed_line_key_challenges", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    c.cleanup().await;
}

#[tokio::test]
async fn setup_retention_drains_before_any_database_work() {
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    let draining = Arc::new(AtomicBool::new(true));
    let notify = Arc::new(tokio::sync::Notify::new());
    tokio::time::timeout(
        Duration::from_millis(100),
        Retention::new("invalid".into()).run(draining, notify),
    )
    .await
    .unwrap();
    let draining = Arc::new(AtomicBool::new(false));
    let notify = Arc::new(tokio::sync::Notify::new());
    let task = tokio::spawn(Retention::new("invalid".into()).run(draining.clone(), notify.clone()));
    tokio::task::yield_now().await;
    draining.store(true, Ordering::Release);
    notify.notify_waiters();
    tokio::time::timeout(Duration::from_millis(100), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn setup_startup_schema_rejects_absent_guard_constraint_and_partial_install() {
    let c = Case::new().await;
    lifecycle::require_installed(&c.owner.f.db).await.unwrap();
    c.owner.f.db.batch_execute("ALTER TABLE sealed_line_key_receipts DISABLE TRIGGER sealed_line_key_receipt_before_update").await.unwrap();
    assert!(lifecycle::require_installed(&c.owner.f.db).await.is_err());
    c.owner.f.db.batch_execute("ALTER TABLE sealed_line_key_receipts ENABLE TRIGGER sealed_line_key_receipt_before_update; ALTER TABLE sealed_line_key_challenges DROP CONSTRAINT sealed_line_key_challenges_generation_check").await.unwrap();
    assert!(lifecycle::require_installed(&c.owner.f.db).await.is_err());
    c.owner.f.db.batch_execute("ALTER TABLE sealed_line_key_challenges ADD CONSTRAINT sealed_line_key_challenges_generation_check CHECK(generation>0); ALTER TABLE sealed_line_activation_exchanges RENAME TO incomplete_exchange").await.unwrap();
    assert!(lifecycle::require_installed(&c.owner.f.db).await.is_err());
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn setup_cleanup_skips_locked_challenge_and_preserves_renewed_exact_identity() {
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let id = Uuid::from_bytes(statement.scope().challenge);
    // The challenge is public and not yet signed/consumed. Model an expired
    // row and a concurrently renewed user request under its real row lock.
    let old = statement.scope().issued_ms as i64 - 600000;
    c.owner.f.db.execute("UPDATE sealed_line_key_challenges SET issued_ms=$2,expires_ms=$3 WHERE challenge_id=$1", &[&id,&old,&(old+300000)]).await.unwrap();
    let mut renewing = c.owner.f.connect().await;
    let tx = renewing.transaction().await.unwrap();
    tx.query_one(
        "SELECT challenge_id FROM sealed_line_key_challenges WHERE challenge_id=$1 FOR UPDATE",
        &[&id],
    )
    .await
    .unwrap();
    assert_eq!(registration::cleanup(&c.owner.f.db, 1000).await.unwrap(), 0);
    let renewed = Uuid::new_v4();
    let now = statement.scope().issued_ms as i64;
    tx.execute("UPDATE sealed_line_key_challenges SET challenge_id=$2,issued_ms=$3,expires_ms=$4 WHERE challenge_id=$1", &[&id,&renewed,&now,&(now+300000)]).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(registration::cleanup(&c.owner.f.db, 100).await.unwrap(), 0);
    assert_eq!(
        c.owner
            .f
            .db
            .query_one("SELECT challenge_id FROM sealed_line_key_challenges", &[])
            .await
            .unwrap()
            .get::<_, Uuid>(0),
        renewed
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn setup_fresh_root_fixture_preserves_initialized_enrollment_history() {
    for initialized in [false, true] {
        let c = if initialized {
            Case::new().await
        } else {
            Case::without_root().await
        };
        let account = c.owner.principal.tenant.account_id();
        let row=c.owner.f.db.query_one("SELECT (SELECT count(*) FROM sealed_manifest_authorities WHERE account_id=$1),(SELECT count(*) FROM sealed_root_enrollments WHERE account_id=$1),(SELECT count(*) FROM known_signing_role_claims WHERE account_id=$1 AND role='sealed_root')", &[&account]).await.unwrap();
        let expected = i64::from(initialized);
        assert_eq!(row.get::<_, i64>(0), expected);
        assert_eq!(row.get::<_, i64>(1), expected);
        assert_eq!(row.get::<_, i64>(2), expected);
        assert_eq!(c.owner.f.db.query_one("SELECT count(*) FROM device_keys k JOIN device_sessions s USING(device_id,account_id) WHERE k.account_id=$1 AND k.device_id=$2 AND k.revoked_at IS NULL AND s.lease_until>clock_timestamp()", &[&account,&c.device]).await.unwrap().get::<_,i64>(0),1);
        assert_eq!(
            crate::auth::authenticate_session(&c.owner.f.db, &c.owner.hasher, &c.owner.token)
                .await
                .unwrap()
                .session_id,
            c.owner.principal.session_id
        );
        lifecycle::require_installed(&c.owner.f.db).await.unwrap();
        c.cleanup().await;
    }
}
