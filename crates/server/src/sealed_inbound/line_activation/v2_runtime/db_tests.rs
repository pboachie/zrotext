// SPDX-License-Identifier: AGPL-3.0-only
//! Real account/MFA/owner-key/device enrollment; isolated synthetic transport.
//! Cleanup runs only after a known completed control, never on panic/UNKNOWN.
use super::*;
use crate::{
    auth::{self, TokenHasher, mfa::MfaCipher},
    enrollment::{self, EnrollmentHasher},
    http_auth,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
    pkcs8::EncodePublicKey,
};
use std::sync::Arc;
use tower::ServiceExt;

fn unavailable<T>(result: Result<T>) -> bool {
    matches!(result, Err(LineActivationError::Unavailable))
}

pub(crate) const ORIGIN: &str = "https://owner.example.test";
pub(crate) struct SmsCase {
    pub db: Client,
    pub url: String,
    pub schema: String,
    pub hasher: Arc<TokenHasher>,
    pub cipher: Arc<MfaCipher>,
    pub principal: SessionPrincipal,
    pub credentials: auth::SessionCredentials,
    pub device: Uuid,
    pub line: Uuid,
    pub paired: SigningKey,
    pub approval: SigningKey,
}
impl SmsCase {
    pub(crate) async fn new() -> Self {
        let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
        let (db, connection) = tokio_postgres::connect(&raw, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.expect("fixture connection completion");
        });
        let schema = format!("manifest_authority_{}", Uuid::new_v4().simple());
        db.batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
        auth::test_schema::apply(&db).await;
        schema::require_installed(&db).await.unwrap();
        let sep = if raw.contains('?') { '&' } else { '?' };
        let url = format!("{raw}{sep}options=-csearch_path%3D{schema}");
        let mut db = db;
        let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
        let cipher = Arc::new(MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
        let password = format!("synthetic-owner-{}", Uuid::new_v4().simple());
        let email = "v2-owner@example.test";
        let signup = auth::register(&mut db, &hasher, email, &password)
            .await
            .unwrap();
        assert!(
            auth::verify_email(&mut db, &hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let credentials = auth::login(&db, &hasher, email, &password).await.unwrap();
        let principal = auth::authenticate_session(&db, &hasher, &credentials.token)
            .await
            .unwrap();
        let mfa = auth::mfa::begin_enrollment(&mut db, &cipher, &principal, &password)
            .await
            .unwrap();
        let code = totp_rs::Builder::new()
            .with_secret(totp_rs::Secret::try_from_base32(&mfa.secret_base32).unwrap())
            .build()
            .unwrap()
            .generate_current()
            .to_string();
        let recovery = auth::mfa::confirm_enrollment(&mut db, &cipher, &hasher, &principal, &code)
            .await
            .unwrap()
            .codes;
        // A real MFA-required login consumes a distinct recovery factor.
        assert!(matches!(
            auth::login(&db, &hasher, email, &password).await,
            Err(auth::AuthError::MfaRequired { .. })
        ));
        let login = auth::mfa::begin_login_challenge(
            &db,
            &hasher,
            signup.account_id,
            signup.user_id,
            &password,
        )
        .await
        .unwrap();
        let second =
            auth::mfa::complete_login(&mut db, Some(&cipher), &hasher, &login, &recovery[1])
                .await
                .unwrap();
        assert_ne!(second.id, credentials.id);
        assert!(
            auth::mfa::complete_login(&mut db, Some(&cipher), &hasher, &login, &recovery[1])
                .await
                .is_err()
        );
        let approval = SigningKey::generate_from_rng(&mut rand::rng());
        let paired = SigningKey::generate_from_rng(&mut rand::rng());
        let enrol = EnrollmentHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
        let ticket = enrollment::create_pairing(&db, &enrol, &principal, "synthetic v2 phone")
            .await
            .unwrap();
        let spki = paired.verifying_key().to_public_key_der().unwrap();
        let claim =
            enrollment::claim_pairing(&mut db, &enrol, ticket.id, &ticket.token, spki.as_bytes())
                .await
                .unwrap();
        let fp = digest(paired.verifying_key().to_sec1_point(false).as_bytes());
        let statement = enrollment::enrollment_challenge_bytes(
            signup.account_id,
            ticket.id,
            &fp,
            &claim.challenge_nonce,
        );
        let signature: Signature = paired.sign(&statement);
        assert!(
            enrollment::prove_pairing_key(
                &mut db,
                &enrol,
                ticket.id,
                &claim.challenge_nonce,
                signature.to_der().as_bytes()
            )
            .await
            .unwrap()
        );
        let device = enrollment::approve_pairing(
            &mut db,
            &principal,
            ticket.id,
            &claim.comparison_code,
            &claim.key_fingerprint,
        )
        .await
        .unwrap();
        let c = Self {
            db,
            url,
            schema,
            hasher,
            cipher,
            principal,
            credentials,
            device,
            line: Uuid::new_v4(),
            paired,
            approval,
        };
        let app = c.app();
        let point = c.approval.verifying_key().to_sec1_point(false);
        let response = app
            .clone()
            .oneshot(c.request(
                "POST",
                "/sms-line-owner-keys/challenge",
                serde_json::json!({"signing_key_sec1_b64":STANDARD.encode(point.as_bytes())}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        let id: Uuid = body["challenge_id"].as_str().unwrap().parse().unwrap();
        let nonce = STANDARD
            .decode(body["nonce_b64"].as_str().unwrap())
            .unwrap();
        let mut statement = b"ZTSMS/owner-key/register/v1\0".to_vec();
        for id in [signup.account_id, signup.user_id, c.credentials.id, id] {
            statement.extend_from_slice(id.as_bytes());
        }
        statement.extend_from_slice(&nonce);
        statement.extend_from_slice(&digest(point.as_bytes()));
        let signature: Signature = c.approval.sign(&statement);
        let response=app.oneshot(c.request("POST","/sms-line-owner-keys",serde_json::json!({"challenge_id":id,"nonce_b64":body["nonce_b64"],"signature_der_b64":STANDARD.encode(signature.to_der().as_bytes()),"mfa_code":recovery[0]}))).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        c.db.execute("INSERT INTO sites(site_id) VALUES('v2-test')", &[])
            .await
            .unwrap();
        c
    }
    pub(crate) fn app(&self) -> Router {
        http_auth::router(
            http_auth::AuthHttpState::new(
                self.url.clone(),
                self.hasher.clone(),
                ORIGIN.into(),
                Arc::new(http_auth::DisabledVerificationDispatcher),
            )
            .unwrap()
            .with_mfa_cipher(self.cipher.clone())
            .with_sms_line_activation_enabled(),
        )
    }
    pub(crate) fn request(
        &self,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("origin", ORIGIN)
            .header(
                "cookie",
                format!(
                    "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                    self.credentials.token, self.credentials.csrf_token
                ),
            )
            .header("x-zrotext-csrf", &self.credentials.csrf_token)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }
    pub(crate) async fn connect(&self) -> Client {
        let (db, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.expect("fixture connection completion");
        });
        db
    }
    /// Seeded lease isolates transaction controls. Socket controls claim it
    /// through the real authenticated handshake instead of calling this.
    pub(crate) async fn seed_lease(&self, version: i16) -> InboundSession<'_> {
        let row=self.db.query_one("INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,deployment_epoch,lease_until,line_activation_version) VALUES($1,$2,'v2-test','fixture',1,1,clock_timestamp()+interval '10 minutes',$3) ON CONFLICT(device_id) DO UPDATE SET connection_epoch=device_sessions.connection_epoch+1,line_activation_version=EXCLUDED.line_activation_version,lease_until=EXCLUDED.lease_until RETURNING connection_epoch",&[&self.device,&self.principal.tenant.account_id(),&version]).await.unwrap();
        self.session(row.get(0))
    }
    pub(crate) fn session(&self, epoch: i64) -> InboundSession<'_> {
        InboundSession {
            account_id: self.principal.tenant.account_id(),
            device_id: self.device,
            site_id: "v2-test",
            instance_id: "fixture",
            connection_epoch: epoch,
            deployment_epoch: 1,
        }
    }
    pub(crate) async fn cleanup(self) {
        crate::sealed_manifest_store::tests::cleanup::drop_fixture(&self.db, &self.schema)
            .await
            .expect("guarded completed fixture cleanup");
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; genuine auth and enrollment in isolated schema"]
async fn complete_set_sms_uses_real_keys_and_immutable_original_session() {
    let c = SmsCase::new().await;
    let mut db = c.connect().await;
    c.seed_lease(1).await;
    assert!(
        open(
            &mut db,
            &c.principal,
            c.line,
            c.device,
            Purpose::Sms,
            Uuid::new_v4(),
            None
        )
        .await
        .is_err()
    );
    let session = c.seed_lease(2).await;
    let opening = Uuid::new_v4();
    let challenge = open(
        &mut db,
        &c.principal,
        c.line,
        c.device,
        Purpose::Sms,
        opening,
        None,
    )
    .await
    .unwrap();
    let retry = open(
        &mut db,
        &c.principal,
        c.line,
        c.device,
        Purpose::Sms,
        opening,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            challenge.tuple.id,
            challenge.expires_at_ms,
            challenge.tuple.nonce
        ),
        (retry.tuple.id, retry.expires_at_ms, retry.tuple.nonce)
    );
    let observation = super::tests::observation(2, 2);
    let statement = v2::device_statement(PurposeV2::Sms, &challenge.tuple, &observation).unwrap();
    let signature: Signature = c.paired.sign(&statement.bytes());
    let der = signature.to_der();
    assert!(
        !record_device_proof(
            &mut db,
            session,
            Purpose::Sealed,
            challenge.tuple.id,
            &observation.encode(),
            der.as_bytes()
        )
        .await
        .unwrap()
    );
    assert!(
        record_device_proof(
            &mut db,
            session,
            Purpose::Sms,
            challenge.tuple.id,
            &observation.encode(),
            der.as_bytes()
        )
        .await
        .unwrap()
    );
    assert!(
        record_device_proof(
            &mut db,
            session,
            Purpose::Sms,
            challenge.tuple.id,
            &observation.encode(),
            der.as_bytes()
        )
        .await
        .unwrap()
    );
    let changed = super::tests::observation(1, 256);
    let bad = v2::device_statement(PurposeV2::Sms, &challenge.tuple, &changed).unwrap();
    let sig: Signature = c.paired.sign(&bad.bytes());
    assert!(
        !record_device_proof(
            &mut db,
            session,
            Purpose::Sms,
            challenge.tuple.id,
            &changed.encode(),
            sig.to_der().as_bytes()
        )
        .await
        .unwrap()
    );
    for sql in [
        "UPDATE line_activation_v2_observations SET observation=observation",
        "DELETE FROM line_activation_v2_observations",
        "UPDATE line_activation_v2_pending SET opening_id=gen_random_uuid()",
    ] {
        assert_eq!(
            c.db.batch_execute(sql).await.unwrap_err().code(),
            Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
        );
    }
    let view = view(
        &mut db,
        &c.principal,
        c.line,
        challenge.tuple.id,
        Purpose::Sms,
    )
    .await
    .unwrap();
    assert_eq!(view.status, "awaiting_owner");
    let approval: Signature = c.approval.sign(&view.owner_statement.unwrap());
    let mut stranger = c.principal.clone();
    stranger.session_id = Uuid::new_v4();
    assert!(
        approve(
            &mut db,
            &stranger,
            c.line,
            challenge.tuple.id,
            Purpose::Sms,
            approval.to_der().as_bytes()
        )
        .await
        .is_err()
    );
    approve(
        &mut db,
        &c.principal,
        c.line,
        challenge.tuple.id,
        Purpose::Sms,
        approval.to_der().as_bytes(),
    )
    .await
    .unwrap();
    let ack = next_ack(&mut db, session, Purpose::Sms, &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ack.device_statement_sha256, digest(&statement.bytes()));
    assert_eq!(ack.device_signature_sha256, digest(der.as_bytes()));
    approve(
        &mut db,
        &c.principal,
        c.line,
        challenge.tuple.id,
        Purpose::Sms,
        approval.to_der().as_bytes(),
    )
    .await
    .unwrap();
    assert!(
        next_ack(&mut db, session, Purpose::Sealed, &[])
            .await
            .unwrap()
            .is_none()
    );
    let next = c.seed_lease(1).await;
    assert!(current_ack(&mut db, next, ack).await.is_err());
    assert!(current_ack(&mut db, session, ack).await.is_err());
    let row=c.db.query_one("SELECT count(*) FROM pg_attribute WHERE attrelid='line_activation_v2_observations'::regclass AND attname IN ('nonce','device_statement','owner_statement') AND NOT attisdropped",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    drop(db);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; genuine auth and enrollment in isolated schema"]
async fn schema_and_same_epoch_version_changes_refuse_without_promotion() {
    let c = SmsCase::new().await;
    c.seed_lease(1).await;
    assert_eq!(
        c.db.execute(
            "UPDATE device_sessions SET line_activation_version=2 WHERE device_id=$1",
            &[&c.device]
        )
        .await
        .unwrap_err()
        .code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    assert_eq!(
        c.db.query_one(
            "SELECT line_activation_version FROM device_sessions WHERE device_id=$1",
            &[&c.device]
        )
        .await
        .unwrap()
        .get::<_, i16>(0),
        1
    );
    c.db.batch_execute("ALTER TABLE line_activation_v2_observations DISABLE TRIGGER line_activation_v2_observation_before_insert_or_update_or_delete").await.unwrap();
    assert!(schema::require_installed(&c.db).await.is_err());
    c.db.batch_execute("ALTER TABLE line_activation_v2_observations ENABLE TRIGGER line_activation_v2_observation_before_insert_or_update_or_delete").await.unwrap();
    schema::require_installed(&c.db).await.unwrap();
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; exact installed catalog mutations in isolated transactions"]
async fn schema_refuses_same_count_constraint_target_default_and_trigger_drift() {
    let mut c = SmsCase::new().await;
    // Each mutation leaves the constraint count unchanged. Rollback preserves
    // the exact production migration train between independent controls.
    for (table, pattern, replacement) in [
        (
            "line_activation_v2_pending",
            "%protocol_version%",
            "CHECK (protocol_version IN (1,2))",
        ),
        (
            "line_activation_v2_pending",
            "%octet_length(nonce)%",
            "CHECK (nonce IS NULL OR octet_length(nonce) IN (16,32))",
        ),
        (
            "line_activation_v2_pending",
            "%FOREIGN KEY (initiating_session_id)%",
            "FOREIGN KEY (initiating_session_id) REFERENCES users(id)",
        ),
        (
            "line_activation_v2_pending",
            "%UNIQUE (account_id, purpose, opening_id)%",
            "UNIQUE (opening_id)",
        ),
        (
            "line_activation_v2_observations",
            "%octet_length(observation)%",
            "CHECK (octet_length(observation) BETWEEN 120 AND 121)",
        ),
        (
            "line_activation_v2_observations",
            "%FOREIGN KEY%",
            "FOREIGN KEY (challenge_id) REFERENCES line_activation_challenges(id)",
        ),
    ] {
        let tx = c.db.transaction().await.unwrap();
        // PostgreSQL 18 catalogs NOT NULL columns as constraints too; the
        // verifier ignores them, so drift lookups must as well.
        let name:String=tx.query_one("SELECT quote_ident(conname) FROM pg_constraint WHERE conrelid=to_regclass($1) AND contype<>'n' AND pg_get_constraintdef(oid) LIKE $2",&[&table,&pattern]).await.unwrap().get(0);
        tx.batch_execute(&format!("ALTER TABLE {table} DROP CONSTRAINT {name}; ALTER TABLE {table} ADD CONSTRAINT {name} {replacement}")).await.unwrap();
        assert!(
            unavailable(schema::require_installed(&tx).await),
            "{table}: {replacement}"
        );
        tx.rollback().await.unwrap();
        schema::require_installed(&c.db).await.unwrap();
    }
    for mutation in [
        "ALTER TABLE device_sessions DROP CONSTRAINT device_sessions_line_activation_version; ALTER TABLE device_sessions ADD CONSTRAINT device_sessions_line_activation_version CHECK (line_activation_version IN (1,2,12))",
        "ALTER TABLE line_activation_v2_pending ALTER COLUMN protocol_version SET DEFAULT 1",
        "ALTER TABLE line_activation_v2_pending ALTER COLUMN created_at SET DEFAULT now()",
        "ALTER TABLE line_activation_v2_pending ALTER CONSTRAINT line_activation_v2_pending_initiating_session_id_fkey DEFERRABLE",
        "ALTER FUNCTION line_activation_v2_pending_guard() SET search_path=public",
        "ALTER FUNCTION line_activation_v2_pending_guard() SECURITY DEFINER",
        "DROP TRIGGER line_activation_v2_pending_before_delete ON line_activation_v2_pending; CREATE TRIGGER line_activation_v2_pending_before_delete BEFORE DELETE ON line_activation_v2_pending FOR EACH ROW WHEN (true) EXECUTE FUNCTION line_activation_v2_pending_guard()",
        "CREATE TRIGGER unexpected_v2_pending_guard BEFORE DELETE ON line_activation_v2_pending FOR EACH ROW EXECUTE FUNCTION line_activation_v2_pending_guard()",
    ] {
        let tx = c.db.transaction().await.unwrap();
        tx.batch_execute(mutation).await.unwrap();
        assert!(
            unavailable(schema::require_installed(&tx).await),
            "{mutation}"
        );
        tx.rollback().await.unwrap();
        schema::require_installed(&c.db).await.unwrap();
    }
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; production migrations in a unique disposable schema"]
async fn schema_guard_uses_installed_function_path_and_rejects_drift() {
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let (mut db, connection) = tokio_postgres::connect(&raw, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.expect("fixture connection completion");
    });
    // A quoted identifier also checks that the expected configuration uses the
    // installed schema's SQL spelling rather than its unquoted catalog name.
    let name = format!("guard schema {}", Uuid::new_v4().simple());
    let quoted = format!("\"{name}\"");
    db.batch_execute(&format!(
        "CREATE SCHEMA {quoted}; SET search_path TO {quoted}"
    ))
    .await
    .unwrap();
    auth::test_schema::apply(&db).await;
    schema::require_installed(&db).await.unwrap();
    let installed = db.query("SELECT p.proowner, p.proacl::text, p.prosecdef, p.proconfig FROM pg_proc p WHERE p.pronamespace=$1::text::regnamespace ORDER BY p.proname", &[&quoted]).await.unwrap();
    // Match the stock runtime role's pg_catalog-first policy without rewriting
    // the installed functions, their owner, ACLs or SECURITY INVOKER behavior.
    db.batch_execute(&format!("SET search_path TO pg_catalog, {quoted}"))
        .await
        .unwrap();
    schema::require_lease(&db).await.unwrap();
    schema::require_installed(&db).await.unwrap();
    let after = db.query("SELECT p.proowner, p.proacl::text, p.prosecdef, p.proconfig FROM pg_proc p WHERE p.pronamespace=$1::text::regnamespace ORDER BY p.proname", &[&quoted]).await.unwrap();
    for (before, after) in installed.iter().zip(&after) {
        assert_eq!(before.get::<_, u32>(0), after.get::<_, u32>(0));
        assert_eq!(
            before.get::<_, Option<String>>(1),
            after.get::<_, Option<String>>(1)
        );
        assert_eq!(before.get::<_, bool>(2), after.get::<_, bool>(2));
        assert_eq!(
            before.get::<_, Option<Vec<String>>>(3),
            after.get::<_, Option<Vec<String>>>(3)
        );
    }
    for mutation in [
        "ALTER FUNCTION device_session_line_activation_version_guard() SET search_path FROM CURRENT",
        "ALTER FUNCTION device_session_line_activation_version_guard() RESET search_path",
        "ALTER FUNCTION device_session_line_activation_version_guard() SET statement_timeout='1s'",
        "ALTER FUNCTION device_session_line_activation_version_guard() SECURITY DEFINER",
        "ALTER FUNCTION device_session_line_activation_version_guard() IMMUTABLE",
        "ALTER FUNCTION device_session_line_activation_version_guard() STRICT",
        "ALTER TABLE device_sessions DISABLE TRIGGER device_session_line_activation_version_before_update",
        "ALTER FUNCTION line_activation_v2_pending_guard() SET search_path FROM CURRENT",
        "ALTER FUNCTION line_activation_v2_pending_guard() SECURITY DEFINER",
    ] {
        let tx = db.transaction().await.unwrap();
        tx.batch_execute(mutation).await.unwrap();
        assert!(
            unavailable(schema::require_installed(&tx).await),
            "{mutation}"
        );
        tx.rollback().await.unwrap();
        schema::require_installed(&db).await.unwrap();
    }
    let tx = db.transaction().await.unwrap();
    tx.batch_execute(&format!("CREATE OR REPLACE FUNCTION {quoted}.device_session_line_activation_version_guard() RETURNS trigger LANGUAGE plpgsql SET search_path TO {quoted} AS $$ BEGIN RETURN NEW; END; $$"))
        .await
        .unwrap();
    assert!(unavailable(schema::require_lease(&tx).await));
    tx.rollback().await.unwrap();
    schema::require_installed(&db).await.unwrap();
    db.batch_execute(&format!("DROP SCHEMA {quoted} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; observed lock wait and actual clock expiry"]
async fn proof_wait_cannot_spend_a_challenge_that_expires_behind_the_binding_lock() {
    let c = SmsCase::new().await;
    let session = c.seed_lease(2).await;
    let mut db = c.connect().await;
    let challenge = super::super::issue_challenge_selected(
        &mut db,
        &c.principal,
        c.line,
        c.device,
        3,
        LinePurpose::Sms,
        None,
        Some((Purpose::Sms, Uuid::new_v4())),
    )
    .await
    .unwrap();
    let mut blocker = c.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.query_one(
        "SELECT generation FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 FOR UPDATE",
        &[&session.account_id, &c.line],
    )
    .await
    .unwrap();
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let observation = super::tests::observation(1, 2);
    let statement = v2::device_statement(PurposeV2::Sms, &challenge, &observation).unwrap();
    let signature: Signature = c.paired.sign(&statement.bytes());
    let der = signature.to_der();
    let raw = observation.encode();
    let proof = record_device_proof(
        &mut db,
        session,
        Purpose::Sms,
        challenge.id,
        &raw,
        der.as_bytes(),
    );
    let mut proof = Box::pin(proof);
    let wait = async {
        loop {
            if c.db
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
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    tokio::select! {result=&mut proof=>panic!("proof completed before observed lock wait: {}",matches!(result,Ok(true))),result=tokio::time::timeout(std::time::Duration::from_secs(2),wait)=>result.expect("actual backend lock evidence")}
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    assert!(
        c.db.query_one(
            "SELECT expires_at<=clock_timestamp() FROM line_activation_challenges WHERE id=$1",
            &[&challenge.id]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    lock.commit().await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), &mut proof)
        .await
        .expect("known proof completion");
    assert!(!result.expect("expired proof is a typed refusal, not a database error"));
    assert_eq!(
        c.db.query_one(
            "SELECT count(*) FROM line_activation_v2_observations WHERE challenge_id=$1",
            &[&challenge.id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert!(
        c.db.query_one(
            "SELECT consumed_at IS NULL FROM line_activation_challenges WHERE id=$1",
            &[&challenge.id]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    drop(proof);
    drop(blocker);
    c.cleanup().await;
}

async fn signed_pending(c: &SmsCase, db: &mut Client) -> (LineChallenge, Vec<u8>) {
    let session = c.seed_lease(2).await;
    let challenge = open(
        db,
        &c.principal,
        c.line,
        c.device,
        Purpose::Sms,
        Uuid::new_v4(),
        None,
    )
    .await
    .unwrap()
    .tuple;
    let observation = super::tests::observation(2, 256);
    let statement = v2::device_statement(PurposeV2::Sms, &challenge, &observation).unwrap();
    let proof: Signature = c.paired.sign(&statement.bytes());
    assert!(
        record_device_proof(
            db,
            session,
            Purpose::Sms,
            challenge.id,
            &observation.encode(),
            proof.to_der().as_bytes()
        )
        .await
        .unwrap()
    );
    let view = view(db, &c.principal, c.line, challenge.id, Purpose::Sms)
        .await
        .unwrap();
    let approval: Signature = c.approval.sign(&view.owner_statement.unwrap());
    (challenge, approval.to_der().as_bytes().to_vec())
}

async fn unchanged_pending(c: &SmsCase, id: Uuid) {
    let r=c.db.query_one("SELECT b.state,c.consumed_at IS NULL,p.approved_at IS NULL,p.installed_at IS NULL,p.nonce IS NOT NULL,l.last_issued_generation FROM line_activation_v2_pending p JOIN line_activation_challenges c ON c.id=p.challenge_id JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(p.account_id,p.line_id,p.device_id,p.generation) JOIN phone_lines l ON (l.account_id,l.id)=(b.account_id,b.line_id) WHERE p.challenge_id=$1",&[&id]).await.unwrap();
    assert_eq!(r.get::<_, String>(0), "pending");
    for column in 1..5 {
        assert!(r.get::<_, bool>(column));
    }
    assert_eq!(r.get::<_, i64>(5), 1);
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; observed original-owner/device lock barriers and rollback"]
async fn approval_rechecks_owner_membership_device_revocation_and_owner_expiry_after_waits() {
    for case in [
        "owner_revoked",
        "owner_expired",
        "membership_revoked",
        "device_revoked",
    ] {
        let c = SmsCase::new().await;
        let mut db = c.connect().await;
        let (challenge, der) = signed_pending(&c, &mut db).await;
        if case == "owner_expired" {
            c.db.execute(
                "UPDATE sessions SET expires_at=clock_timestamp()+interval '3 seconds' WHERE id=$1",
                &[&c.principal.session_id],
            )
            .await
            .unwrap();
        }
        let mut blocker = c.connect().await;
        let tx = blocker.transaction().await.unwrap();
        match case {
            "membership_revoked" => {
                // The memberships owner-revocation check makes this state
                // unreachable in production; dropping it before the approval
                // starts (never under lock contention) lets this disposable
                // fixture still prove that a lapsed owner membership fails
                // the LIVE recheck. The identity trigger permits revoked_at
                // because it only guards identity and role.
                tx.execute(
                    "ALTER TABLE memberships DROP CONSTRAINT memberships_owner_not_revoked",
                    &[],
                )
                .await
                .unwrap();
                tx.query_one(
                    "SELECT user_id FROM memberships WHERE account_id=$1 AND user_id=$2 FOR UPDATE",
                    &[&c.principal.tenant.account_id(), &c.principal.user_id],
                )
                .await
                .unwrap();
            }
            "device_revoked" => {
                tx.query_one(
                    "SELECT id FROM devices WHERE id=$1 FOR UPDATE",
                    &[&c.device],
                )
                .await
                .unwrap();
            }
            _ => {
                tx.query_one(
                    "SELECT id FROM sessions WHERE id=$1 FOR UPDATE",
                    &[&c.principal.session_id],
                )
                .await
                .unwrap();
            }
        }
        let pid: i32 = db
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let mut approval = Box::pin(approve(
            &mut db,
            &c.principal,
            c.line,
            challenge.id,
            Purpose::Sms,
            &der,
        ));
        let wait = async {
            loop {
                if c.db
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
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };
        tokio::select! {result=&mut approval=>panic!("{case}: approval completed before barrier: {}",result.is_ok()),result=tokio::time::timeout(std::time::Duration::from_secs(2),wait)=>result.expect("actual approval lock wait")}
        match case {
            "owner_revoked" => {
                tx.execute(
                    "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
                    &[&c.principal.session_id],
                )
                .await
                .unwrap();
            }
            "membership_revoked" => {
                tx.execute(
                    "UPDATE memberships SET revoked_at=clock_timestamp() WHERE account_id=$1 AND user_id=$2",
                    &[&c.principal.tenant.account_id(), &c.principal.user_id],
                )
                .await
                .unwrap();
            }
            "device_revoked" => {
                tx.execute(
                    "UPDATE devices SET revoked_at=clock_timestamp() WHERE id=$1",
                    &[&c.device],
                )
                .await
                .unwrap();
            }
            _ => {
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        if c.db
                            .query_one(
                                "SELECT expires_at<=clock_timestamp() FROM sessions WHERE id=$1",
                                &[&c.principal.session_id],
                            )
                            .await
                            .unwrap()
                            .get::<_, bool>(0)
                        {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("actual owner expiry before release");
            }
        }
        tx.commit().await.unwrap();
        assert!(
            unavailable(
                tokio::time::timeout(std::time::Duration::from_secs(5), &mut approval)
                    .await
                    .expect("known approval completion")
            ),
            "{case}"
        );
        drop(approval);
        drop(db);
        drop(blocker);
        unchanged_pending(&c, challenge.id).await;
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; actual lease expiry behind an observed admission-row lock"]
async fn current_phone_admission_cannot_survive_lease_expiry_during_a_lock_wait() {
    let c = SmsCase::new().await;
    let session = c.seed_lease(2).await;
    c.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()+interval '3 seconds' WHERE device_id=$1",&[&c.device]).await.unwrap();
    let mut blocker = c.connect().await;
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT device_id FROM device_sessions WHERE device_id=$1 FOR UPDATE",
        &[&c.device],
    )
    .await
    .unwrap();
    let mut db = c.connect().await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let mut admission = Box::pin(current(&mut db, session));
    let wait = async {
        loop {
            if c.db
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
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    tokio::select! {result=&mut admission=>panic!("admission completed before observed wait: {}",result.is_ok()),result=tokio::time::timeout(std::time::Duration::from_secs(2),wait)=>result.expect("actual admission lock wait")}
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if c.db
                .query_one(
                    "SELECT lease_until<=clock_timestamp() FROM device_sessions WHERE device_id=$1",
                    &[&c.device],
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("actual lease expiry");
    tx.commit().await.unwrap();
    assert!(unavailable(
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut admission)
            .await
            .expect("known admission completion")
    ));
    drop(admission);
    drop(db);
    drop(blocker);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; current activated tuple invalidation and superseding generation"]
async fn activated_ack_requires_current_generation_device_key_site_deployment_and_v2_lease() {
    for case in [
        "generation",
        "device",
        "key",
        "site",
        "deployment",
        "version",
        "expired",
    ] {
        let c = SmsCase::new().await;
        let mut db = c.connect().await;
        let (challenge, der) = signed_pending(&c, &mut db).await;
        approve(
            &mut db,
            &c.principal,
            c.line,
            challenge.id,
            Purpose::Sms,
            &der,
        )
        .await
        .unwrap();
        let epoch =
            c.db.query_one(
                "SELECT connection_epoch FROM device_sessions WHERE device_id=$1",
                &[&c.device],
            )
            .await
            .unwrap()
            .get(0);
        let session = c.session(epoch);
        let ack = next_ack(&mut db, session, Purpose::Sms, &[])
            .await
            .unwrap()
            .unwrap();
        assert!(current_ack(&mut db, session, ack).await.is_ok());
        assert_eq!(retire_sms(&mut db, session).await.unwrap(), 0);
        match case {
            "generation" => {
                let (next, der) = signed_pending(&c, &mut db).await;
                assert!(next.generation > challenge.generation);
                approve(&mut db, &c.principal, c.line, next.id, Purpose::Sms, &der)
                    .await
                    .unwrap();
            }
            "device" => {
                c.db.execute(
                    "UPDATE devices SET revoked_at=clock_timestamp() WHERE id=$1",
                    &[&c.device],
                )
                .await
                .unwrap();
            }
            "key" => {
                c.db.execute(
                    "UPDATE device_keys SET revoked_at=clock_timestamp() WHERE device_id=$1",
                    &[&c.device],
                )
                .await
                .unwrap();
            }
            "site" => {
                c.db.execute(
                    "UPDATE sites SET enabled=false WHERE site_id='v2-test'",
                    &[],
                )
                .await
                .unwrap();
            }
            "deployment" => {
                c.db.execute(
                    "UPDATE deployment_authority SET epoch=epoch+1 WHERE singleton=true",
                    &[],
                )
                .await
                .unwrap();
            }
            "version" => {
                c.seed_lease(1).await;
            }
            _ => {
                c.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second' WHERE device_id=$1",&[&c.device]).await.unwrap();
            }
        }
        let check_session = if case == "generation" {
            let epoch =
                c.db.query_one(
                    "SELECT connection_epoch FROM device_sessions WHERE device_id=$1",
                    &[&c.device],
                )
                .await
                .unwrap()
                .get(0);
            let fresh = c.session(epoch);
            let next = next_ack(&mut db, fresh, Purpose::Sms, &[])
                .await
                .unwrap()
                .unwrap();
            assert!(next.generation > ack.generation);
            assert!(current_ack(&mut db, fresh, next).await.is_ok());
            fresh
        } else {
            session
        };
        assert!(
            unavailable(current_ack(&mut db, check_session, ack).await),
            "{case}"
        );
        drop(db);
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; production proof/approval identity and current lease fences"]
async fn approval_refuses_changed_opening_purpose_der_key_site_and_deployment_without_consumption()
{
    for case in [
        "opening",
        "purpose",
        "der",
        "device_key",
        "owner_key",
        "site",
        "deployment",
        "lease",
    ] {
        let c = SmsCase::new().await;
        let mut db = c.connect().await;
        let (challenge, mut der) = signed_pending(&c, &mut db).await;
        match case {
            "opening" => {
                assert!(unavailable(
                    open(
                        &mut db,
                        &c.principal,
                        Uuid::new_v4(),
                        c.device,
                        Purpose::Sms,
                        observation_store::load(&c.db, challenge.account_id, challenge.id)
                            .await
                            .unwrap()
                            .opening,
                        None
                    )
                    .await
                ));
            }
            "purpose" => {
                assert!(unavailable(
                    approve(
                        &mut db,
                        &c.principal,
                        c.line,
                        challenge.id,
                        Purpose::Sealed,
                        &der
                    )
                    .await
                ));
            }
            "der" => {
                let wrong: Signature = c.paired.sign(b"different owner approval");
                der = wrong.to_der().as_bytes().to_vec();
            }
            "device_key" => {
                c.db.execute(
                    "UPDATE device_keys SET revoked_at=clock_timestamp() WHERE device_id=$1",
                    &[&c.device],
                )
                .await
                .unwrap();
            }
            "owner_key" => {
                c.db.execute("UPDATE sms_line_owner_approval_keys SET revoked_at=clock_timestamp() WHERE account_id=$1",&[&challenge.account_id]).await.unwrap();
            }
            "site" => {
                c.db.execute(
                    "UPDATE sites SET draining=true WHERE site_id='v2-test'",
                    &[],
                )
                .await
                .unwrap();
            }
            "deployment" => {
                c.db.execute(
                    "UPDATE deployment_authority SET epoch=epoch+1 WHERE singleton=true",
                    &[],
                )
                .await
                .unwrap();
            }
            _ => {
                c.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second' WHERE device_id=$1",&[&c.device]).await.unwrap();
            }
        }
        if !matches!(case, "opening" | "purpose") {
            assert!(
                unavailable(
                    approve(
                        &mut db,
                        &c.principal,
                        c.line,
                        challenge.id,
                        Purpose::Sms,
                        &der
                    )
                    .await
                ),
                "{case}"
            );
        }
        unchanged_pending(&c, challenge.id).await;
        drop(db);
        c.cleanup().await;
    }
}

async fn observed_wait(c: &SmsCase, pid: i32) {
    loop {
        if c.db
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)",
                &[&pid],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn observed_expiry(c: &SmsCase, query: &str, id: Uuid) {
    tokio::time::timeout(std::time::Duration::from_secs(7), async {
        loop {
            if c.db
                .query_one(query, &[&id])
                .await
                .unwrap()
                .get::<_, bool>(0)
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("actual database-clock expiry before unchanged lock release");
}

async fn exchange_snapshot(c: &SmsCase, id: Uuid) -> String {
    c.db.query_one("SELECT jsonb_build_array(to_jsonb(p),to_jsonb(c),to_jsonb(b),to_jsonb(l),(SELECT to_jsonb(o) FROM line_activation_v2_observations o WHERE o.challenge_id=p.challenge_id))::text FROM line_activation_v2_pending p JOIN line_activation_challenges c ON c.id=p.challenge_id JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(p.account_id,p.line_id,p.device_id,p.generation) JOIN phone_lines l ON (l.account_id,l.id)=(b.account_id,b.line_id) WHERE p.challenge_id=$1",&[&id]).await.unwrap().get(0)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; natural expiry behind an unchanged binding lock"]
async fn exact_opening_retry_rechecks_challenge_owner_and_phone_expiry_after_binding_wait() {
    for case in ["challenge", "owner", "phone"] {
        let c = SmsCase::new().await;
        c.seed_lease(2).await;
        let mut db = c.connect().await;
        let opening = Uuid::new_v4();
        let challenge = super::super::issue_challenge_selected(
            &mut db,
            &c.principal,
            c.line,
            c.device,
            if case == "challenge" {
                5
            } else {
                CHALLENGE_LIFETIME_SECS
            },
            LinePurpose::Sms,
            None,
            Some((Purpose::Sms, opening)),
        )
        .await
        .unwrap();
        let (query, expiry_id) = match case {
            "owner" => {
                c.db.execute("UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1",&[&c.principal.session_id]).await.unwrap();
                (
                    "SELECT expires_at<=clock_timestamp() FROM sessions WHERE id=$1",
                    c.principal.session_id,
                )
            }
            "phone" => {
                c.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()+interval '5 seconds' WHERE device_id=$1",&[&c.device]).await.unwrap();
                (
                    "SELECT lease_until<=clock_timestamp() FROM device_sessions WHERE device_id=$1",
                    c.device,
                )
            }
            _ => (
                "SELECT expires_at<=clock_timestamp() FROM line_activation_challenges WHERE id=$1",
                challenge.id,
            ),
        };
        let before = exchange_snapshot(&c, challenge.id).await;
        let mut blocker = c.connect().await;
        let lock = blocker.transaction().await.unwrap();
        lock.query_one("SELECT generation FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 FOR UPDATE",&[&challenge.account_id,&c.line]).await.unwrap();
        let pid = db
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let mut retry = Box::pin(open(
            &mut db,
            &c.principal,
            c.line,
            c.device,
            Purpose::Sms,
            opening,
            None,
        ));
        tokio::select! {
            result=&mut retry=>panic!("{case}: retry completed before observed binding wait: {}",result.is_ok()),
            result=tokio::time::timeout(std::time::Duration::from_secs(2),observed_wait(&c,pid))=>result.expect("actual retry binding wait"),
        }
        observed_expiry(&c, query, expiry_id).await;
        lock.commit().await.unwrap();
        assert!(
            unavailable(
                tokio::time::timeout(std::time::Duration::from_secs(5), &mut retry)
                    .await
                    .expect("known retry completion")
            ),
            "{case}"
        );
        drop(retry);
        unchanged_pending(&c, challenge.id).await;
        assert_eq!(
            before,
            exchange_snapshot(&c, challenge.id).await,
            "{case}: retry changed exchange state"
        );
        drop(db);
        drop(blocker);
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; approved owner reads behind an unchanged binding lock"]
async fn approved_view_and_idempotent_approval_recheck_owner_expiry_after_binding_wait() {
    for retry in [false, true] {
        let c = SmsCase::new().await;
        let mut db = c.connect().await;
        let (challenge, der) = signed_pending(&c, &mut db).await;
        approve(
            &mut db,
            &c.principal,
            c.line,
            challenge.id,
            Purpose::Sms,
            &der,
        )
        .await
        .unwrap();
        c.db.execute(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1",
            &[&c.principal.session_id],
        )
        .await
        .unwrap();
        let before = exchange_snapshot(&c, challenge.id).await;
        let mut blocker = c.connect().await;
        let lock = blocker.transaction().await.unwrap();
        lock.query_one("SELECT generation FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 FOR UPDATE",&[&challenge.account_id,&c.line]).await.unwrap();
        let pid = db
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let mut response = Box::pin(async {
            if retry {
                approve(
                    &mut db,
                    &c.principal,
                    c.line,
                    challenge.id,
                    Purpose::Sms,
                    &der,
                )
                .await
            } else {
                view(&mut db, &c.principal, c.line, challenge.id, Purpose::Sms)
                    .await
                    .map(|_| ())
            }
        });
        tokio::select! {
            result=&mut response=>panic!("approved response completed before observed binding wait: {}",result.is_ok()),
            result=tokio::time::timeout(std::time::Duration::from_secs(2),observed_wait(&c,pid))=>result.expect("actual approved-response binding wait"),
        }
        observed_expiry(
            &c,
            "SELECT expires_at<=clock_timestamp() FROM sessions WHERE id=$1",
            c.principal.session_id,
        )
        .await;
        lock.commit().await.unwrap();
        assert!(unavailable(
            tokio::time::timeout(std::time::Duration::from_secs(5), &mut response)
                .await
                .expect("known approved response completion")
        ));
        drop(response);
        assert_eq!(
            before,
            exchange_snapshot(&c, challenge.id).await,
            "owner response changed accepted receipt"
        );
        drop(db);
        drop(blocker);
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; immutable historical activation and natural SMS receipt expiry"]
async fn sms_ack_rechecks_receipt_lifetime_after_an_unchanged_binding_wait() {
    for current_only in [false, true] {
        let c = SmsCase::new().await;
        let mut db = c.connect().await;
        let (challenge, der) = signed_pending(&c, &mut db).await;
        let pending = observation_store::load(&db, challenge.account_id, challenge.id)
            .await
            .unwrap();
        let proof = observation_store::proof(&db, &pending)
            .await
            .unwrap()
            .unwrap();
        let statement =
            v2::device_statement(PurposeV2::Sms, &challenge, &proof.observation).unwrap();
        let owner_statement = v2::owner_statement(&statement, &proof.der).unwrap();
        let owner_digest = super::super::proof_digest(&owner_statement.bytes(), &der);
        // Initialize the first activation timestamp near its lifetime boundary.
        // All canonical constraints/triggers remain installed; an already-set
        // immutable timestamp is never rewritten and no clock is substituted.
        let tx = db.transaction().await.unwrap();
        assert_eq!(tx.execute("UPDATE device_line_bindings SET state='active',activated_at=clock_timestamp()-interval '895 seconds',owner_approval_digest=$2,device_confirmation_digest=$3 WHERE account_id=$1 AND line_id=$4 AND state='pending' AND activated_at IS NULL",&[&challenge.account_id,&&owner_digest[..],&&proof.confirmation[..],&c.line]).await.unwrap(),1);
        tx.execute("UPDATE phone_lines SET state='active',approved_at=clock_timestamp(),current_binding_generation=$2 WHERE id=$1",&[&c.line,&challenge.generation]).await.unwrap();
        tx.execute(
            "UPDATE line_activation_challenges SET consumed_at=clock_timestamp() WHERE id=$1",
            &[&challenge.id],
        )
        .await
        .unwrap();
        observation_store::mark_approved(&tx, &challenge, &der)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let session = c.session(pending.lease.connection);
        let ack = next_ack(&mut db, session, Purpose::Sms, &[])
            .await
            .unwrap()
            .unwrap();
        current_ack(&mut db, session, ack).await.unwrap();
        let before = exchange_snapshot(&c, challenge.id).await;
        let mut blocker = c.connect().await;
        let lock = blocker.transaction().await.unwrap();
        lock.query_one("SELECT generation FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 FOR UPDATE",&[&challenge.account_id,&c.line]).await.unwrap();
        let pid = db
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let mut response = Box::pin(async {
            if current_only {
                current_ack(&mut db, session, ack).await.map(|_| true)
            } else {
                next_ack(&mut db, session, Purpose::Sms, &[])
                    .await
                    .map(|ack| ack.is_some())
            }
        });
        tokio::select! {
            result=&mut response=>panic!("ACK completed before observed binding wait: {}",result.is_ok()),
            result=tokio::time::timeout(std::time::Duration::from_secs(2),observed_wait(&c,pid))=>result.expect("actual ACK binding wait"),
        }
        observed_expiry(&c,"SELECT activated_at<clock_timestamp()-interval '900 seconds' FROM device_line_bindings WHERE line_id=$1",c.line).await;
        lock.commit().await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), &mut response)
            .await
            .expect("known ACK completion");
        if current_only {
            assert!(unavailable(result));
        } else {
            assert!(!result.expect("expired ACK selection returns None, not a database error"));
        }
        drop(response);
        assert_eq!(
            before,
            exchange_snapshot(&c, challenge.id).await,
            "expired ACK changed accepted receipt"
        );
        drop(db);
        drop(blocker);
        c.cleanup().await;
    }
}
