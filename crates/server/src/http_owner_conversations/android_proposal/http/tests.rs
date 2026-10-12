// SPDX-License-Identifier: AGPL-3.0-only
//! Source-only draft: maintained authentication with synthetic public prerequisites.
//! These tests do not establish phone provenance, archive recovery or private custody.
use super::*;
use crate::{
    auth::{self, AuthError, SessionCredentials, SessionPrincipal, TokenHasher},
    sealed_manifest_store::tests::Fixture,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://owner.example.test";
const PATH: &str = "/v1/owner/conversation/android-proposal";
const CONTEXT_PATH: &str = "/v1/owner/conversation/android-proposal/context";

#[test]
fn optional_public_inputs_preserve_missing_versus_null_and_duplicate_field_refusal() {
    let missing =
        serde_json::json!({"kind":4,"proposal_b64":"YQ==","expected_session_id":Uuid::new_v4()});
    let parsed = serde_json::from_value::<MapOnly<Register>>(missing.clone())
        .unwrap()
        .0;
    assert!(parsed.phone_export_b64.is_none() && parsed.encrypted_archive_b64.is_none());
    for name in ["phone_export_b64", "encrypted_archive_b64"] {
        let mut null = missing.clone();
        null[name] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MapOnly<Register>>(null).is_err());
        let mut present = missing.clone();
        present[name] = serde_json::json!("YQ==");
        let parsed = serde_json::from_value::<MapOnly<Register>>(present.clone())
            .unwrap()
            .0;
        assert!(parsed.phone_export_b64.is_some() || parsed.encrypted_archive_b64.is_some());
        let mut raw = present.to_string();
        assert_eq!(raw.pop(), Some('}'));
        raw.push_str(&format!(
            ",{}:\"YQ==\"}}",
            serde_json::to_string(name).unwrap()
        ));
        assert!(serde_json::from_str::<MapOnly<Register>>(&raw).is_err());
    }
}

#[test]
fn streamed_http_dtos_require_objects_and_preserve_escaped_duplicate_refusal() {
    let id = Uuid::new_v4();
    let register = serde_json::json!({"kind":3,"proposal_b64":"YQ==","expected_session_id":id,
        "encrypted_archive_b64":"YQ==","phone_export_b64":"YQ=="});
    let context = serde_json::json!({"kind":3,"proposal_sha256_hex":"00".repeat(32),"expected_session_id":id});
    assert!(serde_json::from_value::<MapOnly<Register>>(register.clone()).is_ok());
    assert!(serde_json::from_value::<MapOnly<Context>>(context.clone()).is_ok());
    for scalar in [
        serde_json::Value::Null,
        serde_json::json!(true),
        serde_json::json!(3),
        serde_json::json!("object"),
    ] {
        assert!(serde_json::from_value::<MapOnly<Register>>(scalar.clone()).is_err());
        assert!(serde_json::from_value::<MapOnly<Context>>(scalar).is_err());
    }
    assert!(
        serde_json::from_value::<MapOnly<Register>>(serde_json::json!([
            3, "YQ==", id, "YQ==", "YQ=="
        ]))
        .is_err()
    );
    assert!(
        serde_json::from_value::<MapOnly<Context>>(serde_json::json!([3, "00".repeat(32), id]))
            .is_err()
    );
    for (object, is_register) in [(register, true), (context, false)] {
        let mut duplicate = object.to_string();
        assert_eq!(duplicate.pop(), Some('}'));
        duplicate.push_str(",\"k");
        duplicate.push('\\');
        duplicate.push_str("u0069nd\":3}");
        if is_register {
            assert!(serde_json::from_str::<MapOnly<Register>>(&duplicate).is_err());
        } else {
            assert!(serde_json::from_str::<MapOnly<Context>>(&duplicate).is_err());
        }
    }
}

struct SignedIn {
    principal: SessionPrincipal,
    credentials: SessionCredentials,
    email: String,
    password: String,
}
impl SignedIn {
    async fn register(f: &Fixture, hasher: &TokenHasher) -> Self {
        let mut db = f.connect().await;
        let email = format!("{}@example.test", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        let signup = auth::register(&mut db, hasher, &email, &password)
            .await
            .unwrap();
        assert!(matches!(
            auth::login(&db, hasher, &email, &password).await,
            Err(AuthError::EmailNotVerified)
        ));
        assert!(
            !auth::verify_email_with_password(
                &mut db,
                hasher,
                &signup.verification_token,
                &Uuid::new_v4().to_string()
            )
            .await
            .unwrap()
        );
        assert!(
            auth::verify_email_with_password(
                &mut db,
                hasher,
                &signup.verification_token,
                &password
            )
            .await
            .unwrap()
        );
        assert!(
            !auth::verify_email_with_password(
                &mut db,
                hasher,
                &signup.verification_token,
                &password
            )
            .await
            .unwrap()
        );
        let credentials = auth::login(&db, hasher, &email, &password).await.unwrap();
        let principal = auth::authenticate_session(&db, hasher, &credentials.token)
            .await
            .unwrap();
        assert_eq!(principal.tenant.account_id(), signup.account_id);
        assert_eq!(principal.user_id, signup.user_id);
        assert_eq!(principal.session_id, credentials.id);
        assert_eq!(principal.role, auth::Role::Owner);
        let row = db
            .query_one(
                "SELECT email_verified_at IS NOT NULL,mfa_enabled FROM users WHERE id=$1",
                &[&principal.user_id],
            )
            .await
            .unwrap();
        assert!(row.get::<_, bool>(0));
        assert!(!row.get::<_, bool>(1));
        Self {
            principal,
            credentials,
            email,
            password,
        }
    }
    fn cookie(&self) -> String {
        format!(
            "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
            self.credentials.token, self.credentials.csrf_token
        )
    }
}

struct GenuineCase {
    f: Fixture,
    hasher: Arc<TokenHasher>,
    owner: SignedIn,
    device: Uuid,
    line: Uuid,
    paired: SigningKey,
    root: SigningKey,
    pin: Vec<u8>,
}
impl GenuineCase {
    async fn new() -> Self {
        // The inherited schema and its unrelated account/device are synthetic.
        // It applies a prerequisite subset, not a full migration replay.
        let f = Fixture::without_authority().await;
        for sql in [
            include_str!(
                "../../../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"
            ),
            include_str!(
                "../../../../../../deploy/compose/migrations/064_owner_conversation_consent.sql"
            ),
            include_str!(
                "../../../../../../deploy/compose/migrations/065_conversation_activation.sql"
            ),
            include_str!(
                "../../../../../../deploy/compose/migrations/097_owner_android_proposals.sql"
            ),
        ] {
            f.db.batch_execute(sql).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(93)).unwrap());
        let owner = SignedIn::register(&f, &hasher).await;
        let account = owner.principal.tenant.account_id();
        let device = Uuid::new_v4();
        let line = Uuid::new_v4();
        let paired = SigningKey::generate_from_rng(&mut rand::rng());
        // Synthetic test-only root data may sign fixture manifests; it is
        // never a production RootSecret/unlock API or actual custody proof.
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let root_point = root.verifying_key().to_sec1_point(false);
        let pin = [
            b"ZTRP\x02".as_slice(),
            account.as_bytes(),
            &1u64.to_be_bytes(),
            root_point.as_bytes(),
        ]
        .concat();
        let rootfp = zrotext_root_material::sealed_root_enrollment::root_fingerprint(
            &pin,
            account.as_bytes(),
        )
        .unwrap();
        // Synthetic independently-pinned v0 root, approved line and paired
        // connection model prerequisites; these inserts do not prove phone acts.
        f.db.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)",
            &[&account,&pin,&rootfp.as_slice(),&vec![0u8;32]]).await.unwrap();
        f.db.execute(
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
        f.db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
            &[&device,&account,&point,&fp]).await.unwrap();
        f.db.execute("INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,deployment_epoch,lease_until) VALUES($1,$2,'manifest-test','fixture',1,1,clock_timestamp()+interval '10 minutes')",
            &[&device,&account]).await.unwrap();
        f.db.execute("INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) VALUES($1,$2,'active',now(),1,1)",
            &[&line,&account]).await.unwrap();
        f.db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,owner_approval_digest,device_confirmation_digest,activated_at,purpose) VALUES($1,$2,$3,1,'active',$4,$5,now(),'sealed')",
            &[&account,&line,&device,&vec![2u8;32],&vec![3u8;32]]).await.unwrap();
        Self {
            f,
            hasher,
            owner,
            device,
            line,
            paired,
            root,
            pin,
        }
    }
    fn state(&self) -> OwnerConversationsState {
        let sep = if self.f.url.contains('?') { '&' } else { '?' };
        OwnerConversationsState {
            database_url: format!(
                "{}{sep}options=-csearch_path%3D{}",
                self.f.url, self.f.schema
            ),
            auth_hasher: self.hasher.clone(),
            canonical_origin: ORIGIN.into(),
        }
    }
    fn session(&self) -> crate::inbound::InboundSession<'_> {
        crate::inbound::InboundSession {
            account_id: self.owner.principal.tenant.account_id(),
            device_id: self.device,
            site_id: "manifest-test",
            instance_id: "fixture",
            connection_epoch: 1,
            deployment_epoch: 1,
        }
    }
    async fn now(&self) -> i64 {
        self.f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn rows(&self) -> Vec<String> {
        self.f.db.query("SELECT row_to_json(p)::text FROM owner_android_proposals p ORDER BY account_id,kind",&[])
            .await.unwrap().into_iter().map(|r| r.get(0)).collect()
    }
    async fn authority_rows(&self) -> Vec<String> {
        self.f.db.query("SELECT 'root:'||row_to_json(r)::text AS snapshot FROM sealed_manifest_authorities r WHERE account_id=$1 UNION ALL SELECT 'consent:'||row_to_json(c)::text FROM owner_conversation_consents c WHERE account_id=$1 UNION ALL SELECT 'interval:'||row_to_json(i)::text FROM conversation_intervals i WHERE account_id=$1 ORDER BY snapshot", &[&self.owner.principal.tenant.account_id()])
            .await.unwrap().into_iter().map(|r| r.get(0)).collect()
    }
    async fn cleanup(self) {
        self.f.cleanup().await;
    }
}

async fn raw(
    c: &GenuineCase,
    who: Option<&SignedIn>,
    path: &str,
    body: Vec<u8>,
    origin: Option<&str>,
    csrf: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::post(path).header("content-type", "application/json");
    if let Some(who) = who {
        builder = builder.header("cookie", who.cookie());
    }
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-zrotext-csrf", csrf);
    }
    let response = router(c.state())
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 32768).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}
async fn request(
    c: &GenuineCase,
    path: &str,
    value: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    raw(
        c,
        Some(&c.owner),
        path,
        serde_json::to_vec(value).unwrap(),
        Some(ORIGIN),
        Some(&c.owner.credentials.csrf_token),
    )
    .await
}
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn registration(c: &GenuineCase, packet: &[u8], phone: &[u8], archive: &[u8]) -> serde_json::Value {
    serde_json::json!({"kind":3,"proposal_b64":STANDARD.encode(packet),
        "expected_session_id":c.owner.principal.session_id,
        "phone_export_b64":STANDARD.encode(phone),"encrypted_archive_b64":STANDARD.encode(archive)})
}
fn context(c: &GenuineCase, packet: &[u8]) -> serde_json::Value {
    serde_json::json!({"kind":3,"proposal_sha256_hex":hex_bytes(&Sha256::digest(packet)),
        "expected_session_id":c.owner.principal.session_id})
}

#[path = "ceremonies.rs"]
mod ceremonies;
#[path = "fences.rs"]
mod fences;

fn startup_fixture(
    c: &GenuineCase,
) -> (
    crate::http_owner_conversations::composition::Startup,
    crate::device_socket::DeviceSocketState,
) {
    use crate::device_socket::{DeviceSocketState, MmsSpikePolicy};
    use std::sync::atomic::AtomicBool;
    let package = crate::http_owner_conversations::browser_assets::test_files::Package::new();
    for name in [
        "conversation-custody",
        "conversation-archive-custody",
        "draft02-manifest",
        "conversation-refresh-proposal",
        "conversation-activation-proposal",
        "conversation-genesis-proposal",
        "owner-context-authoring",
    ] {
        package
            .write(&format!("sdk/{name}.js"), b"export const fixture = true;")
            .unwrap();
    }
    let startup = crate::http_owner_conversations::composition::Startup::load(
        true,
        Some(package.root()),
        Some("wss://example.org"),
    )
    .unwrap()
    .unwrap();
    // Startup owns the package snapshot; the mounted routes need no later file reads.
    drop(package);
    let socket = DeviceSocketState {
        database_url: c.state().database_url,
        site_id: "manifest-test".into(),
        instance_id: "fixture".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(
            crate::enrollment::EnrollmentHasher::new(crate::test_keys::key(92)).unwrap(),
        ),
        auth_hasher: c.hasher.clone(),
        alpha_policy: Arc::new(crate::alpha_policy::AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        sealed_dispatch_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        mms_spike_policy: Arc::new(MmsSpikePolicy::parse(None, None, None).unwrap()),
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(tokio::sync::Notify::new()),
    };
    (startup, socket)
}

async fn mounted(c: &GenuineCase) -> Result<axum::Router, &'static str> {
    let (startup, socket) = startup_fixture(c);
    let (router, retention) = startup
        .router_with_sealed_line_setup(
            c.state(),
            socket,
            1,
            false,
            Arc::new(crate::auth::mfa::MfaCipher::new(crate::test_keys::key(92)).unwrap()),
        )
        .await?;
    // This test exercises the explicit composition, never spawns its worker.
    drop(retention);
    Ok(router)
}

async fn mounted_request(
    c: &GenuineCase,
    router: axum::Router,
    path: &str,
    value: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = router
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .header("cookie", c.owner.cookie())
                .header("origin", ORIGIN)
                .header("x-zrotext-csrf", &c.owner.credentials.csrf_token)
                .body(Body::from(serde_json::to_vec(value).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 32768).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual opt-in startup and synthetic public prerequisites"]
async fn explicit_startup_requires_complete_proposal_schema_and_mounts_issue_and_context() {
    let c = GenuineCase::new().await;
    for sql in [
        include_str!(
            "../../../../../../deploy/compose/migrations/086_sealed_line_key_registration.sql"
        ),
        include_str!(
            "../../../../../../deploy/compose/migrations/087_sealed_line_activation_exchanges.sql"
        ),
    ] {
        c.f.db.batch_execute(sql).await.unwrap();
    }
    c.f.db.batch_execute("DROP TABLE owner_android_proposals; DROP FUNCTION reject_owner_android_proposal_update()")
        .await.unwrap();
    assert!(matches!(
        mounted(&c).await,
        Err("Typed proposal schema unavailable")
    ));
    c.f.db
        .batch_execute("CREATE TABLE owner_android_proposals(account_id uuid)")
        .await
        .unwrap();
    assert!(matches!(
        mounted(&c).await,
        Err("Typed proposal schema unavailable")
    ));
    c.f.db
        .batch_execute("DROP TABLE owner_android_proposals")
        .await
        .unwrap();
    c.f.db
        .batch_execute(include_str!(
            "../../../../../../deploy/compose/migrations/097_owner_android_proposals.sql"
        ))
        .await
        .unwrap();
    c.f.db
        .batch_execute(
            "ALTER TABLE owner_android_proposals DISABLE TRIGGER owner_android_proposals_immutable",
        )
        .await
        .unwrap();
    assert!(matches!(
        mounted(&c).await,
        Err("Typed proposal schema unavailable")
    ));
    c.f.db
        .batch_execute(
            "ALTER TABLE owner_android_proposals ENABLE TRIGGER owner_android_proposals_immutable",
        )
        .await
        .unwrap();
    let router = mounted(&c).await.unwrap();
    let (packet, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
    let (status, receipt) = mounted_request(
        &c,
        router.clone(),
        PATH,
        &registration(&c, &packet, &phone, &archive),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    let rows = c.rows().await;
    let (status, got) =
        mounted_request(&c, router.clone(), CONTEXT_PATH, &context(&c, &packet)).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["proposal_b64"], STANDARD.encode(&packet));
    assert_eq!(got["expires_ms"], receipt["expires_ms"]);
    assert_eq!(c.rows().await, rows);
    let unauthorized = router
        .oneshot(
            Request::post(CONTEXT_PATH)
                .header("content-type", "application/json")
                .body(Body::from(context(&c, &packet).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(c.rows().await, rows);
    c.cleanup().await;
}
