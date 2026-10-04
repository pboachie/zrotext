// SPDX-License-Identifier: AGPL-3.0-only
//! Ordinary candidate-router/store tests: actual auth and migrations, followed
//! by the uninstalled proposal in a generated disposable schema. No provider I/O.
use super::*;
use crate::auth::{self, SessionCredentials, SessionPrincipal, TokenHasher};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio_postgres::{Client, NoTls};
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://test.example";
const COLLECTION: &str = "/v1/owner/provider-configurations";
const PROPOSAL: &str =
    include_str!("../../../../../protocol/v1/provider-configuration-storage-proposal.sql");

struct Fixture {
    admin: Client,
    db: Client,
    schema: String,
    database_url: String,
    hasher: Arc<TokenHasher>,
    owner: SessionPrincipal,
    session: SessionCredentials,
}
impl Fixture {
    async fn new(installed: bool) -> Self {
        let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set disposable ZT_AUTH_TEST_DATABASE_URL");
        let (admin, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("provider_config_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let database_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        auth::test_schema::apply(&db).await;
        if installed {
            db.batch_execute(PROPOSAL).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(47)).unwrap());
        let (owner, session) =
            registered_owner(&mut db, &hasher, "configuration@example.test", 1).await;
        Self {
            admin,
            db,
            schema,
            database_url,
            hasher,
            owner,
            session,
        }
    }
    fn app(&self) -> Router {
        http::router(http::StateConfig {
            database_url: self.database_url.clone(),
            auth_hasher: self.hasher.clone(),
            canonical_origin: ORIGIN.into(),
        })
    }
    fn erasure(&self) -> Router {
        crate::http_owner_erasure::router(crate::http_owner_erasure::OwnerErasureState {
            database_url: self.database_url.clone(),
            auth_hasher: self.hasher.clone(),
            canonical_origin: ORIGIN.into(),
            mfa_cipher: None,
        })
    }
    fn export(&self) -> Router {
        crate::http_owner_export::router(crate::http_owner_export::OwnerExportState {
            database_url: self.database_url.clone(),
            auth_hasher: self.hasher.clone(),
            canonical_origin: ORIGIN.into(),
            contacts_vault: None,
        })
    }
    async fn cleanup(self) {
        let suffix = self.schema.strip_prefix("provider_config_test_").unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
        let current: String = self
            .db
            .query_one("SELECT current_schema()", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(current, self.schema);
        drop(self.db);
        self.admin
            .batch_execute("SET lock_timeout='3s'; SET statement_timeout='10s'")
            .await
            .unwrap();
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}
async fn registered_owner(
    db: &mut Client,
    hasher: &TokenHasher,
    email: &str,
    key: u8,
) -> (SessionPrincipal, SessionCredentials) {
    let password = crate::test_keys::password(key);
    let signup = auth::register(db, hasher, email, &password).await.unwrap();
    auth::verify_email(db, hasher, &signup.verification_token)
        .await
        .unwrap();
    let session = auth::login(db, hasher, email, &password).await.unwrap();
    let owner = auth::authenticate_session(db, hasher, &session.token)
        .await
        .unwrap();
    (owner, session)
}
fn request(session: &SessionCredentials, method: &str, path: &str, payload: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(
            "cookie",
            format!(
                "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                session.token, session.csrf_token
            ),
        )
        .header("x-zrotext-csrf", &session.csrf_token);
    if method == "POST" {
        builder = builder
            .header("origin", ORIGIN)
            .header("content-type", "application/json");
    }
    builder.body(Body::from(payload.to_owned())).unwrap()
}
fn input(config: Uuid, request: Uuid, expected: i64) -> Value {
    json!({"request_id":request,"config_id":config,"expected_record_version":expected,"declaration":declaration()})
}
fn mutation(config: Uuid, request: Uuid, expected: i64) -> Mutation {
    serde_json::from_value(input(config, request, expected)).unwrap()
}
fn withdrawal(config: Uuid, request: Uuid, expected: i64) -> Withdrawal {
    serde_json::from_value(
        json!({"request_id":request,"config_id":config,"expected_record_version":expected}),
    )
    .unwrap()
}
async fn json_response(response: Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn configuration_routes_acknowledge_only_metadata_and_preserve_exact_request_identity() {
    let mut f = Fixture::new(true).await;
    let config = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let raw = input(config, operation, 0).to_string();
    let ack = json_response(
        f.app()
            .oneshot(request(&f.session, "POST", COLLECTION, &raw))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(ack["acceptance"], "unavailable");
    assert_eq!(ack["record_version"], 1);
    assert_eq!(ack.as_object().unwrap().len(), 5);
    assert!(!ack.to_string().contains("sender"));
    let replay = json_response(
        f.app()
            .oneshot(request(&f.session, "POST", COLLECTION, &raw))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(replay, ack);
    let mut conflict = input(config, operation, 0);
    conflict["declaration"]["owner_label"] = json!("Changed");
    assert_eq!(
        f.app()
            .oneshot(request(
                &f.session,
                "POST",
                COLLECTION,
                &conflict.to_string()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let details = json_response(
        f.app()
            .oneshot(request(
                &f.session,
                "GET",
                &format!("{COLLECTION}/{config}"),
                "",
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(details["declaration"]["owner_label"], "Example");
    assert_eq!(details["unavailable_reasons"].as_array().unwrap().len(), 4);
    let next = input(config, Uuid::new_v4(), 1).to_string();
    let revised = json_response(
        f.app()
            .oneshot(request(
                &f.session,
                "POST",
                &format!("{COLLECTION}/{config}/revise"),
                &next,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(revised["config_version"], 2);
    let stale = revise(&mut f.db, &f.owner, mutation(config, Uuid::new_v4(), 1)).await;
    assert!(matches!(stale, Err(ConversationError::Conflict)));
    let count: i64 =
        f.db.query_one(
            "SELECT count(*) FROM provider_configuration_mutations WHERE account_id=$1",
            &[&f.owner.tenant.account_id()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn configuration_candidate_ingress_uses_real_cookie_csrf_origin_and_closed_raw_types() {
    let f = Fixture::new(true).await;
    let raw = input(Uuid::new_v4(), Uuid::new_v4(), 0).to_string();
    let mut missing = request(&f.session, "GET", COLLECTION, "");
    missing.headers_mut().remove("cookie");
    assert_eq!(
        f.app().oneshot(missing).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut missing = request(&f.session, "GET", COLLECTION, "");
    missing.headers_mut().remove("x-zrotext-csrf");
    assert_eq!(
        f.app().oneshot(missing).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut bearer = request(&f.session, "GET", COLLECTION, "");
    bearer
        .headers_mut()
        .insert("authorization", "Bearer synthetic".parse().unwrap());
    assert_eq!(
        f.app().oneshot(bearer).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut bad = request(&f.session, "POST", COLLECTION, &raw);
    bad.headers_mut()
        .insert("origin", "https://other.example".parse().unwrap());
    assert_eq!(
        f.app().oneshot(bad).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    // Retain the maintained helper's first-value header/cookie semantics;
    // this candidate must not invent a separate authentication parser.
    let mut repeated = request(&f.session, "GET", COLLECTION, "");
    repeated
        .headers_mut()
        .append("x-zrotext-csrf", f.session.csrf_token.parse().unwrap());
    assert!(crate::http_auth::require_owner_read_headers(repeated.headers()).is_ok());
    assert_eq!(
        f.app().oneshot(repeated).await.unwrap().status(),
        StatusCode::OK
    );
    let mut mismatch = request(&f.session, "GET", COLLECTION, "");
    mismatch
        .headers_mut()
        .insert("x-zrotext-csrf", "incorrect".parse().unwrap());
    mismatch
        .headers_mut()
        .append("x-zrotext-csrf", f.session.csrf_token.parse().unwrap());
    assert!(crate::http_auth::require_owner_read_headers(mismatch.headers()).is_err());
    assert_eq!(
        f.app().oneshot(mismatch).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let duplicate = raw.replacen(
        '{',
        r#"{"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","#,
        1,
    );
    let escaped = raw.replacen(
        '{',
        r#"{"request_\u0069d":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","#,
        1,
    );
    let unknown = raw.replacen('{', "{\"enabled\":true,", 1);
    for invalid in [duplicate, escaped, unknown] {
        let value = json_response(
            f.app()
                .oneshot(request(&f.session, "POST", COLLECTION, &invalid))
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(value, json!({"code":"invalid_request"}));
    }
    let excessive = " ".repeat(model::BODY + 1);
    assert_eq!(
        f.app()
            .oneshot(request(&f.session, "POST", COLLECTION, &excessive))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn configuration_withdrawal_scrubs_all_versions_and_replay_never_returns_private_bytes() {
    let mut f = Fixture::new(true).await;
    let config = Uuid::new_v4();
    let first = Uuid::new_v4();
    let last = Uuid::new_v4();
    create(&mut f.db, &f.owner, mutation(config, first, 0))
        .await
        .unwrap();
    for version in 1..16 {
        revise(
            &mut f.db,
            &f.owner,
            mutation(config, Uuid::new_v4(), version),
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        revise(&mut f.db, &f.owner, mutation(config, Uuid::new_v4(), 16)).await,
        Err(ConversationError::Conflict)
    ));
    let withdrawn = withdraw(&mut f.db, &f.owner, withdrawal(config, last, 16))
        .await
        .unwrap();
    assert_eq!(withdrawn.config_version, 16);
    assert_eq!(withdrawn.record_version, 17);
    let count:i64=f.db.query_one("SELECT count(*) FROM provider_configuration_versions WHERE account_id=$1 AND declaration IS NOT NULL",&[&f.owner.tenant.account_id()]).await.unwrap().get(0);
    assert_eq!(count, 0);
    let replay = create(&mut f.db, &f.owner, mutation(config, first, 0))
        .await
        .unwrap();
    assert_eq!(replay.state, "draft");
    assert_eq!(replay.record_version, 1);
    assert!(!serde_json::to_string(&replay).unwrap().contains("sender"));
    assert!(
        read(&mut f.db, &f.owner, config)
            .await
            .unwrap()
            .declaration
            .is_none()
    );
    assert!(matches!(
        create(&mut f.db, &f.owner, mutation(config, Uuid::new_v4(), 0)).await,
        Err(ConversationError::Conflict)
    ));
    assert!(matches!(
        revise(&mut f.db, &f.owner, mutation(config, Uuid::new_v4(), 17)).await,
        Err(ConversationError::Conflict)
    ));
    let bytes = declaration().bytes().unwrap();
    assert!(f.db.execute("UPDATE provider_configuration_versions SET declaration=$3 WHERE account_id=$1 AND config_id=$2",&[&f.owner.tenant.account_id(),&config,&bytes]).await.is_err());
    assert!(f.db.execute("INSERT INTO provider_configuration_versions(account_id,config_id,version,declaration,declaration_digest) VALUES($1,$2,1,$3,$4)",&[&f.owner.tenant.account_id(),&config,&bytes,&vec![1u8;32]]).await.is_err());
    let exported = serde_json::to_string(
        &lifecycle::export(&mut f.db, &f.owner, None, None, None)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!exported.contains("sender"));
    assert!(!exported.contains("Example"));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn configuration_commit_guard_requires_complete_scrub_and_preserves_prior_transaction_state()
{
    let mut f = Fixture::new(true).await;
    let config = Uuid::new_v4();
    create(&mut f.db, &f.owner, mutation(config, Uuid::new_v4(), 0))
        .await
        .unwrap();
    let tx = f.db.transaction().await.unwrap();
    tx.execute("UPDATE provider_configuration_heads SET state='withdrawn',record_version=2 WHERE account_id=$1 AND config_id=$2",&[&f.owner.tenant.account_id(),&config]).await.unwrap();
    assert!(tx.commit().await.is_err());
    let details = read(&mut f.db, &f.owner, config).await.unwrap();
    assert_eq!(details.metadata.state, "draft");
    assert!(details.declaration.is_some());
    // Changing any immutable digest together with NULL is refused immediately;
    // a failed withdrawal transaction restores its head and all private bytes.
    let tx = f.db.transaction().await.unwrap();
    tx.execute("UPDATE provider_configuration_heads SET state='withdrawn',record_version=2 WHERE account_id=$1 AND config_id=$2",&[&f.owner.tenant.account_id(),&config]).await.unwrap();
    assert!(tx.execute("UPDATE provider_configuration_versions SET declaration=NULL,declaration_digest=$3 WHERE account_id=$1 AND config_id=$2",&[&f.owner.tenant.account_id(),&config,&vec![2u8;32]]).await.is_err());
    tx.rollback().await.unwrap();
    assert!(
        read(&mut f.db, &f.owner, config)
            .await
            .unwrap()
            .declaration
            .is_some()
    );
    withdraw(&mut f.db, &f.owner, withdrawal(config, Uuid::new_v4(), 1))
        .await
        .unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn configuration_absent_and_partial_schema_fail_closed_and_current_owner_is_required() {
    let mut f = Fixture::new(false).await;
    assert!(matches!(
        create(
            &mut f.db,
            &f.owner,
            mutation(Uuid::new_v4(), Uuid::new_v4(), 0)
        )
        .await,
        Err(ConversationError::Unavailable)
    ));
    assert!(
        lifecycle::export(&mut f.db, &f.owner, None, None, None)
            .await
            .unwrap()
            .heads
            .items
            .is_empty()
    );
    assert!(matches!(
        lifecycle::export(&mut f.db, &f.owner, Some(Uuid::new_v4()), None, None).await,
        Err(ConversationError::NotFound)
    ));
    f.db.batch_execute("CREATE TABLE provider_configuration_heads(placeholder boolean)")
        .await
        .unwrap();
    assert!(matches!(
        lifecycle::export(&mut f.db, &f.owner, None, None, None).await,
        Err(ConversationError::Unavailable)
    ));
    let response = f
        .erasure()
        .oneshot(request(
            &f.session,
            "POST",
            "/v1/owner/erasure",
            &json!({"current_password":crate::test_keys::password(1),"code":null}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let exists: bool =
        f.db.query_one(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1)",
            &[&f.owner.tenant.account_id()],
        )
        .await
        .unwrap()
        .get(0);
    assert!(exists);
    f.db.batch_execute("DROP TABLE provider_configuration_heads")
        .await
        .unwrap();
    assert!(
        lifecycle::export(&mut f.db, &f.owner, None, None, None)
            .await
            .unwrap()
            .heads
            .items
            .is_empty()
    );
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&f.owner.session_id],
    )
    .await
    .unwrap();
    assert!(matches!(
        lifecycle::export(&mut f.db, &f.owner, None, None, None).await,
        Err(ConversationError::Forbidden)
    ));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn configuration_owner_isolation_pagination_and_actual_account_erasure_are_composed() {
    let mut f = Fixture::new(true).await;
    let (other, _) =
        registered_owner(&mut f.db, &f.hasher, "other-configuration@example.test", 2).await;
    let mut ids = Vec::new();
    for _ in 0..21 {
        let id = Uuid::new_v4();
        create(&mut f.db, &f.owner, mutation(id, Uuid::new_v4(), 0))
            .await
            .unwrap();
        ids.push(id);
    }
    let foreign = Uuid::new_v4();
    let foreign_request = Uuid::new_v4();
    create(&mut f.db, &other, mutation(foreign, foreign_request, 0))
        .await
        .unwrap();
    assert!(matches!(
        read(&mut f.db, &f.owner, foreign).await,
        Err(ConversationError::NotFound)
    ));
    assert!(matches!(
        lifecycle::heads(&mut f.db, &f.owner, Some(foreign), false).await,
        Err(ConversationError::NotFound)
    ));
    let foreign_version = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!({"config_id":foreign,"version":1})).unwrap());
    assert!(matches!(
        lifecycle::export(&mut f.db, &f.owner, None, Some(&foreign_version), None).await,
        Err(ConversationError::NotFound)
    ));
    assert!(matches!(
        lifecycle::export(&mut f.db, &f.owner, None, None, Some(foreign_request)).await,
        Err(ConversationError::NotFound)
    ));
    let first = lifecycle::export(&mut f.db, &f.owner, None, None, None)
        .await
        .unwrap();
    assert_eq!(first.heads.items.len(), 20);
    assert_eq!(first.versions.items.len(), 20);
    assert_eq!(first.mutations.items.len(), 20);
    let mounted = json_response(
        f.export()
            .oneshot(request(&f.session, "GET", "/v1/owner/export", ""))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        mounted["provider_configurations"]["heads"]["items"]
            .as_array()
            .unwrap()
            .len(),
        20
    );
    assert!(
        !mounted["provider_configurations"]
            .to_string()
            .contains("sender")
    );
    let last = lifecycle::export(
        &mut f.db,
        &f.owner,
        first.heads.next_cursor,
        first.versions.next_cursor.as_deref(),
        first.mutations.next_cursor,
    )
    .await
    .unwrap();
    assert_eq!(last.heads.items.len(), 1);
    assert_eq!(last.versions.items.len(), 1);
    assert_eq!(last.mutations.items.len(), 1);
    let app = f.erasure();
    let wrong = app
        .clone()
        .oneshot(request(
            &f.session,
            "POST",
            "/v1/owner/erasure",
            &json!({"current_password":"invalid","code":null}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert!(
        read(&mut f.db, &f.owner, ids[0])
            .await
            .unwrap()
            .declaration
            .is_some()
    );
    let response = app
        .oneshot(request(
            &f.session,
            "POST",
            "/v1/owner/erasure",
            &json!({"current_password":crate::test_keys::password(1),"code":null}).to_string(),
        ))
        .await
        .unwrap();
    let erased = json_response(response, StatusCode::OK).await;
    for table in [
        "provider_configuration_mutations",
        "provider_configuration_versions",
        "provider_configuration_heads",
    ] {
        let count: i64 =
            f.db.query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&f.owner.tenant.account_id()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 0);
        assert!(
            erased["deleted"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["table"] == table && v["rows"] == 21)
        );
    }
    assert!(
        read(&mut f.db, &other, foreign)
            .await
            .unwrap()
            .declaration
            .is_some()
    );
    assert!(matches!(
        read(&mut f.db, &f.owner, ids[0]).await,
        Err(ConversationError::Forbidden)
    ));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn configuration_fixed_capacity_retains_duplicate_ack_and_reserved_withdrawal_scrub() {
    let mut f = Fixture::new(true).await;
    let mut configs = Vec::new();
    let first_request = Uuid::new_v4();
    for i in 0..64 {
        let id = Uuid::new_v4();
        create(
            &mut f.db,
            &f.owner,
            mutation(
                id,
                if i == 0 {
                    first_request
                } else {
                    Uuid::new_v4()
                },
                0,
            ),
        )
        .await
        .unwrap();
        configs.push(id);
    }
    assert!(matches!(
        create(
            &mut f.db,
            &f.owner,
            mutation(Uuid::new_v4(), Uuid::new_v4(), 0)
        )
        .await,
        Err(ConversationError::Conflict)
    ));
    // Populate the remaining valid bounded revision history through the store;
    // every durable operation has an actual owner, CAS and immutable ACK.
    for id in &configs {
        for version in 1..15 {
            revise(&mut f.db, &f.owner, mutation(*id, Uuid::new_v4(), version))
                .await
                .unwrap();
        }
    }
    let count: i64 =
        f.db.query_one(
            "SELECT count(*) FROM provider_configuration_mutations WHERE account_id=$1",
            &[&f.owner.tenant.account_id()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 960);
    assert!(matches!(
        revise(
            &mut f.db,
            &f.owner,
            mutation(configs[0], Uuid::new_v4(), 15)
        )
        .await,
        Err(ConversationError::Conflict)
    ));
    create(&mut f.db, &f.owner, mutation(configs[0], first_request, 0))
        .await
        .unwrap();
    let withdrawal_request = Uuid::new_v4();
    for (i, id) in configs.iter().enumerate() {
        withdraw(
            &mut f.db,
            &f.owner,
            withdrawal(
                *id,
                if i == 0 {
                    withdrawal_request
                } else {
                    Uuid::new_v4()
                },
                15,
            ),
        )
        .await
        .unwrap();
    }
    let row=f.db.query_one("SELECT (SELECT count(*) FROM provider_configuration_mutations WHERE account_id=$1),(SELECT count(*) FROM provider_configuration_versions WHERE account_id=$1 AND declaration IS NOT NULL)",&[&f.owner.tenant.account_id()]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1024);
    assert_eq!(row.get::<_, i64>(1), 0);
    withdraw(
        &mut f.db,
        &f.owner,
        withdrawal(configs[0], withdrawal_request, 15),
    )
    .await
    .unwrap();
    create(&mut f.db, &f.owner, mutation(configs[0], first_request, 0))
        .await
        .unwrap();
    assert!(matches!(
        create(
            &mut f.db,
            &f.owner,
            mutation(Uuid::new_v4(), Uuid::new_v4(), 0)
        )
        .await,
        Err(ConversationError::Conflict)
    ));
    f.cleanup().await;
}
