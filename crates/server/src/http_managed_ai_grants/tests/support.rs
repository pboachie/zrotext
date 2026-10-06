// SPDX-License-Identifier: AGPL-3.0-only
//! Real maintained owner sessions; deliberately synthetic SQL grant metadata.
use super::super::*;
use crate::auth::{self, SessionCredentials, SessionPrincipal};
use axum::{
    body::{Body, Bytes},
    http::Request,
};
use futures_util::FutureExt;
use serde_json::{Value, json};
use std::{
    ops::AsyncFnOnce,
    panic::{AssertUnwindSafe, resume_unwind},
};
use tokio_postgres::{Client, NoTls};
use tower::ServiceExt;
use uuid::Uuid;

pub(super) const ORIGIN: &str = "https://example.test";
pub(super) const COLLECTION: &str = "/v1/owner/managed-ai/grants";

pub(super) fn request_scope() -> crate::managed_ai::GrantRequest {
    use crate::managed_ai::{PolicyIdentity, Selection, SourceKind};
    crate::managed_ai::GrantRequest {
        policy: PolicyIdentity {
            id: Uuid::new_v4(),
            version: 1,
            digest: [1; 32],
            reader: Uuid::new_v4(),
            reader_generation: 1,
        },
        contact: Uuid::new_v4(),
        purpose: crate::workflow_runtime::Purpose::Operational,
        instruction_digest: [2; 32],
        expires_ms: 1,
        max_calls: 8,
        max_input_bytes: 4000,
        max_cost_microunits: 40,
        selections: vec![Selection {
            kind: SourceKind::WorkflowContextV1,
            id: Uuid::new_v4(),
            version: 1,
            digest: [3; 32],
        }],
    }
}
pub(super) fn create_body(scope: &crate::managed_ai::GrantRequest) -> Value {
    json!({"password":"synthetic password", "factor":"synthetic factor", "request":scope})
}
pub(super) fn stalled_body() -> Body {
    Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>())
}
pub(super) fn assert_private(response: &Response) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    assert!(!response.headers().contains_key(header::SET_COOKIE));
}
pub(super) async fn json_response(response: Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1_048_576)
            .await
            .unwrap(),
    )
    .unwrap()
}
pub(super) fn unreachable_owner() -> OwnerConversationsState {
    OwnerConversationsState {
        database_url: String::new(),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(37)).unwrap()),
        canonical_origin: ORIGIN.into(),
    }
}

// The guard is installed immediately after CREATE SCHEMA, before migration/auth
// assertions. Fixture::run awaits cleanup before resuming an assertion unwind.
// Cancellation/runtime teardown retains only a best-effort Drop fallback.
struct SchemaCleanup {
    setup: Option<Client>,
    schema: String,
}
impl SchemaCleanup {
    async fn finish(&mut self) {
        self.setup
            .as_ref()
            .unwrap()
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
        drop(self.setup.take());
    }
}
impl Drop for SchemaCleanup {
    fn drop(&mut self) {
        if let Some(setup) = self.setup.take() {
            let schema = self.schema.clone();
            tokio::spawn(async move {
                let _ = setup
                    .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
                    .await;
            });
        }
    }
}
pub(super) struct Owner {
    pub principal: SessionPrincipal,
    pub credentials: SessionCredentials,
    pub password: String,
}
pub(super) struct Fixture {
    pub db: Client,
    pub url: String,
    pub hasher: Arc<TokenHasher>,
    pub owner: Owner,
    cleanup: SchemaCleanup,
}
impl Fixture {
    pub async fn new() -> Self {
        let base =
            std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable test database required");
        let (setup, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("managed_grant_http_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let mut cleanup = SchemaCleanup {
            setup: Some(setup),
            schema: schema.clone(),
        };
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let built = AssertUnwindSafe(async {
            let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            auth::test_schema::apply(&db).await;
            let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(37)).unwrap());
            let owner = Self::register(&mut db, &hasher).await;
            (db, hasher, owner)
        })
        .catch_unwind()
        .await;
        let (db, hasher, owner) = match built {
            Ok(value) => value,
            Err(panic) => {
                cleanup.finish().await;
                resume_unwind(panic)
            }
        };
        Self {
            db,
            url,
            hasher,
            owner,
            cleanup,
        }
    }
    pub async fn run<F>(body: F)
    where
        F: for<'a> AsyncFnOnce(&'a mut Self),
    {
        let mut fixture = Self::new().await;
        let result = AssertUnwindSafe(body(&mut fixture)).catch_unwind().await;
        fixture.finish().await;
        if let Err(panic) = result {
            resume_unwind(panic);
        }
    }
    async fn register(db: &mut Client, hasher: &TokenHasher) -> Owner {
        let password = Uuid::new_v4().to_string();
        let email = format!("{}@example.test", Uuid::new_v4().simple());
        let signup = auth::register(db, hasher, &email, &password).await.unwrap();
        assert!(
            auth::verify_email_with_password(db, hasher, &signup.verification_token, &password)
                .await
                .unwrap()
        );
        let credentials = auth::login(db, hasher, &email, &password).await.unwrap();
        let principal = auth::authenticate_session(db, hasher, &credentials.token)
            .await
            .unwrap();
        Owner {
            principal,
            credentials,
            password,
        }
    }
    pub async fn another_owner(&mut self) -> Owner {
        Self::register(&mut self.db, &self.hasher).await
    }
    pub fn state(&self) -> OwnerConversationsState {
        OwnerConversationsState {
            database_url: self.url.clone(),
            auth_hasher: self.hasher.clone(),
            canonical_origin: ORIGIN.into(),
        }
    }
    pub fn app(&self) -> Router {
        router(self.state(), None, true)
    }
    pub fn request(&self, owner: &Owner, method: &str, uri: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, ORIGIN)
            .header(
                header::COOKIE,
                format!(
                    "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                    owner.credentials.token, owner.credentials.csrf_token
                ),
            )
            .header("x-zrotext-csrf", &owner.credentials.csrf_token)
            .body(body)
            .unwrap()
    }
    pub async fn send(&self, app: Router, uri: &str, body: Value) -> Response {
        app.oneshot(self.request(&self.owner, "POST", uri, Body::from(body.to_string())))
            .await
            .unwrap()
    }
    pub async fn install_candidate(&self) {
        self.db
            .batch_execute(include_str!(
                "../../../../../deploy/compose/migration-candidates/managed_reader_grants.sql"
            ))
            .await
            .unwrap();
    }
    /// Direct SQL only: no claimed root/phone/service-reader/policy provenance.
    /// The intentionally non-cryptographic key bytes are never used by issuance.
    pub async fn synthetic_grant(
        &mut self,
        r: &crate::managed_ai::GrantRequest,
        version: i64,
    ) -> Uuid {
        let account = self.owner.principal.tenant.account_id();
        let id = Uuid::new_v4();
        let tx = self.db.transaction().await.unwrap();
        tx.execute("INSERT INTO managed_reader_keys(account_id,id,generation,key_id,key_point,expires_ms) VALUES($1,$2,1,$3,$4,1)", &[&account,&r.policy.reader,&vec![1u8;32],&vec![4u8;65]]).await.unwrap();
        tx.execute("INSERT INTO managed_reader_policies(account_id,id,version,digest,reader_id,reader_generation,provider_id,provider_version,provider_digest,budget_id,budget_version,budget_digest,expires_ms,max_calls,max_input_bytes,max_cost_microunits) VALUES($1,$2,1,$3,$4,1,$5,1,$6,$7,1,$6,1,8,4000,40)", &[&account,&r.policy.id,&r.policy.digest.as_slice(),&r.policy.reader,&Uuid::new_v4(),&vec![1u8;32],&Uuid::new_v4()]).await.unwrap();
        tx.execute("INSERT INTO managed_reader_grants(account_id,id,contact_id,purpose,current_version) VALUES($1,$2,$3,$4,$5)", &[&account,&id,&r.contact,&r.purpose.slug(),&version]).await.unwrap();
        let binding = serde_json::to_string(r).unwrap();
        tx.execute("INSERT INTO managed_reader_grant_versions(account_id,grant_id,id,version,policy_id,policy_version,policy_digest,reader_id,reader_generation,binding,created_by_user,created_session,created_ms) VALUES($1,$2,$3,$4,$5,1,$6,$7,1,$8::text::jsonb,$9,$10,1)", &[&account,&id,&Uuid::new_v4(),&version,&r.policy.id,&r.policy.digest.as_slice(),&r.policy.reader,&binding,&self.owner.principal.user_id,&self.owner.principal.session_id]).await.unwrap();
        for s in &r.selections {
            tx.execute("INSERT INTO managed_reader_selections(account_id,id,grant_id,grant_version,kind,source_id,source_version,digest) VALUES($1,$2,$3,$4,'workflow_context_v1',$5,$6,$7)", &[&account,&Uuid::new_v4(),&id,&version,&s.id,&s.version,&s.digest.as_slice()]).await.unwrap();
        }
        tx.execute("INSERT INTO managed_reader_events(account_id,id,grant_id,grant_version,operation,actor_user_id,actor_session_id,created_ms) VALUES($1,$2,$3,$4,'create',$5,$6,1)", &[&account,&Uuid::new_v4(),&id,&version,&self.owner.principal.user_id,&self.owner.principal.session_id]).await.unwrap();
        tx.commit().await.unwrap();
        id
    }
    pub async fn counts(&self) -> [i64; 6] {
        let mut result = [0; 6];
        for (i, table) in crate::managed_ai::lifecycle::TABLES.iter().enumerate() {
            result[i] = self
                .db
                .query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get(0);
        }
        result
    }
    pub async fn now(&self) -> i64 {
        self.db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
    pub async fn independent_client(&self) -> Client {
        let (db, connection) = tokio_postgres::connect(&self.url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        db
    }
    pub async fn finish(mut self) {
        self.cleanup.finish().await;
    }
}
