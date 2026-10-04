// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::OwnerConversationsState;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac, digest::KeyInit};
use serde_json::{Value, json};
use sha2::Sha256;
use std::sync::Arc;
use tower::ServiceExt;

const BASE: &str = "/v1/owner/exposure/test";
const ORIGIN: &str = "https://zrotext.example";

fn state(database_url: String) -> OwnerConversationsState {
    OwnerConversationsState {
        database_url,
        auth_hasher: Arc::new(crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap()),
        canonical_origin: ORIGIN.into(),
    }
}
#[tokio::test]
async fn exposure_http_is_unmounted_by_default_and_authenticates_before_body_or_storage() {
    let state = state("postgres://unused".into());
    for path in ["reserve", "cancel", "first-intent", "settle"] {
        let response = super::super::http::router(state.clone(), false)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("{BASE}/{path}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    for path in ["reserve", "cancel"] {
        for bearer in [false, true] {
            let mut request = Request::builder()
                .method("POST")
                .uri(format!("{BASE}/{path}"));
            if bearer {
                request = request
                    .header(header::AUTHORIZATION, "Bearer synthetic")
                    .header(header::COOKIE, "__Host-zrotext_session=synthetic");
            }
            let response = super::super::http::router(state.clone(), true)
                .oneshot(request.body(Body::from(vec![0; 2049])).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
        }
    }
    let response = super::super::http::router(state, true)
        .oneshot(
            Request::builder()
                .uri(format!("{BASE}/{}", Uuid::new_v4()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

struct Browser {
    app: Router,
    cookie: String,
    csrf: String,
}
impl Browser {
    async fn new(f: &Fixture) -> Self {
        let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let hash = |domain: &[u8], value: &str| {
            let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
            mac.update(domain);
            mac.update(&[0]);
            mac.update(value.as_bytes());
            mac.finalize().into_bytes().to_vec()
        };
        f.case
            .base
            .f
            .db
            .execute(
                "UPDATE sessions SET token_hash=$2,csrf_hash=$3 WHERE id=$1",
                &[
                    &f.case.base.owner.session_id,
                    &hash(b"session-v1", &token),
                    &hash(b"csrf-v1", &csrf),
                ],
            )
            .await
            .unwrap();
        let fixture = &f.case.base.f;
        let separator = if fixture.url.contains('?') { '&' } else { '?' };
        let url = format!(
            "{}{separator}options=-csearch_path%3D{}",
            fixture.url, fixture.schema
        );
        Self {
            app: super::super::http::router(state(url), true),
            cookie: format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}"),
            csrf,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        value: Value,
        origin: &str,
        csrf: bool,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{BASE}/{path}"))
            .header(header::COOKIE, &self.cookie)
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json");
        if csrf {
            request = request.header("x-zrotext-csrf", &self.csrf);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(value.to_string())).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let status = response.status();
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (status, value)
    }
    async fn post(&self, path: &str, value: Value) -> (StatusCode, Value) {
        self.request("POST", path, value, ORIGIN, true).await
    }
    async fn get(&self, id: Uuid) -> (StatusCode, Value) {
        self.request("GET", &id.to_string(), Value::Null, ORIGIN, true)
            .await
    }
}
fn request(f: &Fixture, id: Uuid) -> Value {
    json!({"action":f.action,"route_policy_id":f.route,"reservation_id":id})
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual owner TEST HTTP and isolated synthetic schema"]
async fn exposure_http_reserves_server_bound_once_and_cleans_unstarted_work_without_stripe() {
    let f = Fixture::new(1).await;
    let browser = Browser::new(&f).await;
    let id = Uuid::new_v4();
    assert_eq!(
        browser
            .request(
                "POST",
                "reserve",
                request(&f, id),
                "https://other.example",
                true
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        browser
            .request("POST", "reserve", request(&f, id), ORIGIN, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let mut cost = request(&f, id);
    cost["maximum_units"] = json!(0);
    assert_eq!(
        browser.post("reserve", cost).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut foreign = f.action;
    foreign.account_id = Uuid::new_v4();
    assert_eq!(
        browser
            .post(
                "reserve",
                json!({"action":foreign,"route_policy_id":f.route,"reservation_id":id})
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.liability().await, (0, 0));
    let (status, value) = browser.post("reserve", request(&f, id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["maximum_units"], "1");
    assert_eq!(value["created"], true);
    assert_eq!(value["execution_authorized"], false);
    let replay = browser.post("reserve", request(&f, id)).await;
    assert_eq!(replay.0, StatusCode::OK);
    assert_eq!(replay.1["created"], false);
    let second = f.another_action().await;
    assert_eq!(
        browser
            .post(
                "reserve",
                json!({"action":second,"route_policy_id":f.route,"reservation_id":Uuid::new_v4()})
            )
            .await
            .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(f.liability().await, (1, 0));
    let (status, value) = browser.get(id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["state"], "reserved");
    assert_eq!(value["intent_issued"], false);
    assert!(value.get("lease_id").is_none());
    assert_eq!(browser.get(Uuid::new_v4()).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        f.case
            .base
            .f
            .db
            .query_one("SELECT count(*) FROM billing_customers", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    // Policy withdrawal does not block status/cleanup or manufacture execution.
    f.case
        .base
        .f
        .db
        .execute("UPDATE exposure_route_policies SET enabled=false", &[])
        .await
        .unwrap();
    let cancel = json!({"reservation_id":id});
    assert_eq!(
        browser.post("cancel", cancel.clone()).await.1["changed"],
        true
    );
    assert_eq!(browser.post("cancel", cancel).await.1["changed"], false);
    assert_eq!(browser.get(id).await.1["state"], "released");
    assert_eq!(f.liability().await, (0, 0));
    assert_eq!(
        f.case
            .base
            .f
            .db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual owner TEST HTTP and isolated synthetic schema"]
async fn exposure_http_never_releases_issued_intent_or_serves_revoked_or_foreign_owner() {
    let f = Fixture::new(2).await;
    let browser = Browser::new(&f).await;
    let id = Uuid::new_v4();
    assert_eq!(
        browser.post("reserve", request(&f, id)).await.0,
        StatusCode::OK
    );
    let engine = TestExposure::synthetic_candidate();
    engine
        .first_test_intent(
            &mut f.case.base.f.connect().await,
            &f.case.base.owner,
            f.action,
            id,
        )
        .await
        .unwrap();
    assert_eq!(browser.get(id).await.1["intent_issued"], true);
    assert_eq!(
        browser.post("cancel", json!({"reservation_id":id})).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(f.liability().await, (1, 0));
    // A valid foreign owner receives the same missing status as an absent UUID.
    let (account, user, session) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    f.case
        .base
        .f
        .db
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    f.case.base.f.db.execute("INSERT INTO users(id,email,password_hash,email_verified_at,mfa_enabled) VALUES($1,$2,'unused',clock_timestamp(),true)",&[&user,&format!("{}@example.test",user.simple())]).await.unwrap();
    f.case
        .base
        .f
        .db
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&account, &user],
        )
        .await
        .unwrap();
    f.case
        .base
        .f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&f.case.base.owner.session_id],
        )
        .await
        .unwrap();
    assert_ne!(browser.get(id).await.0, StatusCode::OK);
    assert_ne!(
        browser.post("reserve", request(&f, Uuid::new_v4())).await.0,
        StatusCode::OK
    );
    assert_ne!(
        browser.post("cancel", json!({"reservation_id":id})).await.0,
        StatusCode::OK
    );
    let hashes = f
        .case
        .base
        .f
        .db
        .query_one(
            "SELECT token_hash,csrf_hash FROM sessions WHERE id=$1",
            &[&f.case.base.owner.session_id],
        )
        .await
        .unwrap();
    f.case
        .base
        .f
        .db
        .execute(
            "UPDATE sessions SET token_hash=sha256(token_hash) WHERE id=$1",
            &[&f.case.base.owner.session_id],
        )
        .await
        .unwrap();
    f.case.base.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
        &[&session,&account,&user,&hashes.get::<_,Vec<u8>>(0),&hashes.get::<_,Vec<u8>>(1)]).await.unwrap();
    assert_eq!(browser.get(id).await.0, StatusCode::NOT_FOUND);
    assert_eq!(browser.get(Uuid::new_v4()).await.0, StatusCode::NOT_FOUND);
    assert_ne!(
        browser.post("cancel", json!({"reservation_id":id})).await.0,
        StatusCode::OK
    );
    assert_eq!(f.liability().await, (1, 0));
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual owner TEST HTTP and isolated synthetic schema"]
async fn exposure_http_refuses_cancelled_actions_and_uncertain_hosted_entitlement() {
    let f = Fixture::new(2).await;
    let browser = Browser::new(&f).await;
    let current = decisions::read(
        &mut f.case.base.f.connect().await,
        &f.case.base.owner,
        f.action,
    )
    .await
    .unwrap();
    decisions::decide(
        &mut f.case.base.f.connect().await,
        &f.case.base.owner,
        Uuid::new_v4(),
        current.record_version,
        f.action,
        Decision::Cancel,
    )
    .await
    .unwrap();
    assert_ne!(
        browser.post("reserve", request(&f, Uuid::new_v4())).await.0,
        StatusCode::OK
    );
    let second = f.another_action().await;
    f.case.base.f.db.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_exposurehttpfixture')",&[&f.action.account_id]).await.unwrap();
    assert_ne!(
        browser
            .post(
                "reserve",
                json!({"action":second,"route_policy_id":f.route,"reservation_id":Uuid::new_v4()})
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(f.liability().await, (0, 0));
    assert_eq!(
        f.case
            .base
            .f
            .db
            .query_one("SELECT count(*) FROM exposure_reservations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.case.cleanup().await;
}
