// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine stored sessions and activated server authority. The context fixture
//! is structurally sealed; these tests do not claim HPKE producer/SDK pairing.
use super::*;
use crate::http_owner_conversations::context::decisions::tests::Case;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

mod refusals;

struct HttpCase {
    case: Case,
    state: OwnerConversationsState,
    cookie: String,
    csrf: String,
    session: Uuid,
}

fn auth_hash(domain: &[u8], token: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
    mac.update(domain);
    mac.update(&[0]);
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

impl HttpCase {
    async fn new() -> Self {
        let case = Case::new().await;
        let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let hasher = crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap();
        let session = Uuid::new_v4();
        case.base.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
            &[&session, &case.base.f.account, &case.base.owner.user_id,
                &auth_hash(b"session-v1", &token), &auth_hash(b"csrf-v1", &csrf)])
            .await.unwrap();
        let separator = if case.base.f.url.contains('?') {
            '&'
        } else {
            '?'
        };
        let state = OwnerConversationsState {
            database_url: format!(
                "{}{separator}options=-csearch_path%3D{}",
                case.base.f.url, case.base.f.schema
            ),
            auth_hasher: Arc::new(hasher),
            canonical_origin: "https://zrotext.example".into(),
        };
        let cookie = format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}");
        Self {
            case,
            state,
            cookie,
            csrf,
            session,
        }
    }

    fn request(&self, path: &str) -> axum::http::request::Builder {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::COOKIE, &self.cookie)
            .header(header::ORIGIN, &self.state.canonical_origin)
            .header("x-zrotext-csrf", &self.csrf)
            .header(ACCOUNT_HEADER, self.case.base.f.account.to_string())
            .header(header::CONTENT_TYPE, "application/json")
    }

    async fn input(&self) -> Value {
        let now: i64 = self
            .case
            .base
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        json!({"request_id":Uuid::new_v4(),"opening_id":Uuid::new_v4(),"capacity":2,
            "description":{"context_id":self.case.base.h.context,"revision":self.case.base.h.revision,
                "digest":Sha256::digest(self.case.base.bytes()).iter().map(|b|format!("{b:02x}")).collect::<String>()},
            "decision_deadline_ms":(now+30000).min(self.case.base.h.expires_ms-1000).to_string()})
    }

    async fn send(&self, path: &str, input: &Value) -> Response {
        router(self.state.clone())
            .oneshot(
                self.request(path)
                    .body(Body::from(serde_json::to_vec(input).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn counts(&self) -> (i64, i64) {
        let row = self.case.base.f.db.query_one(
            "SELECT (SELECT count(*) FROM workflow_openings),(SELECT count(*) FROM workflow_opening_requests)", &[])
            .await.unwrap();
        (row.get(0), row.get(1))
    }
}

async fn account_counts(c: &HttpCase, account: Uuid) -> (i64, i64) {
    let row = c.case.base.f.db.query_one("SELECT (SELECT count(*) FROM workflow_openings WHERE account_id=$1),(SELECT count(*) FROM workflow_opening_requests WHERE account_id=$1)", &[&account]).await.unwrap();
    (row.get(0), row.get(1))
}

async fn json_response(response: Response) -> Value {
    protected(&response);
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine stored owner sessions and isolated candidate schema"]
async fn intended_account_refusal_does_not_poll_body_or_mutate_either_account() {
    let a = HttpCase::new().await;
    // Both accounts and credentials coexist in the SAME schema and router.
    let b_account = Uuid::new_v4();
    let b_user = Uuid::new_v4();
    let b_token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let b_csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    a.case
        .base
        .f
        .db
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&b_account])
        .await
        .unwrap();
    a.case.base.f.db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,'unused',now())",
        &[&b_user,&format!("{}@example.test",b_user.simple())]).await.unwrap();
    a.case
        .base
        .f
        .db
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&b_account, &b_user],
        )
        .await
        .unwrap();
    a.case.base.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
        &[&Uuid::new_v4(),&b_account,&b_user,&auth_hash(b"session-v1",&b_token),&auth_hash(b"csrf-v1",&b_csrf)]).await.unwrap();
    let before_a = account_counts(&a, a.case.base.f.account).await;
    let before_b = account_counts(&a, b_account).await;
    let mut authenticated = a
        .request("/v1/owner/workflow/openings")
        .body(Body::empty())
        .unwrap();
    authenticated.headers_mut().insert(
        header::COOKIE,
        format!("__Host-zrotext_session={b_token}; __Host-zrotext_csrf={b_csrf}")
            .parse()
            .unwrap(),
    );
    authenticated
        .headers_mut()
        .insert("x-zrotext-csrf", b_csrf.parse().unwrap());
    let principal = crate::http_auth::require_owner(
        &a.case.base.f.db,
        &a.state.auth_hasher,
        &a.state.canonical_origin,
        authenticated.headers(),
        true,
    )
    .await
    .unwrap();
    assert_eq!(principal.tenant.account_id(), b_account);
    for path in [
        "/v1/owner/workflow/openings",
        "/v1/owner/workflow/openings/00000000-0000-0000-0000-000000000001/status",
    ] {
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(Some(Err::<axum::body::Bytes, _>(std::io::Error::other(
                "synthetic unread body",
            ))))
        }));
        let mut request = a.request(path).body(body).unwrap();
        request.headers_mut().insert(
            header::COOKIE,
            format!("__Host-zrotext_session={b_token}; __Host-zrotext_csrf={b_csrf}")
                .parse()
                .unwrap(),
        );
        request
            .headers_mut()
            .insert("x-zrotext-csrf", b_csrf.parse().unwrap());
        request.headers_mut().insert(
            ACCOUNT_HEADER,
            a.case.base.f.account.to_string().parse().unwrap(),
        );
        let response = router(a.state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        protected(&response);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }
    assert_eq!(account_counts(&a, a.case.base.f.account).await, before_a);
    assert_eq!(account_counts(&a, b_account).await, before_b);
    assert_eq!(
        crate::http_auth::preauth::AccountSlot::in_flight(b_account),
        0
    );
    a.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine authenticated mounted create and status"]
async fn mounted_create_exact_replay_conflict_and_status_preserve_typed_identity() {
    let c = HttpCase::new().await;
    let input = c.input().await;
    let created = json_response(c.send("/v1/owner/workflow/openings", &input).await).await;
    assert_eq!(created["account_id"], c.case.base.f.account.to_string());
    assert_eq!(created["request_id"], input["request_id"]);
    assert_eq!(created["outcome"]["applied"], true);
    assert_eq!(created["outcome"]["recorded"], true);
    assert_eq!(
        created["outcome"]["receipt"]["opening"]["opening_id"],
        input["opening_id"]
    );
    assert_eq!(created["outcome"]["receipt"]["pending"], "0");
    assert_eq!(created["outcome"]["receipt"]["confirmed"], "0");
    let replay = json_response(c.send("/v1/owner/workflow/openings", &input).await).await;
    assert_eq!(replay["outcome"]["applied"], false);
    assert_eq!(replay["outcome"]["receipt"], created["outcome"]["receipt"]);
    for field in ["capacity", "decision_deadline_ms", "description"] {
        let mut changed = input.clone();
        changed[field] = match field {
            "capacity" => json!(3),
            "decision_deadline_ms" => {
                json!((input[field].as_str().unwrap().parse::<i64>().unwrap() + 1).to_string())
            }
            _ => {
                let mut source = input[field].clone();
                source["revision"] = json!(2);
                source
            }
        };
        let response = c.send("/v1/owner/workflow/openings", &changed).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        protected(&response);
    }
    assert_eq!(c.counts().await, (1, 1));
    let path = format!(
        "/v1/owner/workflow/openings/{}/status",
        input["opening_id"].as_str().unwrap()
    );
    let status = json_response(c.send(&path, &json!({})).await).await;
    assert_eq!(status["receipt"], created["outcome"]["receipt"]);
    assert!(status.get("outcome").is_none());
    assert!(status.get("request_id").is_none());
    let mut client = c.case.base.f.connect().await;
    let tx = client.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &c.case.base.owner)
        .await
        .unwrap();
    crate::workflow_runtime::lifecycle::erase_context(
        &tx,
        c.case.base.f.account,
        c.case.base.h.context,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let refusal = c.send("/v1/owner/workflow/openings", &input).await;
    assert_eq!(refusal.status(), StatusCode::NOT_FOUND);
    protected(&refusal);
    let scrubbed_status = json_response(c.send(&path, &json!({})).await).await;
    assert_eq!(scrubbed_status["receipt"]["phase"], "closed");
    c.case.base.f.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1", &[&c.case.base.f.account]).await.unwrap();
    let refusal = c.send("/v1/owner/workflow/openings", &input).await;
    assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
    protected(&refusal);
    let status_after_root_loss = json_response(c.send(&path, &json!({})).await).await;
    assert_eq!(status_after_root_loss, scrubbed_status);
    assert_eq!(c.counts().await, (1, 1));
    c.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual absent and partial isolated opening schemas"]
async fn mounted_openings_refuse_absent_and_partial_candidate_before_effects() {
    for partial in [false, true] {
        let c = HttpCase::new().await;
        if partial {
            c.case
                .base
                .f
                .db
                .batch_execute("DROP TABLE workflow_opening_requests")
                .await
                .unwrap();
        } else {
            c.case
                .base
                .f
                .db
                .batch_execute(
                    "DROP TABLE workflow_opening_requests, workflow_opening_allocations, \
             workflow_opening_offers, workflow_openings CASCADE
",
                )
                .await
                .unwrap();
        }
        let input = c.input().await;
        let context_count: i64 = c
            .case
            .base
            .f
            .db
            .query_one("SELECT count(*) FROM workflow_contexts", &[])
            .await
            .unwrap()
            .get(0);
        let response = c.send("/v1/owner/workflow/openings", &input).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        protected(&response);
        let response = c
            .send(
                "/v1/owner/workflow/openings/00000000-0000-0000-0000-000000000001/status",
                &json!({}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        protected(&response);
        assert_eq!(
            c.case
                .base
                .f
                .db
                .query_one("SELECT count(*) FROM workflow_contexts", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            context_count
        );
        if partial {
            assert_eq!(
                c.case
                    .base
                    .f
                    .db
                    .query_one("SELECT count(*) FROM workflow_openings", &[])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                0
            );
        } else {
            for name in [
                "workflow_openings",
                "workflow_opening_offers",
                "workflow_opening_allocations",
                "workflow_opening_requests",
            ] {
                assert!(
                    c.case
                        .base
                        .f
                        .db
                        .query_one("SELECT to_regclass($1)::text", &[&name])
                        .await
                        .unwrap()
                        .get::<_, Option<String>>(0)
                        .is_none()
                );
            }
        }
        assert_eq!(
            crate::http_auth::preauth::AccountSlot::in_flight(c.case.base.f.account),
            0
        );
        c.case.cleanup().await;
    }
}
