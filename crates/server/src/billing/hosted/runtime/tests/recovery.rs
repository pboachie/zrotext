// SPDX-License-Identifier: AGPL-3.0-only
use super::{fixture::*, *};
use axum::{
    body::{Body, to_bytes},
    http::StatusCode,
};
use serde_json::Value;
use tower::ServiceExt;
async fn read(f: &Fixture, r: &Arc<Runtime>) -> Value {
    let response = r
        .router()
        .oneshot(f.request("/status", "GET"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}
async fn pending(f: &Fixture) -> Arc<Runtime> {
    let r = f.runtime(Mode::Live).await;
    f.fake.inner.lock().unwrap().lose_checkout = true;
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    f.runtime(Mode::Live).await
}
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; explicit same-operation recovery refusals"]
async fn checkout_recovery_refuses_unstarted_known_terminal_unbound_expired_changed_and_risky_operations_without_provider_mutations()
 {
    let mut f = Fixture::new(Mode::Live).await;
    let r = f.runtime(Mode::Live).await;
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert!(f.fake.inner.lock().unwrap().operations.is_empty());
    let r = pending(&f).await;
    let row = f
        .database
        .owner
        .query_one(
            "SELECT checkout_started_at,checkout_request_digest FROM hosted_billing_customers",
            &[],
        )
        .await
        .unwrap();
    let started: i64 = row.get(0);
    let digest: Vec<u8> = row.get(1);
    let none = f
        .fake
        .inner
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|(method, path)| method == "POST" && path == "/v1/customers")
        .count();
    for state in ["none", "open", "complete", "expired"] {
        f.database
            .owner
            .execute(
                "UPDATE hosted_billing_customers SET checkout_state=$1",
                &[&state],
            )
            .await
            .unwrap();
        assert_eq!(
            r.router()
                .oneshot(f.request("/checkout/recover", "POST"))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
    }
    f.database
        .owner
        .execute(
            "UPDATE hosted_billing_customers SET checkout_state='pending'",
            &[],
        )
        .await
        .unwrap();
    f.database
        .owner
        .execute(
            "UPDATE hosted_billing_customers SET checkout_id='cs_fixture'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    f.database
        .owner
        .execute("UPDATE hosted_billing_customers SET checkout_id=NULL", &[])
        .await
        .unwrap();

    for when in [started - 23 * 60 * 60 - 5, started + 60] {
        f.database
            .owner
            .execute(
                "UPDATE hosted_billing_customers SET checkout_started_at=$1",
                &[&when],
            )
            .await
            .unwrap();
        assert_eq!(read(&f, &r).await["checkout"]["state"], "pending");
        assert_eq!(
            r.router()
                .oneshot(f.request("/checkout/recover", "POST"))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
    }
    f.database.owner.execute("UPDATE hosted_billing_customers SET checkout_started_at=$1,checkout_request_digest=NULL",&[&started]).await.unwrap();
    assert_eq!(read(&f, &r).await["checkout"]["state"], "pending");
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    f.database
        .owner
        .execute(
            "UPDATE hosted_billing_customers SET checkout_request_digest=$1",
            &[&&[0u8; 32][..]],
        )
        .await
        .unwrap();
    assert_eq!(read(&f, &r).await["checkout"]["state"], "pending");
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    f.database
        .owner
        .execute(
            "UPDATE hosted_billing_customers SET checkout_request_digest=$1,payment_hold=true",
            &[&digest],
        )
        .await
        .unwrap();
    assert_eq!(read(&f, &r).await["checkout"]["state"], "pending");
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    f.database
        .owner
        .execute(
            "UPDATE hosted_billing_customers SET payment_hold=false,review_required=true",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    f.database
        .owner
        .execute(
            "UPDATE hosted_billing_customers SET review_required=false",
            &[],
        )
        .await
        .unwrap();
    f.database
        .owner
        .execute(
            "UPDATE hosted_billing_namespaces SET review_required=true",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(read(&f, &r).await["checkout"]["state"], "pending");
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    f.database
        .owner
        .execute(
            "UPDATE hosted_billing_namespaces SET review_required=false",
            &[],
        )
        .await
        .unwrap();
    let mut request = f.request("/checkout/recover", "POST");
    request.headers_mut().remove("x-zrotext-csrf");
    assert_eq!(
        r.router().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut request = f.request("/checkout/recover", "POST");
    *request.body_mut() = Body::from("{\"price\":\"price_foreign\"}");
    assert_eq!(
        r.router().oneshot(request).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    let password = crate::test_keys::password(4);
    let signup = crate::auth::register(
        &mut f.database.owner,
        &f.auth.hasher,
        "other@example.test",
        &password,
    )
    .await
    .unwrap();
    crate::auth::verify_email(
        &mut f.database.owner,
        &f.auth.hasher,
        &signup.verification_token,
    )
    .await
    .unwrap();
    let other = crate::auth::login(
        &f.database.owner,
        &f.auth.hasher,
        "other@example.test",
        &password,
    )
    .await
    .unwrap();
    let mut request = f.request("/checkout/recover", "POST");
    request.headers_mut().insert(
        "cookie",
        format!(
            "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
            other.token, other.csrf_token
        )
        .parse()
        .unwrap(),
    );
    request
        .headers_mut()
        .insert("x-zrotext-csrf", other.csrf_token.parse().unwrap());
    assert_eq!(
        r.router().oneshot(request).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    f.database
        .owner
        .execute("UPDATE sessions SET revoked_at=clock_timestamp()", &[])
        .await
        .unwrap();
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    {
        let s = f.fake.inner.lock().unwrap();
        assert_eq!(s.operations.len(), 1);
        assert_eq!(
            s.requests
                .iter()
                .filter(|(method, path)| method == "POST" && path == "/v1/customers")
                .count(),
            none
        );
    }
    drop(r);
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; same operation recovered already closed"]
async fn checkout_recovery_after_restart_returns_closed_observation_without_new_operation_or_redirect()
 {
    let f = Fixture::new(Mode::Live).await;
    let r = pending(&f).await;
    f.fake.inner.lock().unwrap().checkout.as_mut().unwrap()["status"] =
        serde_json::json!("complete");
    let response = r
        .router()
        .oneshot(f.request("/checkout/recover", "POST"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert!(body["url"].is_null());
    assert_eq!(
        read(&f, &r).await["checkout"]["state"],
        "reconciliation_required"
    );
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    {
        let s = f.fake.inner.lock().unwrap();
        assert_eq!(s.operations.len(), 2);
        assert_eq!(s.operations[0], s.operations[1]);
    }
    drop(r);
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; changed runtime terms cannot rewrite pending intent"]
async fn pending_checkout_recovery_refuses_changed_runtime_terms_without_replaying_provider_operation()
 {
    let f = Fixture::new(Mode::Live).await;
    let _old = pending(&f).await;
    for case in 0..4 {
        let mut changed = options(Mode::Live);
        match case {
            0 => changed.automatic_tax = true,
            1 => changed.plan = Plan::new("price_fixture", 9, 2, 7 * 24 * 3600).unwrap(),
            2 => changed.plan = Plan::new("price_fixture", 10, 1, 7 * 24 * 3600).unwrap(),
            _ => changed.plan = Plan::new("price_fixture", 10, 2, 24 * 3600).unwrap(),
        }
        let r = Runtime::start_with(
            f.auth.clone(),
            changed,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Notify::new()),
            provider::Provider::fake(f.base.clone()),
        )
        .await
        .unwrap();
        assert_eq!(read(&f, &r).await["checkout"]["state"], "pending");
        assert_eq!(
            r.router()
                .oneshot(f.request("/checkout/recover", "POST"))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(f.fake.inner.lock().unwrap().operations.len(), 1);
        drop(r);
    }
    f.cleanup().await;
}
