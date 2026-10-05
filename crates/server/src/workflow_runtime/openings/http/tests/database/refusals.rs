// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine owner auth and closed mounted wire"]
async fn authenticated_invalid_headers_queries_and_bodies_have_no_opening_effect() {
    let c = HttpCase::new().await;
    for path in [
        "/v1/owner/workflow/openings",
        "/v1/owner/workflow/openings/00000000-0000-0000-0000-000000000001/status",
    ] {
        for variant in ["missing", "duplicate", "uppercase", "nil", "csrf", "origin"] {
            let mut request = c.request(path).body(Body::from("not json")).unwrap();
            match variant {
                "missing" => {
                    request.headers_mut().remove(ACCOUNT_HEADER);
                }
                "duplicate" => {
                    request.headers_mut().append(
                        ACCOUNT_HEADER,
                        c.case.base.f.account.to_string().parse().unwrap(),
                    );
                }
                "uppercase" => {
                    request.headers_mut().insert(
                        ACCOUNT_HEADER,
                        "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA".parse().unwrap(),
                    );
                }
                "nil" => {
                    request
                        .headers_mut()
                        .insert(ACCOUNT_HEADER, Uuid::nil().to_string().parse().unwrap());
                }
                "csrf" => {
                    request
                        .headers_mut()
                        .insert("x-zrotext-csrf", "synthetic-mismatch".parse().unwrap());
                }
                "origin" => {
                    request
                        .headers_mut()
                        .insert(header::ORIGIN, "https://other.example".parse().unwrap());
                }
                _ => unreachable!(),
            }
            let response = router(c.state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{variant}");
            protected(&response);
            assert_eq!(c.counts().await, (0, 0));
        }
    }
    let valid = serde_json::to_string(&c.input().await).unwrap();
    let duplicate = valid.replacen("\"capacity\":2", "\"capacity\":2,\"capacity\":2", 1);
    assert_ne!(duplicate, valid);
    for body in ["[]", "{}", "null", duplicate.as_str()] {
        let response = router(c.state.clone())
            .oneshot(
                c.request("/v1/owner/workflow/openings")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        protected(&response);
    }
    let response = router(c.state.clone())
        .oneshot(
            c.request("/v1/owner/workflow/openings")
                .body(Body::from(vec![b' '; 8193]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    protected(&response);
    let response = c
        .send(
            "/v1/owner/workflow/openings/00000000-0000-0000-0000-000000000001/status?unused=1",
            &json!({}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    protected(&response);
    let response = c
        .send("/v1/owner/workflow/openings?unused=1", &c.input().await)
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    protected(&response);
    let path = "/v1/owner/workflow/openings/00000000-0000-0000-0000-000000000001/status";
    for body in [
        "[]",
        "{\"unexpected\":true}",
        "{\"unexpected\":true,\"unexpected\":false}",
    ] {
        let response = router(c.state.clone())
            .oneshot(c.request(path).body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        protected(&response);
    }
    assert_eq!(c.counts().await, (0, 0));
    assert_eq!(
        crate::http_auth::preauth::AccountSlot::in_flight(c.case.base.f.account),
        0
    );
    c.case
        .base
        .f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.session],
        )
        .await
        .unwrap();
    let response = c
        .send("/v1/owner/workflow/openings", &c.input().await)
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    protected(&response);
    c.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine observer membership and session"]
async fn observer_session_cannot_create_or_expire_openings() {
    let c = HttpCase::new().await;
    let user = Uuid::new_v4();
    let session = Uuid::new_v4();
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    c.case.base.f.db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,'unused',now())",
        &[&user, &format!("{}@example.test",user.simple())]).await.unwrap();
    c.case
        .base
        .f
        .db
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&c.case.base.f.account, &user],
        )
        .await
        .unwrap();
    c.case.base.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
        &[&session,&c.case.base.f.account,&user,&auth_hash(b"session-v1",&token),&auth_hash(b"csrf-v1",&csrf)]).await.unwrap();
    for path in [
        "/v1/owner/workflow/openings",
        "/v1/owner/workflow/openings/00000000-0000-0000-0000-000000000001/status",
    ] {
        let mut request = c.request(path).body(Body::from("not json")).unwrap();
        request.headers_mut().insert(
            header::COOKIE,
            format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}")
                .parse()
                .unwrap(),
        );
        request
            .headers_mut()
            .insert("x-zrotext-csrf", csrf.parse().unwrap());
        let principal = crate::http_auth::require_member(
            &c.case.base.f.db,
            &c.state.auth_hasher,
            &c.state.canonical_origin,
            request.headers(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(principal.user_id, user);
        assert_eq!(principal.tenant.account_id(), c.case.base.f.account);
        assert_eq!(principal.role, crate::auth::Role::Observer);
        let response = router(c.state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        protected(&response);
    }
    assert_eq!(c.counts().await, (0, 0));
    c.case.cleanup().await;
}
