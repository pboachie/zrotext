// SPDX-License-Identifier: AGPL-3.0-only
//! Real public authentication and transactions over explicitly synthetic grants.
use super::*;
use crate::http_auth::preauth::{ACCOUNT_IN_FLIGHT, AccountSlot};

fn operation(id: Uuid, name: &str) -> String {
    format!("{COLLECTION}/{id}/{name}")
}
async fn head(f: &Fixture, id: Uuid) -> (i64, i64, Option<i64>) {
    let row = f.db.query_one("SELECT current_version,revocation_generation,revoked_ms FROM managed_reader_grants WHERE account_id=$1 AND id=$2", &[&f.owner.principal.tenant.account_id(),&id]).await.unwrap();
    (row.get(0), row.get(1), row.get(2))
}
async fn wait_for_slots(account: Uuid, count: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while AccountSlot::in_flight(account) != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn production_issuance_refuses_installed_synthetic_metadata_without_factor_effects() {
    Fixture::run(async |f| {
    f.install_candidate().await;
    let scope = request_scope();
    let id = f.synthetic_grant(&scope, 1).await;
    let before = f.counts().await;
    let cipher = Arc::new(MfaCipher::new(crate::test_keys::key(37)).unwrap());
    let app = router(f.state(), Some(cipher), true);
    let auth_before: (bool, i64) = {
        let row = f.db.query_one("SELECT mfa_enabled,(SELECT count(*) FROM auth_abuse_counters) FROM users WHERE id=$1", &[&f.owner.principal.user_id]).await.unwrap();
        (row.get(0), row.get(1))
    };
    let response = f.send(app.clone(), COLLECTION, create_body(&scope)).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_private(&response);
    assert_eq!(json_response(response).await, json!({"code":"unavailable"}));
    let mut replacement = create_body(&scope);
    replacement["expected_version"] = json!(1);
    let response = f.send(app, &operation(id, "replace"), replacement).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_private(&response);
    assert_eq!(f.counts().await, before);
    assert_eq!(head(f, id).await, (1, 0, None));
    let row =
        f.db.query_one(
            "SELECT mfa_enabled,(SELECT count(*) FROM auth_abuse_counters) FROM users WHERE id=$1",
            &[&f.owner.principal.user_id],
        )
        .await
        .unwrap();
    assert_eq!((row.get::<_, bool>(0), row.get::<_, i64>(1)), auth_before);

    }).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn expired_reduction_accepts_empty_zero_scope_and_revoke_is_idempotent_at_128() {
    Fixture::run(async |f| {
        f.install_candidate().await;
        let old = request_scope();
        let id = f.synthetic_grant(&old, 127).await;
        // Synthetic reader/policy expired at 1; there is no root or archive source.
        // Reduction also remains available to an already MFA-enabled owner session.
        f.db.execute(
            "UPDATE users SET mfa_enabled=true WHERE id=$1",
            &[&f.owner.principal.user_id],
        )
        .await
        .unwrap();
        let mut reduced = old.clone();
        reduced.selections.clear();
        reduced.max_calls = 0;
        reduced.max_input_bytes = 0;
        reduced.max_cost_microunits = 0;
        let response = f
            .send(
                f.app(),
                &operation(id, "narrow"),
                json!({"expected_version":127,"request":reduced}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_private(&response);
        assert_eq!(
            json_response(response).await,
            json!({"grant_id":id,"current_version":128})
        );
        assert_eq!(head(f, id).await, (128, 0, None));
        for _ in 0..2 {
            let response = f.send(f.app(), &operation(id, "revoke"), json!({})).await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_private(&response);
            assert!(
                axum::body::to_bytes(response.into_body(), 1)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        let (version, generation, revoked) = head(f, id).await;
        assert_eq!((version, generation), (128, 1));
        assert!(revoked.is_some());
        let row =
        f.db.query_one(
            "SELECT count(*) FROM managed_reader_events WHERE grant_id=$1 AND operation='revoke'",
            &[&id],
        )
        .await
        .unwrap();
        assert_eq!(row.get::<_, i64>(0), 1);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn absent_and_partial_schema_refuse_without_creating_grants() {
    Fixture::run(async |f| {
        let id = Uuid::new_v4();
        for body in [
            json!({"expected_version":1,"request":request_scope()}),
            json!({}),
        ] {
            let name = if body.get("request").is_some() {
                "narrow"
            } else {
                "revoke"
            };
            let response = f.send(f.app(), &operation(id, name), body).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_private(&response);
        }
        f.db.batch_execute("CREATE TABLE managed_reader_keys(synthetic_marker integer)")
            .await
            .unwrap();
        let response = f.send(f.app(), &operation(id, "revoke"), json!({})).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json_response(response).await, json!({"code":"unavailable"}));
        let row =
            f.db.query_one("SELECT count(*) FROM managed_reader_keys", &[])
                .await
                .unwrap();
        assert_eq!(row.get::<_, i64>(0), 0);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn real_owner_csrf_role_and_account_boundaries_precede_poisoned_body() {
    Fixture::run(async |f| {
        f.install_candidate().await;
        let old = request_scope();
        let id = f.synthetic_grant(&old, 1).await;
        let other = f.another_owner().await;
        let before = f.counts().await;
        let response = f
            .app()
            .oneshot(f.request(&other, "POST", &operation(id, "revoke"), Body::from("{}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        for (header_name, value) in [
            (header::ORIGIN.as_str(), "https://other.example.test"),
            ("x-zrotext-csrf", "synthetic mismatch"),
        ] {
            let mut request = f.request(&f.owner, "POST", &operation(id, "revoke"), stalled_body());
            request.headers_mut().insert(
                header_name.parse::<header::HeaderName>().unwrap(),
                value.parse().unwrap(),
            );
            let response = tokio::time::timeout(Duration::from_secs(1), f.app().oneshot(request))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_private(&response);
        }
        let observer = f.observer().await;
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            f.app()
                .oneshot(f.request(&observer, "POST", &operation(id, "revoke"), stalled_body())),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_private(&response);
        f.db.execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&f.owner.principal.session_id],
        )
        .await
        .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            f.app()
                .oneshot(f.request(&f.owner, "POST", &operation(id, "revoke"), stalled_body())),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_private(&response);
        assert_eq!(f.counts().await, before);
        assert_eq!(head(f, id).await, (1, 0, None));
    })
    .await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn authenticated_stalled_bodies_hold_four_slots_and_cancel_or_timeout_releases_them() {
    Fixture::run(async |f| {
        f.install_candidate().await;
        let other = f.another_owner().await;
        let account = f.owner.principal.tenant.account_id();
        let mut tasks = Vec::new();
        for _ in 0..ACCOUNT_IN_FLIGHT {
            let app = f.app();
            let request = f.request(&f.owner, "POST", COLLECTION, stalled_body());
            tasks.push(tokio::spawn(
                async move { app.oneshot(request).await.unwrap() },
            ));
        }
        wait_for_slots(account, ACCOUNT_IN_FLIGHT).await;
        let response = f
            .send(f.app(), COLLECTION, create_body(&request_scope()))
            .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_private(&response);
        let response = f
            .app()
            .oneshot(f.request(
                &other,
                "POST",
                &operation(Uuid::new_v4(), "revoke"),
                Body::from("{}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            assert!(task.await.unwrap_err().is_cancelled());
        }
        wait_for_slots(account, 0).await;
        let app = routed(
            Arc::new(GrantHttpState {
                owner: f.state(),
                cipher: None,
            }),
            Duration::from_millis(50),
        );
        let response = app
            .oneshot(f.request(&f.owner, "POST", COLLECTION, stalled_body()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_private(&response);
        wait_for_slots(account, 0).await;
    })
    .await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn stale_widened_changed_identity_and_concurrent_versions_do_not_partially_commit() {
    Fixture::run(async |f| {
    f.install_candidate().await;
    let old = request_scope();
    let id = f.synthetic_grant(&old, 1).await;
    let before = f.counts().await;
    let mut wider = old.clone();
    wider.max_calls += 1;
    let mut identity = old.clone();
    identity.instruction_digest = [9; 32];
    let mut policy=old.clone(); policy.policy.id=Uuid::new_v4();
    let mut contact=old.clone(); contact.contact=Uuid::new_v4();
    let mut purpose=old.clone(); purpose.purpose=crate::workflow_runtime::Purpose::Marketing;
    let mut source=old.clone(); source.selections[0].digest=[8;32];
    for (version, scope, status) in [(2, old.clone(), 409), (1, wider, 403), (1, identity, 403),(1,policy,403),(1,contact,403),(1,purpose,403),(1,source,403)] {
        let response = f
            .send(
                f.app(),
                &operation(id, "narrow"),
                json!({"expected_version":version,"request":scope}),
            )
            .await;
        assert_eq!(response.status().as_u16(), status);
        assert_private(&response);
        assert_eq!(f.counts().await, before);
        assert_eq!(head(f, id).await, (1, 0, None));
    }
    f.db.batch_execute("CREATE FUNCTION synthetic_reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic rollback control'; END $$; CREATE TRIGGER synthetic_reject_event BEFORE INSERT ON managed_reader_events FOR EACH ROW EXECUTE FUNCTION synthetic_reject_event()").await.unwrap();
    let body = json!({"expected_version":1,"request":old});
    let response = f
        .send(f.app(), &operation(id, "narrow"), body.clone())
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(f.counts().await, before);
    assert_eq!(head(f, id).await, (1, 0, None));
    f.db.batch_execute("DROP TRIGGER synthetic_reject_event ON managed_reader_events; DROP FUNCTION synthetic_reject_event()").await.unwrap();
    // Synthetic SQL scheduling hook: expire the authenticated session AFTER
    // the grant/version writes, so only the final fresh-owner fence rejects.
    // Its session update must roll back with every metadata write.
    f.db.batch_execute("CREATE FUNCTION synthetic_expire_after_writes() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=NEW.actor_session_id; RETURN NEW; END $$; CREATE TRIGGER synthetic_expire_after_writes BEFORE INSERT ON managed_reader_events FOR EACH ROW EXECUTE FUNCTION synthetic_expire_after_writes()").await.unwrap();
    let response = f
        .send(f.app(), &operation(id, "narrow"), body.clone())
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.counts().await, before);
    assert_eq!(head(f, id).await, (1, 0, None));
    assert!(
        f.db.query_one(
            "SELECT expires_at>clock_timestamp() FROM sessions WHERE id=$1",
            &[&f.owner.principal.session_id]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    f.db.batch_execute("DROP TRIGGER synthetic_expire_after_writes ON managed_reader_events; DROP FUNCTION synthetic_expire_after_writes()").await.unwrap();
    let uri = operation(id, "narrow");
    let (a, b) = tokio::join!(
        f.send(f.app(), &uri, body.clone()),
        f.send(f.app(), &uri, body)
    );
    let mut statuses = [a.status().as_u16(), b.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 409]);
    assert_eq!(head(f, id).await, (2, 0, None));
    let row=f.db.query_one("SELECT binding::text FROM managed_reader_grant_versions WHERE grant_id=$1 AND version=2", &[&id]).await.unwrap();
    assert_eq!(serde_json::from_str::<crate::managed_ai::GrantRequest>(&row.get::<_,String>(0)).unwrap(),old);
    assert!(f.db.execute("UPDATE managed_reader_grant_versions SET binding=binding WHERE grant_id=$1 AND version=1", &[&id]).await.is_err());
    let response = f.send(f.app(), &operation(id, "revoke"), json!({})).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = f
        .send(
            f.app(),
            &operation(id, "narrow"),
            json!({"expected_version":2,"request":old}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    }).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn owner_session_expiry_committed_while_account_lock_waits_refuses_mutation() {
    Fixture::run(async |f| {
        f.install_candidate().await;
        let old = request_scope();
        let id = f.synthetic_grant(&old, 1).await;
        let before = f.counts().await;
        let account = f.owner.principal.tenant.account_id();
        let mut blocker = f.independent_client().await;
        let tx = blocker.transaction().await.unwrap();
        tx.query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[&account],
        )
        .await
        .unwrap();
        let app = f.app();
        let request = f.request(
            &f.owner,
            "POST",
            &operation(id, "narrow"),
            Body::from(json!({"expected_version":1,"request":old}).to_string()),
        );
        let task = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
        wait_for_slots(account, 1).await;
        f.db.execute(
            "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
            &[&f.owner.principal.session_id],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let response = task.await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_private(&response);
        assert_eq!(f.counts().await, before);
        assert_eq!(head(f, id).await, (1, 0, None));
        wait_for_slots(account, 0).await;

        // Independently restore this synthetic clock edge, then exercise an actual
        // operation deadline while its transaction queues behind the account lock.
        f.db.execute(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1",
            &[&f.owner.principal.session_id],
        )
        .await
        .unwrap();
        let tx = blocker.transaction().await.unwrap();
        tx.query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[&account],
        )
        .await
        .unwrap();
        let app = routed(
            Arc::new(GrantHttpState {
                owner: f.state(),
                cipher: None,
            }),
            Duration::from_millis(500),
        );
        let response = app
            .oneshot(f.request(&f.owner, "POST", &operation(id, "revoke"), Body::from("{}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_private(&response);
        tx.commit().await.unwrap();
        assert_eq!(f.counts().await, before);
        assert_eq!(head(f, id).await, (1, 0, None));
        wait_for_slots(account, 0).await;
    })
    .await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn maintained_consent_withdrawal_does_not_revive_grants_after_renewal() {
    Fixture::run(async |f| {
    f.install_candidate().await;
    let scope = request_scope();
    let id = f.synthetic_grant(&scope, 1).await;
    // Synthetic routing identity, never a real destination or provider action.
    let recipient = "+12";
    f.db.execute(
        "INSERT INTO contacts(id,account_id,recipient_e164) VALUES($1,$2,$3)",
        &[
            &scope.contact,
            &f.owner.principal.tenant.account_id(),
            &recipient,
        ],
    )
    .await
    .unwrap();
    let app = crate::http_owner_contacts::router(crate::http_owner_contacts::OwnerContactsState {
        database_url: f.url.clone(),
        auth_hasher: f.hasher.clone(),
        canonical_origin: ORIGIN.into(),
        vault: None,
    });
    let uri = format!("/v1/owner/contacts/{}/consents", scope.contact);
    for (offset, action) in [(3000, "grant"), (2000, "withdraw"), (1000, "grant")] {
        let response=f.send(app.clone(),&uri,json!({"purpose":"operational","action":action,"source":"manual_entry","effective_at_ms":f.now().await-offset,"expires_at_ms":null})).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(head(f, id).await.1, 1);
    assert!(head(f, id).await.2.is_some());
    let row =
        f.db.query_one(
            "SELECT count(*) FROM managed_reader_events WHERE grant_id=$1 AND operation='withdraw'",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    let response = f
        .send(
            f.app(),
            &operation(id, "narrow"),
            json!({"expected_version":1,"request":scope}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    }).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn owner_export_pages_grants_twenty_at_a_time_with_real_account_isolation() {
    Fixture::run(async |f| {
        f.install_candidate().await;
        let mut ids = Vec::new();
        for _ in 0..21 {
            ids.push(f.synthetic_grant(&request_scope(), 1).await);
        }
        ids.sort();
        let app = crate::http_owner_export::router(crate::http_owner_export::OwnerExportState {
            database_url: f.url.clone(),
            auth_hasher: f.hasher.clone(),
            canonical_origin: ORIGIN.into(),
            contacts_vault: None,
        });
        let response = app
            .clone()
            .oneshot(f.request(&f.owner, "GET", "/v1/owner/export", Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page = json_response(response).await;
        let grants = &page["managed_reader_grants"]["grants"];
        assert_eq!(grants["items"].as_array().unwrap().len(), 20);
        assert_eq!(grants["next_cursor"], ids[19].to_string());
        let uri = format!("/v1/owner/export?managed_grants_after={}", ids[19]);
        let response = app
            .clone()
            .oneshot(f.request(&f.owner, "GET", &uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page = json_response(response).await;
        assert_eq!(
            page["managed_reader_grants"]["grants"]["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            page["managed_reader_grants"]["grants"]["items"][0]["id"],
            ids[20].to_string()
        );
        assert!(page["managed_reader_grants"]["grants"]["next_cursor"].is_null());
        let other = f.another_owner().await;
        let response = app
            .oneshot(f.request(&other, "GET", "/v1/owner/export", Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page = json_response(response).await;
        assert!(
            page["managed_reader_grants"]["grants"]["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; unique disposable managed-grant schema"]
async fn maintained_erasure_reports_six_child_counts_and_later_failure_rolls_back() {
    Fixture::run(async |f| {
    f.install_candidate().await;
    f.synthetic_grant(&request_scope(), 1).await;
    let before = f.counts().await;
    let app = crate::http_owner_erasure::router(crate::http_owner_erasure::OwnerErasureState {
        database_url: f.url.clone(),
        auth_hasher: f.hasher.clone(),
        canonical_origin: ORIGIN.into(),
        mfa_cipher: None,
    });
    f.db.batch_execute("CREATE FUNCTION synthetic_reject_account_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic erasure rollback'; END $$; CREATE TRIGGER synthetic_reject_account_delete BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION synthetic_reject_account_delete()").await.unwrap();
    let body = json!({"current_password":f.owner.password,"code":null});
    let response = f.send(app.clone(), "/v1/owner/erasure", body.clone()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(f.counts().await, before);
    f.db.batch_execute("DROP TRIGGER synthetic_reject_account_delete ON accounts; DROP FUNCTION synthetic_reject_account_delete()").await.unwrap();
    let response = f.send(app, "/v1/owner/erasure", body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let erased = json_response(response).await;
    let deleted = erased["deleted"].as_array().unwrap();
    for (i, table) in crate::managed_ai::lifecycle::TABLES.iter().enumerate() {
        let entry = deleted.iter().find(|v| v["table"] == *table).unwrap();
        assert_eq!(entry["rows"], before[i]);
    }
    assert_eq!(f.counts().await, [0; 6]);
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM accounts WHERE id=$1",
            &[&f.owner.principal.tenant.account_id()]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );

    }).await;
}
