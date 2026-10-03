// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    managed_ai::{GrantRequest, PolicyIdentity, Selection, SourceKind},
    workflow_runtime::Purpose,
};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use sha2::{Digest, Sha256};

/// Relational expired-history fixture only, not service-reader issuance or
/// approval. This erasable owner has no immutable root/device trust history.
async fn history(db: &mut tokio_postgres::Client, owner: &crate::auth::SessionPrincipal) {
    let account = owner.tenant.account_id();
    let reader = Uuid::new_v4();
    let policy = Uuid::new_v4();
    let id = Uuid::new_v4();
    let digest: [u8; 32] = Sha256::digest(policy.as_bytes()).into();
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let point = key.verifying_key().to_sec1_point(false);
    let key_id = crate::sealed_manifest::key_id(3, point.as_bytes());
    let request = GrantRequest {
        policy: PolicyIdentity {
            id: policy,
            version: 1,
            digest,
            reader,
            reader_generation: 1,
        },
        contact: Uuid::new_v4(),
        purpose: Purpose::Operational,
        instruction_digest: Sha256::digest(id.as_bytes()).into(),
        expires_ms: 1,
        max_calls: 0,
        max_input_bytes: 0,
        max_cost_microunits: 0,
        selections: vec![Selection {
            kind: SourceKind::WorkflowContextV1,
            id: Uuid::new_v4(),
            version: 1,
            digest,
        }],
    };
    let tx = db.transaction().await.unwrap();
    tx.execute("INSERT INTO managed_reader_keys(account_id,id,generation,key_id,key_point,expires_ms) VALUES($1,$2,1,$3,$4,1)",&[&account,&reader,&key_id.as_slice(),&point.as_bytes()]).await.unwrap();
    tx.execute("INSERT INTO managed_reader_policies(account_id,id,version,digest,reader_id,reader_generation,provider_id,provider_version,provider_digest,budget_id,budget_version,budget_digest,expires_ms,max_calls,max_input_bytes,max_cost_microunits) VALUES($1,$2,1,$3,$4,1,$5,1,$3,$6,1,$3,1,0,0,0)",&[&account,&policy,&digest.as_slice(),&reader,&Uuid::new_v4(),&Uuid::new_v4()]).await.unwrap();
    tx.execute("INSERT INTO managed_reader_grants(account_id,id,contact_id,purpose,current_version,revoked_ms,revocation_generation) VALUES($1,$2,$3,'operational',1,1,1)",&[&account,&id,&request.contact]).await.unwrap();
    tx.execute("INSERT INTO managed_reader_grant_versions(account_id,grant_id,id,version,policy_id,policy_version,policy_digest,reader_id,reader_generation,binding,created_by_user,created_session,created_ms) VALUES($1,$2,$3,1,$4,1,$5,$6,1,$7::text::jsonb,$8,$9,1)",&[&account,&id,&Uuid::new_v4(),&policy,&digest.as_slice(),&reader,&serde_json::to_string(&request).unwrap(),&owner.user_id,&owner.session_id]).await.unwrap();
    tx.execute("INSERT INTO managed_reader_selections(account_id,id,grant_id,grant_version,kind,source_id,source_version,digest) VALUES($1,$2,$3,1,'workflow_context_v1',$4,1,$5)",&[&account,&Uuid::new_v4(),&id,&request.selections[0].id,&digest.as_slice()]).await.unwrap();
    tx.execute("INSERT INTO managed_reader_events(account_id,id,grant_id,grant_version,operation,actor_user_id,actor_session_id,created_ms) VALUES($1,$2,$3,1,'create',$4,$5,1)",&[&account,&Uuid::new_v4(),&id,&owner.user_id,&owner.session_id]).await.unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated managed history erasure schema"]
async fn managed_grants_mounted_owner_erasure_reports_counts_and_rolls_back_later_failure() {
    for fail_later in [false, true] {
        let (admin, mut db, url, schema) = migrated_schema("managed_grants").await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(23)).unwrap());
        let (a, session, b, other_session, app) = fixture(&mut db, &hasher, &url, None).await;
        let owner = principal_of(&db, &hasher, &session).await;
        let other = principal_of(&db, &hasher, &other_session).await;
        history(&mut db, &owner).await;
        history(&mut db, &other).await;
        if fail_later {
            db.batch_execute("CREATE FUNCTION managed_fixture_late_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic later erasure failure'; END $$; CREATE TRIGGER managed_fixture_late_failure BEFORE DELETE ON messages FOR EACH ROW EXECUTE FUNCTION managed_fixture_late_failure()").await.unwrap();
        }
        let response = app
            .oneshot(erasure_post(
                Some(&session.token),
                Some(&session.csrf_token),
                Some(ORIGIN),
                &crate::test_keys::password(1),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        if fail_later {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                db.query_one(
                    "SELECT disabled_at IS NULL FROM accounts WHERE id=$1",
                    &[&a.account_id]
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
            );
            assert!(
                db.query_one(
                    "SELECT revoked_at IS NULL FROM sessions WHERE id=$1",
                    &[&session.id]
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
            );
        } else {
            assert_eq!(response.status(), StatusCode::OK);
            let report = body(response).await;
            for table in crate::managed_ai::lifecycle::TABLES {
                assert_eq!(deleted_count(&report, table), 1, "{table}");
            }
            assert_eq!(deleted_count(&report, "accounts"), 1);
        }
        for table in crate::managed_ai::lifecycle::TABLES {
            let rows: i64 = db
                .query_one(
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    &[&a.account_id],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(rows, i64::from(fail_later), "{table}");
            let others: i64 = db
                .query_one(
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    &[&b.account_id],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(others, 1, "{table} other account");
        }
        let accounts: i64 = db
            .query_one(
                "SELECT count(*) FROM accounts WHERE id=$1",
                &[&a.account_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(accounts, i64::from(fail_later));
        crate::sealed_manifest_store::tests::cleanup::drop_fixture(&admin, &schema)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated optional managed proposal schema"]
async fn managed_grants_absence_preserves_owner_erasure_and_partial_schema_fails_preflight() {
    for partial in [false, true] {
        let (admin, mut db, url, schema) = migrated_schema("managed_optional").await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(23)).unwrap());
        let (a, session, _, _, app) = fixture(&mut db, &hasher, &url, None).await;
        if partial {
            let owner = principal_of(&db, &hasher, &session).await;
            history(&mut db, &owner).await;
            db.batch_execute("DROP TABLE managed_reader_events")
                .await
                .unwrap();
        } else {
            // Only this generated fixture schema is affected.
            for table in crate::managed_ai::lifecycle::TABLES {
                db.batch_execute(&format!("DROP TABLE {table} CASCADE"))
                    .await
                    .unwrap();
            }
        }
        let response = app
            .oneshot(erasure_post(
                Some(&session.token),
                Some(&session.csrf_token),
                Some(ORIGIN),
                &crate::test_keys::password(1),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        if partial {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            for table in &crate::managed_ai::lifecycle::TABLES[1..] {
                assert_eq!(
                    db.query_one(
                        &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                        &[&a.account_id]
                    )
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                    1,
                    "{table}"
                );
            }
            assert!(
                db.query_one(
                    "SELECT disabled_at IS NULL FROM accounts WHERE id=$1",
                    &[&a.account_id]
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
            );
        } else {
            assert_eq!(response.status(), StatusCode::OK);
            let report = body(response).await;
            assert_eq!(deleted_count(&report, "accounts"), 1);
            assert!(report["deleted"].as_array().unwrap().iter().all(|row| {
                !row["table"]
                    .as_str()
                    .unwrap()
                    .starts_with("managed_reader_")
            }));
        }
        crate::sealed_manifest_store::tests::cleanup::drop_fixture(&admin, &schema)
            .await
            .unwrap();
    }
}
