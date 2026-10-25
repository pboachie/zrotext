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

/// The exact107 schema is historical SQL-contract coverage only. Native entry
/// refuses it; no authenticated HTTP acceptance is asserted by these fixtures.
async fn historical_fixture() -> (
    tokio_postgres::Client,
    String,
    crate::auth::SessionPrincipal,
    crate::auth::SessionPrincipal,
) {
    let (_admin, mut db, _url, schema) = migrated_schema("managed_grants").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(23)).unwrap());
    let mut owners = Vec::new();
    for email in ["erase-managed@example.test", "keep-managed@example.test"] {
        let password = crate::test_keys::password(1);
        let signup = register(&mut db, &hasher, email, &password).await.unwrap();
        assert!(
            crate::auth::verify_email_with_password(
                &mut db,
                &hasher,
                &signup.verification_token,
                &password
            )
            .await
            .unwrap()
        );
        let session = login(&db, &hasher, email, &password).await.unwrap();
        let owner = principal_of(&db, &hasher, &session).await;
        history(&mut db, &owner).await;
        owners.push(owner);
    }
    (db, schema, owners.remove(0), owners.remove(0))
}

async fn rows<C: tokio_postgres::GenericClient + Sync>(db: &C, account: Uuid) -> Vec<String> {
    let mut rows = Vec::new();
    for table in crate::managed_ai::lifecycle::TABLES {
        rows.push(db.query_one(
            &format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]'::jsonb)::text FROM {table} t WHERE account_id=$1"),
            &[&account],
        ).await.unwrap().get(0));
    }
    rows
}

async fn owner_rows(
    db: &tokio_postgres::Client,
    owner: &crate::auth::SessionPrincipal,
) -> Vec<String> {
    let mut rows = Vec::new();
    for (table, id) in [
        ("accounts", owner.tenant.account_id()),
        ("sessions", owner.session_id),
    ] {
        rows.push(
            db.query_one(
                &format!("SELECT to_jsonb(t)::text FROM {table} t WHERE id=$1"),
                &[&id],
            )
            .await
            .unwrap()
            .get(0),
        );
    }
    rows
}

async fn execute_managed_plan(tx: &tokio_postgres::Transaction<'_>, account: Uuid) {
    // Filter, never copy, the actual production statements and retain their
    // actual order. A removed/reordered child must fail this contract.
    let plan: Vec<_> = DELETE_PLAN
        .iter()
        .filter(|(table, _)| crate::managed_ai::lifecycle::TABLES.contains(table))
        .collect();
    assert_eq!(
        plan.iter().map(|(table, _)| *table).collect::<Vec<_>>(),
        crate::managed_ai::lifecycle::TABLES
    );
    for &&(table, sql) in &plan {
        assert_eq!(tx.execute(sql, &[&account]).await.unwrap(), 1, "{table}");
    }
    assert_eq!(rows(tx, account).await, vec!["[]"; 6]);
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical107 managed SQL-plan contract"]
async fn historical_managed_grants_exact_child_plan_commits_counts_and_account_isolation() {
    let (mut db, schema, owner, other) = historical_fixture().await;
    let other_before = rows(&db, other.tenant.account_id()).await;
    let owner_before = owner_rows(&db, &owner).await;
    let tx = db.transaction().await.unwrap();
    execute_managed_plan(&tx, owner.tenant.account_id()).await;
    tx.commit().await.unwrap();
    // Independent post-commit reads distinguish durable deletion from merely
    // reaching zero rows inside an uncommitted transaction.
    assert_eq!(rows(&db, owner.tenant.account_id()).await, vec!["[]"; 6]);
    assert_eq!(rows(&db, other.tenant.account_id()).await, other_before);
    assert_eq!(owner_rows(&db, &owner).await, owner_before);
    crate::sealed_manifest_store::tests::cleanup::drop_fixture(&db, &schema)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical107 managed SQL-plan contract"]
async fn historical_managed_grants_exact_child_plan_rolls_back_witnessed_later_failure() {
    let (mut db, schema, owner, other) = historical_fixture().await;
    let before = rows(&db, owner.tenant.account_id()).await;
    let other_before = rows(&db, other.tenant.account_id()).await;
    let owner_before = owner_rows(&db, &owner).await;
    db.batch_execute("CREATE SEQUENCE managed_fixture_failure_reached; CREATE FUNCTION managed_fixture_late_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('managed_fixture_failure_reached'); RAISE EXCEPTION 'synthetic later managed erasure failure' USING ERRCODE='P0001'; END $$; CREATE TRIGGER managed_fixture_late_failure BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION managed_fixture_late_failure()").await.unwrap();
    assert!(
        !db.query_one("SELECT is_called FROM managed_fixture_failure_reached", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let tx = db.transaction().await.unwrap();
    execute_managed_plan(&tx, owner.tenant.account_id()).await;
    // Only the six child statements and this deliberately failing later
    // account delete run: this is not the complete HTTP erasure transaction.
    let error = tx
        .execute(
            "DELETE FROM accounts WHERE id=$1",
            &[&owner.tenant.account_id()],
        )
        .await
        .unwrap_err();
    let error = error
        .as_db_error()
        .expect("the injected trigger must reject this account delete");
    assert_eq!(
        error.code(),
        &tokio_postgres::error::SqlState::RAISE_EXCEPTION
    );
    assert_eq!(error.message(), "synthetic later managed erasure failure");
    tx.rollback().await.unwrap();
    // nextval is nontransactional: unchanged grant rows alone would not prove
    // the intended later statement was reached before rollback.
    assert!(
        db.query_one("SELECT is_called FROM managed_fixture_failure_reached", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(rows(&db, owner.tenant.account_id()).await, before);
    assert_eq!(rows(&db, other.tenant.account_id()).await, other_before);
    assert_eq!(owner_rows(&db, &owner).await, owner_before);
    crate::sealed_manifest_store::tests::cleanup::drop_fixture(&db, &schema)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical107 managed preflight contract"]
async fn historical_managed_grants_partial_schema_fails_preflight_without_changes() {
    let (mut db, schema, owner, other) = historical_fixture().await;
    let before = rows(&db, owner.tenant.account_id()).await;
    let other_before = rows(&db, other.tenant.account_id()).await;
    let owner_before = owner_rows(&db, &owner).await;
    db.batch_execute("DROP TABLE managed_reader_events")
        .await
        .unwrap();
    let tx = db.transaction().await.unwrap();
    let error = crate::managed_ai::lifecycle::installed(&tx)
        .await
        .unwrap_err();
    let error = error
        .as_db_error()
        .expect("partial proposal must fail preflight");
    assert_eq!(
        error.code(),
        &tokio_postgres::error::SqlState::RAISE_EXCEPTION
    );
    assert_eq!(error.message(), "incomplete managed reader proposal");
    tx.rollback().await.unwrap();
    for (i, table) in crate::managed_ai::lifecycle::TABLES
        .iter()
        .enumerate()
        .skip(1)
    {
        for (account, expected) in [
            (owner.tenant.account_id(), &before[i]),
            (other.tenant.account_id(), &other_before[i]),
        ] {
            let remaining: String = db.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]'::jsonb)::text FROM {table} t WHERE account_id=$1"), &[&account]).await.unwrap().get(0);
            assert_eq!(&remaining, expected, "{table}");
        }
    }
    assert_eq!(owner_rows(&db, &owner).await, owner_before);
    crate::sealed_manifest_store::tests::cleanup::drop_fixture(&db, &schema)
        .await
        .unwrap();
}
