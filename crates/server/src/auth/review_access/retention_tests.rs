// SPDX-License-Identifier: AGPL-3.0-only
//! Expiry-only owner-seeded historical metadata, not authentication evidence.
//! The installed unmodified cleanup runs through a real ordinary LOGIN role.
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster; real ordinary-role bounded retention"]
async fn finite_cleanup_preserves_live_context_workspace_locator_and_unverified_owner() {
    let mut f = Fixture::create().await;
    let (browser, prep) = f.prepared_with_browser("pilot").await;
    f.access
        .login(&prep, "synthetic-review-password")
        .await
        .unwrap();
    let runtime = f.access.connect().await.unwrap();
    assert!(
        runtime
            .execute("DELETE FROM public.review_access_sessions", &[])
            .await
            .is_err()
    );
    drop(runtime);
    let old = Uuid::new_v4();
    let token = rand::random::<[u8; 32]>();
    let csrf = rand::random::<[u8; 32]>();
    // Only the fixture owner seeds expired rows. They have no authentication
    // result or active delivery generation and can never authenticate a caller.
    f.owner.execute("INSERT INTO public.review_access_sessions(id,realm_id,account_id,user_id,broker_id,credential_id,credential_revision, \
        broker_session_id,authentication_event_id,browser_digest,delivery_generation,auth_key_commitment,config_revision,config_digest,origin,slot, \
        token_digest,csrf_digest,source,source_request_id,bootstrap_attempt_id,source_result_digest,issued_ms,expires_ms,last_used_ms) \
        SELECT $1,realm_id,account_id,user_id,broker_id,credential_id,credential_revision,broker_session_id,authentication_event_id,browser_digest, \
        delivery_generation,auth_key_commitment,config_revision,config_digest,origin,2,$2,$3,source,source_request_id,bootstrap_attempt_id,source_result_digest, \
        floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint-7201000, \
        floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint-7200000, \
        floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint-7201000 FROM public.review_access_sessions WHERE id=$4",
        &[&old,&&token[..],&&csrf[..],&prep.identities.owner_session]).await.unwrap();
    let digest = rand::random::<[u8; 32]>();
    let s = &f.access.scope;
    f.owner.execute("INSERT INTO public.review_access_preparations(browser_digest,realm_id,database_commitment,auth_key_commitment,config_revision,config_digest,origin,created_ms,browser_expires_ms) \
        VALUES($1,$2,$3,$4,$5,$6,$7,floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint-10800000, \
        floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint-7200000)",
        &[&&digest[..],&s.realm,&&s.database[..],&&s.key[..],&(s.config_revision as i64),&&s.config[..],&s.origin]).await.unwrap();
    let original_request = Uuid::new_v4();
    let original_preparation = Uuid::new_v4();
    f.owner.execute("UPDATE public.review_access_preparations SET browser_confirmed_ms=created_ms,generation=1,state='prepared', \
        preparation_id=$2,request_id=$3,operation=1,request_digest=$4,prepared_csrf_digest=$5,prepared_ms=created_ms, \
        create_deadline_ms=created_ms+300000,delivery_deadline_ms=browser_expires_ms WHERE browser_digest=$1",
        &[&&digest[..],&original_preparation,&original_request,&&token[..],&&csrf[..]]).await.unwrap();
    f.owner.execute("UPDATE public.review_access_preparations SET state='confirmed' WHERE browser_digest=$1",&[&&digest[..]]).await.unwrap();
    f.owner
        .execute(
            "UPDATE public.review_access_preparations SET state='checking' WHERE browser_digest=$1",
            &[&&digest[..]],
        )
        .await
        .unwrap();
    assert_eq!(f.access.prune_once().await.unwrap(), 1);
    assert!(
        !f.owner
            .query_one(
                "SELECT EXISTS(SELECT FROM public.review_access_sessions WHERE id=$1)",
                &[&old]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(f.access.prune_once().await.unwrap(), 1);
    assert!(!f.owner.query_one("SELECT EXISTS(SELECT FROM public.review_access_preparations WHERE browser_digest=$1)",&[&&digest[..]]).await.unwrap().get::<_,bool>(0));
    assert_eq!(f.access.prune_once().await.unwrap(), 0);
    for table in [
        "review_workspaces",
        "review_access_sessions",
        "review_access_locators",
        "review_access_authentications",
    ] {
        assert_eq!(f.count(table).await, 1, "{table}");
    }
    let c = f
        .access
        .credentials(
            prep.identities.broker_session,
            &prep.candidates.broker,
            &prep.candidates.broker_csrf,
            prep.identities.owner_session,
            &prep.candidates.owner,
            &prep.candidates.owner_csrf,
        )
        .unwrap();
    f.access
        .context(&browser, &c, Uuid::new_v4())
        .await
        .unwrap();
    // Review users remain genuinely unverified; ordinary signup-age cleanup
    // must not erase their separate persistent resource association.
    f.owner.execute("UPDATE public.users SET created_at=pg_catalog.clock_timestamp()-interval '2 days' WHERE id=$1",&[&prep.identities.user]).await.unwrap();
    assert_eq!(
        crate::auth::prune_expired_pending_owners(&mut f.owner)
            .await
            .unwrap(),
        0
    );
    let mut tx = f.owner.transaction().await.unwrap();
    assert!(
        !crate::auth::discard_pending_owner(&mut tx, prep.identities.user, prep.identities.account)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert!(f.owner.query_one("SELECT email_verified_at IS NULL AND NOT mfa_enabled FROM public.users WHERE id=$1",&[&prep.identities.user]).await.unwrap().get::<_,bool>(0));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster; ordinary cleanup in a quoted installation"]
async fn ordinary_pending_cleanup_checks_its_own_quoted_installation() {
    let mut f = Fixture::create().await;
    // Actual numbered component dependencies, not a fake review association.
    // Remove only this fixture's public installation: an old hardcoded public
    // lookup must fail here rather than accidentally pass against an empty table.
    f.owner
        .batch_execute("DROP SCHEMA public CASCADE")
        .await
        .unwrap();
    assert!(
        f.owner
            .query_one(
                "SELECT pg_catalog.to_regclass('public.review_workspaces') IS NULL",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let namespace = "Review'Cleanup";
    f.owner
        .batch_execute(&format!(
            "CREATE SCHEMA {}; SET search_path TO {},pg_catalog",
            escape_identifier(namespace),
            escape_identifier(namespace)
        ))
        .await
        .unwrap();
    for sql in [
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!(
            "../../../../../deploy/compose/migrations/100_payload_profile_account_anchors.sql"
        ),
        include_str!(
            "../../../../../deploy/compose/migrations/102_review_workspace_persistence.sql"
        ),
        include_str!("../../../../../deploy/compose/migrations/104_review_root_access.sql"),
    ] {
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(sql).await.unwrap();
        tx.commit().await.unwrap();
    }
    let account = Uuid::new_v4();
    let user = Uuid::new_v4();
    f.owner
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    f.owner.execute("INSERT INTO users(id,email,password_hash,created_at) VALUES($1,'pending@review.invalid','!',pg_catalog.clock_timestamp()-interval '2 days')",&[&user]).await.unwrap();
    f.owner
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&account, &user],
        )
        .await
        .unwrap();
    let old=f.owner.query("SELECT u.id FROM users u WHERE NOT EXISTS(SELECT FROM public.review_workspaces w WHERE w.user_id=u.id)",&[]).await.unwrap_err();
    assert_eq!(
        old.code(),
        Some(&tokio_postgres::error::SqlState::UNDEFINED_TABLE),
        "the prior public-qualified exclusion must fail"
    );
    assert_eq!(
        crate::auth::prune_expired_pending_owners(&mut f.owner)
            .await
            .unwrap(),
        1
    );
    let account = Uuid::new_v4();
    let user = Uuid::new_v4();
    f.owner
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    f.owner.execute("INSERT INTO users(id,email,password_hash,created_at) VALUES($1,'pending@review.invalid','!',pg_catalog.clock_timestamp()-interval '2 days')",&[&user]).await.unwrap();
    f.owner
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&account, &user],
        )
        .await
        .unwrap();
    let mut tx = f.owner.transaction().await.unwrap();
    assert!(
        crate::auth::discard_pending_owner(&mut tx, user, account)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert_eq!(
        f.owner
            .query_one("SELECT count(*) FROM users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(
        f.owner
            .query_one(
                "SELECT pg_catalog.to_regclass('public.review_workspaces') IS NULL",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.cleanup().await;
}
