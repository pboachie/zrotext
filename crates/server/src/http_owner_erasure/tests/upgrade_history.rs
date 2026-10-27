// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::test_database::Fixture;
use futures_util::FutureExt;
use std::panic::{AssertUnwindSafe, resume_unwind};

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; genuine pre045 history upgraded unchanged to current"]
async fn genuine_pre_guard_null_fence_upgrade_erases_through_current_runtime() {
    let (f, account) = Fixture::with_history("ZT_AUTH_TEST_DATABASE_URL", 44, async |owner| {
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        let message = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        owner.execute("INSERT INTO accounts(id) VALUES($1)", &[&account]).await.unwrap();
        owner.execute("INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Synthetic legacy fence')", &[&device,&account]).await.unwrap();
        owner.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+12',$4,'synthetic_alpha',$5,$4,'queued',clock_timestamp()+interval '1 hour')", &[&message,&account,&device,&vec![1u8;32],&vec![2u8]]).await.unwrap();
        owner.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,1,1,'failed')", &[&attempt,&account,&message,&device]).await.unwrap();
        // 003's nullable account column and composite FKs allow this history.
        // 045 has not yet installed alpha_fence_before_write: no protection
        // is disabled, rewritten, or re-pinned to create the old row.
        assert!(!owner.query_one("SELECT EXISTS(SELECT FROM pg_trigger WHERE tgrelid='dispatch_fences'::regclass AND tgname='alpha_fence_before_write')", &[]).await.unwrap().get::<_,bool>(0));
        owner.execute("INSERT INTO dispatch_fences(message_id,account_id,device_id,attempt_id,generation,session_epoch,deployment_epoch,grant_expires_at,outcome) VALUES($1,NULL,$2,$3,1,1,1,clock_timestamp(),'failed')", &[&message,&device,&attempt]).await.unwrap();
        account
    }).await;
    let qualified = AssertUnwindSafe(async {
        f.verify().await;
        crate::hosted_runtime_identity::require(&f.runtime)
            .await
            .unwrap();
    })
    .catch_unwind()
    .await;
    if let Err(panic) = qualified {
        f.finish().await;
        resume_unwind(panic);
    }
    current_fixture::with_fixture(f, async |db, _admin, database_url| {
        assert_eq!(db.query_one("SELECT count(*) FROM dispatch_fences WHERE account_id IS NULL", &[]).await.unwrap().get::<_,i64>(0), 1);
        // Current rules still refuse creating a new NULL-account fence.
        let rejected = db.execute("INSERT INTO dispatch_fences SELECT * FROM dispatch_fences WHERE account_id IS NULL", &[]).await.unwrap_err();
        assert_eq!(rejected.code(), Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION));
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(26)).unwrap());
        let password = crate::test_keys::password(1);
        let other = register(db, &hasher, "keep-upgrade-owner@example.test", &password).await.unwrap();
        assert!(verify_email(db, &hasher, &other.verification_token).await.unwrap());
        // The historical account predates current registration APIs. Attach
        // its ordinary owner using a current-generated verifier, then use the
        // real login/session/password paths; this is not authentication bypass.
        let user = Uuid::new_v4();
        assert_eq!(db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,'erase-upgrade-owner@example.test',password_hash,clock_timestamp() FROM users WHERE id=$2", &[&user,&other.user_id]).await.unwrap(), 1);
        db.execute("INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')", &[&account,&user]).await.unwrap();
        let session = login(&*db, &hasher, "erase-upgrade-owner@example.test", &password).await.unwrap();
        assert_eq!(authenticate_session(&*db, &hasher, &session.token).await.unwrap().tenant.account_id(), account);
        let app = router(OwnerErasureState { database_url: database_url.to_owned(), auth_hasher: hasher.clone(), canonical_origin: ORIGIN.into(), mfa_cipher: None });
        let response = app.oneshot(erasure_post(Some(&session.token),Some(&session.csrf_token),Some(ORIGIN),&password,None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let report = body(response).await;
        for table in ["dispatch_fences","message_attempts","messages","devices","users","accounts"] { assert_eq!(deleted_count(&report, table), 1, "{table}"); }
        assert_eq!(db.query_one("SELECT count(*) FROM dispatch_fences", &[]).await.unwrap().get::<_,i64>(0), 0);
        assert_eq!(db.query_one("SELECT count(*) FROM accounts WHERE id=$1", &[&other.account_id]).await.unwrap().get::<_,i64>(0), 1);
        assert_eq!(db.query_one("SELECT count(*) FROM users WHERE id=$1", &[&other.user_id]).await.unwrap().get::<_,i64>(0), 1);
        assert!(authenticate_session(&*db, &hasher, &session.token).await.is_err());
        let retained = db.query_one("SELECT state,selection_epoch FROM payload_profile_account_anchors WHERE account_id=$1", &[&account]).await.unwrap();
        assert_eq!(retained.get::<_,String>(0), "deleted");
        assert_eq!(retained.get::<_,i64>(1), 1);
    }).await;
}
