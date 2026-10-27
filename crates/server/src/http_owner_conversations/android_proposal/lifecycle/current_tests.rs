// SPDX-License-Identifier: AGPL-3.0-only
//! The immutable proposal trigger and mandatory current writer are one pair.
use super::*;
use crate::test_database::Fixture;
use futures_util::FutureExt;
use std::{
    ops::AsyncFnOnce,
    panic::{AssertUnwindSafe, resume_unwind},
};

async fn current_case<F>(test: F)
where
    F: for<'a> AsyncFnOnce(&'a mut Fixture),
{
    let mut f = Fixture::for_store("ZT_AUTH_TEST_DATABASE_URL").await;
    let result = AssertUnwindSafe(test(&mut f)).catch_unwind().await;
    f.finish().await;
    if let Err(panic) = result {
        resume_unwind(panic);
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; exact current proposal trigger pair"]
async fn current_immutable_and_verified_writer_pair_supports_erasure_preparation() {
    current_case(async |f| {
        assert!(crate::payload_profile_writer::optional(&f.runtime, "owner_android_proposals")
            .await.unwrap());
        let row = f.runtime.query_one(
            "SELECT count(*),bool_and(tgname IN('owner_android_proposals_immutable','zz_payload_profile_writer_before_change') AND tgenabled='O') FROM pg_trigger WHERE tgrelid='public.owner_android_proposals'::regclass AND NOT tgisinternal",
            &[],
        ).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 2);
        assert!(row.get::<_, bool>(1));
        assert!(installed(&f.runtime).await.unwrap());
        let tx = crate::runtime_db::begin_native(&mut f.runtime).await.unwrap();
        assert!(prepare_erase(&tx).await.unwrap());
        tx.rollback().await.unwrap();
        f.verify().await;
    }).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; changed current trigger pairs refuse"]
async fn current_writer_pair_refuses_missing_renamed_disabled_extra_and_mutated_triggers() {
    for corruption in [
        "DROP TRIGGER zz_payload_profile_writer_before_change ON public.owner_android_proposals",
        "ALTER TRIGGER zz_payload_profile_writer_before_change ON public.owner_android_proposals RENAME TO synthetic_wrong_writer",
        "ALTER TABLE public.owner_android_proposals DISABLE TRIGGER zz_payload_profile_writer_before_change",
        "CREATE TRIGGER synthetic_extra_proposal_trigger BEFORE UPDATE OR DELETE ON public.owner_android_proposals FOR EACH ROW EXECUTE FUNCTION public.reject_owner_android_proposal_update()",
        "CREATE OR REPLACE FUNCTION public.payload_profile_writer_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS 'BEGIN RETURN NEW; END'",
        "DROP TRIGGER owner_android_proposals_immutable ON public.owner_android_proposals",
    ] {
        current_case(async |f| {
            let account = Uuid::new_v4();
            f.runtime
                .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
                .await
                .unwrap();
            let before: String = f
                .runtime
                .query_one(
                    "SELECT to_jsonb(a)::text FROM accounts a WHERE id=$1",
                    &[&account],
                )
                .await
                .unwrap()
                .get(0);
            assert!(installed(&f.runtime).await.unwrap());
            // Owner-only disposable corruption is never used to seed accepted
            // application state, disable a protection for success, or re-pin it.
            f.owner.batch_execute(corruption).await.unwrap();
            assert!(
                crate::payload_profile_writer::optional(&f.runtime, "owner_android_proposals")
                    .await
                    .is_err()
            );
            assert!(installed(&f.runtime).await.is_err());
            let tx = f.runtime.transaction().await.unwrap();
            assert!(prepare_erase(&tx).await.is_err());
            assert_eq!(
                tx.query_one(
                    "SELECT to_jsonb(a)::text FROM accounts a WHERE id=$1",
                    &[&account]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
                before
            );
            assert_eq!(
                tx.query_one("SELECT count(*) FROM owner_android_proposals", &[])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                0
            );
            tx.rollback().await.unwrap();
        })
        .await;
    }
}
