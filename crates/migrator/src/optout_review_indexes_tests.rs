// SPDX-License-Identifier: AGPL-3.0-only
use super::online_index_tests::{connect, disposable_database, finish_database};
use super::*;

/// Fresh installs build both review indexes online, drop the redundant active
/// index, and the gate refuses any later re-creation or removal (#506).
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn fresh_install_builds_optout_review_indexes_and_drops_the_duplicate() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == OPTOUT_REVIEW_INDEXES_MIGRATION)
        .unwrap();

    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    let active_present: bool = client
        .query_one(
            "SELECT to_regclass('public.recipient_suppressions_active') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(active_present, "migration 031 creates the redundant index");

    apply(&mut client, &directory, false).await.unwrap();
    assert!(verify_optout_review_indexes(&client).await.is_ok());
    for index in [
        "recipient_suppressions_review_queue",
        "recipient_suppressions_review_event",
    ] {
        let present: bool = client
            .query_one(
                "SELECT to_regclass($1) IS NOT NULL",
                &[&format!("public.{index}")],
            )
            .await
            .unwrap()
            .get(0);
        assert!(present, "{index} must exist after the migration");
    }
    let active_gone: bool = client
        .query_one(
            "SELECT to_regclass('public.recipient_suppressions_active') IS NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(active_gone, "the redundant active index must be gone");

    // A re-created duplicate or a dropped review index must fail the gate on
    // every later migrator run.
    client
        .batch_execute(
            "CREATE INDEX recipient_suppressions_active \
             ON public.recipient_suppressions(account_id, recipient_e164) WHERE active",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::OptoutReviewIndexesUnavailable)
    ));
    client
        .batch_execute("DROP INDEX public.recipient_suppressions_active")
        .await
        .unwrap();
    client
        .batch_execute("DROP INDEX public.recipient_suppressions_review_event")
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::OptoutReviewIndexesUnavailable)
    ));
    // The prepare is idempotent, so restoring the index lets the run complete.
    prepare_optout_review_indexes(&client).await.unwrap();
    assert!(apply(&mut client, &directory, false).await.is_ok());

    finish_database(&name, &admin).await;
    drop(client);
}
