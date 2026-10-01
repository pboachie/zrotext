// SPDX-License-Identifier: AGPL-3.0-only
use super::online_index_tests::{connect, disposable_database, finish_database};
use super::*;

/// Fresh installs build the index online, and the gate refuses a later
/// removal or a same-name stand-in of the wrong shape (issue #660).
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn fresh_install_builds_conversation_erasure_fk_indexes() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == CONVERSATION_ERASURE_FK_INDEXES_MIGRATION)
        .unwrap();

    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    let present: bool = client
        .query_one(
            "SELECT to_regclass('public.erasure_fk_conversation_interval_session') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!present, "the index must not exist before the migration");

    apply(&mut client, &directory, false).await.unwrap();
    assert!(
        verify_conversation_erasure_fk_indexes(&client)
            .await
            .is_ok()
    );
    let present: bool = client
        .query_one(
            "SELECT to_regclass('public.erasure_fk_conversation_interval_session') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(present, "the index must exist after the migration");

    // A dropped index or a same-name stand-in of the wrong shape must fail
    // the gate on every later migrator run.
    client
        .batch_execute("DROP INDEX public.erasure_fk_conversation_interval_session")
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::ConversationErasureFkIndexesUnavailable)
    ));
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_conversation_interval_session \
             ON public.conversation_intervals(initiating_session_id,account_id)",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::ConversationErasureFkIndexesUnavailable)
    ));
    // The prepare is idempotent, so restoring the exact index lets the run
    // complete only after the wrong stand-in is gone.
    client
        .batch_execute("DROP INDEX public.erasure_fk_conversation_interval_session")
        .await
        .unwrap();
    prepare_conversation_erasure_fk_indexes(&client)
        .await
        .unwrap();
    assert!(apply(&mut client, &directory, false).await.is_ok());

    finish_database(&name, &admin).await;
    drop(client);
}
