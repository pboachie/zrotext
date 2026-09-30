// SPDX-License-Identifier: AGPL-3.0-only
use super::online_index_tests::{connect, disposable_database, finish_database};
use super::*;
use std::path::Path;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn fresh_install_checks_erasure_fk_indexes_and_rejects_conflicting_or_lost_indexes() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    // Later migrations may follow 056; the ledger checks below cover them too.
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == ERASURE_FK_INDEX_MIGRATION)
        .unwrap();
    let from_index: Vec<i64> = migrations[index_position..]
        .iter()
        .map(|migration| migration.version)
        .collect();

    // A matching name with a wrong key order must not be replaced, and 056
    // must remain absent from the checksummed ledger.
    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_webhook_deliveries_event \
             ON public.webhook_deliveries(event_id,account_id)",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::ErasureFkIndexConflict(
            "erasure_fk_webhook_deliveries_event"
        ))
    ));
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM schema_migrations WHERE version>=$1",
            &[&ERASURE_FK_INDEX_MIGRATION],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);

    client
        .batch_execute(DROP_WEBHOOK_DELIVERIES_EVENT_INDEX)
        .await
        .unwrap();
    let applied = apply(&mut client, &directory, false).await.unwrap();
    assert_eq!(
        applied
            .iter()
            .map(|migration| migration.version)
            .collect::<Vec<_>>(),
        from_index
    );
    verify_erasure_fk_indexes(&client).await.unwrap();
    assert!(
        apply(&mut client, &directory, false)
            .await
            .unwrap()
            .is_empty()
    );

    // Losing a prepared index, or finding an operator-owned shape under our
    // name, must fail the numbered validation gate.
    client
        .batch_execute(DROP_SUPPRESSIONS_ATTEMPT_INDEX)
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::ErasureFkIndexUnavailable(_))
    ));
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_suppressions_attempt \
             ON public.recipient_suppressions(source_attempt_id,account_id)",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::ErasureFkIndexUnavailable(_))
    ));
    // The numbered file must independently reject the wrong shape: with the
    // exact expected index restored it reports ready, and with a same-name
    // stand-in of the wrong key it reports not ready, without the migrator
    // taking part.
    client
        .batch_execute(DROP_SUPPRESSIONS_ATTEMPT_INDEX)
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_suppressions_attempt \
             ON public.recipient_suppressions(source_attempt_id)",
        )
        .await
        .unwrap();
    let gate_ready: bool = client
        .query_one("SELECT public.erasure_fk_indexes_ready('public')", &[])
        .await
        .unwrap()
        .get(0);
    assert!(gate_ready, "the exact expected shape must satisfy the gate");
    client
        .batch_execute(DROP_SUPPRESSIONS_ATTEMPT_INDEX)
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_suppressions_attempt \
             ON public.recipient_suppressions(account_id)",
        )
        .await
        .unwrap();
    let gate_ready: bool = client
        .query_one("SELECT public.erasure_fk_indexes_ready('public')", &[])
        .await
        .unwrap()
        .get(0);
    assert!(!gate_ready, "a wrong-key stand-in must fail the gate");

    finish_database(&name, &admin).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn erasure_fk_partial_indexes_reject_missing_predicates() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == ERASURE_FK_INDEX_MIGRATION)
        .unwrap();
    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    // An unpredicated index with the same name and keys is a different shape:
    // the FK support must stay partial so it never indexes NULL references.
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_holds_release_event \
             ON public.owner_recipient_holds(account_id,release_event_id)",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::ErasureFkIndexConflict(
            "erasure_fk_holds_release_event"
        ))
    ));
    finish_database(&name, &admin).await;
}
