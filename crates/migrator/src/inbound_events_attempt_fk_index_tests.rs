// SPDX-License-Identifier: AGPL-3.0-only
use super::online_index_tests::{connect, disposable_database, finish_database};
use super::*;
use std::path::Path;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn fresh_install_checks_the_inbound_events_attempt_index_and_rejects_wrong_shapes() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    // Later migrations may follow 060; the ledger checks below cover them too.
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == INBOUND_EVENTS_ATTEMPT_FK_INDEX_MIGRATION)
        .unwrap();
    let from_index: Vec<i64> = migrations[index_position..]
        .iter()
        .map(|migration| migration.version)
        .collect();

    // A matching name with a wrong key order must not be replaced, and 061
    // must remain absent from the checksummed ledger.
    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_inbound_events_attempt \
             ON public.inbound_events(attempt_id,message_id,device_id,account_id)",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::ErasureFkIndexConflict(
            "erasure_fk_inbound_events_attempt"
        ))
    ));
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM schema_migrations WHERE version>=$1",
            &[&INBOUND_EVENTS_ATTEMPT_FK_INDEX_MIGRATION],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);

    client
        .batch_execute(DROP_INBOUND_EVENTS_ATTEMPT_FK_INDEX)
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
    verify_inbound_events_attempt_fk_index(&client)
        .await
        .unwrap();
    assert!(
        apply(&mut client, &directory, false)
            .await
            .unwrap()
            .is_empty()
    );

    // Losing the prepared index, or finding an operator-owned shape under our
    // name, must fail the numbered validation gate.
    client
        .batch_execute(DROP_INBOUND_EVENTS_ATTEMPT_FK_INDEX)
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::ErasureFkIndexUnavailable(_))
    ));
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_inbound_events_attempt \
             ON public.inbound_events(account_id,attempt_id)",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::ErasureFkIndexUnavailable(_))
    ));
    // The numbered file must independently reject the wrong shape: with the
    // exact expected index restored it reports ready, and with a prefix-only
    // stand-in of the same name it reports not ready, without the migrator
    // taking part.
    client
        .batch_execute(DROP_INBOUND_EVENTS_ATTEMPT_FK_INDEX)
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_inbound_events_attempt \
             ON public.inbound_events(account_id,device_id,message_id,attempt_id)",
        )
        .await
        .unwrap();
    let gate_ready: bool = client
        .query_one(
            "SELECT public.inbound_events_attempt_fk_index_ready('public')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(gate_ready, "the exact expected shape must satisfy the gate");
    client
        .batch_execute(DROP_INBOUND_EVENTS_ATTEMPT_FK_INDEX)
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE INDEX erasure_fk_inbound_events_attempt \
             ON public.inbound_events(account_id,message_id)",
        )
        .await
        .unwrap();
    let gate_ready: bool = client
        .query_one(
            "SELECT public.inbound_events_attempt_fk_index_ready('public')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !gate_ready,
        "a prefix-only stand-in must fail the gate: the FK probe keys on all four columns"
    );

    finish_database(&name, &admin).await;
}
