// SPDX-License-Identifier: AGPL-3.0-only
use super::online_index_tests::{connect, disposable_database, finish_database};
use super::*;
use std::path::Path;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn fresh_install_checks_owner_queue_indexes_and_rejects_conflicting_or_lost_indexes() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    // Later migrations may follow 049; the ledger checks below cover them too.
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == OWNER_QUEUE_INDEX_MIGRATION)
        .unwrap();
    let from_index: Vec<i64> = migrations[index_position..]
        .iter()
        .map(|migration| migration.version)
        .collect();

    // A matching name with a wrong key order must not be replaced, and 049
    // must remain absent from the checksummed ledger.
    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE INDEX messages_owner_pending_state ON public.messages(state,created_at,device_id) \
             WHERE state IN ('accepted','queued','claimed')",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::OwnerQueueIndexConflict(
            "messages_owner_pending_state"
        ))
    ));
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM schema_migrations WHERE version>=$1",
            &[&OWNER_QUEUE_INDEX_MIGRATION],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);

    client
        .batch_execute(DROP_OWNER_PENDING_STATE_INDEX)
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
    verify_owner_queue_indexes(&client).await.unwrap();
    assert!(
        apply(&mut client, &directory, false)
            .await
            .unwrap()
            .is_empty()
    );

    // Losing either prepared index, or finding an operator-owned shape under
    // our name, must fail the numbered validation gate.
    for definition in [
        (
            DROP_OWNER_IN_FLIGHT_STATE_INDEX,
            "CREATE INDEX messages_owner_in_flight_state ON public.messages(device_id,created_at,state) \
             WHERE state IN ('submitting','submitted')",
        ),
        (
            DROP_OWNER_PENDING_STATE_INDEX,
            "CREATE INDEX messages_owner_pending_state ON public.messages(device_id,state,created_at) \
             WHERE state IN ('accepted','queued')",
        ),
    ] {
        client.batch_execute(definition.0).await.unwrap();
        assert!(matches!(
            apply(&mut client, &directory, false).await,
            Err(MigrationError::OwnerQueueIndexUnavailable(_))
        ));
        client.batch_execute(definition.1).await.unwrap();
        assert!(matches!(
            apply(&mut client, &directory, false).await,
            Err(MigrationError::OwnerQueueIndexUnavailable(_))
        ));
        // The numbered file must independently reject the wrong shape.
        assert!(
            client
                .batch_execute(include_str!(
                    "../../../deploy/compose/migrations/049_owner_queue_probe_indexes.sql"
                ))
                .await
                .is_err()
        );
        client
            .batch_execute(DROP_OWNER_PENDING_STATE_INDEX)
            .await
            .unwrap();
        client
            .batch_execute(DROP_OWNER_IN_FLIGHT_STATE_INDEX)
            .await
            .unwrap();
        prepare_owner_queue_indexes(&client).await.unwrap();
        verify_owner_queue_indexes(&client).await.unwrap();
    }
    finish_database(&name, &admin).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn owner_queue_probes_read_partial_indexes_without_filtering_history() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    apply(&mut client, &directory, false).await.unwrap();
    client
        .batch_execute(
            r#"
        INSERT INTO accounts(id) VALUES(md5('account')::uuid);
        INSERT INTO devices(id,account_id,display_name)
            VALUES(md5('device')::uuid,md5('account')::uuid,'Synthetic gateway');
        INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,
            transport_mode,transport_payload,request_digest,state,expires_at)
            SELECT md5('delivered-'||g)::uuid,md5('account')::uuid,md5('device')::uuid,
            '+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',
            decode('01','hex'),decode(repeat('22',32),'hex'),'delivered',now()
            FROM generate_series(1,30000) g;
        INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,
            transport_mode,transport_payload,request_digest,state,expires_at)
            SELECT md5('queued-'||g)::uuid,md5('account')::uuid,md5('device')::uuid,
            '+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',
            decode('01','hex'),decode(repeat('22',32),'hex'),'queued',now()
            FROM generate_series(1,1200) g;
        INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,
            transport_mode,transport_payload,request_digest,state,expires_at)
            SELECT md5('submitted-'||g)::uuid,md5('account')::uuid,md5('device')::uuid,
            '+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',
            decode('01','hex'),decode(repeat('22',32),'hex'),'submitted',now()
            FROM generate_series(1,1200) g;
        ANALYZE messages;
    "#,
        )
        .await
        .unwrap();
    // These are the exact queue probes from OWNER_DEVICE_STATUS_QUERY. The
    // partial predicates prove the state filter, so no supported PostgreSQL
    // release may filter the delivered history at probe time.
    for (states, index) in [
        (
            "('accepted','queued','claimed')",
            "messages_owner_pending_state",
        ),
        (
            "('submitting','submitted')",
            "messages_owner_in_flight_state",
        ),
    ] {
        let sql = format!(
            "EXPLAIN (ANALYZE) SELECT count(*) FROM (SELECT 1 FROM messages m \
             WHERE m.account_id=md5('account')::uuid AND m.device_id=md5('device')::uuid \
             AND m.state IN {states} ORDER BY m.state,m.created_at LIMIT 1000) probes"
        );
        let plan = client
            .query(&sql, &[])
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(plan.contains(index), "{plan}");
        assert!(
            !plan.contains("Rows Removed by Filter")
                && !plan.contains("Rows Removed by Index Recheck"),
            "{plan}"
        );
        assert!(!plan.contains("Seq Scan on messages"), "{plan}");
    }
    finish_database(&name, &admin).await;
}
