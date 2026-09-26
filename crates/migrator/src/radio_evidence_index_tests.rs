// SPDX-License-Identifier: AGPL-3.0-only
use super::online_index_tests::{connect, disposable_database, finish_database};
use super::*;
use std::time::Duration;
use tokio::time::{sleep, timeout};

async fn wait_for_invalid(client: &Client) {
    timeout(Duration::from_secs(5), async {
        loop {
            if radio_evidence_index_status(client).await.unwrap() == Some((true, false)) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("concurrent build never exposed an invalid index");
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn fresh_install_checks_index_and_rejects_conflicting_or_lost_index() {
    let (name, admin, config) = disposable_database().await;
    let mut client = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let migrations = read_migrations(&directory).unwrap();
    // Later migrations may follow 040; the ledger checks below cover them too.
    let index_position = migrations
        .iter()
        .position(|migration| migration.version == RADIO_EVIDENCE_INDEX_MIGRATION)
        .unwrap();
    let from_index: Vec<i64> = migrations[index_position..]
        .iter()
        .map(|migration| migration.version)
        .collect();

    // A matching name with a wrong key order must not be replaced, and 040
    // must remain absent from the checksummed ledger.
    apply_locked(&mut client, &migrations[..index_position], false)
        .await
        .unwrap();
    client
        .batch_execute(
            "CREATE INDEX message_events_attempt_evidence ON public.message_events(evidence_code,attempt_id)",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::RadioEvidenceIndexConflict)
    ));
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM schema_migrations WHERE version>=$1",
            &[&RADIO_EVIDENCE_INDEX_MIGRATION],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);

    client
        .batch_execute(DROP_RADIO_EVIDENCE_INDEX)
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
    verify_radio_evidence_index(&client).await.unwrap();
    assert!(
        apply(&mut client, &directory, false)
            .await
            .unwrap()
            .is_empty()
    );

    client
        .batch_execute(DROP_RADIO_EVIDENCE_INDEX)
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::RadioEvidenceIndexUnavailable)
    ));
    client
        .batch_execute(
            "CREATE INDEX message_events_attempt_evidence ON public.message_events(evidence_code,attempt_id)",
        )
        .await
        .unwrap();
    assert!(matches!(
        apply(&mut client, &directory, false).await,
        Err(MigrationError::RadioEvidenceIndexUnavailable)
    ));
    finish_database(&name, &admin).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn concurrent_build_allows_writes_and_retries_interrupted_invalid_index() {
    let (name, admin, config) = disposable_database().await;
    let holder = connect(&config).await;
    let observer = connect(&config).await;
    holder
        .batch_execute(
            "CREATE TABLE public.message_events(id uuid PRIMARY KEY,attempt_id uuid,evidence_code text NOT NULL)",
        )
        .await
        .unwrap();

    holder
        .batch_execute(
            "BEGIN; INSERT INTO public.message_events VALUES('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000010','durable_intent')",
        )
        .await
        .unwrap();
    let builder = connect(&config).await;
    let first_build = tokio::spawn(async move { prepare_radio_evidence_index(&builder).await });
    wait_for_invalid(&observer).await;
    assert!(matches!(
        prepare_radio_evidence_index(&observer).await,
        Err(MigrationError::RadioEvidenceIndexBuildInProgress)
    ));
    // A plain CREATE INDEX waiting behind holder's write lock would also
    // block this later writer. The concurrent build must allow it to finish.
    timeout(
        Duration::from_secs(2),
        observer.batch_execute(
            "INSERT INTO public.message_events VALUES('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000010','durable_intent')",
        ),
    )
    .await
    .expect("index build blocked a concurrent writer")
    .unwrap();
    holder.batch_execute("COMMIT").await.unwrap();
    timeout(Duration::from_secs(10), first_build)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        radio_evidence_index_status(&observer).await.unwrap(),
        Some((true, true))
    );
    observer
        .batch_execute(include_str!(
            "../../../deploy/compose/migrations/040_radio_evidence_index.sql"
        ))
        .await
        .unwrap();
    verify_radio_evidence_index(&observer).await.unwrap();

    observer
        .batch_execute(DROP_RADIO_EVIDENCE_INDEX)
        .await
        .unwrap();
    holder
        .batch_execute(
            "BEGIN; INSERT INTO public.message_events VALUES('00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000010','durable_intent')",
        )
        .await
        .unwrap();
    let interrupted_builder = connect(&config).await;
    let backend_pid: i32 = interrupted_builder
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let interrupted =
        tokio::spawn(async move { prepare_radio_evidence_index(&interrupted_builder).await });
    wait_for_invalid(&observer).await;
    let canceled: bool = observer
        .query_one("SELECT pg_cancel_backend($1)", &[&backend_pid])
        .await
        .unwrap()
        .get(0);
    assert!(canceled);
    assert!(interrupted.await.unwrap().is_err());
    holder.batch_execute("COMMIT").await.unwrap();
    assert_eq!(
        radio_evidence_index_status(&observer).await.unwrap(),
        Some((true, false))
    );
    assert!(matches!(
        verify_radio_evidence_index(&observer).await,
        Err(MigrationError::RadioEvidenceIndexUnavailable)
    ));

    prepare_radio_evidence_index(&observer).await.unwrap();
    assert_eq!(
        radio_evidence_index_status(&observer).await.unwrap(),
        Some((true, true))
    );
    verify_radio_evidence_index(&observer).await.unwrap();
    finish_database(&name, &admin).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn radio_evidence_probes_use_index_with_retained_history() {
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
            VALUES(md5('message')::uuid,md5('account')::uuid,md5('device')::uuid,
            '+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',
            decode('01','hex'),decode(repeat('22',32),'hex'),'unknown',now()+interval '1 hour');
        INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,
            session_epoch,deployment_epoch,status)
            SELECT md5('attempt-'||g)::uuid,md5('account')::uuid,md5('message')::uuid,
                md5('device')::uuid,g,1,1,'unknown' FROM generate_series(1,30000) g;
        INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code,
            event_digest,observed_at,resulting_state)
            SELECT md5('event-'||g)::uuid,md5('account')::uuid,md5('message')::uuid,
                md5('attempt-'||g)::uuid,'durable_intent',decode(repeat('33',32),'hex'),
                now(),'unknown' FROM generate_series(1,30000) g;
        ANALYZE message_events;
    "#,
        )
        .await
        .unwrap();
    // These are the three distinct EXISTS probes in record_radio_event.
    // Test both present and absent attempts under ordinary planner settings.
    for attempt in ["attempt-15000", "missing-attempt"] {
        for predicate in [
            "evidence_code='callback_conflict'",
            "evidence_code IN ('sent_callback_ok','sent_callback_failed','delivery_callback_ok','callback_conflict')",
            "evidence_code='durable_intent'",
        ] {
            let sql = format!(
                "EXPLAIN (ANALYZE, BUFFERS) SELECT EXISTS(SELECT 1 FROM message_events WHERE attempt_id=md5($1)::uuid AND {predicate})"
            );
            let plan = client
                .query(&sql, &[&attempt])
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.get::<_, String>(0))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(plan.contains("message_events_attempt_evidence"), "{plan}");
            assert!(!plan.contains("Seq Scan on message_events"), "{plan}");
        }
    }
    // Prove the fixture exercises the missing access path without forcing
    // enable_seqscan off or relying only on catalog existence.
    client
        .batch_execute(DROP_RADIO_EVIDENCE_INDEX)
        .await
        .unwrap();
    let plan = client.query("EXPLAIN SELECT EXISTS(SELECT 1 FROM message_events WHERE attempt_id=md5('missing-attempt')::uuid AND evidence_code='callback_conflict')", &[])
        .await.unwrap().into_iter().map(|row| row.get::<_, String>(0)).collect::<Vec<_>>().join("\n");
    assert!(plan.contains("Seq Scan on message_events"), "{plan}");
    finish_database(&name, &admin).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB on a disposable PostgreSQL cluster"]
async fn radio_index_refuses_operator_owned_shapes_without_replacement() {
    let (name, admin, config) = disposable_database().await;
    let client = connect(&config).await;
    client
        .batch_execute(
            "CREATE TABLE message_events(id uuid,attempt_id uuid,evidence_code text NOT NULL)",
        )
        .await
        .unwrap();
    for definition in [
        "CREATE INDEX message_events_attempt_evidence ON message_events(attempt_id DESC,evidence_code)",
        "CREATE INDEX message_events_attempt_evidence ON message_events(attempt_id,evidence_code text_pattern_ops)",
        "CREATE INDEX message_events_attempt_evidence ON message_events(attempt_id,evidence_code) INCLUDE(id)",
        "CREATE INDEX message_events_attempt_evidence ON message_events(attempt_id,evidence_code) WHERE attempt_id IS NOT NULL",
        "CREATE UNIQUE INDEX message_events_attempt_evidence ON message_events(attempt_id,evidence_code)",
        "CREATE INDEX message_events_attempt_evidence ON message_events(attempt_id,lower(evidence_code))",
    ] {
        client.batch_execute(definition).await.unwrap();
        let oid: u32 = client
            .query_one(
                "SELECT 'message_events_attempt_evidence'::regclass::oid",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(matches!(
            prepare_radio_evidence_index(&client).await,
            Err(MigrationError::RadioEvidenceIndexConflict)
        ));
        let unchanged: u32 = client
            .query_one(
                "SELECT 'message_events_attempt_evidence'::regclass::oid",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(oid, unchanged);
        // The numbered validation gate must independently reject the shape.
        assert!(
            client
                .batch_execute(include_str!(
                    "../../../deploy/compose/migrations/040_radio_evidence_index.sql"
                ))
                .await
                .is_err()
        );
        client
            .batch_execute(DROP_RADIO_EVIDENCE_INDEX)
            .await
            .unwrap();
    }
    finish_database(&name, &admin).await;
}
