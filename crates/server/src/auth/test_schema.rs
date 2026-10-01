// SPDX-License-Identifier: AGPL-3.0-only
use tokio_postgres::Client;

/// Apply actual migrations and their required autocommit index preparation.
/// The caller must provide a connection to a unique disposable schema.
pub(crate) async fn apply(db: &Client) {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut files = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect::<Vec<_>>();
    files.sort();
    for file in files {
        prepare_indexes(db, file.file_name().unwrap().to_str().unwrap()).await;
        let transaction = file
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("070_");
        if transaction {
            db.batch_execute("BEGIN").await.unwrap();
        }
        let result = db
            .batch_execute(&std::fs::read_to_string(file).unwrap())
            .await;
        if transaction {
            db.batch_execute(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .await
                .unwrap();
        }
        result.unwrap();
    }
}

/// Mirror the migrator's autocommit preparation on this unique test schema.
/// The exact numbered validation files still run unchanged afterwards.
async fn prepare_indexes(db: &Client, file: &str) {
    let statements: &[&str] = match &file[..3] {
        "034" => &[
            "CREATE INDEX CONCURRENTLY messages_in_flight_updated ON messages(updated_at,id) WHERE state IN ('claimed','submitting','submitted')",
        ],
        "040" => &[
            "CREATE INDEX CONCURRENTLY message_events_attempt_evidence ON message_events(attempt_id,evidence_code)",
        ],
        "049" => &[
            "CREATE INDEX CONCURRENTLY messages_owner_pending_state ON messages(device_id,state,created_at) WHERE state IN ('accepted','queued','claimed')",
            "CREATE INDEX CONCURRENTLY messages_owner_in_flight_state ON messages(device_id,state,created_at) WHERE state IN ('submitting','submitted')",
        ],
        "050" => &[
            "CREATE INDEX CONCURRENTLY message_attempts_device_created ON message_attempts(account_id,device_id,created_at)",
        ],
        "052" => &[
            "CREATE INDEX CONCURRENTLY messages_admission_pending ON messages(account_id,device_id) WHERE state IN ('queued','claimed')",
        ],
        "057" => &[
            "CREATE INDEX CONCURRENTLY webhook_deliveries_history ON webhook_deliveries(endpoint_id,created_at DESC,id DESC)",
        ],
        "058" => &["DROP INDEX CONCURRENTLY auth_abuse_counters_stale"],
        "059" => &[
            "CREATE INDEX CONCURRENTLY erasure_fk_webhook_deliveries_event ON webhook_deliveries(account_id,event_id)",
            "CREATE INDEX CONCURRENTLY erasure_fk_suppressions_attempt ON recipient_suppressions(source_attempt_id)",
            "CREATE INDEX CONCURRENTLY erasure_fk_suppressions_event ON recipient_suppressions(account_id,source_event_id)",
            "CREATE INDEX CONCURRENTLY erasure_fk_holds_release_event ON owner_recipient_holds(account_id,release_event_id) WHERE release_event_id IS NOT NULL",
            "CREATE INDEX CONCURRENTLY erasure_fk_opt_out_audit_release_event ON owner_opt_out_audit(account_id,release_event_id) WHERE release_event_id IS NOT NULL",
        ],
        "060" => &[
            "CREATE INDEX CONCURRENTLY recipient_suppressions_review_queue ON recipient_suppressions(account_id,changed_at DESC,recipient_e164 DESC) WHERE active AND source IN ('sms_review','sms_unsolicited_review')",
            "CREATE INDEX CONCURRENTLY recipient_suppressions_review_event ON recipient_suppressions(account_id,COALESCE(source_event_id,source_unsolicited_event_id)) WHERE source IN ('sms_review','sms_unsolicited_review')",
            "DROP INDEX CONCURRENTLY IF EXISTS recipient_suppressions_active",
        ],
        "061" => &[
            "CREATE INDEX CONCURRENTLY erasure_fk_inbound_events_attempt ON inbound_events(account_id,device_id,message_id,attempt_id)",
        ],
        "062" => &[
            "CREATE INDEX CONCURRENTLY messages_pending_recipient ON messages(recipient_e164,account_id) WHERE state IN ('queued','claimed') AND recipient_e164 IS NOT NULL",
        ],
        "066" => &[
            "CREATE INDEX CONCURRENTLY erasure_fk_conversation_interval_session ON conversation_intervals(account_id,initiating_session_id)",
        ],
        "070" => &[
            "CREATE INDEX CONCURRENTLY messages_summary_queue ON messages(account_id,state,created_at) WHERE state IN ('accepted','queued','claimed','submitting','submitted')",
        ],
        _ => &[],
    };
    for statement in statements {
        db.batch_execute(statement).await.unwrap();
    }
}
