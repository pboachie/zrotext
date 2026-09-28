use super::*;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_postgres::NoTls;
use uuid::Uuid;
use zrotext_delivery_store::{DeliveryStore, NewMessage, StoreError};

#[test]
fn parse_usage_limit_plans_accepts_only_quota_shaped_catalogs() {
    assert!(parse_usage_limit_plans("").unwrap().is_empty());
    assert!(parse_usage_limit_plans("  ").unwrap().is_empty());
    let plans = parse_usage_limit_plans("starter:100, standard:2500 ").unwrap();
    assert_eq!(
        plans,
        vec![
            UsageLimitPlan {
                plan_key: "starter".into(),
                outbound_limit: 100
            },
            UsageLimitPlan {
                plan_key: "standard".into(),
                outbound_limit: 2500
            },
        ]
    );
    // No prices, no device fields, no third column: a commercial shape is a
    // configuration error, not silently truncated input.
    for invalid in [
        "starter:100:2",
        "starter:0",
        "starter:-5",
        "starter:",
        ":100",
        "starter",
        "starter:100,starter:200",
        "Starter:100",
        "starter plan:100",
        "starter:abc",
        "a-very-long-plan-key-name-over-32-chars:100",
        "-starter:100",
    ] {
        assert!(parse_usage_limit_plans(invalid).is_err(), "{invalid}");
    }
}

/// Each test owns a unique schema, so ignored PostgreSQL tests can run in
/// parallel without sharing rows; the schema is dropped on exit.
async fn isolated_database(prefix: &str) -> (tokio_postgres::Client, String, String) {
    let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema = format!("usage_plans_{prefix}_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    for sql in [
        include_str!("../../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!(
            "../../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!(
            "../../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"
        ),
        // 049 validates owner queue probe indexes prepared outside this list;
        // usage plans do not depend on it.
        include_str!("../../../../../deploy/compose/migrations/050_usage_limit_plans.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    (db, scoped_url, schema)
}

async fn drop_schema(scoped_url: &str, schema: &str) {
    let (setup, connection) = tokio_postgres::connect(scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

async fn new_account(db: &tokio_postgres::Client) -> (Uuid, Uuid) {
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'usage plan fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    (account, device)
}

fn future_expiry_ms() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("monotonic clock")
        .as_millis() as i64;
    now + 10 * 60 * 1000
}

fn message(account: Uuid, device: Uuid, key: &'static str) -> NewMessage<'static> {
    NewMessage {
        account_id: account,
        client_message_id: Uuid::new_v4(),
        device_id: device,
        idempotency_key: key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"ZROtext synthetic test: usage plans",
        expires_at_ms: future_expiry_ms(),
    }
}

fn catalog(entries: &[(&str, i64)]) -> Vec<UsageLimitPlan> {
    entries
        .iter()
        .map(|(key, limit)| UsageLimitPlan {
            plan_key: (*key).to_owned(),
            outbound_limit: *limit,
        })
        .collect()
}

async fn policy_limit(db: &tokio_postgres::Client, account: Uuid) -> i64 {
    db.query_one(
        "SELECT limit_units FROM usage_quota_policies \
         WHERE account_id=$1 AND metric='outbound_message'",
        &[&account],
    )
    .await
    .unwrap()
    .get(0)
}

async fn audit_reasons(db: &tokio_postgres::Client, account: Uuid) -> Vec<String> {
    db.query(
        "SELECT reason FROM usage_plan_audit WHERE account_id=$1 ORDER BY id",
        &[&account],
    )
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.get(0))
    .collect()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_enforces_assigned_plan_limits_with_honest_errors() {
    let (mut db, scoped_url, schema) = isolated_database("enforce").await;
    let (account, device) = new_account(&db).await;
    let (unassigned, unassigned_device) = new_account(&db).await;
    db.execute(
        "INSERT INTO usage_plan_assignments(account_id,plan_key) VALUES($1,'starter')",
        &[&account],
    )
    .await
    .unwrap();
    apply_usage_plan_assignments(&scoped_url, true, &catalog(&[("starter", 2)]))
        .await
        .unwrap();

    // The assignment is projected as a quota-only policy with plan provenance.
    let policy = db
        .query_one(
            "SELECT limit_units,source FROM usage_quota_policies \
             WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        )
        .await
        .unwrap();
    assert_eq!(policy.get::<_, i64>(0), 2);
    assert_eq!(policy.get::<_, String>(1), "usage_plan");
    assert_eq!(audit_reasons(&db, account).await, vec!["assigned"]);

    // With metered admission on, the plan limit is enforced through the same
    // store errors the alpha route maps to 429 quota_exceeded and 503
    // billing_pending. An exact replay reserves nothing further.
    let mut store = DeliveryStore::new(&mut db);
    assert!(
        store
            .accept_alpha(message(account, device, "plan-key-1"), true)
            .await
            .is_ok()
    );
    let first = message(account, device, "plan-key-2");
    let replay = NewMessage {
        client_message_id: first.client_message_id,
        ..message(account, device, "plan-key-2")
    };
    assert!(store.accept_alpha(first, true).await.is_ok());
    assert!(!store.accept_alpha(replay, true).await.unwrap().created);
    assert!(matches!(
        store
            .accept_alpha(message(account, device, "plan-key-3"), true)
            .await,
        Err(StoreError::QuotaExceeded)
    ));
    let reserved: i64 = db
        .query_one(
            "SELECT reserved_units FROM usage_periods \
             WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(reserved, 2);

    // An account without an assignment fails closed rather than sending
    // unmetered while limits are enabled.
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept_alpha(message(unassigned, unassigned_device, "plan-key-4"), true)
            .await,
        Err(StoreError::QuotaNotConfigured)
    ));
    drop_schema(&scoped_url, &schema).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_reprojects_skips_billed_and_clears_on_disable() {
    let (mut db, scoped_url, schema) = isolated_database("reproject").await;
    let (account, device) = new_account(&db).await;
    let (removed, removed_device) = new_account(&db).await;
    let (billed, _) = new_account(&db).await;
    let (keeper, _) = new_account(&db).await;
    for (id, key) in [
        (account, "starter"),
        (removed, "retired"),
        (billed, "starter"),
        (keeper, "starter"),
    ] {
        db.execute(
            "INSERT INTO usage_plan_assignments(account_id,plan_key) VALUES($1,$2)",
            &[&id, &key],
        )
        .await
        .unwrap();
    }
    // A bound tenant's quota stays owned by Stripe reconciliation; a usage
    // plan assignment must neither overwrite nor shadow it.
    db.execute(
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_usageplans1')",
        &[&billed],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) \
         VALUES($1,'outbound_message',77,'stripe_test')",
        &[&billed],
    )
    .await
    .unwrap();

    apply_usage_plan_assignments(
        &scoped_url,
        true,
        &catalog(&[("starter", 100), ("retired", 50)]),
    )
    .await
    .unwrap();
    assert_eq!(policy_limit(&db, account).await, 100);
    assert_eq!(policy_limit(&db, removed).await, 50);
    assert_eq!(policy_limit(&db, keeper).await, 100);
    assert_eq!(policy_limit(&db, billed).await, 77);
    let billed_source: String = db
        .query_one(
            "SELECT source FROM usage_quota_policies WHERE account_id=$1",
            &[&billed],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(billed_source, "stripe_test");
    assert_eq!(audit_reasons(&db, billed).await, vec!["skipped_billed"]);

    // Reservations survive a catalog downgrade; the period limit follows.
    assert!(
        DeliveryStore::new(&mut db)
            .accept_alpha(message(account, device, "reproject-key-1"), true)
            .await
            .is_ok()
    );
    apply_usage_plan_assignments(&scoped_url, true, &catalog(&[("starter", 60)]))
        .await
        .unwrap();
    assert_eq!(policy_limit(&db, account).await, 60);
    let period = db
        .query_one(
            "SELECT limit_units,reserved_units FROM usage_periods \
             WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        )
        .await
        .unwrap();
    assert_eq!(period.get::<_, i64>(0), 60);
    assert_eq!(period.get::<_, i64>(1), 1);
    assert_eq!(
        audit_reasons(&db, account).await,
        vec!["assigned", "reprojected"]
    );
    // A plan that left the catalog projects zero for its assignments.
    assert_eq!(
        audit_reasons(&db, removed).await,
        vec!["assigned", "plan_removed"]
    );
    assert_eq!(policy_limit(&db, removed).await, 0);

    // A restart with an unchanged catalog reprojects but writes no audit
    // rows, because only real limit changes are audited.
    let audit_count: i64 = db
        .query_one("SELECT count(*) FROM usage_plan_audit", &[])
        .await
        .unwrap()
        .get(0);
    apply_usage_plan_assignments(&scoped_url, true, &catalog(&[("starter", 60)]))
        .await
        .unwrap();
    let unchanged: i64 = db
        .query_one("SELECT count(*) FROM usage_plan_audit", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(audit_count, unchanged);

    // Deleting an assignment row zeroes its policy on the next restart with
    // an unchanged catalog.
    db.execute(
        "DELETE FROM usage_plan_assignments WHERE account_id=$1",
        &[&account],
    )
    .await
    .unwrap();
    apply_usage_plan_assignments(&scoped_url, true, &catalog(&[("starter", 60)]))
        .await
        .unwrap();
    assert_eq!(
        audit_reasons(&db, account).await,
        vec!["assigned", "reprojected", "assignment_removed"]
    );
    assert_eq!(policy_limit(&db, account).await, 0);
    assert_eq!(policy_limit(&db, keeper).await, 60);

    // Disabling the feature clears every usage_plan allowance; the bound
    // tenant's Stripe policy stays untouched, and admission without billing
    // returns to unmetered acceptance.
    apply_usage_plan_assignments(&scoped_url, false, &[])
        .await
        .unwrap();
    assert_eq!(policy_limit(&db, keeper).await, 0);
    assert_eq!(
        audit_reasons(&db, keeper).await,
        vec!["assigned", "reprojected", "disabled"]
    );
    assert_eq!(policy_limit(&db, billed).await, 77);
    assert!(
        DeliveryStore::new(&mut db)
            .accept_alpha(message(removed, removed_device, "reproject-key-9"), false)
            .await
            .is_ok()
    );
    drop_schema(&scoped_url, &schema).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_assignment_changes_apply_on_every_enabled_startup() {
    let (mut db, scoped_url, schema) = isolated_database("reassign").await;
    let (first, first_device) = new_account(&db).await;
    let (second, second_device) = new_account(&db).await;
    db.execute(
        "INSERT INTO usage_plan_assignments(account_id,plan_key) VALUES($1,'starter')",
        &[&first],
    )
    .await
    .unwrap();
    let catalog = catalog(&[("starter", 5)]);
    apply_usage_plan_assignments(&scoped_url, true, &catalog)
        .await
        .unwrap();
    assert_eq!(policy_limit(&db, first).await, 5);

    // An assignment added after the last startup must gain its limit on the
    // next restart even though the catalog itself did not change; otherwise
    // the account stays fail-closed on billing_pending forever.
    db.execute(
        "INSERT INTO usage_plan_assignments(account_id,plan_key) VALUES($1,'starter')",
        &[&second],
    )
    .await
    .unwrap();
    apply_usage_plan_assignments(&scoped_url, true, &catalog)
        .await
        .unwrap();
    assert_eq!(policy_limit(&db, second).await, 5);
    assert_eq!(audit_reasons(&db, second).await, vec!["assigned"]);
    assert!(
        DeliveryStore::new(&mut db)
            .accept_alpha(message(second, second_device, "reassign-key-1"), true)
            .await
            .is_ok()
    );

    // Deleting the new assignment removes its allowance at the next restart
    // with the same catalog; the other account is untouched.
    db.execute(
        "DELETE FROM usage_plan_assignments WHERE account_id=$1",
        &[&second],
    )
    .await
    .unwrap();
    apply_usage_plan_assignments(&scoped_url, true, &catalog)
        .await
        .unwrap();
    assert_eq!(policy_limit(&db, second).await, 0);
    assert_eq!(policy_limit(&db, first).await, 5);
    assert!(
        DeliveryStore::new(&mut db)
            .accept_alpha(message(first, first_device, "reassign-key-2"), true)
            .await
            .is_ok()
    );
    drop_schema(&scoped_url, &schema).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_concurrent_sends_cannot_exceed_the_plan_limit() {
    let (db, scoped_url, schema) = isolated_database("concurrent").await;
    let (account, device) = new_account(&db).await;
    db.execute(
        "INSERT INTO usage_plan_assignments(account_id,plan_key) VALUES($1,'starter')",
        &[&account],
    )
    .await
    .unwrap();
    apply_usage_plan_assignments(&scoped_url, true, &catalog(&[("starter", 3)]))
        .await
        .unwrap();

    // Eight concurrent metered admissions against a limit of three: exactly
    // three reserve, the rest get the honest over-limit store error, and no
    // reservation leaks past the period limit.
    let mut tasks = Vec::new();
    for index in 0..8 {
        let url = scoped_url.clone();
        let key: &'static str = Box::leak(format!("concurrent-key-{index}").into_boxed_str());
        tasks.push(tokio::spawn(async move {
            let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            DeliveryStore::new(&mut client)
                .accept_alpha(message(account, device, key), true)
                .await
                .is_ok()
        }));
    }
    let mut accepted = 0;
    for task in tasks {
        if task.await.unwrap() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 3);
    let reserved: i64 = db
        .query_one(
            "SELECT reserved_units FROM usage_periods \
             WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(reserved, 3);
    drop_schema(&scoped_url, &schema).await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_without_migration_050_feature_stays_disabled() {
    let (db, scoped_url, schema) = isolated_database("noschema").await;
    db.batch_execute(
        "DROP TABLE usage_plan_audit CASCADE; \
         DROP TABLE usage_plan_assignments CASCADE",
    )
    .await
    .unwrap();
    // Pre-050 databases: disabling is a no-op and enabling fails closed with
    // an explicit schema error instead of silently ignoring configuration.
    apply_usage_plan_assignments(&scoped_url, false, &[])
        .await
        .unwrap();
    assert!(matches!(
        apply_usage_plan_assignments(&scoped_url, true, &catalog(&[("starter", 10)])).await,
        Err(UsagePlanError::SchemaMissing)
    ));
    drop_schema(&scoped_url, &schema).await;
}
