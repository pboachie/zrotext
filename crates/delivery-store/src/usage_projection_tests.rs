// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use tokio_postgres::NoTls;

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
}

struct TestDb {
    admin: Client,
    client: Client,
    schema: String,
}

impl TestDb {
    async fn new() -> Self {
        let root_url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
            .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let admin = connect(&root_url).await;
        let schema = format!("usage_projection_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        let client = connect(&root_url).await;
        client
            .batch_execute(&format!("SET search_path TO {schema}"))
            .await
            .unwrap();
        // The shared reviewed fixture applies every numbered migration in
        // order, including the metering tables this projection reads.
        tests::apply_test_migrations(&client).await;
        Self {
            admin,
            client,
            schema,
        }
    }

    async fn drop(self) {
        self.admin
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {} CASCADE",
                self.schema
            ))
            .await
            .unwrap();
    }
}

async fn account(client: &Client) -> Uuid {
    let id = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&id])
        .await
        .unwrap();
    id
}

async fn seed_period(
    client: &Client,
    account: Uuid,
    months_ago: i32,
    limit_units: i64,
    reserved: i64,
    refunded: i64,
) -> String {
    let start: String = client
        .query_one(
            "WITH m AS (SELECT date_trunc('month',current_date AT TIME ZONE 'UTC') \
                 - ($1::int * interval '1 month') AS s) \
             SELECT s::date::text FROM m",
            &[&months_ago],
        )
        .await
        .unwrap()
        .get(0);
    client
        .execute(
            "WITH m AS (SELECT (date_trunc('month',current_date AT TIME ZONE 'UTC') \
                 - ($2::int * interval '1 month'))::date AS s) \
             INSERT INTO usage_periods(account_id,metric,period_start,period_end, \
             limit_units,reserved_units,refunded_units) \
             SELECT $1,'outbound_message',s,(s + interval '1 month')::date,$3,$4,$5 FROM m",
            &[&account, &months_ago, &limit_units, &reserved, &refunded],
        )
        .await
        .unwrap();
    start
}

/// History pages newest-first with a working cursor, and the counter
/// semantics stay reservation-based (#631).
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn usage_history_pages_newest_first_with_bounds_and_counters() {
    let db = TestDb::new().await;
    let a = account(&db.client).await;
    let current = seed_period(&db.client, a, 0, 100, 100, 3).await;
    seed_period(&db.client, a, 1, 100, 60, 0).await;
    let oldest = seed_period(&db.client, a, 2, 50, 10, 1).await;

    let page = usage_history(&db.client, a, None, 2).await.unwrap();
    assert_eq!(
        page.periods
            .iter()
            .map(|p| p.period_start.as_str())
            .collect::<Vec<_>>(),
        vec![&current, page.periods[1].period_start.as_str()],
        "periods are newest first"
    );
    assert_eq!(page.periods.len(), 2);
    assert_eq!(
        page.next_before.as_deref(),
        Some(page.periods[1].period_start.as_str()),
        "a full page carries a cursor"
    );

    let rest = usage_history(&db.client, a, page.next_before.as_deref(), USAGE_PAGE_MAX)
        .await
        .unwrap();
    assert_eq!(rest.periods.len(), 1);
    assert_eq!(rest.periods[0].period_start, oldest);
    assert_eq!(rest.next_before, None, "history is exhausted");

    let exact = usage_history(&db.client, a, None, 3).await.unwrap();
    assert_eq!(exact.periods.len(), 3);
    assert_eq!(
        exact.next_before, None,
        "an exact-size final page is exhausted"
    );

    let head = &page.periods[0];
    assert_eq!(head.period_end, head.next_month_end());
    assert_eq!(
        head.consumed_units(),
        97,
        "consumed is reservations minus refunds"
    );
    assert_eq!(
        head.reserved_units, head.limit_units,
        "quota boundary is visible"
    );
    assert_eq!(head.metric, "outbound_message");

    db.drop().await;
}

/// Tenant isolation: another account's periods are invisible, absent history
/// is an empty page, and repeated reads are identical (stable replay).
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn usage_history_is_tenant_scoped_empty_and_replayable() {
    let db = TestDb::new().await;
    let a = account(&db.client).await;
    let b = account(&db.client).await;
    seed_period(&db.client, b, 0, 10, 1, 0).await;

    let empty = usage_history(&db.client, a, None, USAGE_PAGE_MAX)
        .await
        .unwrap();
    assert_eq!(empty.periods, Vec::new());
    assert_eq!(empty.next_before, None);

    seed_period(&db.client, a, 0, 10, 4, 1).await;
    let first = usage_history(&db.client, a, None, USAGE_PAGE_MAX)
        .await
        .unwrap();
    let second = usage_history(&db.client, a, None, USAGE_PAGE_MAX)
        .await
        .unwrap();
    assert_eq!(
        first, second,
        "a read is a stable replay of committed state"
    );
    assert_eq!(
        first.periods.len(),
        1,
        "the other account's period is invisible"
    );

    db.drop().await;
}

/// Malformed and calendrically impossible cursors are client input errors.
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn usage_history_rejects_bad_cursors_and_clamps_limits() {
    let db = TestDb::new().await;
    let a = account(&db.client).await;
    for bad in ["not-a-date", "2026-13-01", "2026-02-30", "20260201"] {
        assert!(
            matches!(
                usage_history(&db.client, a, Some(bad), 5).await,
                Err(StoreError::InvalidInput)
            ),
            "cursor {bad} must be rejected as input"
        );
    }
    // Clamping, not errors: an oversized limit behaves as the maximum.
    seed_period(&db.client, a, 0, 10, 1, 0).await;
    let page = usage_history(&db.client, a, None, 10_000).await.unwrap();
    assert_eq!(page.periods.len(), 1);

    db.drop().await;
}

impl UsagePeriodView {
    /// The exclusive end is the first day of the following month.
    fn next_month_end(&self) -> String {
        let y = self.period_start[0..4].parse::<i32>().unwrap();
        let m = self.period_start[5..7].parse::<i32>().unwrap();
        let (ey, em) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
        format!("{ey:04}-{em:02}-01")
    }
}

async fn device_for(client: &Client, account_id: Uuid) -> Uuid {
    let device_id = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) \
             VALUES($1,$2,'usage projection test phone')",
            &[&device_id, &account_id],
        )
        .await
        .unwrap();
    device_id
}

async fn policy(client: &Client, account_id: Uuid, limit: i64) {
    client
        .execute(
            "INSERT INTO usage_quota_policies(account_id,metric,limit_units) \
             VALUES($1,'outbound_message',$2) \
             ON CONFLICT(account_id,metric) DO UPDATE SET limit_units=$2",
            &[&account_id, &limit],
        )
        .await
        .unwrap();
}

fn metered_message<'a>(
    account_id: Uuid,
    device_id: Uuid,
    message_id: Uuid,
    key: &'a str,
    expiry: i64,
) -> NewMessage<'a> {
    NewMessage {
        account_id,
        client_message_id: message_id,
        device_id,
        idempotency_key: key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"usage projection test only",
        expires_at_ms: expiry,
    }
}

async fn unix_ms(client: &Client, value: &str) -> i64 {
    client
        .query_one(
            "SELECT (extract(epoch FROM $1::text::timestamptz)*1000)::bigint",
            &[&value],
        )
        .await
        .unwrap()
        .get(0)
}

/// The projection reports the metering core's authoritative semantics, never
/// its own counters (#631): an idempotent digest replay reserves once even
/// across a month boundary, a quota boundary rejects admission, a cancelled
/// message refunds exactly once into its original period, and a rollover
/// period starts fresh with the then-current policy limit while existing
/// periods keep their stored limit under a later downgrade.
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn usage_history_exposes_ledger_semantics_across_periods() {
    let mut db = TestDb::new().await;
    let account_id = account(&db.client).await;
    let device_id = device_for(&db.client, account_id).await;
    let january = unix_ms(&db.client, "2026-01-31 23:59:59+00").await;
    let february = unix_ms(&db.client, "2026-02-01 00:00:00+00").await;
    let expiry = now_ms() + 3_600_000;
    let one = Uuid::new_v4();
    let two = Uuid::new_v4();

    policy(&db.client, account_id, 1).await;
    {
        let mut store = DeliveryStore::new(&mut db.client);
        assert!(
            store
                .accept_metered_at(
                    metered_message(account_id, device_id, one, "one", expiry),
                    january
                )
                .await
                .unwrap()
                .created
        );
        // The same digest replays its original reservation - across the month
        // boundary it must not reserve a second unit in February.
        assert!(
            !store
                .accept_metered_at(
                    metered_message(account_id, device_id, one, "one", expiry),
                    february
                )
                .await
                .unwrap()
                .created
        );
        // January's limit of one is exhausted.
        assert!(matches!(
            store
                .accept_metered_at(
                    metered_message(account_id, device_id, two, "two", expiry),
                    january
                )
                .await,
            Err(StoreError::QuotaExceeded)
        ));
    }
    // A raised policy reprojects only the period created afterwards.
    policy(&db.client, account_id, 3).await;
    {
        let mut store = DeliveryStore::new(&mut db.client);
        assert!(
            store
                .accept_metered_at(
                    metered_message(account_id, device_id, two, "two", expiry),
                    february
                )
                .await
                .unwrap()
                .created
        );
        // Cancellation refunds once; the second attempt is an invalid
        // transition, so the refund can never count twice.
        assert!(store.cancel(account_id, one).await.unwrap());
        assert!(matches!(
            store.cancel(account_id, one).await,
            Err(StoreError::InvalidTransition)
        ));
    }

    let page = usage_history(&db.client, account_id, None, USAGE_PAGE_MAX)
        .await
        .unwrap();
    assert_eq!(page.next_before, None, "the whole history fits one page");
    assert_eq!(page.periods.len(), 2, "the month boundary rolled over");
    let february_period = &page.periods[0];
    let january_period = &page.periods[1];
    assert_eq!(
        (
            january_period.period_start.as_str(),
            january_period.period_end.as_str()
        ),
        ("2026-01-01", "2026-02-01")
    );
    assert_eq!(
        january_period.limit_units, 1,
        "a period keeps its stored limit"
    );
    assert_eq!(
        january_period.reserved_units, 1,
        "the replayed digest reserved exactly one unit"
    );
    assert_eq!(january_period.refunded_units, 1, "the refund counted once");
    assert_eq!(january_period.consumed_units(), 0);
    assert_eq!(
        (
            february_period.period_start.as_str(),
            february_period.period_end.as_str()
        ),
        ("2026-02-01", "2026-03-01")
    );
    assert_eq!(
        february_period.limit_units, 3,
        "the rollover period carries the then-current limit"
    );
    assert_eq!(
        (
            february_period.reserved_units,
            february_period.refunded_units
        ),
        (1, 0)
    );
    assert_eq!(february_period.consumed_units(), 1);

    // A later downgrade changes the policy, never stored periods: the same
    // read replays identically.
    policy(&db.client, account_id, 0).await;
    let replay = usage_history(&db.client, account_id, None, USAGE_PAGE_MAX)
        .await
        .unwrap();
    assert_eq!(
        replay, page,
        "reads reflect committed periods, not the policy"
    );

    db.drop().await;
}
