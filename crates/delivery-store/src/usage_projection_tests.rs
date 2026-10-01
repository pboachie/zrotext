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
