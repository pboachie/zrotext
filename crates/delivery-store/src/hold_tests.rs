// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::time::Duration;
use tokio_postgres::NoTls;

const RECIPIENT: &str = "+15550104400";

struct TestDb {
    admin: Client,
    client: Client,
    schema: String,
    scoped_url: String,
}

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
}

impl TestDb {
    async fn new() -> Self {
        let root_url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
            .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let admin = connect(&root_url).await;
        let schema = format!("owner_hold_test_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if root_url.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{root_url}{separator}options=-csearch_path%3D{schema}");
        let client = connect(&scoped_url).await;
        for migration in [
            include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
            include_str!("../../../deploy/compose/migrations/031_recipient_suppression.sql"),
            include_str!("../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        ] {
            client.batch_execute(migration).await.unwrap();
        }
        Self {
            admin,
            client,
            schema,
            scoped_url,
        }
    }

    /// An account, an owner membership for the hold's author, and one device.
    async fn tenant(&self) -> (Uuid, Uuid, Uuid) {
        let (account, owner, device) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        self.client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        self.client
            .execute(
                "INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused')",
                &[&owner, &format!("hold-{}@example.test", owner.simple())],
            )
            .await
            .unwrap();
        self.client
            .execute(
                "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
                &[&account, &owner],
            )
            .await
            .unwrap();
        self.client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'hold test phone')",
                &[&device, &account],
            )
            .await
            .unwrap();
        (account, owner, device)
    }

    async fn close(self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

/// Mirrors the owner route: take the admission lock, then write the hold.
const HOLD_UNDER_ACCOUNT_LOCK: &str = "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE";
const INSERT_HOLD: &str = "INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by) \
     VALUES($1,$2,$3,'email','opt_out',clock_timestamp(),$4)";

fn expiry_ms() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    i64::try_from(now).unwrap() + 3_600_000
}

fn message(account_id: Uuid, device_id: Uuid, message_id: Uuid, key: &str) -> NewMessage<'_> {
    NewMessage {
        account_id,
        client_message_id: message_id,
        device_id,
        idempotency_key: key,
        recipient_e164: RECIPIENT,
        synthetic_payload: b"owner hold test only",
        expires_at_ms: expiry_ms(),
    }
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn owner_hold_blocks_new_admission_and_exact_replay_for_its_tenant_only() {
    let mut db = TestDb::new().await;
    let (account, owner, device) = db.tenant().await;
    let (other_account, _, other_device) = db.tenant().await;
    let first = Uuid::new_v4();
    DeliveryStore::new(&mut db.client)
        .accept(message(account, device, first, "before-hold"))
        .await
        .unwrap();

    let tx = db.client.transaction().await.unwrap();
    tx.query_one(HOLD_UNDER_ACCOUNT_LOCK, &[&account])
        .await
        .unwrap();
    tx.execute(
        INSERT_HOLD,
        &[&Uuid::new_v4(), &account, &RECIPIENT, &owner],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // An exact replay must not report the earlier acceptance once held.
    assert!(matches!(
        DeliveryStore::new(&mut db.client)
            .accept(message(account, device, first, "before-hold"))
            .await,
        Err(StoreError::RecipientSuppressed)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut db.client)
            .accept(message(account, device, Uuid::new_v4(), "after-hold"))
            .await,
        Err(StoreError::RecipientSuppressed)
    ));
    let messages: i64 = db
        .client
        .query_one(
            "SELECT count(*) FROM messages WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(messages, 1);

    // The hold is account-scoped: another tenant can still admit the number.
    DeliveryStore::new(&mut db.client)
        .accept(message(
            other_account,
            other_device,
            Uuid::new_v4(),
            "other-tenant",
        ))
        .await
        .unwrap();

    // A second active hold for the same recipient is refused, and the guard
    // rejects deletion or an unverified release.
    let duplicate = db
        .client
        .execute(
            INSERT_HOLD,
            &[&Uuid::new_v4(), &account, &RECIPIENT, &owner],
        )
        .await;
    assert!(duplicate.is_err());
    assert!(
        db.client
            .execute(
                "DELETE FROM owner_recipient_holds WHERE account_id=$1",
                &[&account]
            )
            .await
            .is_err()
    );
    assert!(
        db.client
            .execute(
                "UPDATE owner_recipient_holds SET released_at=clock_timestamp(),release_event_id=$2 WHERE account_id=$1",
                &[&account, &Uuid::new_v4()],
            )
            .await
            .is_err()
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn hold_and_admission_serialize_on_the_account_lock() {
    let db = TestDb::new().await;
    let (account, owner, device) = db.tenant().await;
    let writer = connect(&db.scoped_url).await;
    writer.batch_execute("BEGIN").await.unwrap();
    writer
        .query_one(HOLD_UNDER_ACCOUNT_LOCK, &[&account])
        .await
        .unwrap();
    writer
        .execute(
            INSERT_HOLD,
            &[&Uuid::new_v4(), &account, &RECIPIENT, &owner],
        )
        .await
        .unwrap();

    let url = db.scoped_url.clone();
    let admission = tokio::spawn(async move {
        let mut client = connect(&url).await;
        DeliveryStore::new(&mut client)
            .accept(message(account, device, Uuid::new_v4(), "racing"))
            .await
    });
    // Admission must wait for the uncommitted hold rather than read past it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!admission.is_finished());
    writer.batch_execute("COMMIT").await.unwrap();
    assert!(matches!(
        admission.await.unwrap(),
        Err(StoreError::RecipientSuppressed)
    ));
    db.close().await;
}
