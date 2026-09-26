// SPDX-License-Identifier: AGPL-3.0-only
//! Database-known role history only; these fixtures do not model an owner ceremony.
use crate::sealed_manifest_store::{admit, tests::Fixture};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_postgres::{Error, GenericClient};
use uuid::Uuid;

const MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/044_sealed_root_role_reservations.sql");

fn point() -> Vec<u8> {
    SigningKey::generate_from_rng(&mut rand::rng())
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec()
}
fn pin_for(f: &Fixture, account: Uuid, key: &[u8]) -> Vec<u8> {
    let mut pin = f.pin.clone();
    pin[5..21].copy_from_slice(account.as_bytes());
    pin[29..].copy_from_slice(key);
    pin
}
async fn provision(db: &impl GenericClient, account: Uuid, pin: &[u8]) -> Result<u64, Error> {
    let fingerprint = Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), pin].concat()).to_vec();
    db.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)", &[&account,&pin,&fingerprint,&vec![0u8;32]]).await
}
async fn extra_device(f: &Fixture) -> Uuid {
    let id = Uuid::new_v4();
    f.db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
        &[&id, &f.account],
    )
    .await
    .unwrap();
    id
}
async fn role(
    db: &impl GenericClient,
    account: Uuid,
    device: Uuid,
    key: &[u8],
    role: &str,
) -> Result<u64, Error> {
    let fingerprint = Sha256::digest(key).to_vec();
    match role {
        "device" => db.execute("INSERT INTO device_keys(account_id,device_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&account,&device,&key,&fingerprint]).await,
        "line" => db.execute("INSERT INTO line_owner_approval_keys(account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3)", &[&account,&key,&fingerprint]).await,
        "sms" => db.execute("INSERT INTO sms_line_owner_approval_keys(account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3)", &[&account,&key,&fingerprint]).await,
        _ => panic!("test role"),
    }
}
async fn count(db: &impl GenericClient, table: &str, account: Uuid) -> i64 {
    assert!(matches!(
        table,
        "sealed_manifest_authorities" | "sealed_root_enrollments" | "known_signing_role_claims"
    ));
    db.query_one(
        &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
        &[&account],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn root_reservations_simultaneous_genesis_commits_one_permanent_identity() {
    let f = Fixture::without_authority().await;
    let first = f.pin.clone();
    let second = pin_for(&f, f.account, &point());
    let a = f.connect().await;
    let b = f.connect().await;
    let (left, right) = tokio::join!(
        provision(&a, f.account, &first),
        provision(&b, f.account, &second)
    );
    assert_ne!(left.is_ok(), right.is_ok());
    let expected = if left.is_ok() { first } else { second };
    assert_eq!(
        count(&f.db, "sealed_manifest_authorities", f.account).await,
        1
    );
    assert_eq!(count(&f.db, "sealed_root_enrollments", f.account).await, 1);
    assert_eq!(
        f.db.query_one(
            "SELECT root_pin FROM sealed_root_enrollments WHERE account_id=$1",
            &[&f.account]
        )
        .await
        .unwrap()
        .get::<_, Vec<u8>>(0),
        expected
    );
    assert!(provision(&f.db, f.account, &expected).await.is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn root_reservations_root_and_existing_roles_exclude_aliases_in_both_lock_orders() {
    for kind in ["sms", "line", "device"] {
        for root_first in [false, true] {
            let f = Fixture::without_authority().await;
            let device = extra_device(&f).await;
            let key = &f.pin[29..];
            let mut first = f.connect().await;
            let second = f.connect().await;
            let tx = first.transaction().await.unwrap();
            if root_first {
                provision(&tx, f.account, &f.pin).await.unwrap();
                let mut pending = Box::pin(role(&second, f.account, device, key, kind));
                assert!(
                    tokio::time::timeout(Duration::from_millis(40), &mut pending)
                        .await
                        .is_err()
                );
                tx.commit().await.unwrap();
                assert!(pending.await.is_err(), "{kind}");
                assert_eq!(count(&f.db, "sealed_root_enrollments", f.account).await, 1);
            } else {
                role(&tx, f.account, device, key, kind).await.unwrap();
                let mut pending = Box::pin(provision(&second, f.account, &f.pin));
                assert!(
                    tokio::time::timeout(Duration::from_millis(40), &mut pending)
                        .await
                        .is_err()
                );
                tx.commit().await.unwrap();
                assert!(pending.await.is_err(), "{kind}");
                assert_eq!(
                    count(&f.db, "sealed_manifest_authorities", f.account).await,
                    0
                );
                assert_eq!(count(&f.db, "sealed_root_enrollments", f.account).await, 0);
            }
            f.cleanup().await;
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn root_reservations_rollback_does_not_leave_a_marker_or_point_claim() {
    let f = Fixture::without_authority().await;
    let device = extra_device(&f).await;
    let mut db = f.connect().await;
    let other = f.connect().await;
    let tx = db.transaction().await.unwrap();
    provision(&tx, f.account, &f.pin).await.unwrap();
    assert_eq!(count(&tx, "sealed_root_enrollments", f.account).await, 1);
    let mut pending = Box::pin(role(&other, f.account, device, &f.pin[29..], "device"));
    assert!(
        tokio::time::timeout(Duration::from_millis(40), &mut pending)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    pending.await.unwrap();
    assert_eq!(count(&f.db, "sealed_root_enrollments", f.account).await, 0);
    assert_eq!(
        count(&f.db, "sealed_manifest_authorities", f.account).await,
        0
    );
    assert!(!f.db.query_one("SELECT EXISTS(SELECT 1 FROM known_signing_role_claims WHERE account_id=$1 AND role='sealed_root')", &[&f.account]).await.unwrap().get::<_,bool>(0));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn root_reservations_survive_authority_deletion_and_reject_history_mutation() {
    let f = Fixture::new().await;
    for sql in [
        "UPDATE sealed_root_enrollments SET root_pin=root_pin",
        "DELETE FROM sealed_root_enrollments",
        "TRUNCATE sealed_root_enrollments",
        "UPDATE known_signing_role_claims SET role=role",
        "DELETE FROM known_signing_role_claims",
        "TRUNCATE known_signing_role_claims",
    ] {
        assert!(f.db.batch_execute(sql).await.is_err(), "{sql}");
    }
    f.db.execute(
        "DELETE FROM sealed_manifest_authorities WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    assert_eq!(count(&f.db, "sealed_root_enrollments", f.account).await, 1);
    assert!(provision(&f.db, f.account, &f.pin).await.is_err());
    assert!(
        provision(&f.db, f.account, &pin_for(&f, f.account, &point()))
            .await
            .is_err()
    );
    let device = extra_device(&f).await;
    for kind in ["sms", "line", "device"] {
        assert!(
            role(&f.db, f.account, device, &f.pin[29..], kind)
                .await
                .is_err()
        );
    }
    let pin = pin_for(&f, f.account, &point());
    assert!(f.db.execute("INSERT INTO sealed_root_enrollments(account_id,root_pin,root_fingerprint) VALUES($1,$2,$3)", &[&f.account,&pin,&vec![0u8;32]]).await.is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn root_reservations_keep_revoked_replaced_and_deleted_device_points_reserved() {
    let f = Fixture::without_authority().await;
    let previous = point();
    let replacement = point();
    for key in [&previous, &replacement] {
        f.db.execute(
            "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
            &[&f.device, key, &Sha256::digest(key).to_vec()],
        )
        .await
        .unwrap();
    }
    f.db.execute(
        "UPDATE device_keys SET revoked_at=clock_timestamp() WHERE device_id=$1",
        &[&f.device],
    )
    .await
    .unwrap();
    f.db.execute("DELETE FROM device_keys WHERE device_id=$1", &[&f.device])
        .await
        .unwrap();
    for key in [&previous, &replacement] {
        assert!(
            provision(&f.db, f.account, &pin_for(&f, f.account, key))
                .await
                .is_err()
        );
        assert!(
            role(&f.db, f.account, Uuid::nil(), key, "sms")
                .await
                .is_err()
        );
    }
    provision(&f.db, f.account, &f.pin).await.unwrap();
    // Identity UPDATE must respect root reservation, not only device INSERT.
    let device = extra_device(&f).await;
    role(&f.db, f.account, device, &point(), "device")
        .await
        .unwrap();
    assert!(
        f.db.execute(
            "UPDATE device_keys SET signing_key_sec1=$2 WHERE device_id=$1",
            &[&device, &&f.pin[29..]]
        )
        .await
        .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn root_reservations_preserve_existing_role_matrix_and_account_erasure() {
    let f = Fixture::without_authority().await;
    let shared = point();
    let device = extra_device(&f).await;
    role(&f.db, f.account, device, &shared, "device")
        .await
        .unwrap();
    //035 intentionally permits line/device overlap; do not broaden its matrix.
    role(&f.db, f.account, device, &shared, "line")
        .await
        .unwrap();
    assert!(
        role(&f.db, f.account, device, &shared, "sms")
            .await
            .is_err()
    );
    let sms = point();
    role(&f.db, f.account, device, &sms, "sms").await.unwrap();
    f.db.execute(
        "UPDATE sms_line_owner_approval_keys SET revoked_at=clock_timestamp()",
        &[],
    )
    .await
    .unwrap();
    assert!(
        role(&f.db, f.account, extra_device(&f).await, &sms, "device")
            .await
            .is_err()
    );
    assert!(role(&f.db, f.account, device, &sms, "line").await.is_err());
    // A separate account can reserve the same point. This is account-scoped,
    // not a global registry or a complete account-erasure product.
    let erased = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&erased])
        .await
        .unwrap();
    provision(&f.db, erased, &pin_for(&f, erased, &shared))
        .await
        .unwrap();
    f.db.execute("INSERT INTO known_signing_role_claims(account_id,signing_key_sec1,role) VALUES($1,$2,'device_auth')", &[&erased,&point()]).await.unwrap();
    assert_eq!(count(&f.db, "known_signing_role_claims", erased).await, 2);
    f.db.execute("DELETE FROM accounts WHERE id=$1", &[&erased])
        .await
        .unwrap();
    for table in [
        "sealed_manifest_authorities",
        "sealed_root_enrollments",
        "known_signing_role_claims",
    ] {
        assert_eq!(count(&f.db, table, erased).await, 0);
    }
    assert!(count(&f.db, "known_signing_role_claims", f.account).await > 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn root_reservations_backfill_includes_revoked_keys_and_rejects_existing_root_aliases() {
    let f = Fixture::before_role_reservations().await;
    for kind in ["sms", "line", "device"] {
        role(&f.db, f.account, extra_device(&f).await, &point(), kind)
            .await
            .unwrap();
    }
    f.db.batch_execute("UPDATE device_keys SET revoked_at=clock_timestamp(); UPDATE line_owner_approval_keys SET revoked_at=clock_timestamp(); UPDATE sms_line_owner_approval_keys SET revoked_at=clock_timestamp(); UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp()").await.unwrap();
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    tx.batch_execute(MIGRATION).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(count(&f.db, "sealed_root_enrollments", f.account).await, 1);
    assert_eq!(
        count(&f.db, "known_signing_role_claims", f.account).await,
        5
    );
    f.cleanup().await;
    for kind in ["sms", "line", "device"] {
        let f = Fixture::before_role_reservations().await;
        role(&f.db, f.account, extra_device(&f).await, &f.pin[29..], kind)
            .await
            .unwrap();
        let mut db = f.connect().await;
        let tx = db.transaction().await.unwrap();
        assert!(tx.batch_execute(MIGRATION).await.is_err(), "{kind}");
        tx.rollback().await.unwrap();
        assert!(
            f.db.query_one("SELECT to_regclass('sealed_root_enrollments') IS NULL", &[])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        assert_eq!(
            count(&f.db, "sealed_manifest_authorities", f.account).await,
            1
        );
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn root_reservations_genesis_never_waits_on_existing_authority_after_account_lock() {
    let f = Fixture::new().await;
    let mut a = f.connect().await;
    let mut b = f.connect().await;
    let admission_tx = a.transaction().await.unwrap();
    admission_tx
        .query_one(
            "SELECT account_id FROM sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
            &[&f.account],
        )
        .await
        .unwrap();
    let genesis_tx = b.transaction().await.unwrap();
    genesis_tx
        .query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[&f.account],
        )
        .await
        .unwrap();
    let mut pending = Box::pin(admit(&admission_tx, f.session(), f.line, 1, &f.bytes));
    assert!(
        tokio::time::timeout(Duration::from_millis(40), &mut pending)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(500),
            provision(&genesis_tx, f.account, &f.pin)
        )
        .await
        .expect("genesis must not wait for authority")
        .is_err()
    );
    genesis_tx.rollback().await.unwrap();
    let admission = pending.await.unwrap();
    admission.context(&f.wanted()).await.unwrap();
    drop(admission);
    admission_tx.commit().await.unwrap();
    // The opposite order waits on account only, then rejects the existing pin.
    let tx = a.transaction().await.unwrap();
    let admission = admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    let mut pending = Box::pin(provision(&b, f.account, &f.pin));
    assert!(
        tokio::time::timeout(Duration::from_millis(40), &mut pending)
            .await
            .is_err()
    );
    admission.context(&f.wanted()).await.unwrap();
    drop(admission);
    tx.commit().await.unwrap();
    assert!(pending.await.is_err());
    f.cleanup().await;
}
