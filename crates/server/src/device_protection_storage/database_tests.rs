// SPDX-License-Identifier: AGPL-3.0-only
//! Structural SQL/capability tests with the actual full public installation and
//! stock ordinary runtime. This does not authenticate a socket or verify P256
//! signatures; the server's opaque handshake/dual-signature adapter is separate.
use super::*;
use crate::sealed_payload_election03::test_database::Fixture;
use tokio_postgres::{GenericClient, IsolationLevel, Row, error::SqlState};
use uuid::Uuid;

struct Actor {
    account: Uuid,
    device: Uuid,
    setup: Uuid,
    opening: Uuid,
    command: Uuid,
    pairing: Uuid,
    point: Vec<u8>,
}
fn point(scalar: u8) -> Vec<u8> {
    p256::ecdsa::SigningKey::from_slice(&[scalar; 32])
        .unwrap()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec()
}
async fn seed(f: &Fixture) -> Actor {
    f.owner
        .batch_execute("SET lock_timeout='200ms'; SET statement_timeout='15s'")
        .await
        .unwrap();
    let a = Actor {
        account: Uuid::new_v4(),
        device: Uuid::new_v4(),
        setup: Uuid::new_v4(),
        opening: Uuid::new_v4(),
        command: Uuid::new_v4(),
        pairing: Uuid::new_v4(),
        point: point(23),
    };
    let user = Uuid::new_v4();
    let email = format!("synthetic-{user}@example.invalid");
    f.owner
        .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&a.account])
        .await
        .unwrap();
    f.owner
        .execute(
            "INSERT INTO public.users(id,email,password_hash) VALUES($1,$2,'synthetic-unusable')",
            &[&user, &email],
        )
        .await
        .unwrap();
    f.owner
        .execute(
            "INSERT INTO public.memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&a.account, &user],
        )
        .await
        .unwrap();
    f.owner.batch_execute("INSERT INTO public.sites(site_id) VALUES('synthetic-protection') ON CONFLICT DO NOTHING").await.unwrap();
    f.owner.execute("INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'synthetic protection')",&[&a.device,&a.account]).await.unwrap();
    f.owner.execute("INSERT INTO public.pairing_requests(id,account_id,created_by_user_id,token_digest,display_name,created_at,expires_at,claimed_at,signing_key_sec1,key_fingerprint,comparison_code,challenge_digest,challenge_consumed_at,proof_verified_at,approved_at,device_id) VALUES($1,$2,$3,sha256(uuid_send($1)),'synthetic',clock_timestamp()-interval '4 seconds',clock_timestamp()+interval '1 hour',clock_timestamp()-interval '3 seconds',$4,sha256($4),'00000000',sha256(uuid_send($3)),clock_timestamp()-interval '2 seconds',clock_timestamp()-interval '2 seconds',clock_timestamp()-interval '1 second',$5)",&[&a.pairing,&a.account,&user,&a.point,&a.device]).await.unwrap();
    f.owner.execute("INSERT INTO public.device_keys(device_id,account_id,signing_key_sec1,fingerprint,source_pairing_id) VALUES($1,$2,$3,sha256($3),$4)",&[&a.device,&a.account,&a.point,&a.pairing]).await.unwrap();
    f.owner.execute("INSERT INTO public.device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,deployment_epoch,lease_until) VALUES($1,$2,'synthetic-protection','synthetic-process',1,1,clock_timestamp()+interval '10 minutes')",&[&a.device,&a.account]).await.unwrap();
    a
}
async fn open<C: GenericClient + Sync>(
    db: &C,
    a: &Actor,
) -> std::result::Result<Row, tokio_postgres::Error> {
    db.query_one("SELECT * FROM public.device_protection_open($1,$2,'synthetic-protection','synthetic-process',1,1,$3,$4,$5,$6)",&[&a.account,&a.device,&a.setup,&a.opening,&a.command,&vec![71u8;32]]).await
}
async fn lock<C: GenericClient + Sync>(
    db: &C,
    a: &Actor,
) -> std::result::Result<(), tokio_postgres::Error> {
    db.query_one("SELECT public.device_protection_lock($1,$2,'synthetic-protection','synthetic-process',1,1)",&[&a.account,&a.device]).await.map(|_|())
}
fn association(a: &Actor, row: &Row) -> (Vec<u8>, Vec<u8>) {
    let nonce: Vec<u8> = row.get("opening_nonce");
    let key: Vec<u8> = row.get("enrolled_key_id");
    let aes = vec![73u8; 120];
    let mut bytes = b"ZTPA\x01\x01\x00\x00".to_vec();
    for id in [
        a.account, a.device, a.setup, a.opening, a.command, a.pairing,
    ] {
        bytes.extend(id.as_bytes());
    }
    bytes.extend([71u8; 32]);
    bytes.extend(key);
    bytes.extend(Sha256::digest(&nonce));
    bytes.extend([72u8; 32]);
    bytes.extend(Sha256::digest(&aes));
    bytes.extend(point(29));
    assert_eq!(bytes.len(), 329);
    (bytes, aes)
}
async fn attempt<C: GenericClient + Sync>(
    db: &C,
    a: &Actor,
    request: Uuid,
    association: &[u8],
    aes: &[u8],
    prior: Option<&Row>,
) -> std::result::Result<Row, tokio_postgres::Error> {
    let id = prior.map(|r| r.get::<_, Uuid>("attempt_id"));
    let digest = prior.map(|r| r.get::<_, Vec<u8>>("core_sha256"));
    let bundle: Option<Vec<u8>> = None;
    db.query_one("SELECT * FROM public.device_protection_attempt($1,$2,'synthetic-protection','synthetic-process',1,1,$3,$4,$5,$6,$7,$8,$9,$10,$11)",&[&a.account,&a.device,&a.setup,&a.opening,&a.command,&request,&association,&aes,&id,&digest,&bundle]).await
}
async fn accept<C: GenericClient + Sync>(
    db: &C,
    a: &Actor,
    challenge: &Row,
    bundle: &[u8],
) -> std::result::Result<Row, tokio_postgres::Error> {
    let request: Uuid = challenge.get("proof_request_id");
    let id: Uuid = challenge.get("attempt_id");
    db.query_one("SELECT * FROM public.device_protection_accept($1,$2,'synthetic-protection','synthetic-process',1,1,$3,$4,$5,$6,$7,$8)",&[&a.account,&a.device,&a.setup,&a.opening,&a.command,&request,&id,&bundle]).await
}
async fn anchor<C: GenericClient + Sync>(db: &C, a: &Actor) -> String {
    db.query_one(
        "SELECT xmin::text FROM public.payload_profile_account_anchors WHERE account_id=$1",
        &[&a.account],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn original_opening_closure_receipt_and_pruning_preserve_exact_history() {
    let f = Fixture::runtime().await;
    require(&f.reader).await.unwrap();
    assert!(require(&f.owner).await.is_err());
    let a = seed(&f).await;
    let before = anchor(&f.reader, &a).await;
    let opened = open(&f.reader, &a).await.unwrap();
    let after = anchor(&f.reader, &a).await;
    assert_ne!(before, after);
    let retried = open(&f.reader, &a).await.unwrap();
    assert_eq!(
        opened.get::<_, Vec<u8>>("opening_nonce"),
        retried.get::<_, Vec<u8>>("opening_nonce")
    );
    assert_eq!(after, anchor(&f.reader, &a).await);
    let (association, aes) = association(&a, &opened);
    let first = attempt(&f.reader, &a, Uuid::new_v4(), &association, &aes, None)
        .await
        .unwrap();
    let second = attempt(
        &f.reader,
        &a,
        Uuid::new_v4(),
        &association,
        &aes,
        Some(&first),
    )
    .await
    .unwrap();
    let mut old_bundle = first.get::<_, Vec<u8>>("core");
    old_bundle.extend([0u8; 128]);
    assert_eq!(
        accept(&f.reader, &a, &first, &old_bundle)
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::CHECK_VIOLATION)
    );
    // These deliberately synthetic signature bytes test only SQL structure.
    // Actual P256 verification must precede the narrow factory in production.
    let mut bundle = second.get::<_, Vec<u8>>("core");
    bundle.extend([0u8; 128]);
    let receipt = accept(&f.reader, &a, &second, &bundle).await.unwrap();
    let accepted_anchor = anchor(&f.reader, &a).await;
    f.owner
        .execute(
            "DELETE FROM public.pairing_requests WHERE id=$1",
            &[&a.pairing],
        )
        .await
        .unwrap();
    let retried = accept(&f.reader, &a, &second, &bundle).await.unwrap();
    assert_eq!(
        receipt.get::<_, i64>("accepted_ms"),
        retried.get::<_, i64>("accepted_ms")
    );
    assert_eq!(accepted_anchor, anchor(&f.reader, &a).await);
    assert_eq!(receipt.get::<_, Vec<u8>>("bundle"), bundle);
    assert_eq!(
        f.reader
            .query_one(
                "SELECT count(*) FROM public.device_protection_attempts WHERE account_id=$1",
                &[&a.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn explicit_recovery_budget_never_renews_on_retry_or_reconnect() {
    let f = Fixture::runtime().await;
    let a = seed(&f).await;
    let opened = open(&f.reader, &a).await.unwrap();
    let (association, aes) = association(&a, &opened);
    let mut prior = attempt(&f.reader, &a, Uuid::new_v4(), &association, &aes, None)
        .await
        .unwrap();
    for ordinal in 1_i16..=16 {
        prior = attempt(
            &f.reader,
            &a,
            Uuid::new_v4(),
            &association,
            &aes,
            Some(&prior),
        )
        .await
        .unwrap();
        assert_eq!(
            prior.get::<_, Option<i16>>("recovery_window_ordinal"),
            Some(ordinal)
        );
    }
    let request: Uuid = prior.get("proof_request_id");
    let before = anchor(&f.reader, &a).await;
    let previous: Uuid = prior.get("previous_attempt_id");
    let previous = f
        .reader
        .query_one(
            "SELECT * FROM public.device_protection_attempts WHERE account_id=$1 AND attempt_id=$2",
            &[&a.account, &previous],
        )
        .await
        .unwrap();
    let same = attempt(&f.reader, &a, request, &association, &aes, Some(&previous))
        .await
        .unwrap();
    assert_eq!(
        same.get::<_, i64>("issued_ms"),
        prior.get::<_, i64>("issued_ms")
    );
    assert_eq!(before, anchor(&f.reader, &a).await);
    assert_eq!(
        attempt(
            &f.reader,
            &a,
            Uuid::new_v4(),
            &association,
            &aes,
            Some(&prior)
        )
        .await
        .unwrap_err()
        .code(),
        Some(&SqlState::CHECK_VIOLATION)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn enrollment_identity_restoration_cannot_revive_original_public_setup() {
    let mut f = Fixture::runtime().await;
    let a = seed(&f).await;
    open(&f.reader, &a).await.unwrap();
    let held = f.reader.transaction().await.unwrap();
    lock(&held, &a).await.unwrap();
    let conflict=f.owner.execute("UPDATE public.device_keys SET signing_key_sec1=$2,fingerprint=sha256($2) WHERE device_id=$1",&[&a.device,&point(31)]).await.unwrap_err();
    assert_eq!(conflict.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    held.rollback().await.unwrap();
    lock(&f.reader, &a).await.unwrap();
    let writer = f.owner.transaction().await.unwrap();
    writer.execute("UPDATE public.device_keys SET signing_key_sec1=$2,fingerprint=sha256($2) WHERE device_id=$1",&[&a.device,&point(31)]).await.unwrap();
    assert_eq!(
        lock(&f.reader, &a).await.unwrap_err().code(),
        Some(&SqlState::LOCK_NOT_AVAILABLE)
    );
    writer.rollback().await.unwrap();
    lock(&f.reader, &a).await.unwrap();
    f.owner.execute("UPDATE public.device_keys SET signing_key_sec1=$2,fingerprint=sha256($2) WHERE device_id=$1",&[&a.device,&point(31)]).await.unwrap();
    f.owner.execute("UPDATE public.device_keys SET signing_key_sec1=$2,fingerprint=sha256($2) WHERE device_id=$1",&[&a.device,&a.point]).await.unwrap();
    assert_eq!(
        lock(&f.reader, &a).await.unwrap_err().code(),
        Some(&SqlState::CHECK_VIOLATION)
    );
    assert_eq!(
        open(&f.reader, &a).await.unwrap_err().code(),
        Some(&SqlState::CHECK_VIOLATION)
    );
    assert_eq!(
        f.reader
            .query_one(
                "SELECT count(*) FROM public.device_protection_retirements WHERE account_id=$1",
                &[&a.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn original_evidence_survives_device_deletion_and_account_cascade_has_no_history_fk_trap() {
    let f = Fixture::runtime().await;
    let a = seed(&f).await;
    let opened = open(&f.reader, &a).await.unwrap();
    let (association, aes) = association(&a, &opened);
    let challenge = attempt(&f.reader, &a, Uuid::new_v4(), &association, &aes, None)
        .await
        .unwrap();
    let mut bundle = challenge.get::<_, Vec<u8>>("core");
    bundle.extend([0u8; 128]);
    accept(&f.reader, &a, &challenge, &bundle).await.unwrap();
    f.owner
        .execute(
            "DELETE FROM public.pairing_requests WHERE id=$1",
            &[&a.pairing],
        )
        .await
        .unwrap();
    f.owner
        .execute(
            "DELETE FROM public.device_sessions WHERE device_id=$1",
            &[&a.device],
        )
        .await
        .unwrap();
    f.owner
        .execute(
            "DELETE FROM public.device_keys WHERE device_id=$1",
            &[&a.device],
        )
        .await
        .unwrap();
    f.owner
        .execute("DELETE FROM public.devices WHERE id=$1", &[&a.device])
        .await
        .unwrap();
    let original: Vec<u8> = f
        .reader
        .query_one(
            "SELECT bundle FROM public.device_protection_receipts WHERE account_id=$1",
            &[&a.account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(original, bundle);
    assert_eq!(
        f.reader
            .query_one(
                "SELECT count(*) FROM public.device_protection_retirements WHERE account_id=$1",
                &[&a.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.owner
        .execute("DELETE FROM public.accounts WHERE id=$1", &[&a.account])
        .await
        .unwrap();
    for (table, _) in TABLES {
        let query = format!("SELECT count(*) FROM public.{table} WHERE account_id=$1");
        assert_eq!(
            f.reader
                .query_one(&query, &[&a.account])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0,
            "{table}"
        );
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn old_repeatable_and_serializable_snapshots_cannot_cross_new_original_or_retirement() {
    for isolation in [IsolationLevel::RepeatableRead, IsolationLevel::Serializable] {
        let mut f = Fixture::runtime().await;
        let a = seed(&f).await;
        let old = f
            .reader
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        old.query_one(
            "SELECT count(*) FROM public.device_protection_origins WHERE account_id=$1",
            &[&a.account],
        )
        .await
        .unwrap();
        open(&f.owner, &a).await.unwrap();
        assert_eq!(
            lock(&old, &a).await.unwrap_err().code(),
            Some(&SqlState::T_R_SERIALIZATION_FAILURE)
        );
        old.rollback().await.unwrap();
        let old = f
            .reader
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        old.query_one(
            "SELECT count(*) FROM public.device_protection_retirements WHERE account_id=$1",
            &[&a.account],
        )
        .await
        .unwrap();
        f.owner
            .execute(
                "UPDATE public.device_keys SET revoked_at=clock_timestamp() WHERE device_id=$1",
                &[&a.device],
            )
            .await
            .unwrap();
        assert_eq!(
            lock(&old, &a).await.unwrap_err().code(),
            Some(&SqlState::T_R_SERIALIZATION_FAILURE)
        );
        old.rollback().await.unwrap();
        f.finish().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn stock_capability_rejects_direct_writes_partial_graph_and_changed_declarations() {
    let mut f = Fixture::runtime().await;
    require(&f.reader).await.unwrap();
    assert!(optional(&f.owner).await.unwrap());
    assert!(require(&f.owner).await.is_err());
    for statement in [
        "DELETE FROM public.device_protection_origins",
        "UPDATE public.device_protection_attempts SET closed_ms=NULL",
        "TRUNCATE public.device_protection_receipts",
        "INSERT INTO public.device_protection_retirements DEFAULT VALUES",
    ] {
        assert_eq!(
            f.reader.batch_execute(statement).await.unwrap_err().code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE)
        );
    }
    for mutation in [
        "ALTER TABLE public.device_protection_origins ADD COLUMN unknown boolean",
        "ALTER TABLE public.device_protection_attempts DISABLE TRIGGER device_protection_after_change",
        "ALTER TABLE public.devices DISABLE TRIGGER device_protection_device_changed",
        "CREATE RULE unknown AS ON DELETE TO public.device_protection_receipts DO INSTEAD NOTHING",
        "GRANT UPDATE(closed_ms) ON public.device_protection_attempts TO PUBLIC",
        "DROP TABLE public.device_protection_associations CASCADE",
    ] {
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(mutation).await.unwrap();
        assert!(optional(&tx).await.is_err(), "{mutation}");
        tx.rollback().await.unwrap();
        require(&f.reader).await.unwrap();
    }
    f.finish().await;
}
