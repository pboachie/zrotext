// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest_store::tests::Fixture;
use p256::ecdsa::{
    Signature,
    signature::{RandomizedSigner, Signer},
};
use sha2::{Digest, Sha256};

async fn now(f: &Fixture) -> i64 {
    f.db.query_one(
        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

async fn wait_for_database_deadline(f: &Fixture, deadline_ms: i64, phase: &str) {
    let started = std::time::Instant::now();
    loop {
        let observed_ms = now(f).await;
        if observed_ms >= deadline_ms {
            return;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{phase}: database deadline not reached: observed={observed_ms}, deadline={deadline_ms}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

// Keep the operation polled while observing its exact backend's lock wait.
// Elapsed time alone cannot establish that cryptographic preparation finished
// or that the intended SQL lock was reached on a loaded test runner.
async fn wait_for_blocker<T>(
    observer: &tokio_postgres::Client,
    mut pending: std::pin::Pin<&mut impl std::future::Future<Output = T>>,
    waiter: i32,
    blocker: i32,
) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::select! {
            _ = &mut pending => panic!("operation completed before the expected lock wait"),
            _ = async {
                loop {
                    let blocked: bool = observer.query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))",
                        &[&waiter, &blocker],
                    ).await.unwrap().get(0);
                    if blocked {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            } => {}
        }
    })
    .await
    .expect("expected PostgreSQL lock wait was not observed");
}

// SQL composition fixtures sign exact candidate bytes with an ephemeral device
// event key. The opaque test body is not an HPKE/decryption interoperability proof.
fn envelope(f: &Fixture, event: Uuid, sequence: u64, observed: i64, body_length: usize) -> Vec<u8> {
    let mut bytes = b"ZTSE\x02\x02\0\0".to_vec();
    bytes.extend(172u16.to_be_bytes());
    bytes.extend(f.account.as_bytes());
    bytes.extend(event.as_bytes());
    bytes.extend(f.device.as_bytes());
    bytes.extend(f.line.as_bytes());
    bytes.extend(&f.bytes[29..37]);
    bytes.extend(Sha256::digest(&f.bytes[..f.bytes.len() - 64]));
    bytes.extend(f.signer);
    bytes.extend((observed as u64).to_be_bytes());
    bytes.extend(event.as_bytes());
    bytes.extend(sequence.to_be_bytes());
    bytes.push(3);
    bytes.extend(b"+12");
    bytes.extend([3; 12]);
    bytes.extend((body_length as u32).to_be_bytes());
    bytes.extend(vec![7; body_length]);
    bytes.push(1);
    bytes.push(2);
    bytes.extend(f.readers[0].key_id);
    bytes.extend(f.root.verifying_key().to_sec1_point(false).as_bytes());
    bytes.extend([9; 48]);
    bytes.extend([0; 64]);
    resign(f, &mut bytes);
    bytes
}
fn resign(f: &Fixture, bytes: &mut [u8]) {
    let end = bytes.len() - 64;
    let signature: Signature = f.event_signer.sign(
        &[
            b"ZTSE/sign/v2\0".as_slice(),
            &(end as u32).to_be_bytes(),
            &bytes[..end],
        ]
        .concat(),
    );
    bytes[end..].copy_from_slice(&signature.normalize_s().to_bytes());
}
async fn ingest(f: &Fixture, bytes: &[u8]) -> Result<IngestOutcome, IngestError> {
    ingest_candidate02(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &f.bytes,
        bytes,
    )
    .await
}
async fn count(f: &Fixture) -> i64 {
    f.db.query_one("SELECT count(*) FROM sealed_inbound_events", &[])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_stores_exact_bytes_replays_without_rehydration_and_allows_out_of_order() {
    let f = Fixture::new().await;
    let event = Uuid::new_v4();
    let bytes = envelope(&f, event, 9, now(&f).await, 17);
    assert_eq!(bytes.len(), 426);
    assert_eq!(
        ingest(&f, &bytes).await.unwrap(),
        IngestOutcome {
            event_id: event,
            created: true
        }
    );
    assert!(!ingest(&f, &bytes).await.unwrap().created);
    let mut signature_alias = bytes.clone();
    let unsigned_end = bytes.len() - 64;
    let second_signature: Signature = f.event_signer.sign_with_rng(
        &mut rand::rng(),
        &[
            b"ZTSE/sign/v2\0".as_slice(),
            &(unsigned_end as u32).to_be_bytes(),
            &bytes[..unsigned_end],
        ]
        .concat(),
    );
    signature_alias[unsigned_end..].copy_from_slice(&second_signature.normalize_s().to_bytes());
    assert_ne!(signature_alias, bytes);
    assert!(!ingest(&f, &signature_alias).await.unwrap().created);
    let row=f.db.query_one("SELECT envelope,unsigned_digest,part_count,envelope_profile FROM sealed_inbound_events WHERE id=$1",&[&event]).await.unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), bytes);
    assert_eq!(
        row.get::<_, Vec<u8>>(1),
        Sha256::digest(&bytes[..bytes.len() - 64]).as_slice()
    );
    assert_eq!(row.get::<_, Option<i16>>(2), None);
    assert_eq!(row.get::<_, i16>(3), 2);
    f.db.execute(
        "UPDATE sealed_inbound_events SET envelope=NULL WHERE id=$1",
        &[&event],
    )
    .await
    .unwrap();
    assert!(!ingest(&f, &bytes).await.unwrap().created);
    assert!(
        f.db.query_one(
            "SELECT envelope FROM sealed_inbound_events WHERE id=$1",
            &[&event]
        )
        .await
        .unwrap()
        .get::<_, Option<Vec<u8>>>(0)
        .is_none()
    );
    let older = envelope(&f, Uuid::new_v4(), 2, now(&f).await - 60_000, 17);
    assert!(ingest(&f, &older).await.unwrap().created);
    assert_eq!(count(&f).await, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_rejects_event_forks_and_sequence_reuse_under_concurrency() {
    let f = Fixture::new().await;
    let event = Uuid::new_v4();
    let bytes = envelope(&f, event, 1, now(&f).await, 17);
    let (first, second) = tokio::join!(ingest(&f, &bytes), ingest(&f, &bytes));
    assert_eq!(
        [first.unwrap().created, second.unwrap().created]
            .iter()
            .filter(|x| **x)
            .count(),
        1
    );
    let mut changed = bytes.clone();
    changed[198] ^= 1;
    resign(&f, &mut changed);
    assert!(matches!(
        ingest(&f, &changed).await,
        Err(IngestError::EventConflict)
    ));
    let a = envelope(&f, Uuid::new_v4(), 2, now(&f).await, 17);
    let b = envelope(&f, Uuid::new_v4(), 2, now(&f).await, 17);
    let (first, second) = tokio::join!(ingest(&f, &a), ingest(&f, &b));
    assert_eq!(
        [first.is_ok(), second.is_ok()]
            .iter()
            .filter(|x| **x)
            .count(),
        1
    );
    let failure = if first.is_err() { first } else { second };
    assert!(matches!(failure, Err(IngestError::SequenceConflict)));
    assert_eq!(count(&f).await, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_cannot_acknowledge_or_replace_another_accounts_event_identity() {
    let f = Fixture::new().await;
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let line = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    f.db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
        &[&device, &account],
    )
    .await
    .unwrap();
    f.db.execute("INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) VALUES($1,$2,'active',now(),1,1)", &[&line,&account]).await.unwrap();
    f.db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,owner_approval_digest,device_confirmation_digest,activated_at,purpose) VALUES($1,$2,$3,1,'active',$4,$5,now(),'sealed')", &[&account,&line,&device,&vec![2u8;32],&vec![3u8;32]]).await.unwrap();
    let event = Uuid::new_v4();
    let bytes = envelope(&f, event, 1, now(&f).await, 17);
    // Deliberately equal digest: tenant identity must be checked independently
    // of semantic digest equality, including for already purged ciphertext.
    let digest = Sha256::digest(&bytes[..bytes.len() - 64]).to_vec();
    f.db.execute("INSERT INTO sealed_inbound_events(id,account_id,device_id,line_id,binding_generation,device_sequence,observed_at,part_count,envelope,unsigned_digest,envelope_profile) VALUES($1,$2,$3,$4,1,1,clock_timestamp(),NULL,NULL,$5,2)", &[&event,&account,&device,&line,&digest]).await.unwrap();
    assert!(matches!(
        ingest(&f, &bytes).await,
        Err(IngestError::EventConflict)
    ));
    let row =
        f.db.query_one(
            "SELECT account_id,envelope,unsigned_digest FROM sealed_inbound_events WHERE id=$1",
            &[&event],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Uuid>(0), account);
    assert!(row.get::<_, Option<Vec<u8>>>(1).is_none());
    assert_eq!(row.get::<_, Vec<u8>>(2), digest);
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let own_event = envelope(&f, Uuid::new_v4(), 1, now(&f).await, 17);
    assert!(ingest(&f, &own_event).await.unwrap().created);
    assert_eq!(count(&f).await, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_rejects_bad_signature_identity_and_bounds_without_advancing_authority() {
    let f = Fixture::new().await;
    let time = now(&f).await;
    let good = envelope(&f, Uuid::new_v4(), 1, time, 17);
    let mut bad_signature = good.clone();
    let end = bad_signature.len() - 1;
    bad_signature[end] ^= 1;
    let mut wrong_account = good.clone();
    wrong_account[10] ^= 1;
    resign(&f, &mut wrong_account);
    let mut wrong_device = good.clone();
    wrong_device[42] ^= 1;
    resign(&f, &mut wrong_device);
    let mut wrong_line = good.clone();
    wrong_line[58] ^= 1;
    resign(&f, &mut wrong_line);
    let mut wrong_manifest = good.clone();
    wrong_manifest[82] ^= 1;
    resign(&f, &mut wrong_manifest);
    let mut wrong_profile = good.clone();
    wrong_profile[4] = 1;
    let zero_id = envelope(&f, Uuid::nil(), 1, time, 17);
    let zero_sequence = envelope(&f, Uuid::new_v4(), 0, time, 17);
    for bad in [
        bad_signature,
        wrong_account,
        wrong_device,
        wrong_line,
        wrong_manifest,
        wrong_profile,
        zero_id,
        zero_sequence,
        envelope(&f, Uuid::new_v4(), 1, time, 16),
        envelope(&f, Uuid::new_v4(), 1, time, 32_785),
        vec![0; 36_865],
        envelope(&f, Uuid::new_v4(), 1, time - MAX_AGE_MS - 1, 17),
        envelope(&f, Uuid::new_v4(), 1, time + MAX_FUTURE_MS + 60_000, 17),
    ] {
        assert!(ingest(&f, &bad).await.is_err());
        assert_eq!(count(&f).await, 0);
        assert_eq!(
            f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    let maximum_body = envelope(&f, Uuid::new_v4(), 1, time, 32_784);
    assert!(ingest(&f, &maximum_body).await.unwrap().created);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_current_session_and_manifest_are_required_even_for_existing_identity() {
    let mut f = Fixture::new().await;
    let first = envelope(&f, Uuid::new_v4(), 1, now(&f).await, 17);
    ingest(&f, &first).await.unwrap();
    f.advance();
    let next = envelope(&f, Uuid::new_v4(), 2, now(&f).await, 17);
    // A caller cannot advance the manifest while submitting an older envelope.
    assert!(ingest(&f, &first).await.is_err());
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    ingest(&f, &next).await.unwrap();
    assert!(ingest(&f, &first).await.is_err());
    f.db.execute("UPDATE device_sessions SET connection_epoch=2", &[])
        .await
        .unwrap();
    assert!(ingest(&f, &next).await.is_err());
    assert_eq!(count(&f).await, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_rechecks_lease_after_insert_wait_and_rolls_back_staged_high_water() {
    let f = Fixture::new().await;
    let event = Uuid::new_v4();
    let bytes = envelope(&f, event, 1, now(&f).await, 17);
    let mut blocker = f.connect().await;
    let lock = blocker.transaction().await.unwrap();
    // The unique event index can wait even after all authority/session locks.
    // This direct SQL fixture preserves the same immutable candidate shape.
    lock.execute("INSERT INTO sealed_inbound_events(id,account_id,device_id,line_id,binding_generation,device_sequence,observed_at,part_count,envelope,unsigned_digest,envelope_profile) VALUES($1,$2,$3,$4,1,1,clock_timestamp(),NULL,$5,$6,2)",
        &[&event,&f.account,&f.device,&f.line,&bytes,&Sha256::digest(&bytes[..bytes.len()-64]).as_slice()]).await.unwrap();
    f.db.execute(
        "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '500 milliseconds'",
        &[],
    )
    .await
    .unwrap();
    let mut future = Box::pin(ingest(&f, &bytes));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(650), &mut future)
            .await
            .is_err()
    );
    // Host elapsed time proves the insert remains blocked, but only the
    // database clock can establish expiry of the actual stored lease.
    let started = std::time::Instant::now();
    loop {
        let row = lock.query_one(
            "WITH observed AS MATERIALIZED (SELECT clock_timestamp() AS at) SELECT at >= lease_until, at::text, lease_until::text FROM device_sessions CROSS JOIN observed WHERE device_id=$1",
            &[&f.device],
        ).await.unwrap();
        if row.get::<_, bool>(0) {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "insert-wait lease: database deadline not reached: observed={}, deadline={}",
            row.get::<_, String>(1),
            row.get::<_, String>(2)
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    lock.commit().await.unwrap();
    assert!(future.await.is_err());
    assert_eq!(count(&f).await, 1);
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_preserves_legacy_profile_constraints_and_prune_tombstones() {
    let f = Fixture::new().await;
    let event = Uuid::new_v4();
    let candidate = envelope(&f, event, 1, now(&f).await, 17);
    let mut legacy = candidate.clone();
    legacy[4] = 1;
    // The old table accepted bounded prefix-only proof fixtures. Keep that
    // storage compatibility; the new ingest entrypoint never accepts profile01.
    f.db.execute("INSERT INTO sealed_inbound_events(id,account_id,device_id,line_id,binding_generation,device_sequence,observed_at,part_count,envelope,unsigned_digest) VALUES($1,$2,$3,$4,1,1,clock_timestamp(),1,$5,$6)",
        &[&event,&f.account,&f.device,&f.line,&legacy,&Sha256::digest(&candidate[..candidate.len()-64]).as_slice()]).await.unwrap();
    assert!(matches!(
        ingest(&f, &candidate).await,
        Err(IngestError::EventConflict)
    ));
    let other_event = envelope(&f, Uuid::new_v4(), 1, now(&f).await, 17);
    assert!(matches!(
        ingest(&f, &other_event).await,
        Err(IngestError::SequenceConflict)
    ));
    let valid = envelope(&f, Uuid::new_v4(), 2, now(&f).await, 17);
    ingest(&f, &valid).await.unwrap();
    let mut db = f.connect().await;
    for update in [
        "UPDATE sealed_inbound_events SET part_count=NULL WHERE envelope_profile=1",
        "UPDATE sealed_inbound_events SET part_count=1 WHERE envelope_profile=2",
        "UPDATE sealed_inbound_events SET envelope_profile=1 WHERE envelope_profile=2",
        "UPDATE sealed_inbound_events SET envelope=NULL,envelope_profile=1,part_count=1 WHERE envelope_profile=2",
    ] {
        let tx = db.transaction().await.unwrap();
        assert!(tx.execute(update, &[]).await.is_err());
        tx.rollback().await.unwrap();
    }
    // Exercise the real bounded content-prune function with immediate expiry,
    // without changing immutable accepted timestamps just to age a fixture.
    let policy = crate::retention::RetentionPolicy {
        sealed_inbound_days: 0,
        ..Default::default()
    };
    db.batch_execute(include_str!(
        "../../../../../deploy/compose/migrations/064_owner_conversation_consent.sql"
    ))
    .await
    .unwrap();
    db.batch_execute(include_str!(
        "../../../../../deploy/compose/migrations/065_conversation_activation.sql"
    ))
    .await
    .unwrap();
    db.batch_execute(include_str!(
        "../../../../../deploy/compose/migration-candidates/NNN_conversation_confirmation_records.sql"
    ))
    .await
    .unwrap();
    let pruned = crate::retention::prune(&mut db, policy, 10).await.unwrap();
    assert_eq!(pruned.sealed_inbound_events, 2);
    assert_eq!(count(&f).await, 2);
    assert_eq!(f.db.query_one("SELECT count(*) FROM sealed_inbound_events WHERE envelope IS NULL AND octet_length(unsigned_digest)=32",&[]).await.unwrap().get::<_,i64>(0),2);
    assert!(!ingest(&f, &valid).await.unwrap().created);
    assert!(matches!(
        ingest(&f, &candidate).await,
        Err(IngestError::EventConflict)
    ));
    assert!(
        f.db.execute(
            "UPDATE sealed_inbound_events SET envelope=$1 WHERE envelope_profile=2",
            &[&valid]
        )
        .await
        .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_does_not_acknowledge_existing_identity_with_expired_authority_or_event_age()
 {
    // Allow bounded crypto/database setup while authority is live. The replay
    // assertions below still wait for the actual database expiry boundary.
    let setup_window_ms = 2_000;
    for expire_manifest in [false, true] {
        let mut f = Fixture::new().await;
        let time = now(&f).await;
        if expire_manifest {
            f.bytes[45..53].copy_from_slice(&((time + setup_window_ms) as u64).to_be_bytes());
            f.resign();
        }
        let observed = if expire_manifest {
            time
        } else {
            time - MAX_AGE_MS + setup_window_ms
        };
        let bytes = envelope(&f, Uuid::new_v4(), 1, observed, 17);
        ingest(&f, &bytes).await.unwrap();
        let (deadline, phase) = if expire_manifest {
            (time + setup_window_ms, "manifest replay expiry")
        } else {
            // Event age rejects strictly older timestamps, so observe the
            // first database millisecond beyond the inclusive age bound.
            (observed + MAX_AGE_MS + 1, "event replay age")
        };
        wait_for_database_deadline(&f, deadline, phase).await;
        assert!(ingest(&f, &bytes).await.is_err());
        assert_eq!(count(&f).await, 1);
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_revocation_serializes_before_admission_or_after_its_owned_commit() {
    for revoke_first in [false, true] {
        let f = Fixture::new().await;
        let bytes = envelope(&f, Uuid::new_v4(), 1, now(&f).await, 17);
        let mut admission = f.connect().await;
        let admission_pid: i32 = admission
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let mut blocker = f.connect().await;
        let blocker_pid: i32 = blocker
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let tx = blocker.transaction().await.unwrap();
        // Model preparation that takes longer than the former 100ms polling
        // window. The barrier must establish the SQL wait, not assume it.
        let mut pending = Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            ingest_candidate02(&mut admission, f.session(), f.line, 1, &f.bytes, &bytes).await
        });
        if revoke_first {
            tx.execute("UPDATE device_keys SET revoked_at=clock_timestamp()", &[])
                .await
                .unwrap();
            wait_for_blocker(&f.db, pending.as_mut(), admission_pid, blocker_pid).await;
            tx.commit().await.unwrap();
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(10), pending)
                    .await
                    .unwrap()
                    .is_err()
            );
            assert_eq!(count(&f).await, 0);
        } else {
            tx.batch_execute("LOCK TABLE sealed_inbound_events IN ACCESS EXCLUSIVE MODE")
                .await
                .unwrap();
            wait_for_blocker(&f.db, pending.as_mut(), admission_pid, blocker_pid).await;
            let other = f.connect().await;
            let revocation_pid: i32 = other
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0);
            let mut revocation =
                Box::pin(other.execute("UPDATE device_keys SET revoked_at=clock_timestamp()", &[]));
            wait_for_blocker(&f.db, revocation.as_mut(), revocation_pid, admission_pid).await;
            tx.commit().await.unwrap();
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(10), pending)
                    .await
                    .unwrap()
                    .unwrap()
                    .created
            );
            tokio::time::timeout(std::time::Duration::from_secs(10), revocation)
                .await
                .unwrap()
                .unwrap();
            assert!(ingest(&f, &bytes).await.is_err());
            assert_eq!(count(&f).await, 1);
        }
        f.cleanup().await;
    }
}

async fn shared_budget_attempts(f: &Fixture) -> Vec<i32> {
    f.db.query(
        "SELECT attempts FROM auth_abuse_counters WHERE scope='inbound_daily' ORDER BY attempts",
        &[],
    )
    .await
    .unwrap()
    .iter()
    .map(|row| row.get(0))
    .collect()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_ingest_spends_the_shared_storage_budget_and_replays_are_free() {
    let f = Fixture::new().await;
    let stored = envelope(&f, Uuid::new_v4(), 1, now(&f).await, 17);
    assert!(ingest(&f, &stored).await.unwrap().created);
    // One account row and one device row, charged once each.
    assert_eq!(shared_budget_attempts(&f).await, vec![1, 1]);
    assert!(!ingest(&f, &stored).await.unwrap().created);
    assert_eq!(shared_budget_attempts(&f).await, vec![1, 1]);
    // Two writers racing with one new event store it once and charge once.
    let raced = envelope(&f, Uuid::new_v4(), 2, now(&f).await, 17);
    let (first, second) = tokio::join!(ingest(&f, &raced), ingest(&f, &raced));
    assert_eq!(
        [first.unwrap().created, second.unwrap().created]
            .iter()
            .filter(|created| **created)
            .count(),
        1
    );
    assert_eq!(shared_budget_attempts(&f).await, vec![2, 2]);
    // Spend the device's daily allowance. A new envelope is refused before
    // its INSERT; a stored one still replays for free.
    f.db.execute(
        "UPDATE auth_abuse_counters SET attempts=200 WHERE scope='inbound_daily'",
        &[],
    )
    .await
    .unwrap();
    f.db.batch_execute(
        "CREATE FUNCTION reject_budget_insert() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'over-budget sealed INSERT attempted'; END $$; \
         CREATE TRIGGER reject_budget_insert BEFORE INSERT ON sealed_inbound_events \
         FOR EACH ROW EXECUTE FUNCTION reject_budget_insert()",
    )
    .await
    .unwrap();
    let refused = envelope(&f, Uuid::new_v4(), 3, now(&f).await, 17);
    assert!(matches!(
        ingest(&f, &refused).await,
        Err(IngestError::BudgetExhausted)
    ));
    // A BEFORE INSERT trigger fires even for ON CONFLICT DO NOTHING.
    f.db.batch_execute("DROP TRIGGER reject_budget_insert ON sealed_inbound_events")
        .await
        .unwrap();
    assert!(!ingest(&f, &stored).await.unwrap().created);
    assert_eq!(count(&f).await, 2);
    assert_eq!(shared_budget_attempts(&f).await, vec![200, 200]);
    f.cleanup().await;
}
