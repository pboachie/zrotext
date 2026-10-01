// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_envelope::ExpectedRecipient;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, NoTls};

pub(crate) struct Fixture {
    pub(crate) url: String,
    pub(crate) schema: String,
    pub(crate) db: Client,
    pub(crate) account: Uuid,
    pub(crate) device: Uuid,
    pub(crate) line: Uuid,
    pub(crate) root: SigningKey,
    pub(crate) pin: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) readers: Vec<ExpectedRecipient>,
    pub(crate) signer: [u8; 32],
    pub(crate) event_signer: SigningKey,
    #[cfg(feature = "conversation-simulator-tests")]
    pub(crate) archive_key: SigningKey,
}

impl Fixture {
    pub(crate) async fn new() -> Self {
        Self::with_purpose("sealed").await
    }
    pub(crate) async fn with_purpose(purpose: &str) -> Self {
        Self::build(purpose, true, true).await
    }
    pub(crate) async fn without_authority() -> Self {
        Self::build("sealed", false, true).await
    }
    pub(crate) async fn before_role_reservations() -> Self {
        Self::build("sealed", true, false).await
    }
    async fn build(purpose: &str, provision: bool, role_reservations: bool) -> Self {
        let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL").expect("disposable test database");
        let (db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("manifest_authority_{}", Uuid::new_v4().simple());
        db.batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
        // Real prerequisite migrations, not a permissive substitute schema.
        for sql in [
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
            include_str!("../../../../deploy/compose/migrations/019_line_activation_contract.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/020_enrollment_retention_indexes.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
            ),
            include_str!(
                "../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/025_account_recovery.sql"),
            include_str!("../../../../deploy/compose/migrations/026_data_retention.sql"),
            include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
            include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
            include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
            include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
            include_str!("../../../../deploy/compose/migrations/032_line_opt_out_events.sql"),
            include_str!("../../../../deploy/compose/migrations/033_sms_line_binding_scope.sql"),
            include_str!("../../../../deploy/compose/migrations/034_delivery_sweep_index.sql"),
            include_str!("../../../../deploy/compose/migrations/035_sms_owner_key_ceremony.sql"),
            include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/037_sms_line_activation_exchange.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/040_radio_evidence_index.sql"),
            include_str!("../../../../deploy/compose/migrations/041_device_preconditions.sql"),
            include_str!("../../../../deploy/compose/migrations/042_sealed_manifest_authority.sql"),
            include_str!("../../../../deploy/compose/migrations/043_sealed_candidate_inbound.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/044_sealed_root_role_reservations.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/045_sealed_outbound_queue.sql"),
            include_str!("../../../../deploy/compose/migrations/046_sealed_root_ceremonies.sql"),
            include_str!("../../../../deploy/compose/migrations/047_device_network_service.sql"),
            // The retention prune stamp column; this fixture's schemas are
            // exercised through retention::prune.
            include_str!("../../../../deploy/compose/migrations/063_retention_blocked_stamp.sql"),
            include_str!("../../../../deploy/compose/migrations/071_sealed_grant_authority.sql"),
        ] {
            if !role_reservations
                && (sql
                    == include_str!(
                        "../../../../deploy/compose/migrations/044_sealed_root_role_reservations.sql"
                    )
                    || sql
                        == include_str!(
                            "../../../../deploy/compose/migrations/046_sealed_root_ceremonies.sql"
                        ))
            {
                // Backfill tests intentionally start before trust-history
                // guards; the later ceremony triggers depend on those guards.
                continue;
            }
            // Mirror the migrator's autocommit index preparation, followed by
            // each exact numbered validation gate on this complete schema.
            if sql.contains("CREATE FUNCTION messages_in_flight_index_ready") {
                db.batch_execute("CREATE INDEX CONCURRENTLY messages_in_flight_updated ON messages(updated_at,id) WHERE state IN ('claimed','submitting','submitted')").await.unwrap();
            }
            if sql.contains("CREATE FUNCTION message_events_radio_evidence_index_ready") {
                db.batch_execute("CREATE INDEX CONCURRENTLY message_events_attempt_evidence ON message_events(attempt_id,evidence_code)").await.unwrap();
            }
            db.batch_execute(sql).await.unwrap();
        }
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        let line = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        db.execute("INSERT INTO sites(site_id) VALUES('manifest-test')", &[])
            .await
            .unwrap();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
            &[&device, &account],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
            &[&device,&account,&vec![4u8;65],&vec![1u8;32]]).await.unwrap();
        db.execute("INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES($1,$2,'manifest-test','fixture',1,clock_timestamp()+interval '10 minutes',1)", &[&device,&account]).await.unwrap();
        db.execute("INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) VALUES($1,$2,'active',now(),1,1)", &[&line,&account]).await.unwrap();
        db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,owner_approval_digest,device_confirmation_digest,activated_at,purpose) VALUES($1,$2,$3,1,'active',$4,$5,now(),$6)", &[&account,&line,&device,&vec![2u8;32],&vec![3u8;32],&purpose]).await.unwrap();
        let now: i64 = db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let root_point = root.verifying_key().to_sec1_point(false);
        let mut pin = b"ZTRP\x02".to_vec();
        pin.extend(account.as_bytes());
        pin.extend(1u64.to_be_bytes());
        pin.extend(root_point.as_bytes());
        let mut bytes = b"ZTMA\x02".to_vec();
        bytes.extend(account.as_bytes());
        bytes.extend(1u64.to_be_bytes());
        bytes.extend(1u64.to_be_bytes());
        bytes.extend((now as u64 - 1_000).to_be_bytes());
        bytes.extend((now as u64 + 120_000).to_be_bytes());
        bytes.extend([0; 32]);
        bytes.extend(root_point.as_bytes());
        bytes.push(3);
        let mut readers = Vec::new();
        let mut signer = [0; 32];
        let mut event_signer = None;
        #[cfg(feature = "conversation-simulator-tests")]
        let mut archive_key = None;
        for (role, scope) in [(2, 12u16), (4, 2), (6, 0)] {
            let key = SigningKey::generate_from_rng(&mut rand::rng());
            let point = if role == 6 {
                root.verifying_key().to_sec1_point(false)
            } else {
                key.verifying_key().to_sec1_point(false)
            };
            let algorithm: [u8; 2] = if role == 2 { [0, 16] } else { [1, 1] };
            let id: [u8; 32] = Sha256::digest(
                [b"ZTSE/key/v1\0".as_slice(), &algorithm, point.as_bytes()].concat(),
            )
            .into();
            bytes.push(role);
            bytes.extend(id);
            bytes.extend(point.as_bytes());
            bytes.extend(if role == 4 {
                *device.as_bytes()
            } else {
                [0; 16]
            });
            bytes.extend(if role == 4 { *line.as_bytes() } else { [0; 16] });
            bytes.extend(scope.to_be_bytes());
            bytes.extend((now as u64 - 1_000).to_be_bytes());
            bytes.extend((now as u64 + 240_000).to_be_bytes());
            bytes.push(1);
            if role == 2 {
                readers.push(ExpectedRecipient { role, key_id: id });
                #[cfg(feature = "conversation-simulator-tests")]
                {
                    archive_key = Some(key.clone());
                }
            }
            if role == 4 {
                signer = id;
                event_signer = Some(key);
            }
        }
        bytes.extend([0; 64]);
        let mut fixture = Self {
            url,
            schema,
            db,
            account,
            device,
            line,
            root,
            pin,
            bytes,
            readers,
            signer,
            event_signer: event_signer.unwrap(),
            #[cfg(feature = "conversation-simulator-tests")]
            archive_key: archive_key.unwrap(),
        };
        fixture.resign();
        // Test-only provisioning models an already independently compared root.
        let fingerprint =
            Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), &fixture.pin].concat()).to_vec();
        if provision {
            fixture.db.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)", &[&account,&fixture.pin,&fingerprint,&vec![0u8;32]]).await.unwrap();
        }
        fixture
    }
    pub(crate) async fn connect(&self) -> Client {
        let (db, connection) = tokio_postgres::connect(&self.url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        db.batch_execute(&format!(
            "SET search_path TO {}; SET statement_timeout='10s'",
            self.schema
        ))
        .await
        .unwrap();
        db
    }
    pub(crate) fn session(&self) -> InboundSession<'static> {
        InboundSession {
            account_id: self.account,
            device_id: self.device,
            site_id: "manifest-test",
            instance_id: "fixture",
            connection_epoch: 1,
            deployment_epoch: 1,
        }
    }
    pub(crate) fn wanted(&self) -> EnvelopeAuthority<'_> {
        EnvelopeAuthority {
            kind: Kind::Inbound,
            account_id: *self.account.as_bytes(),
            device_id: *self.device.as_bytes(),
            line_id: *self.line.as_bytes(),
            message_id: [8; 16],
            signer_key_id: self.signer,
            peer: b"+12",
            recipients: &self.readers,
        }
    }
    pub(crate) fn resign(&mut self) {
        let n = self.bytes.len() - 64;
        let signature: Signature = self.root.sign(
            &[
                b"ZTSE/manifest/v2\0".as_slice(),
                &(n as u32).to_be_bytes(),
                &self.bytes[..n],
            ]
            .concat(),
        );
        self.bytes[n..].copy_from_slice(&signature.normalize_s().to_bytes());
    }
    pub(crate) fn advance(&mut self) {
        let digest = Sha256::digest(&self.bytes[..self.bytes.len() - 64]);
        let version = u64::from_be_bytes(self.bytes[29..37].try_into().unwrap());
        self.bytes[29..37].copy_from_slice(&(version + 1).to_be_bytes());
        self.bytes[53..85].copy_from_slice(&digest);
        self.resign();
    }
    pub(crate) async fn cleanup(self) {
        self.db
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn manifest_store_persists_chain_and_rejects_fork_gap_rollback_and_bad_signature() {
    let mut f = Fixture::new().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut admission = admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    assert_eq!(admission.change(), AdmissionChange::Advanced);
    assert_eq!(
        admission.context(&f.wanted()).await.unwrap().keyset_version,
        1
    );
    drop(admission);
    tx.commit().await.unwrap();
    let original = f.bytes.clone();
    // Reconnect: persisted high-water, not process memory, controls replay.
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert_eq!(
        admit(&tx, f.session(), f.line, 1, &f.bytes)
            .await
            .unwrap()
            .change(),
        AdmissionChange::Replayed
    );
    tx.commit().await.unwrap();
    let changed_issued = u64::from_be_bytes(f.bytes[37..45].try_into().unwrap()) - 1;
    f.bytes[37..45].copy_from_slice(&changed_issued.to_be_bytes());
    f.resign();
    let tx = db.transaction().await.unwrap();
    assert!(admit(&tx, f.session(), f.line, 1, &f.bytes).await.is_err());
    tx.rollback().await.unwrap();
    f.bytes = original.clone();
    f.advance();
    let second = f.bytes.clone();
    f.advance();
    let tx = db.transaction().await.unwrap();
    assert!(admit(&tx, f.session(), f.line, 1, &f.bytes).await.is_err());
    tx.rollback().await.unwrap();
    f.bytes = second.clone();
    let end = f.bytes.len() - 1;
    f.bytes[end] ^= 1;
    let tx = db.transaction().await.unwrap();
    assert!(admit(&tx, f.session(), f.line, 1, &f.bytes).await.is_err());
    tx.rollback().await.unwrap();
    f.bytes = second;
    let tx = db.transaction().await.unwrap();
    assert_eq!(
        admit(&tx, f.session(), f.line, 1, &f.bytes)
            .await
            .unwrap()
            .change(),
        AdmissionChange::Advanced
    );
    tx.commit().await.unwrap();
    let tx = db.transaction().await.unwrap();
    assert!(admit(&tx, f.session(), f.line, 1, &original).await.is_err());
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn manifest_store_serializes_revocation_in_both_lock_orders() {
    for update in [
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp()",
        "UPDATE accounts SET disabled_at=clock_timestamp()",
        "UPDATE devices SET revoked_at=clock_timestamp()",
        "UPDATE device_keys SET revoked_at=clock_timestamp()",
        "UPDATE sites SET draining=TRUE",
        "UPDATE deployment_authority SET epoch=2",
        "UPDATE phone_lines SET state='revoked'",
        "UPDATE device_line_bindings SET state='revoked'",
        "UPDATE device_sessions SET connection_epoch=2",
    ] {
        for revoke_first in [false, true] {
            let f = Fixture::new().await;
            let mut db = f.connect().await;
            let mut other = f.connect().await;
            let admission_tx = db.transaction().await.unwrap();
            let revocation = other.transaction().await.unwrap();
            if revoke_first {
                revocation.execute(update, &[]).await.unwrap();
                let mut future = Box::pin(admit(&admission_tx, f.session(), f.line, 1, &f.bytes));
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(25), &mut future)
                        .await
                        .is_err(),
                    "{update}"
                );
                revocation.commit().await.unwrap();
                assert!(future.await.is_err(), "{update}");
                admission_tx.rollback().await.unwrap();
            } else {
                let mut admission = admit(&admission_tx, f.session(), f.line, 1, &f.bytes)
                    .await
                    .unwrap();
                let mut future = Box::pin(revocation.execute(update, &[]));
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(25), &mut future)
                        .await
                        .is_err(),
                    "{update}"
                );
                admission.context(&f.wanted()).await.unwrap();
                drop(admission);
                admission_tx.commit().await.unwrap();
                future.await.unwrap();
                revocation.commit().await.unwrap();
                let tx = db.transaction().await.unwrap();
                assert!(
                    admit(&tx, f.session(), f.line, 1, &f.bytes).await.is_err(),
                    "{update}"
                );
                tx.rollback().await.unwrap();
            }
            f.cleanup().await;
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn manifest_store_rechecks_expiry_after_lock_wait_and_before_effects() {
    for expire_manifest in [false, true] {
        let phase = if expire_manifest { "manifest" } else { "lease" };
        let mut f = Fixture::new().await;
        let mut db = f.connect().await;
        let mut blocker = f.connect().await;
        if expire_manifest {
            let expires: i64 = db
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint+500",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            f.bytes[45..53].copy_from_slice(&(expires as u64).to_be_bytes());
            f.resign();
        } else {
            db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()+interval '500 milliseconds'",&[]).await.unwrap();
        }
        let lock = blocker.transaction().await.unwrap();
        // Account lock forces a wait inside the existing line/session preflight,
        // after acquiring authority. Its lease predicate must be checked again.
        lock.query_one("SELECT id FROM accounts FOR UPDATE", &[])
            .await
            .unwrap();
        let tx = db.transaction().await.unwrap();
        let mut future = Box::pin(admit(&tx, f.session(), f.line, 1, &f.bytes));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(650), &mut future)
                .await
                .is_err(),
            "{phase}: admission must still wait for the account lock"
        );
        // Host elapsed time does not establish a database-clock deadline.
        // Keep the blocker until PostgreSQL itself observes expiration; compare
        // the lease's stored timestamp directly, without millisecond rounding.
        let manifest_deadline =
            i64::try_from(u64::from_be_bytes(f.bytes[45..53].try_into().unwrap())).unwrap();
        let mut last_observation: Option<(String, String)> = None;
        let expired = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let observation = lock
                    .query_one(
                        "WITH observed AS MATERIALIZED (SELECT clock_timestamp() AS now) \
                     SELECT observed.now::text,s.lease_until::text, \
                     CASE WHEN $2 THEN floor(extract(epoch FROM observed.now)*1000)::bigint >= $3 \
                          ELSE observed.now >= s.lease_until END \
                     FROM observed CROSS JOIN device_sessions s WHERE s.device_id=$1",
                        &[&f.device, &expire_manifest, &manifest_deadline],
                    )
                    .await
                    .unwrap();
                last_observation = Some((observation.get(0), observation.get(1)));
                if observation.get::<_, bool>(2) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            expired.is_ok(),
            "{phase}: database expiry barrier timed out; (now,lease)={last_observation:?}, signed_deadline_ms={manifest_deadline}"
        );
        lock.commit().await.unwrap();
        let rejected = future.await.is_err();
        let after = tx
            .query_one(
                "SELECT clock_timestamp()::text,last_verified_ms FROM sealed_manifest_authorities WHERE account_id=$1",
                &[&f.account],
            )
            .await
            .ok()
            .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)));
        assert!(
            rejected,
            "{phase}: admission must reject after database expiry; (now,lease)={last_observation:?}, signed_deadline_ms={manifest_deadline}, after(now,accepted_ms)={after:?}"
        );
        tx.rollback().await.unwrap();
        f.cleanup().await;
    }
    let f = Fixture::new().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut admission = admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    tx.execute(
        "UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 millisecond'",
        &[],
    )
    .await
    .unwrap();
    assert!(admission.context(&f.wanted()).await.is_err());
    drop(admission);
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn manifest_store_expired_predecessor_can_advance_but_cannot_replay() {
    let mut f = Fixture::new().await;
    let mut db = f.connect().await;
    let now: i64 = db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    f.bytes[45..53].copy_from_slice(&((now + 500) as u64).to_be_bytes());
    f.resign();
    let tx = db.transaction().await.unwrap();
    admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    tx.commit().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(650)).await;
    let tx = db.transaction().await.unwrap();
    assert!(admit(&tx, f.session(), f.line, 1, &f.bytes).await.is_err());
    tx.rollback().await.unwrap();
    f.advance();
    f.bytes[45..53].copy_from_slice(&((now + 120_000) as u64).to_be_bytes());
    f.resign();
    let tx = db.transaction().await.unwrap();
    assert_eq!(
        admit(&tx, f.session(), f.line, 1, &f.bytes)
            .await
            .unwrap()
            .change(),
        AdmissionChange::Advanced
    );
    tx.commit().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn manifest_store_enforces_scope_high_water_and_immutable_trust_without_blocking_erasure() {
    let f = Fixture::with_purpose("sms").await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(admit(&tx, f.session(), f.line, 1, &f.bytes).await.is_err());
    tx.rollback().await.unwrap();
    f.cleanup().await;

    let f = Fixture::new().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut admission = admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    tx.execute(
        "UPDATE sealed_manifest_authorities SET last_verified_ms=last_verified_ms+60000",
        &[],
    )
    .await
    .unwrap();
    assert!(admission.context(&f.wanted()).await.is_err());
    drop(admission);
    tx.commit().await.unwrap();
    let tx = db.transaction().await.unwrap();
    assert!(admit(&tx, f.session(), f.line, 1, &f.bytes).await.is_err());
    tx.rollback().await.unwrap();
    for update in [
        "UPDATE sealed_manifest_authorities SET generation=2,anchor_digest=decode(repeat('01',32),'hex')",
        "UPDATE sealed_manifest_authorities SET root_pin=decode(repeat('01',94),'hex')",
        "UPDATE sealed_manifest_authorities SET version=version+2",
        "UPDATE sealed_manifest_authorities SET last_verified_ms=last_verified_ms-1",
        "UPDATE sealed_manifest_authorities SET manifest=decode(repeat('01',364),'hex')",
    ] {
        let tx = db.transaction().await.unwrap();
        assert!(tx.execute(update, &[]).await.is_err(), "{update}");
        tx.rollback().await.unwrap();
    }
    // An otherwise empty account proves this table does not obstruct erasure;
    // unrelated legacy line tombstones have their own deletion policy.
    let erased = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&erased])
        .await
        .unwrap();
    db.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) SELECT $1,root_pin,root_fingerprint,generation,anchor_digest FROM sealed_manifest_authorities WHERE account_id=$2",&[&erased,&f.account]).await.unwrap();
    db.execute("DELETE FROM accounts WHERE id=$1", &[&erased])
        .await
        .unwrap();
    assert!(
        db.query_opt(
            "SELECT 1 FROM sealed_manifest_authorities WHERE account_id=$1",
            &[&erased]
        )
        .await
        .unwrap()
        .is_none()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn manifest_store_concurrent_same_version_replays_and_fork_loses() {
    let mut f = Fixture::new().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    tx.commit().await.unwrap();
    f.advance();
    for fork in [false, true] {
        let mut competitor = f.connect().await;
        let tx = db.transaction().await.unwrap();
        admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
        let first = f.bytes.clone();
        if fork {
            let issued = u64::from_be_bytes(f.bytes[37..45].try_into().unwrap()) - 1;
            f.bytes[37..45].copy_from_slice(&issued.to_be_bytes());
            f.resign();
        }
        let waiting = competitor.transaction().await.unwrap();
        let mut request = Box::pin(admit(&waiting, f.session(), f.line, 1, &f.bytes));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut request)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
        let result = request.await;
        if fork {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().change(), AdmissionChange::Replayed);
        }
        waiting.rollback().await.unwrap();
        f.bytes = first;
        f.advance();
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn manifest_store_isolation_missing_pin_and_transaction_rollback_fail_closed() {
    let f = Fixture::new().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(
        admit(
            &tx,
            InboundSession {
                account_id: Uuid::new_v4(),
                ..f.session()
            },
            f.line,
            1,
            &f.bytes
        )
        .await
        .is_err()
    );
    assert!(
        admit(
            &tx,
            InboundSession {
                device_id: Uuid::new_v4(),
                ..f.session()
            },
            f.line,
            1,
            &f.bytes
        )
        .await
        .is_err()
    );
    assert!(
        admit(
            &tx,
            InboundSession {
                connection_epoch: 2,
                ..f.session()
            },
            f.line,
            1,
            &f.bytes
        )
        .await
        .is_err()
    );
    assert!(
        admit(
            &tx,
            InboundSession {
                deployment_epoch: 2,
                ..f.session()
            },
            f.line,
            1,
            &f.bytes
        )
        .await
        .is_err()
    );
    assert!(
        admit(&tx, f.session(), Uuid::new_v4(), 1, &f.bytes)
            .await
            .is_err()
    );
    assert!(admit(&tx, f.session(), f.line, 2, &f.bytes).await.is_err());
    let mut admission = admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    let mut wanted = f.wanted();
    wanted.kind = Kind::Outbound;
    assert!(admission.context(&wanted).await.is_err());
    wanted = f.wanted();
    wanted.device_id = [7; 16];
    assert!(admission.context(&wanted).await.is_err());
    drop(admission);
    tx.rollback().await.unwrap();
    assert_eq!(
        db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    db.execute("DELETE FROM sealed_manifest_authorities", &[])
        .await
        .unwrap();
    let tx = db.transaction().await.unwrap();
    assert!(admit(&tx, f.session(), f.line, 1, &f.bytes).await.is_err());
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn manifest_store_current_revocation_invalidates_earlier_admission_in_same_transaction() {
    let mut f = Fixture::new().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut original = admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    original.context(&f.wanted()).await.unwrap();
    f.advance();
    // The device signer is the second ordered record. A signed revocation must
    // be persistable, while it must never produce an authorized signer context.
    f.bytes[151 + 149 + 148] = 2;
    f.resign();
    let mut revoked = admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    assert!(revoked.context(&f.wanted()).await.is_err());
    assert!(original.context(&f.wanted()).await.is_err());
    drop(revoked);
    drop(original);
    // No effects are allowed on error. Rollback removes both staged advances.
    tx.rollback().await.unwrap();
    assert_eq!(
        db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let tx = db.transaction().await.unwrap();
    f.bytes[29..37].copy_from_slice(&1u64.to_be_bytes());
    f.bytes[53..85].fill(0);
    f.bytes[151 + 149 + 148] = 1;
    f.resign();
    let mut admission = admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    tx.execute(
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp()",
        &[],
    )
    .await
    .unwrap();
    assert!(admission.context(&f.wanted()).await.is_err());
    drop(admission);
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

/// One admission rechecks context at most once per row write: the high-water
/// UPDATE happens in `admit` and in the FIRST `context` only, while later
/// rechecks in the same transaction re-read the row without rewriting it
/// (#509). Without the guard, two context calls rewrote the hot row twice.
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn context_rechecks_write_last_verified_once() {
    let f = Fixture::new().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut admission = admit(&tx, f.session(), f.line, 1, &f.bytes).await.unwrap();
    let first_version = admission.context(&f.wanted()).await.unwrap().keyset_version;
    // The second recheck (the pre-commit one ingest performs) must re-read
    // identity and freshness without another row write.
    let second_version = admission.context(&f.wanted()).await.unwrap().keyset_version;
    assert_eq!(first_version, second_version);
    drop(admission);
    tx.commit().await.unwrap();

    db.batch_execute("SELECT pg_stat_force_next_flush()")
        .await
        .unwrap();
    let updates: i64 = db
        .query_one(
            "SELECT n_tup_upd FROM pg_stat_all_tables \
             WHERE schemaname=current_schema() AND relname='sealed_manifest_authorities'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        updates, 2,
        "admit plus one context must be the only row writes"
    );
    f.cleanup().await;
}
