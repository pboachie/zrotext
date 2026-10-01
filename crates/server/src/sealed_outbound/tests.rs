// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest_store::tests::Fixture;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use p256::{
    ecdsa::{
        Signature, SigningKey,
        signature::{RandomizedSigner, Signer},
    },
    elliptic_curve::Generate,
};
use sha2::{Digest, Sha256};
use std::{ops::Deref, time::Duration};
use zrotext_delivery_store::{Claim, DeliveryStore, NewMessage, SessionRecord};

#[cfg(feature = "sealed-interop-tests")]
mod cross_client_interop;

pub(crate) struct TestCase {
    fixture: Fixture,
    pub(crate) principal: ApiPrincipal,
    pub(crate) hasher: TokenHasher,
    pub(crate) user: Uuid,
    /// The bearer token text; the cross-client interop lane posts through the
    /// real HTTP route, which authenticates from headers, not from a principal.
    #[cfg(feature = "sealed-interop-tests")]
    token: String,
}
impl Deref for TestCase {
    type Target = Fixture;
    fn deref(&self) -> &Fixture {
        &self.fixture
    }
}
impl TestCase {
    pub(crate) async fn new() -> Self {
        Self::with_manifest_lifetime(120_000).await
    }
    async fn with_manifest_lifetime(lifetime: i64) -> Self {
        let mut f = Fixture::new().await;
        let now = now(&f.db).await;
        f.bytes.truncate(150); // Existing exact manifest header, through root point.
        f.bytes[37..45].copy_from_slice(&((now - 1000) as u64).to_be_bytes());
        f.bytes[45..53].copy_from_slice(&((now + lifetime) as u64).to_be_bytes());
        f.bytes.push(4);
        f.readers.clear();
        for (role, scope) in [(1, 4u16), (2, 12), (5, 1), (6, 0)] {
            let key = SigningKey::generate_from_rng(&mut rand::rng());
            let point = if role == 6 {
                f.root.verifying_key().to_sec1_point(false)
            } else {
                key.verifying_key().to_sec1_point(false)
            };
            let algorithm = if role <= 2 { [0u8, 16] } else { [1, 1] };
            let id: [u8; 32] = Sha256::digest(
                [b"ZTSE/key/v1\0".as_slice(), &algorithm, point.as_bytes()].concat(),
            )
            .into();
            f.bytes.push(role);
            f.bytes.extend(id);
            f.bytes.extend(point.as_bytes());
            f.bytes.extend(if role == 1 {
                *f.device.as_bytes()
            } else {
                [0; 16]
            });
            f.bytes.extend(if role == 1 || role == 5 {
                *f.line.as_bytes()
            } else {
                [0; 16]
            });
            f.bytes.extend(scope.to_be_bytes());
            f.bytes.extend(((now - 1000) as u64).to_be_bytes());
            f.bytes.extend(((now + 240_000) as u64).to_be_bytes());
            f.bytes.push(1);
            if role <= 2 {
                f.readers.push(ExpectedRecipient { role, key_id: id });
            }
            if role == 5 {
                f.signer = id;
                f.event_signer = key;
            }
        }
        f.bytes.extend([0; 64]);
        f.resign();
        let digest = Sha256::digest(&f.bytes[..f.bytes.len() - 64]);
        f.db.execute("UPDATE sealed_manifest_authorities SET version=1,semantic_digest=$2,manifest=$3,accepted_at_ms=$4,last_verified_ms=$4 WHERE account_id=$1",
            &[&f.account,&digest.as_slice(),&f.bytes,&now]).await.unwrap();
        let user = Uuid::new_v4();
        let key = Uuid::new_v4();
        let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let pepper = crate::test_keys::key(76);
        let mut mac = Hmac::<Sha256>::new_from_slice(&pepper).unwrap();
        mac.update(b"api-key-v1\0");
        mac.update(token.as_bytes());
        let token_hash = mac.finalize().into_bytes().to_vec();
        f.db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,'unused',now())",
            &[&user,&format!("{}@example.invalid",user.simple())]).await.unwrap();
        f.db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&f.account, &user],
        )
        .await
        .unwrap();
        f.db.execute("INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id) VALUES($1,$2,$3,$4,$5,ARRAY['messages:send'],$6)",
            &[&key,&f.account,&user,&&token[4..16],&token_hash,&f.device]).await.unwrap();
        f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',1000)",&[&f.account]).await.unwrap();
        let hasher = TokenHasher::new(pepper).unwrap();
        let principal = auth::authenticate_api_key(&f.db, &hasher, &token)
            .await
            .unwrap();
        Self {
            fixture: f,
            principal,
            hasher,
            user,
            #[cfg(feature = "sealed-interop-tests")]
            token,
        }
    }
    pub(crate) fn writer(&self) -> WriterContext<'static> {
        WriterContext {
            site_id: "manifest-test",
            deployment_epoch: 1,
            billing_enabled: true,
        }
    }
    async fn admit(&self, bytes: &[u8]) -> Result<AcceptOutcome, AdmitError> {
        admit_candidate02(
            &mut self.connect().await,
            &self.principal,
            &self.hasher,
            self.writer(),
            bytes,
        )
        .await
    }
    pub(crate) async fn envelope(&self, id: Uuid) -> Vec<u8> {
        envelope(self, id, now(&self.db).await, 60_000)
    }
    pub(crate) async fn cleanup(self) {
        self.fixture.cleanup().await;
    }
}
async fn now(db: &Client) -> i64 {
    db.query_one(
        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}
async fn reach_clock(db: &Client, deadline: i64) {
    let started = std::time::Instant::now();
    while now(db).await < deadline {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "disposable database clock did not advance"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
fn signed(f: &Fixture, bytes: &mut [u8]) {
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
// Signed opaque SQL-composition fixtures; not a decryption/provider claim.
fn envelope(f: &Fixture, id: Uuid, observed: i64, lifetime: i64) -> Vec<u8> {
    let mut b = b"ZTSE\x02\x01\0\0".to_vec();
    b.extend(157u16.to_be_bytes());
    b.extend(f.account.as_bytes());
    b.extend(id.as_bytes());
    b.extend(f.device.as_bytes());
    b.extend(f.line.as_bytes());
    b.extend(1u64.to_be_bytes());
    b.extend(Sha256::digest(&f.bytes[..f.bytes.len() - 64]));
    b.extend(f.signer);
    b.extend((observed as u64).to_be_bytes());
    b.extend(((observed + lifetime) as u64).to_be_bytes());
    b.extend([1, 3]);
    b.extend(b"+12");
    b.extend([4; 12]);
    b.extend(17u32.to_be_bytes());
    b.extend([7; 17]);
    b.push(2);
    for r in &f.readers {
        b.push(r.role);
        b.extend(r.key_id);
        b.extend(f.root.verifying_key().to_sec1_point(false).as_bytes());
        b.extend([9; 48]);
    }
    b.extend([0; 64]);
    signed(f, &mut b);
    b
}
async fn counts(f: &Fixture) -> (i64, i64, i64) {
    let r=f.db.query_one("SELECT (SELECT count(*) FROM messages),(SELECT count(*) FROM dispatch_jobs),(SELECT count(*) FROM usage_ledger WHERE entry_kind='reserve')",&[]).await.unwrap();
    (r.get(0), r.get(1), r.get(2))
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_replays_without_spending_or_rehydration_and_refunds_once() {
    let f = TestCase::new().await;
    let id = Uuid::new_v4();
    let bytes = f.envelope(id).await;
    f.db.execute(
        "DELETE FROM device_sessions WHERE device_id=$1",
        &[&f.device],
    )
    .await
    .unwrap(); // Offline queueing.
    assert!(f.admit(&bytes).await.unwrap().created);
    let row=f.db.query_one("SELECT transport_mode,transport_payload,sealed_binding_generation FROM messages WHERE id=$1",&[&id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "sealed_candidate02");
    assert_eq!(row.get::<_, Vec<u8>>(1), bytes);
    assert_eq!(row.get::<_, i64>(2), 1);
    let mut alias = bytes.clone();
    let end = alias.len() - 64;
    let sig: Signature = f
        .event_signer
        .try_sign_with_rng(
            &mut rand::rng(),
            &[
                b"ZTSE/sign/v2\0".as_slice(),
                &(end as u32).to_be_bytes(),
                &alias[..end],
            ]
            .concat(),
        )
        .unwrap();
    alias[end..].copy_from_slice(&sig.normalize_s().to_bytes());
    assert!(!f.admit(&alias).await.unwrap().created);
    assert_eq!(counts(&f).await, (1, 1, 1));
    let mut conflict = bytes.clone();
    conflict[170] ^= 1;
    signed(&f, &mut conflict);
    assert!(matches!(
        f.admit(&conflict).await,
        Err(AdmitError::Queue(StoreError::MessageIdConflict))
    ));
    let mut db = f.connect().await;
    assert!(
        DeliveryStore::new(&mut db)
            .cancel(f.account, id)
            .await
            .unwrap()
    );
    let snapshot_sql = "SELECT state,state_version,updated_at,transport_payload, \
        (SELECT count(*) FROM usage_ledger WHERE message_id=$1 AND entry_kind='refund'), \
        (SELECT coalesce(sum(units),0)::bigint FROM usage_ledger WHERE message_id=$1), \
        (SELECT coalesce(sum(refunded_units),0)::bigint FROM usage_periods WHERE account_id=$2) \
        FROM messages WHERE id=$1";
    let before =
        f.db.query_one(snapshot_sql, &[&id, &f.account])
            .await
            .unwrap();
    assert_eq!(before.get::<_, String>(0), "cancelled");
    assert_eq!(before.get::<_, i64>(4), 1);
    assert_eq!(before.get::<_, i64>(5), 0);
    assert_eq!(before.get::<_, i64>(6), 1);
    assert!(
        DeliveryStore::new(&mut db)
            .cancel(f.account, id)
            .await
            .unwrap()
    );
    assert!(!f.admit(&bytes).await.unwrap().created);
    let after =
        f.db.query_one(snapshot_sql, &[&id, &f.account])
            .await
            .unwrap();
    assert_eq!(after.get::<_, String>(0), before.get::<_, String>(0));
    assert_eq!(after.get::<_, i64>(1), before.get::<_, i64>(1));
    assert_eq!(
        after.get::<_, std::time::SystemTime>(2),
        before.get::<_, std::time::SystemTime>(2)
    );
    assert_eq!(after.get::<_, Vec<u8>>(3), before.get::<_, Vec<u8>>(3));
    for index in 4..=6 {
        assert_eq!(after.get::<_, i64>(index), before.get::<_, i64>(index));
    }
    assert_eq!(counts(&f).await, (1, 1, 1));

    f.db.execute(
        "UPDATE messages SET updated_at=now()-interval '2 days' WHERE id=$1",
        &[&id],
    )
    .await
    .unwrap();
    let policy = crate::retention::RetentionPolicy {
        message_days: 1,
        ..Default::default()
    };
    db.batch_execute(include_str!(
        "../../../../deploy/compose/migrations/064_owner_conversation_consent.sql"
    ))
    .await
    .unwrap();
    db.batch_execute(include_str!(
        "../../../../deploy/compose/migrations/065_conversation_activation.sql"
    ))
    .await
    .unwrap();
    assert_eq!(
        crate::retention::prune(&mut db, policy, 100)
            .await
            .unwrap()
            .messages,
        1
    );
    assert!(!f.admit(&bytes).await.unwrap().created);
    let row=f.db.query_one("SELECT transport_payload IS NULL,(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund') FROM messages WHERE id=$1",&[&id]).await.unwrap();
    assert!(row.get::<_, bool>(0));
    assert_eq!(row.get::<_, i64>(1), 1);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_rejects_signed_context_profile_time_and_identity_changes() {
    let f = TestCase::new().await;
    let bytes = f.envelope(Uuid::new_v4()).await;
    for offset in [10usize, 42, 58, 114] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        signed(&f, &mut bad);
        assert!(f.admit(&bad).await.is_err());
    }
    let mut bad = bytes.clone();
    bad[4] = 1;
    assert!(f.admit(&bad).await.is_err());
    let mut bad = bytes.clone();
    let n = bad.len() - 1;
    bad[n] ^= 1;
    assert!(f.admit(&bad).await.is_err());
    let clock = now(&f.db).await;
    assert!(
        f.admit(&envelope(&f, Uuid::new_v4(), clock + 360_000, 60_000))
            .await
            .is_err()
    );
    assert!(
        f.admit(&envelope(&f, Uuid::new_v4(), clock - 60_000, 10_000))
            .await
            .is_err()
    );
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.db.execute(
        "UPDATE sealed_manifest_authorities SET revoked_at=now() WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    assert!(f.admit(&bytes).await.is_err());
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_serializes_retries_and_last_budget_slot() {
    let f = TestCase::new().await;
    let bytes = f.envelope(Uuid::new_v4()).await;
    let (a, b) = tokio::join!(f.admit(&bytes), f.admit(&bytes));
    assert_ne!(a.unwrap().created, b.unwrap().created);
    assert_eq!(counts(&f).await, (1, 1, 1));
    f.db.execute("UPDATE usage_periods SET limit_units=2", &[])
        .await
        .unwrap();
    let x = f.envelope(Uuid::new_v4()).await;
    let y = f.envelope(Uuid::new_v4()).await;
    let (a, b) = tokio::join!(f.admit(&x), f.admit(&y));
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(counts(&f).await, (2, 2, 2));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_counts_alpha_and_candidate_rows_in_the_same_device_cap() {
    let f = TestCase::new().await;
    let mut alpha_db = f.connect().await;
    DeliveryStore::new(&mut alpha_db)
        .accept(NewMessage {
            account_id: f.account,
            client_message_id: Uuid::new_v4(),
            device_id: f.device,
            idempotency_key: "alpha-before-candidate",
            recipient_e164: "+12",
            synthetic_payload: b"synthetic",
            expires_at_ms: now(&f.db).await + 60_000,
        })
        .await
        .unwrap();
    for _ in 0..14 {
        assert!(
            f.admit(&f.envelope(Uuid::new_v4()).await)
                .await
                .unwrap()
                .created
        );
    }
    let x = f.envelope(Uuid::new_v4()).await;
    let y = f.envelope(Uuid::new_v4()).await;
    let (a, b) = tokio::join!(f.admit(&x), f.admit(&y));
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(counts(&f).await, (16, 16, 15));
    let mut db = f.connect().await;
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept(NewMessage {
                account_id: f.account,
                client_message_id: Uuid::new_v4(),
                device_id: f.device,
                idempotency_key: "alpha-cap",
                recipient_e164: "+12",
                synthetic_payload: b"synthetic",
                expires_at_ms: now(&f.db).await + 60_000
            })
            .await,
        Err(StoreError::QueueFull)
    ));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_cannot_enter_any_alpha_claim_grant_or_database_effect_path() {
    let f = TestCase::new().await;
    let id = Uuid::new_v4();
    assert!(f.admit(&f.envelope(id).await).await.unwrap().created);
    let mut db = f.connect().await;
    let mut store = DeliveryStore::new(&mut db);
    assert!(store.claim_due("worker").await.unwrap().is_none());
    assert!(
        store
            .claim_due_for_device("worker", f.account, f.device)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .claim_due_for_device_and_recipient(
                "worker",
                f.account,
                f.device,
                &Sha256::digest(b"+12").into()
            )
            .await
            .unwrap()
            .is_none()
    );
    f.db.execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let claim = Claim {
        account_id: f.account,
        message_id: id,
        device_id: f.device,
        generation: 1,
        worker_id: "worker".into(),
    };
    let session = SessionRecord {
        account_id: f.account,
        device_id: f.device,
        site_id: "manifest-test".into(),
        instance_id: "fixture".into(),
        epoch: 1,
        deployment_epoch: 1,
    };
    assert!(
        store
            .issue_grant(&claim, &session, Uuid::new_v4())
            .await
            .is_err()
    );
    for sql in [
        "UPDATE messages SET state='claimed' WHERE id=$1",
        "UPDATE messages SET transport_mode='synthetic_alpha' WHERE id=$1",
        "UPDATE messages SET sealed_binding_generation=2 WHERE id=$1",
    ] {
        assert_eq!(
            f.db.execute(sql, &[&id])
                .await
                .unwrap_err()
                .as_db_error()
                .unwrap()
                .code()
                .code(),
            "23514"
        );
    }
    let attempt = Uuid::new_v4();
    assert_eq!(f.db.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,1,1,'granted')",
        &[&attempt,&f.account,&id,&f.device]).await.unwrap_err().as_db_error().unwrap().code().code(),"23514");
    assert_eq!(f.db.execute("INSERT INTO dispatch_fences(message_id,account_id,device_id,attempt_id,generation,session_epoch,deployment_epoch,recipient_digest,grant_expires_at,outcome) VALUES($1,$2,$3,$4,1,1,1,$5,now()+interval '30 seconds','granted')",
        &[&id,&f.account,&f.device,&attempt,&Sha256::digest(b"+12").to_vec()]).await.unwrap_err().as_db_error().unwrap().code().code(),"23514");
    let alpha = Uuid::new_v4();
    store
        .accept(NewMessage {
            account_id: f.account,
            client_message_id: alpha,
            device_id: f.device,
            idempotency_key: "alpha",
            recipient_e164: "+12",
            synthetic_payload: b"synthetic",
            expires_at_ms: now(&f.db).await + 60_000,
        })
        .await
        .unwrap();
    assert_eq!(
        store.claim_due("worker").await.unwrap().unwrap().message_id,
        alpha
    );
    f.cleanup().await;
}

async fn waiting(f: &Fixture, pid: i32, query: &str) {
    for _ in 0..300 {
        if f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE $2)",
            &[&pid,&format!("%{query}%")]).await.unwrap().get::<_,bool>(0) { return; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected the admission lock wait");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_rechecks_expiry_after_blocked_budget_write_and_rolls_everything_back() {
    let f = TestCase::new().await;
    f.db.execute("INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units) VALUES($1,'outbound_message',date_trunc('month',now() AT TIME ZONE 'UTC')::date,(date_trunc('month',now() AT TIME ZONE 'UTC')+interval '1 month')::date,1000)",&[&f.account]).await.unwrap();
    let mut blocker = f.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.query_one("SELECT account_id FROM usage_periods FOR UPDATE", &[])
        .await
        .unwrap();
    let mut db = f.connect().await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let clock = now(&f.db).await;
    let bytes = envelope(&f, Uuid::new_v4(), clock, 1200);
    let operation = admit_candidate02(&mut db, &f.principal, &f.hasher, f.writer(), &bytes);
    let release = async {
        waiting(&f, pid, "INSERT INTO usage_periods").await;
        reach_clock(&f.db, clock + 1200).await;
        lock.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(operation, release);
    assert!(matches!(result, Err(AdmitError::Invalid)));
    assert_eq!(counts(&f).await, (0, 0, 0));
    assert_eq!(
        f.db.query_one("SELECT reserved_units FROM usage_periods", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_sees_key_revocation_that_wins_account_lock() {
    let f = TestCase::new().await;
    let bytes = f.envelope(Uuid::new_v4()).await;
    let mut blocker = f.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
        &[&f.account],
    )
    .await
    .unwrap();
    let mut db = f.connect().await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let operation = admit_candidate02(&mut db, &f.principal, &f.hasher, f.writer(), &bytes);
    let revoke = async {
        waiting(&f, pid, "SELECT id FROM accounts").await;
        lock.execute(
            "UPDATE api_keys SET revoked_at=now() WHERE id=$1",
            &[&f.principal.key_id],
        )
        .await
        .unwrap();
        lock.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(operation, revoke);
    assert!(matches!(result, Err(AdmitError::Forbidden)));
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_owner_hold_wins_account_lock_and_blocks_exact_replay() {
    let f = TestCase::new().await;
    let original = f.envelope(Uuid::new_v4()).await;
    f.admit(&original).await.unwrap();
    let mut blocker = f.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
        &[&f.account],
    )
    .await
    .unwrap();
    let mut db = f.connect().await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let operation = admit_candidate02(&mut db, &f.principal, &f.hasher, f.writer(), &original);
    let hold = async {
        waiting(&f, pid, "SELECT id FROM accounts").await;
        lock.execute("INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by) VALUES($1,$2,'+12','email','opt_out',now(),$3)",
            &[&Uuid::new_v4(), &f.account, &f.user]).await.unwrap();
        lock.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(operation, hold);
    assert!(matches!(
        result,
        Err(AdmitError::Queue(StoreError::RecipientSuppressed))
    ));
    assert!(matches!(
        f.admit(&f.envelope(Uuid::new_v4()).await).await,
        Err(AdmitError::Queue(StoreError::RecipientSuppressed))
    ));
    assert_eq!(counts(&f).await, (1, 1, 1));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_missing_policy_and_clock_rollback_leave_no_partial_rows() {
    let f = TestCase::new().await;
    let bytes = f.envelope(Uuid::new_v4()).await;
    f.db.execute(
        "DELETE FROM usage_quota_policies WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    assert!(matches!(
        f.admit(&bytes).await,
        Err(AdmitError::Queue(StoreError::QuotaNotConfigured))
    ));
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',1000)", &[&f.account]).await.unwrap();
    f.db.execute(
        "UPDATE sealed_manifest_authorities SET last_verified_ms=$2 WHERE account_id=$1",
        &[&f.account, &(now(&f.db).await + 60_000)],
    )
    .await
    .unwrap();
    assert!(matches!(
        f.admit(&bytes).await,
        Err(AdmitError::Authority(_))
    ));
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_rechecks_api_expiry_after_blocked_budget_write() {
    let f = TestCase::new().await;
    f.db.execute("INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units) VALUES($1,'outbound_message',date_trunc('month',now() AT TIME ZONE 'UTC')::date,(date_trunc('month',now() AT TIME ZONE 'UTC')+interval '1 month')::date,1000)",&[&f.account]).await.unwrap();
    let bytes = f.envelope(Uuid::new_v4()).await;
    let mut blocker = f.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.query_one("SELECT account_id FROM usage_periods FOR UPDATE", &[])
        .await
        .unwrap();
    let mut db = f.connect().await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let deadline = now(&f.db).await + 1500;
    f.db.execute("UPDATE api_keys SET expires_at=to_timestamp($2::bigint::double precision/1000) WHERE id=$1", &[&f.principal.key_id,&deadline]).await.unwrap();
    let operation = admit_candidate02(&mut db, &f.principal, &f.hasher, f.writer(), &bytes);
    let release = async {
        waiting(&f, pid, "INSERT INTO usage_periods").await;
        reach_clock(&f.db, deadline).await;
        lock.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(operation, release);
    assert!(matches!(result, Err(AdmitError::Forbidden)));
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_billing_binding_requires_reservation_even_when_billing_flag_is_off() {
    let f = TestCase::new().await;
    f.db.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_outboundTest')", &[&f.account]).await.unwrap();
    let bytes = f.envelope(Uuid::new_v4()).await;
    let mut db = f.connect().await;
    let writer = WriterContext {
        billing_enabled: false,
        ..f.writer()
    };
    assert!(matches!(
        admit_candidate02(&mut db, &f.principal, &f.hasher, writer, &bytes).await,
        Err(AdmitError::Queue(StoreError::QuotaNotConfigured))
    ));
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.db.execute("INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) VALUES('evt_outboundTest','charge.refunded',$1,$2,'queued')", &[&f.account,&vec![1u8;32]]).await.unwrap();
    f.db.execute("INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) VALUES('evt_outboundTest','ch_outboundTest','refund',$1)", &[&f.account]).await.unwrap();
    assert!(matches!(
        f.admit(&bytes).await,
        Err(AdmitError::Queue(StoreError::PaymentHold))
    ));
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_rechecks_current_scope_writer_and_line_instead_of_cached_principal() {
    let f = TestCase::new().await;
    let bytes = f.envelope(Uuid::new_v4()).await;
    let mut db = f.connect().await;
    for writer in [
        WriterContext {
            deployment_epoch: 2,
            ..f.writer()
        },
        WriterContext {
            site_id: "absent",
            ..f.writer()
        },
    ] {
        assert!(matches!(
            admit_candidate02(&mut db, &f.principal, &f.hasher, writer, &bytes).await,
            Err(AdmitError::Forbidden)
        ));
    }
    f.db.execute("UPDATE sites SET draining=TRUE", &[])
        .await
        .unwrap();
    assert!(matches!(f.admit(&bytes).await, Err(AdmitError::Forbidden)));
    f.db.execute("UPDATE sites SET draining=FALSE", &[])
        .await
        .unwrap();
    f.db.execute(
        "UPDATE api_keys SET scopes=ARRAY['messages:read'] WHERE id=$1",
        &[&f.principal.key_id],
    )
    .await
    .unwrap();
    assert!(matches!(f.admit(&bytes).await, Err(AdmitError::Forbidden)));
    f.db.execute(
        "UPDATE api_keys SET scopes=ARRAY['messages:send'] WHERE id=$1",
        &[&f.principal.key_id],
    )
    .await
    .unwrap();
    f.db.execute(
        "UPDATE device_line_bindings SET state='revoked' WHERE line_id=$1",
        &[&f.line],
    )
    .await
    .unwrap();
    assert!(matches!(f.admit(&bytes).await, Err(AdmitError::Forbidden)));
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_expiry_refunds_once_and_never_rehydrates_expired_identity() {
    let f = TestCase::new().await;
    let deadline = now(&f.db).await;
    let bytes = envelope(&f, Uuid::new_v4(), deadline, 1500);
    f.admit(&bytes).await.unwrap();
    reach_clock(&f.db, deadline + 1500).await;
    let mut db = f.connect().await;
    let mut store = DeliveryStore::new(&mut db);
    assert_eq!(store.expire_due(10).await.unwrap(), 1);
    assert_eq!(store.expire_due(10).await.unwrap(), 0);
    assert!(matches!(f.admit(&bytes).await, Err(AdmitError::Invalid)));
    let row=f.db.query_one("SELECT state,(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'),(SELECT refunded_units FROM usage_periods) FROM messages", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "expired");
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_valid_replays_share_the_existing_outbound_attempt_budget() {
    let f = TestCase::new().await;
    let bytes = f.envelope(Uuid::new_v4()).await;
    f.admit(&bytes).await.unwrap();
    let subject = f.account.to_string();
    for _ in 0..58 {
        assert!(
            auth::abuse_limits::consume(
                &f.db,
                &f.hasher,
                auth::abuse_limits::Limit::OutboundAccept,
                Some(&subject)
            )
            .await
            .unwrap()
        );
    }
    assert!(!f.admit(&bytes).await.unwrap().created);
    assert!(matches!(
        f.admit(&bytes).await,
        Err(AdmitError::RateLimited)
    ));
    assert_eq!(counts(&f).await, (1, 1, 1));
    f.cleanup().await;
}

async fn fill_other_device_queues(f: &Fixture, account: Uuid, count: i64) {
    f.db.execute("INSERT INTO devices(id,account_id,display_name) SELECT gen_random_uuid(),$1,'queue-fixture' FROM generate_series(1,8)", &[&account]).await.unwrap();
    f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) SELECT gen_random_uuid(),$1,d.id,'+12',$3,'synthetic_alpha',$4,$3,'queued',clock_timestamp()+interval '5 minutes' FROM devices d CROSS JOIN generate_series(1,16) WHERE d.account_id=$1 AND d.id<>$5 LIMIT $2",
        &[&account,&count,&vec![1u8;32],&b"synthetic".as_slice(),&f.device]).await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_account_cap_and_message_collision_are_tenant_scoped() {
    let f = TestCase::new().await;
    let foreign = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&foreign])
        .await
        .unwrap();
    fill_other_device_queues(&f, foreign, 128).await;
    let foreign_id: Uuid =
        f.db.query_one(
            "SELECT id FROM messages WHERE account_id=$1 LIMIT 1",
            &[&foreign],
        )
        .await
        .unwrap()
        .get(0);
    assert!(matches!(
        f.admit(&f.envelope(foreign_id).await).await,
        Err(AdmitError::Queue(StoreError::MessageIdConflict))
    ));
    assert!(
        f.admit(&f.envelope(Uuid::new_v4()).await)
            .await
            .unwrap()
            .created
    );
    fill_other_device_queues(&f, f.account, 127).await;
    assert!(matches!(
        f.admit(&f.envelope(Uuid::new_v4()).await).await,
        Err(AdmitError::Queue(StoreError::QueueFull))
    ));
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM messages WHERE account_id=$1",
            &[&foreign]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        128
    );
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM messages WHERE account_id=$1",
            &[&f.account]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        128
    );
    assert_eq!(counts(&f).await, (256, 1, 1));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn candidate_queue_rechecks_manifest_expiry_after_blocked_budget_write() {
    let f = TestCase::with_manifest_lifetime(2000).await;
    let deadline = u64::from_be_bytes(f.bytes[45..53].try_into().unwrap()) as i64;
    f.db.execute("INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units) VALUES($1,'outbound_message',date_trunc('month',now() AT TIME ZONE 'UTC')::date,(date_trunc('month',now() AT TIME ZONE 'UTC')+interval '1 month')::date,1000)",&[&f.account]).await.unwrap();
    let bytes = f.envelope(Uuid::new_v4()).await;
    let mut blocker = f.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.query_one("SELECT account_id FROM usage_periods FOR UPDATE", &[])
        .await
        .unwrap();
    let mut db = f.connect().await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let operation = admit_candidate02(&mut db, &f.principal, &f.hasher, f.writer(), &bytes);
    let release = async {
        waiting(&f, pid, "INSERT INTO usage_periods").await;
        reach_clock(&f.db, deadline).await;
        lock.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(operation, release);
    assert!(matches!(result, Err(AdmitError::Authority(_))));
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.cleanup().await;
}
