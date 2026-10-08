// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{auth, sealed_manifest_store::tests::Fixture};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use std::time::Duration;
use tokio_postgres::GenericClient;

async fn wait_for_advisory_lock(
    db: &Client,
    pid: i32,
    pending: std::pin::Pin<&mut impl std::future::Future<Output = Result<Receipt, CeremonyError>>>,
) {
    let barrier = async {
        loop {
            if db.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)",
                &[&pid]).await.unwrap().get::<_, bool>(0) { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        result = pending => panic!("completion ended before its post-mutation lock wait: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(2), barrier) => {
            assert!(result.is_ok(), "completion did not reach the observed advisory lock wait");
        }
    }
}

fn token_digest(pepper: &[u8], domain: &[u8], token: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(pepper).unwrap();
    mac.update(domain);
    mac.update(&[0]);
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().into()
}

const ORIGIN: &str = "https://owner.example.test";

pub(crate) struct Owner {
    pub(crate) f: Fixture,
    pub(crate) principal: SessionPrincipal,
    pub(crate) hasher: TokenHasher,
    pub(crate) cipher: mfa::MfaCipher,
    pub(crate) root: SigningKey,
    pub(crate) pin: [u8; 94],
    pub(crate) recovery: String,
    pub(crate) token: String,
    pub(crate) csrf: String,
    secret: [u8; 20],
}
impl Owner {
    pub(crate) async fn new() -> Self {
        let f = Fixture::without_authority().await;
        // Separate account without protected phone tombstones permits an exact
        // account-erasure cascade exercise alongside the complete parent schema.
        let account = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        let pepper = rand::random::<[u8; 32]>();
        let hasher = TokenHasher::new(pepper.to_vec()).unwrap();
        let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let token_hash = token_digest(&pepper, b"session-v1", &token);
        let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let csrf_hash = token_digest(&pepper, b"csrf-v1", &csrf);
        f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        f.db.execute("INSERT INTO users(id,email,password_hash,email_verified_at,mfa_enabled) VALUES($1,$2,'synthetic',now(),true)",
            &[&user, &format!("{}@example.test", user.simple())]).await.unwrap();
        f.db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&account, &user],
        )
        .await
        .unwrap();
        f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
            &[&session, &account, &user, &&token_hash[..], &&csrf_hash[..]]).await.unwrap();
        let key = rand::random::<[u8; 32]>();
        let nonce = rand::random::<[u8; 12]>();
        let secret = rand::random::<[u8; 20]>();
        let aad = [
            b"zrotext-owner-totp-v1".as_slice(),
            account.as_bytes(),
            user.as_bytes(),
        ]
        .concat();
        let ciphertext = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                &Nonce::try_from(nonce.as_slice()).unwrap(),
                Payload {
                    msg: &secret,
                    aad: &aad,
                },
            )
            .unwrap();
        f.db.execute("INSERT INTO owner_mfa(account_id,user_id,secret_nonce,secret_ciphertext,enabled_at) VALUES($1,$2,$3,$4,now())",
            &[&account, &user, &&nonce[..], &ciphertext]).await.unwrap();
        let recovery = format!("zrc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()));
        let code_hash = token_digest(
            &pepper,
            b"mfa-recovery-v1",
            &format!("{account}:{user}:{recovery}"),
        );
        f.db.execute(
            "INSERT INTO owner_mfa_recovery_codes(account_id,user_id,code_hash) VALUES($1,$2,$3)",
            &[&account, &user, &&code_hash[..]],
        )
        .await
        .unwrap();
        let principal = auth::authenticate_session(&f.db, &hasher, &token)
            .await
            .unwrap();
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let pin = [
            b"ZTRP\x02".as_slice(),
            account.as_bytes(),
            &1u64.to_be_bytes(),
            root.verifying_key().to_sec1_point(false).as_bytes(),
        ]
        .concat()
        .try_into()
        .unwrap();
        Self {
            f,
            principal,
            hasher,
            cipher: mfa::MfaCipher::new(key.to_vec()).unwrap(),
            root,
            pin,
            recovery,
            token,
            csrf,
            secret,
        }
    }
    pub(crate) async fn challenge(&self) -> IssuedChallenge {
        issue_challenge(
            &mut self.f.connect().await,
            &self.hasher,
            &self.principal,
            ORIGIN,
            self.pin,
        )
        .await
        .unwrap()
    }
    pub(crate) fn sign(&self, c: &IssuedChallenge) -> Vec<u8> {
        // Construct the specified transcript independently of the verifier's
        // helper, so a domain or length-prefix regression cannot mirror itself.
        let transcript = [
            b"ZTSE/root-enroll/v1\0".as_slice(),
            &(c.unsigned.len() as u32).to_be_bytes(),
            &c.unsigned,
        ]
        .concat();
        let s: Signature = self.root.sign(&transcript);
        s.normalize_s().to_bytes().to_vec()
    }
    async fn complete(&self, c: &IssuedChallenge) -> Result<Receipt, CeremonyError> {
        complete_genesis(
            &mut self.f.connect().await,
            &self.hasher,
            &self.cipher,
            &self.principal,
            ORIGIN,
            Completion {
                unsigned: &c.unsigned,
                signature: &self.sign(c),
                factor: &self.recovery,
            },
        )
        .await
    }
    pub(crate) async fn empty_authority(&self) {
        for table in [
            "sealed_manifest_authorities",
            "sealed_root_enrollments",
            "sealed_root_receipts",
            "known_signing_role_claims",
            "known_signing_point_reservations",
        ] {
            let n: i64 = self
                .f
                .db
                .query_one(
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    &[&self.principal.tenant.account_id()],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(n, 0, "{table}");
        }
        let used: bool = self
            .f
            .db
            .query_one(
                "SELECT used_at IS NOT NULL FROM owner_mfa_recovery_codes WHERE account_id=$1",
                &[&self.principal.tenant.account_id()],
            )
            .await
            .unwrap()
            .get(0);
        assert!(!used);
    }
    async fn step_up_failures(&self) -> i32 {
        abuse_limits::failures_in_window(
            &self.f.db,
            &self.hasher,
            abuse_limits::Limit::MfaStepUp,
            &self.principal.user_id.to_string(),
        )
        .await
        .unwrap()
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_commits_one_use_factor_authority_history_and_receipt_atomically() {
    let o = Owner::new().await;
    let c = o.challenge().await;
    let receipt = o.complete(&c).await.unwrap();
    assert_eq!(receipt.root_pin, o.pin);
    assert_eq!(
        read_receipt(&mut o.f.connect().await, &o.principal)
            .await
            .unwrap(),
        Some(receipt)
    );
    assert!(o.complete(&c).await.is_err());
    let row = o.f.db.query_one("SELECT a.version,a.manifest IS NULL,c.consumed_ms IS NOT NULL,r.used_at IS NOT NULL \
        FROM sealed_manifest_authorities a JOIN sealed_root_challenges c USING(account_id) JOIN owner_mfa_recovery_codes r USING(account_id) WHERE a.account_id=$1",
        &[&o.principal.tenant.account_id()]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert!(row.get::<_, bool>(1) && row.get::<_, bool>(2) && row.get::<_, bool>(3));
    for sql in [
        "UPDATE sealed_root_receipts SET completed_ms=completed_ms+1",
        "DELETE FROM sealed_root_receipts",
        "TRUNCATE sealed_root_receipts",
    ] {
        assert!(o.f.db.batch_execute(sql).await.is_err(), "{sql}");
    }
    o.f.db
        .execute(
            "DELETE FROM sealed_manifest_authorities WHERE account_id=$1",
            &[&o.principal.tenant.account_id()],
        )
        .await
        .unwrap();
    assert!(
        issue_challenge(
            &mut o.f.connect().await,
            &o.hasher,
            &o.principal,
            ORIGIN,
            o.pin
        )
        .await
        .is_err()
    );
    assert!(
        read_receipt(&mut o.f.connect().await, &o.principal)
            .await
            .unwrap()
            .is_some()
    );
    o.f.db
        .execute(
            "DELETE FROM accounts WHERE id=$1",
            &[&o.principal.tenant.account_id()],
        )
        .await
        .unwrap();
    assert_eq!(
        o.f.db
            .query_one("SELECT count(*) FROM sealed_root_receipts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    o.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_replaced_challenge_origin_and_invalid_signature_cannot_spend_factor() {
    let o = Owner::new().await;
    let old = o.challenge().await;
    let current = o.challenge().await;
    assert!(o.complete(&old).await.is_err());
    assert_eq!(
        o.f.db
            .query_one("SELECT count(*) FROM sealed_root_challenges", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    for (origin, signature) in [
        ("https://other.example.test", o.sign(&current)),
        (ORIGIN, vec![0; 64]),
    ] {
        assert!(
            complete_genesis(
                &mut o.f.connect().await,
                &o.hasher,
                &o.cipher,
                &o.principal,
                origin,
                Completion {
                    unsigned: &current.unsigned,
                    signature: &signature,
                    factor: &o.recovery
                }
            )
            .await
            .is_err()
        );
    }
    o.empty_authority().await;
    o.complete(&current).await.unwrap();
    o.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_invalid_factor_persists_only_budget_and_totp_is_consumed_once() {
    let o = Owner::new().await;
    let c = o.challenge().await;
    assert!(matches!(
        complete_genesis(
            &mut o.f.connect().await,
            &o.hasher,
            &o.cipher,
            &o.principal,
            ORIGIN,
            Completion {
                unsigned: &c.unsigned,
                signature: &o.sign(&c),
                factor: "wrong"
            }
        )
        .await,
        Err(CeremonyError::Authentication(AuthError::InvalidCredentials))
    ));
    o.empty_authority().await;
    assert_eq!(o.step_up_failures().await, 1);
    let now: i64 =
        o.f.db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    let code = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::new_stack(o.secret))
        .build()
        .unwrap()
        .generate(now as u64)
        .to_string();
    complete_genesis(
        &mut o.f.connect().await,
        &o.hasher,
        &o.cipher,
        &o.principal,
        ORIGIN,
        Completion {
            unsigned: &c.unsigned,
            signature: &o.sign(&c),
            factor: &code,
        },
    )
    .await
    .unwrap();
    let step: i64 =
        o.f.db
            .query_one(
                "SELECT last_accepted_step FROM owner_mfa WHERE account_id=$1",
                &[&o.principal.tenant.account_id()],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(step, now / 30);
    assert!(o.complete(&c).await.is_err());
    o.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_each_staged_mutation_failure_rolls_back_factor_and_all_trust() {
    for (table, operation) in [
        ("sealed_manifest_authorities", "INSERT"),
        ("sealed_root_challenges", "UPDATE"),
        ("sealed_root_receipts", "INSERT"),
    ] {
        let o = Owner::new().await;
        let c = o.challenge().await;
        o.f.db.batch_execute(&format!("CREATE FUNCTION reject_ceremony_mutation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic rollback'; END$$; \
            CREATE TRIGGER reject_mutation AFTER {operation} ON {table} FOR EACH ROW EXECUTE FUNCTION reject_ceremony_mutation()" )).await.unwrap();
        assert!(o.complete(&c).await.is_err());
        o.empty_authority().await;
        assert!(
            !o.f.db
                .query_one(
                    "SELECT consumed_ms IS NOT NULL FROM sealed_root_challenges",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        o.f.db
            .batch_execute(&format!("DROP TRIGGER reject_mutation ON {table}"))
            .await
            .unwrap();
        o.complete(&c).await.unwrap();
        o.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_concurrent_completers_commit_exactly_one_genesis() {
    let o = Owner::new().await;
    let c = o.challenge().await;
    let (a, b) = tokio::join!(o.complete(&c), o.complete(&c));
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(
        o.f.db
            .query_one("SELECT count(*) FROM sealed_root_receipts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    o.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_rechecks_revocation_after_account_lock_wait_without_spending_factor() {
    for change in [
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE account_id=$1",
        "UPDATE owner_mfa SET enabled_at=NULL,pending_expires_at=clock_timestamp()+interval '1 minute',pending_session_id=$2 WHERE account_id=$1",
        "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
    ] {
        let o = Owner::new().await;
        let c = o.challenge().await;
        let mut blocker = o.f.connect().await;
        let tx = blocker.transaction().await.unwrap();
        tx.query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[&o.principal.tenant.account_id()],
        )
        .await
        .unwrap();
        {
            let pending = o.complete(&c);
            tokio::pin!(pending);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut pending)
                    .await
                    .is_err()
            );
            if change.contains("$2") {
                tx.execute(
                    change,
                    &[&o.principal.tenant.account_id(), &o.principal.session_id],
                )
                .await
                .unwrap();
            } else {
                tx.execute(change, &[&o.principal.tenant.account_id()])
                    .await
                    .unwrap();
            }
            tx.commit().await.unwrap();
            assert!(pending.await.is_err());
        }
        o.empty_authority().await;
        o.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_expiry_after_receipt_insert_wait_rolls_back_every_staged_effect() {
    let o = Owner::new().await;
    let mut c = o.challenge().await;
    let expiry: i64 =
        o.f.db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint+2000",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    c.challenge.expires_ms = expiry as u64;
    c.unsigned = proof::encode(&c.challenge).unwrap();
    o.f.db
        .execute(
            "UPDATE sealed_root_challenges SET expires_ms=$2 WHERE account_id=$1",
            &[&o.principal.tenant.account_id(), &expiry],
        )
        .await
        .unwrap();
    let gate = (rand::random::<u64>() & i64::MAX as u64) as i64;
    o.f.db.batch_execute(&format!("CREATE FUNCTION wait_before_receipt() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN \
        PERFORM pg_advisory_xact_lock({gate}); RETURN NEW; END$$; \
        CREATE TRIGGER receipt_wait BEFORE INSERT ON sealed_root_receipts FOR EACH ROW EXECUTE FUNCTION wait_before_receipt()" )).await.unwrap();
    let mut blocker = o.f.connect().await;
    let tx = blocker.transaction().await.unwrap();
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&gate])
        .await
        .unwrap();
    let mut connection = o.f.connect().await;
    let pid: i32 = connection
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let signature = o.sign(&c);
    {
        let pending = complete_genesis(
            &mut connection,
            &o.hasher,
            &o.cipher,
            &o.principal,
            ORIGIN,
            Completion {
                unsigned: &c.unsigned,
                signature: &signature,
                factor: &o.recovery,
            },
        );
        tokio::pin!(pending);
        wait_for_advisory_lock(&o.f.db, pid, pending.as_mut()).await;
        let limit = tokio::time::Instant::now() + Duration::from_secs(4);
        loop {
            let expired: bool =
                o.f.db
                    .query_one(
                        "SELECT clock_timestamp()>=to_timestamp($1::double precision/1000)",
                        &[&(expiry as f64)],
                    )
                    .await
                    .unwrap()
                    .get(0);
            if expired {
                break;
            }
            assert!(
                tokio::time::Instant::now() < limit,
                "database expiry premise not reached"
            );
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        tx.commit().await.unwrap();
        assert!(matches!(
            pending.await,
            Err(CeremonyError::Rejected(
                "challenge expired or not yet valid"
            ))
        ));
    }
    o.empty_authority().await;
    assert!(
        !o.f.db
            .query_one(
                "SELECT consumed_ms IS NOT NULL FROM sealed_root_challenges",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    o.f.cleanup().await;
}

#[derive(Debug, Clone, Copy)]
enum FinalFenceExpiry {
    Session,
    Totp,
    Idle,
}

async fn final_fence_after_receipt_wait(expiry: FinalFenceExpiry) {
    let totp = matches!(expiry, FinalFenceExpiry::Totp);
    let idle = matches!(expiry, FinalFenceExpiry::Idle);
    let o = Owner::new().await;
    let c = o.challenge().await;
    let signature = o.sign(&c);
    let gate = (rand::random::<u64>() & i64::MAX as u64) as i64;
    o.f.db.batch_execute(&format!("CREATE FUNCTION wait_before_receipt() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN \
        PERFORM pg_advisory_xact_lock({gate}); RETURN NEW; END$$; \
        CREATE TRIGGER receipt_wait BEFORE INSERT ON sealed_root_receipts FOR EACH ROW EXECUTE FUNCTION wait_before_receipt()" )).await.unwrap();
    let mut blocker = o.f.connect().await;
    let tx = blocker.transaction().await.unwrap();
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&gate])
        .await
        .unwrap();
    let mut connection = o.f.connect().await;
    let pid: i32 = connection
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let mut factor = o.recovery.clone();
    let mut totp_deadline_ms = 0i64;
    if totp {
        let generator = totp_rs::Builder::new()
            .with_secret(totp_rs::Secret::new_stack(o.secret))
            .build()
            .unwrap();
        // Accept the preceding step shortly before the database crosses into
        // the next step. This makes only the accepted-factor final fence expire;
        // the challenge and session still have their ordinary long lifetimes.
        let limit = tokio::time::Instant::now() + Duration::from_secs(35);
        loop {
            let observed: i64 =
                o.f.db
                    .query_one(
                        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
            let step = observed / 30_000;
            let previous = generator.generate(((step - 1) * 30) as u64).to_string();
            let distinct = (step..=step + 2)
                .all(|other| generator.generate((other * 30) as u64).to_string() != previous);
            if (28_500..29_000).contains(&(observed % 30_000)) && distinct {
                factor = previous;
                totp_deadline_ms = (step + 1) * 30_000;
                break;
            }
            assert!(
                tokio::time::Instant::now() < limit,
                "TOTP database boundary not reached: observed={observed}"
            );
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    } else if idle {
        o.f.db.execute(
            "UPDATE sessions SET created_at=clock_timestamp()-interval '73 hours', \
             last_used_at=clock_timestamp()-interval '72 hours'+interval '1500 milliseconds' WHERE id=$1",
            &[&o.principal.session_id],
        ).await.unwrap();
    } else {
        o.f.db.execute(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '1500 milliseconds' WHERE id=$1",
            &[&o.principal.session_id],
        ).await.unwrap();
    }
    {
        let pending = complete_genesis(
            &mut connection,
            &o.hasher,
            &o.cipher,
            &o.principal,
            ORIGIN,
            Completion {
                unsigned: &c.unsigned,
                signature: &signature,
                factor: &factor,
            },
        );
        tokio::pin!(pending);
        // Reaching this exact wait proves the earlier live/factor checks passed
        // and that authority, marker, factor and challenge effects are staged.
        wait_for_advisory_lock(&o.f.db, pid, pending.as_mut()).await;
        let limit = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let expired: bool = if totp {
                o.f.db
                    .query_one(
                        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint >= $1",
                        &[&totp_deadline_ms],
                    )
                    .await
                    .unwrap()
                    .get(0)
            } else if idle {
                o.f.db.query_one(
                        "SELECT clock_timestamp() >= COALESCE(last_used_at,created_at)+interval '72 hours' FROM sessions WHERE id=$1",
                        &[&o.principal.session_id],
                    ).await.unwrap().get(0)
            } else {
                o.f.db
                    .query_one(
                        "SELECT clock_timestamp() >= expires_at FROM sessions WHERE id=$1",
                        &[&o.principal.session_id],
                    )
                    .await
                    .unwrap()
                    .get(0)
            };
            if expired {
                break;
            }
            assert!(
                tokio::time::Instant::now() < limit,
                "post-receipt database expiry premise not reached: {expiry:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tx.commit().await.unwrap();
        let expected = if totp {
            "factor expired after wait"
        } else {
            "owner/session/MFA fence"
        };
        assert!(
            matches!(pending.await, Err(CeremonyError::Rejected(reason)) if reason == expected)
        );
    }
    o.empty_authority().await;
    assert!(
        !o.f.db
            .query_one(
                "SELECT consumed_ms IS NOT NULL FROM sealed_root_challenges",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let last_step: i64 =
        o.f.db
            .query_one(
                "SELECT last_accepted_step FROM owner_mfa WHERE account_id=$1",
                &[&o.principal.tenant.account_id()],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(last_step, -1);
    assert_eq!(o.step_up_failures().await, 0);
    o.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_session_expiry_after_receipt_wait_rolls_back_every_staged_effect() {
    final_fence_after_receipt_wait(FinalFenceExpiry::Session).await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_totp_window_expiry_after_receipt_wait_rolls_back_every_staged_effect() {
    final_fence_after_receipt_wait(FinalFenceExpiry::Totp).await;
}

async fn register_role(
    db: &impl GenericClient,
    o: &Owner,
    device: Uuid,
    role: &str,
) -> Result<u64, tokio_postgres::Error> {
    let account = o.principal.tenant.account_id();
    let point = &o.pin[29..];
    let fingerprint = Sha256::digest(point).to_vec();
    match role {
        "device" => db.execute("INSERT INTO device_keys(account_id,device_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
            &[&account, &device, &point, &fingerprint]).await,
        "sms" => db.execute("INSERT INTO sms_line_owner_approval_keys(account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3)",
            &[&account, &point, &fingerprint]).await,
        _ => panic!("fixture role"),
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_and_known_role_registration_serialize_in_both_orders() {
    for role in ["device", "sms"] {
        for root_first in [false, true] {
            let o = Owner::new().await;
            let c = o.challenge().await;
            let device = Uuid::new_v4();
            o.f.db
                .execute(
                    "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
                    &[&device, &o.principal.tenant.account_id()],
                )
                .await
                .unwrap();
            if root_first {
                // Pause after the authority and permanent role claim are staged,
                // while the owned ceremony still holds the account row lock.
                let gate = (rand::random::<u64>() & i64::MAX as u64) as i64;
                o.f.db.batch_execute(&format!("CREATE FUNCTION wait_root_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN \
                    PERFORM pg_advisory_xact_lock({gate}); RETURN NEW; END$$; \
                    CREATE TRIGGER wait_root BEFORE INSERT ON sealed_root_receipts FOR EACH ROW EXECUTE FUNCTION wait_root_commit()" )).await.unwrap();
                let mut gate_db = o.f.connect().await;
                let gate_tx = gate_db.transaction().await.unwrap();
                gate_tx
                    .query_one("SELECT pg_advisory_xact_lock($1)", &[&gate])
                    .await
                    .unwrap();
                {
                    let mut completion_db = o.f.connect().await;
                    let pid: i32 = completion_db
                        .query_one("SELECT pg_backend_pid()", &[])
                        .await
                        .unwrap()
                        .get(0);
                    let signature = o.sign(&c);
                    let completion = complete_genesis(
                        &mut completion_db,
                        &o.hasher,
                        &o.cipher,
                        &o.principal,
                        ORIGIN,
                        Completion {
                            unsigned: &c.unsigned,
                            signature: &signature,
                            factor: &o.recovery,
                        },
                    );
                    tokio::pin!(completion);
                    wait_for_advisory_lock(&o.f.db, pid, completion.as_mut()).await;
                    let registration_db = o.f.connect().await;
                    let registration = register_role(&registration_db, &o, device, role);
                    tokio::pin!(registration);
                    let observed =
                        tokio::time::timeout(Duration::from_millis(100), &mut registration).await;
                    assert!(
                        observed.is_err(),
                        "{role} registration completed before root release: {observed:?}"
                    );
                    gate_tx.commit().await.unwrap();
                    completion.await.unwrap();
                    assert!(registration.await.is_err());
                }
            } else {
                let mut registration_db = o.f.connect().await;
                let tx = registration_db.transaction().await.unwrap();
                register_role(&tx, &o, device, role).await.unwrap();
                {
                    let completion = o.complete(&c);
                    tokio::pin!(completion);
                    assert!(
                        tokio::time::timeout(Duration::from_millis(100), &mut completion)
                            .await
                            .is_err()
                    );
                    tx.commit().await.unwrap();
                    assert!(completion.await.is_err());
                }
                let used: bool = o.f.db.query_one("SELECT used_at IS NOT NULL FROM owner_mfa_recovery_codes WHERE account_id=$1",
                    &[&o.principal.tenant.account_id()]).await.unwrap().get(0);
                assert!(!used, "failed root role reservation rolls back factor");
                assert_eq!(
                    o.f.db
                        .query_one("SELECT count(*) FROM sealed_root_receipts", &[])
                        .await
                        .unwrap()
                        .get::<_, i64>(0),
                    0
                );
            }
            let roles: Vec<String> = o.f.db.query("SELECT role FROM known_signing_role_claims WHERE account_id=$1 AND signing_key_sec1=$2",
                &[&o.principal.tenant.account_id(), &&o.pin[29..]]).await.unwrap().iter().map(|r| r.get(0)).collect();
            assert_eq!(roles.len(), 1);
            assert_eq!(
                roles[0],
                if root_first {
                    "sealed_root"
                } else if role == "device" {
                    "device_auth"
                } else {
                    "sms_approval"
                }
            );
            o.f.cleanup().await;
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_owner_identity_and_genesis_generation_cannot_be_rebound() {
    let mut o = Owner::new().await;
    let c = o.challenge().await;
    let session = o.principal.session_id;
    // Another real session for the same owner cannot complete the old challenge.
    let other_session = Uuid::new_v4();
    o.f.db
        .execute(
            "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) \
        SELECT $1,account_id,user_id,$2,csrf_hash,expires_at FROM sessions WHERE id=$3",
            &[
                &other_session,
                &rand::random::<[u8; 32]>().to_vec(),
                &session,
            ],
        )
        .await
        .unwrap();
    o.principal.session_id = other_session;
    assert!(o.complete(&c).await.is_err());
    o.principal.session_id = session;
    let user = o.principal.user_id;
    o.principal.user_id = Uuid::new_v4();
    assert!(o.complete(&c).await.is_err());
    o.principal.user_id = user;
    let mut second_generation = o.pin;
    second_generation[21..29].copy_from_slice(&2u64.to_be_bytes());
    assert!(
        issue_challenge(
            &mut o.f.connect().await,
            &o.hasher,
            &o.principal,
            ORIGIN,
            second_generation
        )
        .await
        .is_err()
    );
    o.empty_authority().await;
    o.complete(&c).await.unwrap();
    o.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_idle_expiry_after_receipt_wait_rolls_back_every_staged_effect() {
    final_fence_after_receipt_wait(FinalFenceExpiry::Idle).await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn ceremony_idle_policy_uses_creation_fallback_and_recent_use_without_refreshing_it() {
    let o = Owner::new().await;
    let c = o.challenge().await;
    o.f.db.execute(
        "UPDATE sessions SET created_at=clock_timestamp()-interval '73 hours',last_used_at=NULL WHERE id=$1",
        &[&o.principal.session_id],
    ).await.unwrap();
    assert!(matches!(
        issue_challenge(
            &mut o.f.connect().await,
            &o.hasher,
            &o.principal,
            ORIGIN,
            o.pin
        )
        .await,
        Err(CeremonyError::Rejected("owner/session/MFA fence"))
    ));
    assert!(matches!(
        o.complete(&c).await,
        Err(CeremonyError::Rejected("owner/session/MFA fence"))
    ));
    assert!(matches!(
        read_receipt(&mut o.f.connect().await, &o.principal).await,
        Err(CeremonyError::Rejected("owner/session/MFA fence"))
    ));
    o.empty_authority().await;
    let before: String = o.f.db.query_one(
        "UPDATE sessions SET last_used_at=clock_timestamp()-interval '1 hour' WHERE id=$1 RETURNING last_used_at::text",
        &[&o.principal.session_id],
    ).await.unwrap().get(0);
    let fresh = o.challenge().await;
    let receipt = o.complete(&fresh).await.unwrap();
    assert_eq!(
        read_receipt(&mut o.f.connect().await, &o.principal)
            .await
            .unwrap(),
        Some(receipt)
    );
    let after: String =
        o.f.db
            .query_one(
                "SELECT last_used_at::text FROM sessions WHERE id=$1",
                &[&o.principal.session_id],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(before, after);
    o.f.cleanup().await;
}

// These controls use registration rather than the historical seeded Owner.
// An unfinished operation retains its namespace; aborting a driver is not a
// claim that its server-side work or a canceled authentication request settled.
struct RegisteredConnection {
    client: Option<Client>,
    driver: Option<tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>>,
}

impl RegisteredConnection {
    async fn connect(
        config: &tokio_postgres::Config,
        deadline: tokio::time::Instant,
    ) -> Result<Self, String> {
        let (client, connection) =
            registered_step(deadline, "connect", config.connect(tokio_postgres::NoTls)).await?;
        Ok(Self {
            client: Some(client),
            driver: Some(tokio::spawn(connection)),
        })
    }

    fn db(&self) -> Result<&Client, String> {
        self.require_driver()?;
        self.client
            .as_ref()
            .ok_or_else(|| "client already released".into())
    }

    fn db_mut(&mut self) -> Result<&mut Client, String> {
        self.require_driver()?;
        self.client
            .as_mut()
            .ok_or_else(|| "client already released".into())
    }

    fn require_driver(&self) -> Result<(), String> {
        if self
            .driver
            .as_ref()
            .is_none_or(|driver| driver.is_finished())
        {
            return Err("connection driver ended before known settlement".into());
        }
        Ok(())
    }

    async fn finish(mut self, deadline: tokio::time::Instant) -> Result<(), String> {
        self.require_driver()?;
        let limit = registered_limit(deadline)?;
        drop(self.client.take());
        let driver = self.driver.as_mut().ok_or("missing owned driver")?;
        match tokio::time::timeout_at(limit, driver).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(_) => Err("owned driver did not settle successfully".into()),
            Err(_) => {
                // Drop still owns the handle if this future is canceled.
                Err("owned driver settlement unknown; retain namespace".into())
            }
        }
    }
}

impl Drop for RegisteredConnection {
    fn drop(&mut self) {
        // Failure/panic is deliberately not a schema-cleanup path.
        drop(self.client.take());
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

fn registered_limit(deadline: tokio::time::Instant) -> Result<tokio::time::Instant, String> {
    let now = tokio::time::Instant::now();
    if now >= deadline {
        return Err("fixture lifetime exhausted; retain namespace".into());
    }
    Ok(deadline.min(now + Duration::from_secs(30)))
}

async fn registered_step<T, E>(
    deadline: tokio::time::Instant,
    stage: &'static str,
    operation: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, String> {
    match tokio::time::timeout_at(registered_limit(deadline)?, operation).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(format!("{stage} failed; retain namespace")),
        Err(_) => Err(format!("{stage} completion unknown; retain namespace")),
    }
}

struct RegisteredOwnerCase {
    schema: String,
    deadline: tokio::time::Instant,
    setup: RegisteredConnection,
    db: RegisteredConnection,
    cleanup: RegisteredConnection,
    hasher: TokenHasher,
    pepper: zeroize::Zeroizing<Vec<u8>>,
    cipher: mfa::MfaCipher,
    account: Uuid,
    user: Uuid,
    confirming_id: Uuid,
    other_id: Uuid,
    confirming_token: zeroize::Zeroizing<String>,
    other_token: zeroize::Zeroizing<String>,
    email: String,
    password: zeroize::Zeroizing<String>,
    recovery: zeroize::Zeroizing<Vec<String>>,
}

impl RegisteredOwnerCase {
    async fn assert_schema(
        connection: &RegisteredConnection,
        schema: &str,
        deadline: tokio::time::Instant,
    ) -> Result<(), String> {
        let row = registered_step(deadline, "schema binding", connection.db()?.query_one(
            "SELECT current_schema()=$1,current_setting('search_path')=$1,EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1 AND nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user))",
            &[&schema],
        )).await?;
        assert!(
            row.get::<_, bool>(0) && row.get::<_, bool>(1) && row.get::<_, bool>(2),
            "owned schema binding"
        );
        Ok(())
    }

    async fn assert_empty_table(
        db: &Client,
        table: &str,
        deadline: tokio::time::Instant,
    ) -> Result<(), String> {
        // Every caller below supplies a fixed source literal, never an input.
        let row = registered_step(
            deadline,
            "empty application state",
            db.query_one(&format!("SELECT count(*) FROM {table}"), &[]),
        )
        .await?;
        assert_eq!(row.get::<_, i64>(0), 0, "{table}");
        Ok(())
    }

    async fn assert_no_authority(
        db: &Client,
        deadline: tokio::time::Instant,
    ) -> Result<(), String> {
        for table in [
            "sealed_manifest_authorities",
            "sealed_root_enrollments",
            "sealed_root_challenges",
            "sealed_root_receipts",
            "sealed_root_custody",
            "known_signing_point_reservations",
            "known_signing_role_claims",
        ] {
            Self::assert_empty_table(db, table, deadline).await?;
        }
        // Numbered migrations do not install the candidate issuer schema.
        // Resolve only this namespace, rather than falling back to public.
        let row = registered_step(deadline, "optional issuer absence", db.query_one(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relname IN ('contact_reader_state','contact_reader_pending','contact_reader_receipts')", &[],
        )).await?;
        assert_eq!(
            row.get::<_, i64>(0),
            0,
            "candidate issuer catalog must be absent"
        );
        Ok(())
    }

    fn assert_principal(principal: &SessionPrincipal, account: Uuid, user: Uuid, session: Uuid) {
        assert_eq!(principal.tenant.account_id(), account);
        assert_eq!(principal.user_id, user);
        assert_eq!(principal.session_id, session);
        assert_eq!(principal.role, auth::Role::Owner);
    }

    async fn new(schema: String, deadline: tokio::time::Instant) -> Result<Self, String> {
        // Missing opt-in is refusal, including when this ignored test is selected.
        let url = zeroize::Zeroizing::new(
            std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
                .map_err(|_| "requires explicit ZT_INBOUND_TEST_DATABASE_URL")?,
        );
        let mut config: tokio_postgres::Config = url
            .parse()
            .map_err(|_| "invalid disposable database configuration")?;
        let setup = RegisteredConnection::connect(&config, deadline).await?;
        registered_step(
            deadline,
            "create owned schema",
            setup.db()?.batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            )),
        )
        .await?;
        Self::assert_schema(&setup, &schema, deadline).await?;
        config.options(format!("-csearch_path={schema}"));
        let mut db = RegisteredConnection::connect(&config, deadline).await?;
        let cleanup = RegisteredConnection::connect(&config, deadline).await?;
        Self::assert_schema(&db, &schema, deadline).await?;
        Self::assert_schema(&cleanup, &schema, deadline).await?;
        // apply can panic. The entire fixture operation is an owned task below;
        // a panic is observed there and does not call cleanup or pass this test.
        registered_step(deadline, "all maintained migrations", async {
            auth::test_schema::apply(db.db()?).await;
            Ok::<(), String>(())
        })
        .await?;
        for table in [
            "accounts",
            "users",
            "memberships",
            "sessions",
            "owner_mfa",
            "owner_mfa_login_challenges",
            "owner_mfa_recovery_codes",
        ] {
            Self::assert_empty_table(db.db()?, table, deadline).await?;
        }
        Self::assert_no_authority(db.db()?, deadline).await?;
        let pepper = zeroize::Zeroizing::new(rand::random::<[u8; 32]>().to_vec());
        // The maintained hasher owns its own operational copy; this fixture
        // makes no claim that API-internal allocations are zero-copy secrets.
        let hasher = TokenHasher::new(pepper.to_vec()).map_err(|_| "token hasher construction")?;
        let cipher = mfa::MfaCipher::new(rand::random::<[u8; 32]>().to_vec())
            .map_err(|_| "MFA cipher construction")?;
        let email = format!("{}@example.test", Uuid::new_v4().simple());
        let password = zeroize::Zeroizing::new(Uuid::new_v4().to_string());
        let signup = registered_step(
            deadline,
            "registration",
            auth::register(db.db_mut()?, &hasher, &email, &password),
        )
        .await?;
        let verification = zeroize::Zeroizing::new(signup.verification_token);
        assert!(
            registered_step(
                deadline,
                "password-backed verification",
                auth::verify_email_with_password(db.db_mut()?, &hasher, &verification, &password)
            )
            .await?
        );
        let first = registered_step(
            deadline,
            "confirming login",
            auth::login(db.db()?, &hasher, &email, &password),
        )
        .await?;
        let confirming_id = first.id;
        let confirming_token = zeroize::Zeroizing::new(first.token);
        let _confirming_csrf = zeroize::Zeroizing::new(first.csrf_token);
        let principal = registered_step(
            deadline,
            "confirming authentication",
            auth::authenticate_session(db.db()?, &hasher, &confirming_token),
        )
        .await?;
        Self::assert_principal(&principal, signup.account_id, signup.user_id, confirming_id);
        let second = registered_step(
            deadline,
            "second login",
            auth::login(db.db()?, &hasher, &email, &password),
        )
        .await?;
        let other_id = second.id;
        assert_ne!(confirming_id, other_id);
        let other_token = zeroize::Zeroizing::new(second.token);
        let _other_csrf = zeroize::Zeroizing::new(second.csrf_token);
        let other = registered_step(
            deadline,
            "second authentication",
            auth::authenticate_session(db.db()?, &hasher, &other_token),
        )
        .await?;
        Self::assert_principal(&other, signup.account_id, signup.user_id, other_id);
        let enrollment = registered_step(
            deadline,
            "begin MFA",
            mfa::begin_enrollment(db.db_mut()?, &cipher, &principal, &password),
        )
        .await?;
        let secret = zeroize::Zeroizing::new(enrollment.secret_base32);
        let _provisioning = zeroize::Zeroizing::new(enrollment.provisioning_uri);
        let generator = totp_rs::Builder::new()
            .with_secret(
                totp_rs::Secret::try_from_base32(&secret)
                    .map_err(|_| "generated MFA secret decoding")?,
            )
            .build()
            .map_err(|_| "generated MFA code construction")?;
        let code = zeroize::Zeroizing::new(generator.generate_current().to_string());
        let codes = registered_step(
            deadline,
            "confirm MFA",
            mfa::confirm_enrollment(db.db_mut()?, &cipher, &hasher, &principal, &code),
        )
        .await?;
        let recovery = zeroize::Zeroizing::new(codes.codes);
        assert_eq!(recovery.len(), 10);
        Ok(Self {
            schema,
            deadline,
            setup,
            db,
            cleanup,
            hasher,
            pepper,
            cipher,
            account: signup.account_id,
            user: signup.user_id,
            confirming_id,
            other_id,
            confirming_token,
            other_token,
            email,
            password,
            recovery,
        })
    }

    fn recovery_digest(&self, index: usize) -> [u8; 32] {
        let subject = zeroize::Zeroizing::new(format!(
            "{}:{}:{}",
            self.account, self.user, self.recovery[index]
        ));
        token_digest(&self.pepper, b"mfa-recovery-v1", &subject)
    }

    async fn assert_recovery(&self, index: usize, used: bool) -> Result<(), String> {
        let hash = self.recovery_digest(index);
        let row = registered_step(self.deadline, "exact recovery ledger", self.db.db()?.query_one(
            "SELECT used_at IS NOT NULL FROM owner_mfa_recovery_codes WHERE account_id=$1 AND user_id=$2 AND code_hash=$3",
            &[&self.account, &self.user, &&hash[..]],
        )).await?;
        assert_eq!(row.get::<_, bool>(0), used, "recovery allocation {index}");
        Ok(())
    }

    async fn assert_confirming_survives(&self) -> Result<(), String> {
        let principal = registered_step(
            self.deadline,
            "preserved confirming session",
            auth::authenticate_session(self.db.db()?, &self.hasher, &self.confirming_token),
        )
        .await?;
        Self::assert_principal(&principal, self.account, self.user, self.confirming_id);
        let refusal = registered_step(self.deadline, "revoked other session", async {
            Ok::<_, String>(
                auth::authenticate_session(self.db.db()?, &self.hasher, &self.other_token).await,
            )
        })
        .await?;
        assert!(matches!(refusal, Err(auth::AuthError::Unauthorized)));
        let row = registered_step(self.deadline, "actual enrollment and revocation", self.db.db()?.query_one(
            "SELECT u.mfa_enabled,m.enabled_at IS NOT NULL,s.revoked_at IS NOT NULL,(SELECT count(*) FROM owner_mfa_recovery_codes WHERE account_id=$1 AND user_id=$2) FROM users u JOIN owner_mfa m ON m.user_id=u.id AND m.account_id=$1 JOIN sessions s ON s.user_id=u.id AND s.account_id=$1 AND s.id=$3 WHERE u.id=$2",
            &[&self.account, &self.user, &self.other_id],
        )).await?;
        assert!(row.get::<_, bool>(0) && row.get::<_, bool>(1) && row.get::<_, bool>(2));
        assert_eq!(row.get::<_, i64>(3), 10);
        self.assert_recovery(0, false).await?;
        self.assert_recovery(1, false).await?;
        Self::assert_no_authority(self.db.db()?, self.deadline).await
    }

    async fn recovery_login(&mut self) -> Result<(), String> {
        let refusal = registered_step(self.deadline, "ordinary MFA-required login", async {
            Ok::<_, String>(
                auth::login(self.db.db()?, &self.hasher, &self.email, &self.password).await,
            )
        })
        .await?;
        assert!(
            matches!(refusal, Err(auth::AuthError::MfaRequired {account_id, user_id}) if account_id == self.account && user_id == self.user)
        );
        let challenge = zeroize::Zeroizing::new(
            registered_step(
                self.deadline,
                "real login challenge",
                mfa::begin_login_challenge(
                    self.db.db()?,
                    &self.hasher,
                    self.account,
                    self.user,
                    &self.password,
                ),
            )
            .await?,
        );
        let session = registered_step(
            self.deadline,
            "consume recovery two",
            mfa::complete_login(
                self.db.db_mut()?,
                Some(&self.cipher),
                &self.hasher,
                &challenge,
                &self.recovery[2],
            ),
        )
        .await?;
        let token = zeroize::Zeroizing::new(session.token);
        let _csrf = zeroize::Zeroizing::new(session.csrf_token);
        let principal = registered_step(
            self.deadline,
            "new MFA session authentication",
            auth::authenticate_session(self.db.db()?, &self.hasher, &token),
        )
        .await?;
        Self::assert_principal(&principal, self.account, self.user, session.id);
        assert_ne!(session.id, self.confirming_id);
        assert_ne!(session.id, self.other_id);
        self.assert_recovery(2, true).await?;
        self.assert_recovery(0, false).await?;
        self.assert_recovery(1, false).await?;
        let completed_hash = token_digest(&self.pepper, b"mfa-login-challenge-v1", &challenge);
        let completed = registered_step(self.deadline, "committed login challenge", self.db.db()?.query_one(
            "SELECT c.consumed_at IS NOT NULL,c.attempts,m.failed_attempts FROM owner_mfa_login_challenges c JOIN owner_mfa m USING(account_id,user_id) WHERE c.account_id=$1 AND c.user_id=$2 AND c.token_hash=$3",
            &[&self.account, &self.user, &&completed_hash[..]],
        )).await?;
        assert!(completed.get::<_, bool>(0));
        assert_eq!(completed.get::<_, i32>(1), 0);
        assert_eq!(completed.get::<_, i32>(2), 0);
        let challenge = zeroize::Zeroizing::new(
            registered_step(
                self.deadline,
                "separate reuse challenge",
                mfa::begin_login_challenge(
                    self.db.db()?,
                    &self.hasher,
                    self.account,
                    self.user,
                    &self.password,
                ),
            )
            .await?,
        );
        let challenge_hash = token_digest(&self.pepper, b"mfa-login-challenge-v1", &challenge);
        let before = registered_step(
            self.deadline,
            "pre-refusal session count",
            self.db.db()?.query_one(
                "SELECT count(*) FROM sessions WHERE account_id=$1 AND user_id=$2",
                &[&self.account, &self.user],
            ),
        )
        .await?
        .get::<_, i64>(0);
        let refusal = registered_step(self.deadline, "reused recovery refusal", async {
            Ok::<_, String>(
                mfa::complete_login(
                    self.db.db_mut()?,
                    Some(&self.cipher),
                    &self.hasher,
                    &challenge,
                    &self.recovery[2],
                )
                .await,
            )
        })
        .await?;
        assert!(matches!(refusal, Err(auth::AuthError::InvalidCredentials)));
        let row = registered_step(self.deadline, "actual failure budget", self.db.db()?.query_one(
            "SELECT m.failed_attempts,c.attempts,c.consumed_at IS NULL,(SELECT count(*) FROM sessions WHERE account_id=$1 AND user_id=$2) FROM owner_mfa m JOIN owner_mfa_login_challenges c USING(account_id,user_id) WHERE m.account_id=$1 AND m.user_id=$2 AND c.token_hash=$3",
            &[&self.account, &self.user, &&challenge_hash[..]],
        )).await?;
        assert_eq!(row.get::<_, i32>(0), 1);
        assert_eq!(row.get::<_, i32>(1), 1);
        assert!(row.get::<_, bool>(2));
        assert_eq!(row.get::<_, i64>(3), before);
        self.assert_recovery(2, true).await?;
        self.assert_confirming_survives().await
    }

    async fn finish(self) -> Result<(), String> {
        let Self {
            schema,
            deadline,
            setup,
            db,
            cleanup,
            ..
        } = self;
        // Known operation completion only. Drop each Client before joining its
        // exact driver; the separate cleanup connection has remained idle.
        db.finish(deadline).await?;
        setup.finish(deadline).await?;
        Self::assert_schema(&cleanup, &schema, deadline).await?;
        registered_step(
            deadline,
            "guarded owned teardown",
            crate::sealed_manifest_store::tests::cleanup::drop_fixture(cleanup.db()?, &schema),
        )
        .await?;
        cleanup.finish(deadline).await
    }
}

async fn registered_owner_control(recovery_login: bool) {
    // Mint the fixed allowed identity before any CREATE. Only the owned task
    // below may create it; no caller-supplied schema or password is accepted.
    let schema = format!("manifest_authority_{}", Uuid::new_v4().simple());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    let owned_schema = schema.clone();
    let mut operation = tokio::spawn(async move {
        let mut case = RegisteredOwnerCase::new(owned_schema, deadline).await?;
        case.assert_confirming_survives().await?;
        if recovery_login {
            case.recovery_login().await?;
        }
        case.finish().await
    });
    match tokio::time::timeout_at(deadline, &mut operation).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(stage))) => panic!("registered-owner refusal: {stage}; namespace={schema}"),
        Ok(Err(_)) => panic!("registered-owner task panic; retain namespace={schema}"),
        Err(_) => {
            operation.abort();
            panic!("registered-owner task completion unknown; retain namespace={schema}");
        }
    }
}

#[tokio::test]
#[ignore = "requires explicit ZT_INBOUND_TEST_DATABASE_URL; sequential owned-schema control"]
async fn postgres_account_only_empty_registration_preserves_confirming_session() {
    registered_owner_control(false).await;
}

#[tokio::test]
#[ignore = "requires explicit ZT_INBOUND_TEST_DATABASE_URL; sequential owned-schema control"]
async fn postgres_account_only_mfa_required_login_uses_distinct_recovery() {
    registered_owner_control(true).await;
}
