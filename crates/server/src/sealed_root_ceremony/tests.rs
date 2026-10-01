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
