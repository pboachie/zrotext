// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{mfa::MfaCipher, ordinary_owner03::step_up};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::Rng;

const PASSWORD: &str = "held-owner-fixture-password";

struct Credentials {
    cipher: MfaCipher,
    secret: [u8; 20],
}
impl Credentials {
    async fn install(f: &Fixture, s: &Seed) -> Self {
        f.owner.batch_execute(&format!("GRANT SELECT,INSERT,UPDATE ON public.auth_abuse_counters TO {r}; GRANT SELECT,UPDATE ON public.owner_mfa_recovery_codes TO {r}; GRANT UPDATE(last_accepted_step) ON public.owner_mfa TO {r}",r=escape_identifier(&f.reader_role))).await.unwrap();
        let hash = crate::auth::password_work::hash(PASSWORD).await.unwrap();
        f.owner
            .execute(
                "UPDATE public.users SET password_hash=$2 WHERE id=$1",
                &[&s.selector.user, &hash],
            )
            .await
            .unwrap();
        let mut secret = [0; 20];
        let mut nonce = [0; 12];
        rand::rng().fill_bytes(&mut secret);
        rand::rng().fill_bytes(&mut nonce);
        let key: [u8; 32] = rand::random();
        let mut aad = b"zrotext-owner-totp-v1".to_vec();
        aad.extend_from_slice(s.selector.account.as_bytes());
        aad.extend_from_slice(s.selector.user.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let encrypted = cipher
            .encrypt(
                &Nonce::try_from(nonce.as_slice()).unwrap(),
                Payload {
                    msg: &secret,
                    aad: &aad,
                },
            )
            .unwrap();
        f.owner.execute("UPDATE public.owner_mfa SET secret_nonce=$3,secret_ciphertext=$4,last_accepted_step=-1 WHERE account_id=$1 AND user_id=$2", &[&s.selector.account, &s.selector.user, &&nonce[..], &encrypted]).await.unwrap();
        Self {
            cipher: MfaCipher::new(key.to_vec()).unwrap(),
            secret,
        }
    }
    async fn code(&self, db: &Client) -> String {
        let now: i64 = db
            .query_one(
                "SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp()))::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        totp_rs::Builder::new()
            .with_secret(totp_rs::Secret::new_stack(self.secret))
            .build()
            .unwrap()
            .generate(now as u64)
            .to_string()
    }
    async fn recovery(&self, f: &Fixture, s: &Seed) -> String {
        use base64::Engine;
        let code = format!(
            "zrc_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
        );
        let subject = format!("{}:{}:{}", s.selector.account, s.selector.user, code);
        let digest = f.hasher.digest(b"mfa-recovery-v1", &subject);
        f.owner.execute("INSERT INTO public.owner_mfa_recovery_codes(account_id,user_id,code_hash) VALUES($1,$2,$3)", &[&s.selector.account,&s.selector.user,&&digest[..]]).await.unwrap();
        code
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn actual_password_encrypted_totp_and_committed_replay_use_the_same_held_transaction() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let credentials = Credentials::install(&f, &s).await;
    let code = credentials.code(&f.owner).await;
    let before: Option<Vec<u8>> = f
        .owner
        .query_one(
            "SELECT pg_catalog.timestamptz_send(last_used_at) FROM public.sessions WHERE id=$1",
            &[&s.selector.session],
        )
        .await
        .unwrap()
        .get(0);
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &f.hasher, &credentials.cipher, PASSWORD, &code)
            .await
            .unwrap()
    else {
        panic!("genuine factor refused")
    };
    assert_eq!(
        proof.owner_identity_digest(),
        &OwnerSessionIdentity03 {
            account_id: *s.selector.account.as_bytes(),
            user_id: *s.selector.user.as_bytes(),
            session_id: *s.selector.session.as_bytes()
        }
        .digest()
        .unwrap()
    );
    proof.revalidate().await.unwrap();
    drop(proof);
    tx.commit().await.unwrap();
    assert!(
        f.owner
            .query_one(
                "SELECT last_accepted_step>=0 FROM public.owner_mfa WHERE account_id=$1",
                &[&s.selector.account]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let after: Option<Vec<u8>> = f
        .owner
        .query_one(
            "SELECT pg_catalog.timestamptz_send(last_used_at) FROM public.sessions WHERE id=$1",
            &[&s.selector.session],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, after);
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    assert!(matches!(
        step_up::verify(owner, &f.hasher, &credentials.cipher, PASSWORD, &code)
            .await
            .unwrap(),
        step_up::Outcome::Rejected(step_up::Rejection::InvalidCredentials)
    ));
    tx.commit().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn wrong_passwords_and_factors_spend_the_shared_failure_budget_without_consuming_a_factor() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let credentials = Credentials::install(&f, &s).await;
    let code = credentials.code(&f.owner).await;
    // A malformed factor is deterministically wrong, without a rare accidental
    // match with a valid numeric TOTP generated during this test.
    for i in 0..5 {
        let tx = f.reader.transaction().await.unwrap();
        let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
            .await
            .unwrap();
        let (password, factor) = if i % 2 == 0 {
            ("incorrect-owner-password", code.as_str())
        } else {
            (PASSWORD, "xxxxxx")
        };
        assert!(matches!(
            step_up::verify(owner, &f.hasher, &credentials.cipher, password, factor)
                .await
                .unwrap(),
            step_up::Outcome::Rejected(step_up::Rejection::InvalidCredentials)
        ));
        tx.commit().await.unwrap();
    }
    assert_eq!(
        f.owner
            .query_one(
                "SELECT last_accepted_step FROM public.owner_mfa WHERE account_id=$1",
                &[&s.selector.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        -1
    );
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    assert!(matches!(
        step_up::verify(owner, &f.hasher, &credentials.cipher, PASSWORD, &code)
            .await
            .unwrap(),
        step_up::Outcome::Rejected(step_up::Rejection::RateLimited)
    ));
    tx.commit().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn rollback_retains_totp_but_own_transaction_reverting_its_consumption_invalidates_the_proof()
{
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let credentials = Credentials::install(&f, &s).await;
    let code = credentials.code(&f.owner).await;
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &f.hasher, &credentials.cipher, PASSWORD, &code)
            .await
            .unwrap()
    else {
        panic!("factor refused")
    };
    tx.execute(
        "UPDATE public.owner_mfa SET last_accepted_step=-1 WHERE account_id=$1",
        &[&s.selector.account],
    )
    .await
    .unwrap();
    assert!(proof.revalidate().await.is_err());
    drop(proof);
    tx.rollback().await.unwrap();
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    assert!(matches!(
        step_up::verify(owner, &f.hasher, &credentials.cipher, PASSWORD, &code)
            .await
            .unwrap(),
        step_up::Outcome::Verified(_)
    ));
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn recovery_is_one_use_and_its_exact_used_timestamp_cannot_be_replaced_inside_the_transaction()
 {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let credentials = Credentials::install(&f, &s).await;
    let recovery = credentials.recovery(&f, &s).await;
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &f.hasher, &credentials.cipher, PASSWORD, &recovery)
            .await
            .unwrap()
    else {
        panic!("recovery refused")
    };
    tx.execute("UPDATE public.owner_mfa_recovery_codes SET used_at=used_at+interval '1 microsecond' WHERE account_id=$1", &[&s.selector.account]).await.unwrap();
    assert!(proof.revalidate().await.is_err());
    drop(proof);
    tx.rollback().await.unwrap();
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    assert!(matches!(
        step_up::verify(owner, &f.hasher, &credentials.cipher, PASSWORD, &recovery)
            .await
            .unwrap(),
        step_up::Outcome::Verified(_)
    ));
    tx.commit().await.unwrap();
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    assert!(matches!(
        step_up::verify(owner, &f.hasher, &credentials.cipher, PASSWORD, &recovery)
            .await
            .unwrap(),
        step_up::Outcome::Rejected(step_up::Rejection::InvalidCredentials)
    ));
    tx.commit().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn wrong_runtime_cipher_cannot_decrypt_the_owner_factor_or_spend_it() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let credentials = Credentials::install(&f, &s).await;
    let code = credentials.code(&f.owner).await;
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    let other = MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    assert!(matches!(
        step_up::verify(owner, &f.hasher, &other, PASSWORD, &code).await,
        Err(step_up::Error::Credential(crate::auth::AuthError::Crypto))
    ));
    tx.rollback().await.unwrap();
    assert_eq!(
        f.owner
            .query_one(
                "SELECT last_accepted_step FROM public.owner_mfa WHERE account_id=$1",
                &[&s.selector.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        -1
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn concurrent_step_up_refuses_before_work_while_an_unrelated_owner_progresses() {
    let mut f = Fixture::new().await;
    let s = Seed::new(&f.owner, &f.hasher, "owner").await;
    let other = Seed::new(&f.owner, &f.hasher, "owner").await;
    let credentials = Credentials::install(&f, &s).await;
    let other_credentials = Credentials::install(&f, &other).await;
    let (mut second, second_driver) = connect(&f.reader_config).await;
    let tx = f.reader.transaction().await.unwrap();
    let owner = authenticate(&tx, &f.hasher, ORIGIN, s.source())
        .await
        .unwrap();
    let step_up::Outcome::Verified(_proof) = step_up::verify(
        owner,
        &f.hasher,
        &credentials.cipher,
        PASSWORD,
        &credentials.code(&f.owner).await,
    )
    .await
    .unwrap() else {
        panic!("factor refused")
    };
    let second_tx = second.transaction().await.unwrap();
    assert!(
        authenticate(&second_tx, &f.hasher, ORIGIN, s.source())
            .await
            .is_err()
    );
    second_tx.rollback().await.unwrap();
    let second_tx = second.transaction().await.unwrap();
    let unrelated = authenticate(&second_tx, &f.hasher, ORIGIN, other.source())
        .await
        .unwrap();
    assert!(matches!(
        step_up::verify(
            unrelated,
            &f.hasher,
            &other_credentials.cipher,
            PASSWORD,
            &other_credentials.code(&f.owner).await
        )
        .await
        .unwrap(),
        step_up::Outcome::Verified(_)
    ));
    second_tx.rollback().await.unwrap();
    drop(_proof);
    tx.rollback().await.unwrap();
    close(second, second_driver).await;
    f.finish().await;
}
