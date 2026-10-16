// SPDX-License-Identifier: AGPL-3.0-only
//! Actual pending-work/currentness interleavings without production test hooks.
use super::*;
use crate::auth::review_access::{
    current::Credentials,
    roots::{Completion, Material, RootPreparation},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use zeroize::Zeroizing;
use zrotext_root_material::{
    recovery_kit::encode_public_card,
    root_backup::{self, RecoverySecret, RootSecret},
};

async fn observed_worker(counter: &std::sync::atomic::AtomicUsize, before: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while counter.load(std::sync::atomic::Ordering::SeqCst) == before {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("real password worker did not start");
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster; actual pending hash/cancel interleaving"]
async fn cancel_pending_real_password_work_refuses_old_final_and_duplicate_hash() {
    let f = Fixture::create().await;
    let prep = f.prepared("pilot").await;
    let counter = crate::auth::tests::PASSWORD_VERIFICATIONS.with(Arc::clone);
    let before = counter.load(std::sync::atomic::Ordering::SeqCst);
    {
        let pending = f.access.login(&prep, "synthetic-review-password");
        tokio::pin!(pending);
        tokio::select! {result=&mut pending=>panic!("operation ended before interleaving: {}",result.is_ok()),
        ()=observed_worker(&counter,before)=>{}}
        assert!(!f.owner.query_one("SELECT EXISTS(SELECT FROM pg_catalog.pg_stat_activity WHERE datname=pg_catalog.current_database() AND usename=$1 AND xact_start IS NOT NULL)",&[&f.runtime_role]).await.unwrap().get::<_,bool>(0));
        assert!(
            f.access
                .login(&prep, "synthetic-review-password")
                .await
                .is_err()
        );
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            before + 1
        );
        assert_eq!(
            f.access.transition(&prep, "cancel").await.unwrap(),
            "cancelled_no_effect"
        );
        assert!(pending.await.is_err());
    }
    for table in [
        "accounts",
        "users",
        "review_broker_sessions",
        "review_access_authentications",
    ] {
        assert_eq!(f.count(table).await, 0, "{table}");
    }
    assert_eq!(
        f.owner
            .query_one(
                "SELECT state FROM public.review_access_preparations WHERE browser_digest=$1",
                &[&&prep.browser[..]]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "cancelled_no_effect"
    );
    f.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster; actual verifier/config rotation while password work pending"]
async fn owned_verifier_and_config_revision_change_during_work_leave_unknown_without_allocation() {
    for change_verifier in [true, false] {
        let f = Fixture::create().await;
        let prep = f.prepared("pilot").await;
        let verifier = crate::auth::password_work::hash("different synthetic password")
            .await
            .unwrap();
        let counter = crate::auth::tests::PASSWORD_VERIFICATIONS.with(Arc::clone);
        let before = counter.load(std::sync::atomic::Ordering::SeqCst);
        {
            let pending = f.access.login(&prep, "synthetic-review-password");
            tokio::pin!(pending);
            tokio::select! {result=&mut pending=>panic!("operation ended before interleaving: {}",result.is_ok()),
            ()=observed_worker(&counter,before)=>{}}
            if change_verifier {
                f.owner.execute("UPDATE public.review_brokers SET credential_revision=2,password_verifier=$1",&[&verifier]).await.unwrap();
            } else {
                f.owner.execute("UPDATE public.review_realm_installation SET active_config_digest=$1,active_config_revision=2",&[&&[8u8;32][..]]).await.unwrap();
                f.owner.execute("UPDATE public.review_realm_installation SET active_config_digest=$1,active_config_revision=3",&[&&f.access.scope.config[..]]).await.unwrap();
            }
            assert!(pending.await.is_err());
        }
        for table in [
            "accounts",
            "users",
            "review_broker_sessions",
            "review_bootstrap_attempts",
            "review_access_authentications",
        ] {
            assert_eq!(f.count(table).await, 0, "{table}");
        }
        assert_eq!(
            f.owner
                .query_one(
                    "SELECT state FROM public.review_access_preparations WHERE browser_digest=$1",
                    &[&&prep.browser[..]]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            "checking",
            "generic final refusal must remain UNKNOWN"
        );
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster; prospective UUID occupation and erased-result refusal"]
async fn occupied_prospective_account_or_user_is_never_attached_or_removed() {
    for account_occupied in [true, false] {
        let f = Fixture::create().await;
        let prep = f.prepared("pilot").await;
        if account_occupied {
            f.owner
                .execute(
                    "INSERT INTO public.accounts(id) VALUES($1)",
                    &[&prep.identities.account],
                )
                .await
                .unwrap();
        } else {
            f.owner.execute("INSERT INTO public.users(id,email,password_hash) VALUES($1,'unrelated@review.invalid','!')",&[&prep.identities.user]).await.unwrap();
        }
        assert!(
            f.access
                .login(&prep, "synthetic-review-password")
                .await
                .is_err()
        );
        assert_eq!(f.count("accounts").await, i64::from(account_occupied));
        assert_eq!(f.count("users").await, i64::from(!account_occupied));
        for table in [
            "memberships",
            "review_workspaces",
            "review_broker_sessions",
            "review_bootstrap_attempts",
            "review_access_sessions",
            "review_access_authentications",
        ] {
            assert_eq!(f.count(table).await, 0, "{table}");
        }
        f.cleanup().await;
    }
}

async fn login_owner(f: &Fixture) -> (Browser, Preparation, Credentials) {
    let (browser, prep) = f.prepared_with_browser("pilot").await;
    f.access
        .login(&prep, "synthetic-review-password")
        .await
        .unwrap();
    let c = f
        .access
        .credentials(
            prep.identities.broker_session,
            &prep.candidates.broker,
            &prep.candidates.broker_csrf,
            prep.identities.owner_session,
            &prep.candidates.owner,
            &prep.candidates.owner_csrf,
        )
        .unwrap();
    f.access
        .acknowledge(
            &browser,
            &c,
            prep.id,
            prep.request,
            prep.generation,
            &prep.candidates.csrf,
        )
        .await
        .unwrap();
    let now = clock(&f.owner, 0).await.unwrap();
    let selector =
        frames::LocatorSelector::from_initial(&prep, &browser, &f.access.key, &f.access.scope, now)
            .unwrap()
            .seal(&f.access.key, &f.access.scope, now)
            .unwrap();
    let hash: [u8; 32] = Sha256::digest(selector.as_bytes()).into();
    f.access
        .locator_retention(
            &browser,
            &c,
            crate::auth::review_access::current::LocatorObservation {
                phase: crate::auth::review_access::current::LocatorPhase::Confirm,
                preparation: prep.id,
                request: Uuid::new_v4(),
                selector_hash: &hash,
                selector_value: Some(&selector),
            },
        )
        .await
        .unwrap();
    (browser, prep, c)
}
fn material(account: Uuid, origin: &str) -> (SigningKey, Material) {
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let pin: [u8; 94] = [
        b"ZTRP\x02".as_slice(),
        account.as_bytes(),
        &1u64.to_be_bytes(),
        key.verifying_key().to_sec1_point(false).as_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap();
    let compared =
        crate::sealed_root_enrollment::root_fingerprint(&pin, account.as_bytes()).unwrap();
    let expected = root_backup::ExpectedIdentity {
        account_id: *account.as_bytes(),
        origin: origin.into(),
        root_fingerprint: compared,
    };
    let secret = RootSecret::new(Zeroizing::new(key.to_bytes().into())).unwrap();
    let recovery = RecoverySecret::new(Zeroizing::new(rand::random()));
    let backup = root_backup::seal(&secret, &recovery, &expected).unwrap();
    let card = encode_public_card(&pin, &expected, &Sha256::digest(&backup).into()).unwrap();
    (
        key,
        Material {
            pin,
            compared,
            backup,
            card,
        },
    )
}
fn sign(key: &SigningKey, bytes: &[u8]) -> [u8; 64] {
    let signature: Signature = key.sign(bytes);
    signature.normalize_s().to_bytes().into()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster; real shortened original challenge expiry, no altered clock/helper"]
async fn expired_original_root_challenge_preserves_history_and_never_consumes_or_replaces() {
    let f = Fixture::create().await;
    let (browser, _, c) = login_owner(&f).await;
    let account = f
        .owner
        .query_one("SELECT account_id FROM public.review_workspaces", &[])
        .await
        .unwrap()
        .get(0);
    let (key, material) = material(account, &f.access.scope.origin);
    let original = f
        .access
        .prepare_root(
            &browser,
            &c,
            Uuid::new_v4(),
            RootPreparation::Issue(&material),
        )
        .await
        .unwrap();
    f.access
        .transition_root(&browser, &c, &original, "cancel")
        .await
        .unwrap();
    // A legitimate shorter-than-maximum original server preparation. Persist
    // it through the installed exact same helper, without editing a clock,
    // function, trigger, challenge or already-created immutable preparation.
    let now = clock(&f.owner, 0).await.unwrap();
    let short = Preparation {
        operation: Operation::RootIssue,
        browser: original.browser,
        id: Uuid::new_v4(),
        request: Uuid::new_v4(),
        generation: original.generation + 1,
        prepared: now,
        create_deadline: now + 1000,
        delivery_deadline: original.delivery_deadline,
        alias: String::new(),
        identities: original.identities.clone(),
        target: original.target,
        candidates: Candidates::fresh(Operation::RootIssue),
    };
    short
        .validate(&browser, &f.access.key, &f.access.scope, now, true)
        .unwrap();
    let mut client = f.access.connect().await.unwrap();
    let tx = begin(&mut client).await.unwrap();
    let held =
        crate::auth::review_access::current::HeldOwner::acquire(&f.access, &tx, &browser, &c, true)
            .await
            .unwrap();
    let s = &f.access.scope;
    let digest = short.commitment(&f.access.key, s);
    let csrf: [u8; 32] = Sha256::digest(short.candidates.csrf.as_ref()).into();
    tx.query_one("SELECT * FROM public.review_access_prepare($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        &[&s.realm,&&s.database[..],&s.origin,&&s.key[..],&&s.config[..],&(s.config_revision as i64),&&short.browser[..],&short.id,&short.request,&(short.operation as i16),&&digest[..],
            &(short.generation as i64),&(short.prepared as i64),&(short.create_deadline as i64),&(short.delivery_deadline as i64),&&csrf[..]]).await.unwrap();
    held.check(now).await.unwrap();
    drop(held);
    tx.commit().await.unwrap();
    drop(client);
    f.access
        .transition_root(&browser, &c, &short, "confirm")
        .await
        .unwrap();
    let issued = f
        .access
        .issue_root(&browser, &c, &short, &material)
        .await
        .unwrap();
    f.access
        .acknowledge(
            &browser,
            &c,
            short.id,
            short.request,
            short.generation,
            &short.candidates.csrf,
        )
        .await
        .unwrap();
    let unsigned = STANDARD.decode(issued.unsigned_enrollment_b64).unwrap();
    let statement = STANDARD.decode(issued.custody_statement_b64).unwrap();
    let completion = Completion {
        root: issued.root_challenge_id,
        reauth: issued.reauth_challenge_id,
        nonce: STANDARD
            .decode(issued.reauth_nonce_b64)
            .unwrap()
            .try_into()
            .unwrap(),
        enrollment_signature: sign(
            &key,
            &crate::sealed_root_enrollment::transcript(&unsigned).unwrap(),
        ),
        custody_signature: sign(&key, &statement),
        unsigned,
        material,
    };
    let prep = f
        .access
        .prepare_root(
            &browser,
            &c,
            Uuid::new_v4(),
            RootPreparation::Complete(&completion),
        )
        .await
        .unwrap();
    f.access
        .transition_root(&browser, &c, &prep, "confirm")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while clock(&f.owner, 0).await.unwrap() < issued.expires_ms.0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        f.access
            .complete_root(
                &browser,
                &c,
                &prep,
                &completion,
                "synthetic-review-password"
            )
            .await
            .is_err()
    );
    assert_eq!(f.count("sealed_manifest_authorities").await, 0);
    assert_eq!(f.count("sealed_root_receipts").await, 0);
    assert_eq!(f.count("sealed_root_custody").await, 0);
    assert_eq!(
        f.owner
            .query_one("SELECT state FROM public.review_access_root_reauth", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "pending"
    );
    assert!(matches!(
        f.access
            .context(&browser, &c, Uuid::new_v4())
            .await
            .unwrap()
            .root_state,
        crate::http_review_access::dto::RootState::History
    ));
    assert!(
        f.access
            .prepare_root(
                &browser,
                &c,
                Uuid::new_v4(),
                RootPreparation::Issue(&completion.material)
            )
            .await
            .is_err()
    );
    f.cleanup().await;
}
