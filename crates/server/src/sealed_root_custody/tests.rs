// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_root_ceremony::{Completion, IssuedChallenge, tests::Owner};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use zeroize::Zeroizing;
use zrotext_root_material::{
    recovery_kit::encode_public_card,
    root_backup::{RecoverySecret, RootSecret},
};

const ORIGIN: &str = "https://owner.example.test";

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn custody_verifies_shared_public_signature_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/root-custody-01.json"
    ))
    .unwrap();
    let backup: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/root-backup-01.json"
    ))
    .unwrap();
    let card: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/recovery-kit-01.json"
    ))
    .unwrap();
    let unsigned = hex(vector["unsignedHex"].as_str().unwrap());
    let pin = hex(card["rootPinHex"].as_str().unwrap());
    let backup = hex(backup["ciphertextHex"].as_str().unwrap());
    let fingerprint = hex(card["fingerprintHex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let card = hex(card["cardHex"].as_str().unwrap());
    let signature = hex(vector["signatureHex"].as_str().unwrap());
    let account = Uuid::from_bytes([1; 16]);
    assert_eq!(
        statement(&unsigned, &backup, &card, &fingerprint).unwrap(),
        hex(vector["transcriptHex"].as_str().unwrap())
    );
    assert!(
        validate(
            Publication {
                encrypted_backup: &backup,
                public_card: &card,
                independently_compared_fingerprint: fingerprint,
                signature: &signature
            },
            &pin,
            account,
            "https://example.test",
            &unsigned
        )
        .is_ok()
    );
}

pub(crate) fn bundle(root: &SigningKey, pin: &[u8], account: Uuid) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let fingerprint = proof::root_fingerprint(pin, account.as_bytes()).unwrap();
    let expected = root_backup::ExpectedIdentity {
        account_id: *account.as_bytes(),
        origin: ORIGIN.into(),
        root_fingerprint: fingerprint,
    };
    let secret = RootSecret::new(Zeroizing::new(root.to_bytes().into())).unwrap();
    let recovery = RecoverySecret::new(Zeroizing::new(rand::random::<[u8; 32]>()));
    let backup = root_backup::seal(&secret, &recovery, &expected).unwrap();
    let card = encode_public_card(pin, &expected, &Sha256::digest(&backup).into()).unwrap();
    (backup, card, fingerprint)
}

pub(crate) fn sign(root: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    let signature: Signature = root.sign(bytes);
    signature.normalize_s().to_bytes().to_vec()
}

fn signed_publication(
    root: &SigningKey,
    c: &IssuedChallenge,
    backup: &[u8],
    card: &[u8],
    compared: [u8; 32],
) -> (Vec<u8>, [u8; 32]) {
    // Independent construction prevents a helper-domain/digest regression from
    // changing signer and verifier in lockstep.
    let message = [
        b"ZTSE/root-custody/v1\0".as_slice(),
        &(c.unsigned.len() as u32).to_be_bytes(),
        &c.unsigned,
        &Sha256::digest(backup),
        &Sha256::digest(card),
        &compared,
    ]
    .concat();
    (sign(root, &message), compared)
}

fn challenge(root: &SigningKey, account: Uuid) -> (IssuedChallenge, [u8; 94]) {
    let pin: [u8; 94] = [
        b"ZTRP\x02".as_slice(),
        account.as_bytes(),
        &1u64.to_be_bytes(),
        root.verifying_key().to_sec1_point(false).as_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap();
    let c = proof::Challenge {
        account_id: *account.as_bytes(),
        user_id: *Uuid::new_v4().as_bytes(),
        session_id: *Uuid::new_v4().as_bytes(),
        challenge_id: *Uuid::new_v4().as_bytes(),
        nonce: rand::random(),
        root_fingerprint: proof::root_fingerprint(&pin, account.as_bytes()).unwrap(),
        issued_ms: 1,
        expires_ms: 100,
        origin: ORIGIN.into(),
    };
    let unsigned = proof::encode(&c).unwrap();
    (
        IssuedChallenge {
            challenge: c,
            unsigned,
            root_pin: pin,
        },
        pin,
    )
}

#[test]
fn custody_signature_binds_exact_bundle_comparison_and_enrollment() {
    let root = SigningKey::generate_from_rng(&mut rand::rng());
    let account = Uuid::new_v4();
    let (c, pin) = challenge(&root, account);
    let (backup, card, compared) = bundle(&root, &pin, account);
    let (signature, _) = signed_publication(&root, &c, &backup, &card, compared);
    let publication = || Publication {
        encrypted_backup: &backup,
        public_card: &card,
        independently_compared_fingerprint: compared,
        signature: &signature,
    };
    assert!(validate(publication(), &pin, account, ORIGIN, &c.unsigned).is_ok());
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/root-enrollment-01.json"
    ))
    .unwrap();
    let high = vectors["highSignatureHex"]
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    let mut high_publication = publication();
    high_publication.signature = &high;
    assert!(matches!(
        validate(high_publication, &pin, account, ORIGIN, &c.unsigned),
        Err(CeremonyError::Rejected("custody signature canonicality"))
    ));
    let mut wrong = publication();
    wrong.independently_compared_fingerprint[0] ^= 1;
    assert!(validate(wrong, &pin, account, ORIGIN, &c.unsigned).is_err());
    assert!(validate(publication(), &pin, Uuid::new_v4(), ORIGIN, &c.unsigned).is_err());
    assert!(
        validate(
            publication(),
            &pin,
            account,
            "https://foreign.test",
            &c.unsigned
        )
        .is_err()
    );
    let mut changed = c.unsigned.clone();
    changed[69] ^= 1;
    assert!(validate(publication(), &pin, account, ORIGIN, &changed).is_err());
    let mut corrupt = backup.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let expected = root_backup::ExpectedIdentity {
        account_id: *account.as_bytes(),
        origin: ORIGIN.into(),
        root_fingerprint: compared,
    };
    let changed_card =
        encode_public_card(&pin, &expected, &Sha256::digest(&corrupt).into()).unwrap();
    assert!(
        validate(
            Publication {
                encrypted_backup: &corrupt,
                public_card: &changed_card,
                independently_compared_fingerprint: compared,
                signature: &signature
            },
            &pin,
            account,
            ORIGIN,
            &c.unsigned
        )
        .is_err()
    );
    assert!(statement(&c.unsigned, &vec![0; MAX_BACKUP + 1], &card, &compared).is_err());
    assert!(statement(&c.unsigned, &backup, &vec![0; MAX_CARD + 1], &compared).is_err());
    assert!(
        !backup
            .windows(b"synthetic_plaintext_canary".len())
            .any(|v| v == b"synthetic_plaintext_canary")
    );
}

async fn owner() -> Owner {
    let owner = Owner::new().await;
    owner
        .f
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/069_sealed_root_custody.sql"
        ))
        .await
        .unwrap();
    owner
}

async fn complete(
    o: &Owner,
    c: &IssuedChallenge,
    backup: &[u8],
    card: &[u8],
    compared: [u8; 32],
    signature: &[u8],
) -> Result<ceremony::Receipt, CeremonyError> {
    ceremony::complete_with_custody(
        &mut o.f.connect().await,
        &o.hasher,
        &o.cipher,
        &o.principal,
        ORIGIN,
        Completion {
            unsigned: &c.unsigned,
            signature: &o.sign(c),
            factor: &o.recovery,
        },
        Publication {
            encrypted_backup: backup,
            public_card: card,
            independently_compared_fingerprint: compared,
            signature,
        },
    )
    .await
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable PostgreSQL custody tests"]
async fn custody_commits_enrollment_and_exports_exact_ciphertext_after_reconnect() {
    let o = owner().await;
    let c = o.challenge().await;
    let (backup, card, compared) = bundle(&o.root, &o.pin, o.principal.tenant.account_id());
    let (signature, _) = signed_publication(&o.root, &c, &backup, &card, compared);
    let receipt = complete(&o, &c, &backup, &card, compared, &signature)
        .await
        .unwrap();
    let result = export(&mut o.f.connect().await, &o.principal, ORIGIN, &compared)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.encrypted_backup, backup);
    assert_eq!(result.public_card, card);
    let root_secret = o.root.to_bytes();
    assert!(
        !result
            .encrypted_backup
            .windows(32)
            .any(|part| part == root_secret.as_slice())
    );
    assert!(
        !result
            .public_card
            .windows(32)
            .any(|part| part == root_secret.as_slice())
    );
    assert_eq!(result.root_pin, receipt.root_pin);
    assert_eq!(result.generation, 1);
    assert!(
        complete(&o, &c, &backup, &card, compared, &signature)
            .await
            .is_err()
    );
    let mut wrong = compared;
    wrong[0] ^= 1;
    assert!(
        export(&mut o.f.connect().await, &o.principal, ORIGIN, &wrong)
            .await
            .is_err()
    );
    assert!(
        o.f.db
            .execute(
                "UPDATE sealed_root_custody SET encrypted_backup=$2 WHERE account_id=$1",
                &[&o.principal.tenant.account_id(), &vec![0u8; backup.len()]]
            )
            .await
            .is_err()
    );
    assert!(
        o.f.db
            .execute(
                "DELETE FROM sealed_root_custody WHERE account_id=$1",
                &[&o.principal.tenant.account_id()]
            )
            .await
            .is_err()
    );
    assert!(
        o.f.db
            .batch_execute("TRUNCATE sealed_root_custody")
            .await
            .is_err()
    );
    // Account erasure is the sole deletion authority and removes custody.
    o.f.db
        .execute(
            "DELETE FROM accounts WHERE id=$1",
            &[&o.principal.tenant.account_id()],
        )
        .await
        .unwrap();
    assert_eq!(
        o.f.db
            .query_one("SELECT count(*) FROM sealed_root_custody", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    o.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable PostgreSQL custody tests"]
async fn partial_custody_failure_rolls_back_authority_challenge_and_factor() {
    let o = owner().await;
    let c = o.challenge().await;
    let (backup, card, compared) = bundle(&o.root, &o.pin, o.principal.tenant.account_id());
    let (signature, _) = signed_publication(&o.root, &c, &backup, &card, compared);
    o.f.db.batch_execute("CREATE FUNCTION refuse_custody_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END; $$; \
        CREATE TRIGGER refuse_custody BEFORE INSERT ON sealed_root_custody FOR EACH ROW EXECUTE FUNCTION refuse_custody_fixture()").await.unwrap();
    assert!(
        complete(&o, &c, &backup, &card, compared, &signature)
            .await
            .is_err()
    );
    o.empty_authority().await;
    let consumed: bool =
        o.f.db
            .query_one(
                "SELECT consumed_ms IS NOT NULL FROM sealed_root_challenges WHERE account_id=$1",
                &[&o.principal.tenant.account_id()],
            )
            .await
            .unwrap()
            .get(0);
    assert!(!consumed);
    o.f.db
        .batch_execute("DROP TRIGGER refuse_custody ON sealed_root_custody")
        .await
        .unwrap();
    assert!(
        complete(&o, &c, &backup, &card, compared, &signature)
            .await
            .is_ok()
    );
    o.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable PostgreSQL custody tests"]
async fn concurrent_publication_has_one_winner_and_revoked_session_cannot_read() {
    let o = owner().await;
    let c = o.challenge().await;
    let (backup, card, compared) = bundle(&o.root, &o.pin, o.principal.tenant.account_id());
    let (signature, _) = signed_publication(&o.root, &c, &backup, &card, compared);
    let (first, second) = tokio::join!(
        complete(&o, &c, &backup, &card, compared, &signature),
        complete(&o, &c, &backup, &card, compared, &signature)
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let rows: i64 =
        o.f.db
            .query_one(
                "SELECT count(*) FROM sealed_root_custody WHERE account_id=$1",
                &[&o.principal.tenant.account_id()],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(rows, 1);
    o.f.db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&o.principal.session_id],
        )
        .await
        .unwrap();
    assert!(
        export(&mut o.f.connect().await, &o.principal, ORIGIN, &compared)
            .await
            .is_err()
    );
    o.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable PostgreSQL custody tests"]
async fn missing_comparison_foreign_bundle_and_removed_membership_never_publish() {
    let o = owner().await;
    let c = o.challenge().await;
    let (backup, card, compared) = bundle(&o.root, &o.pin, o.principal.tenant.account_id());
    let (signature, _) = signed_publication(&o.root, &c, &backup, &card, compared);
    let mut wrong = compared;
    wrong[0] ^= 1;
    assert!(
        complete(&o, &c, &backup, &card, wrong, &signature)
            .await
            .is_err()
    );
    o.empty_authority().await;
    let foreign = SigningKey::generate_from_rng(&mut rand::rng());
    let foreign_account = Uuid::new_v4();
    let (_, pin) = challenge(&foreign, foreign_account);
    let (foreign_backup, foreign_card, _) = bundle(&foreign, &pin, foreign_account);
    assert!(
        complete(&o, &c, &foreign_backup, &foreign_card, compared, &signature)
            .await
            .is_err()
    );
    o.empty_authority().await;
    o.f.db
        .execute(
            "DELETE FROM memberships WHERE account_id=$1 AND user_id=$2",
            &[&o.principal.tenant.account_id(), &o.principal.user_id],
        )
        .await
        .unwrap();
    assert!(matches!(
        complete(&o, &c, &backup, &card, compared, &signature).await,
        Err(CeremonyError::Rejected("owner membership"))
    ));
    // Removing the membership cascades its factor rows. Check the absence of
    // all publication/authority writes directly rather than asking the shared
    // fixture to inspect a factor which no longer exists.
    for table in [
        "sealed_root_custody",
        "sealed_manifest_authorities",
        "sealed_root_enrollments",
        "sealed_root_receipts",
        "known_signing_role_claims",
        "known_signing_point_reservations",
    ] {
        let count: i64 =
            o.f.db
                .query_one(
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    &[&o.principal.tenant.account_id()],
                )
                .await
                .unwrap()
                .get(0);
        assert_eq!(count, 0, "{table}");
    }
    o.f.cleanup().await;
}
