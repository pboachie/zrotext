// SPDX-License-Identifier: AGPL-3.0-only
use super::{model::*, *};
use serde_json::json;
use uuid::Uuid;

fn create() -> Create {
    Create {
        create_request: Id(Uuid::from_bytes([1; 16])),
        expected_revision: Number(0),
        prior: Prior::Empty {},
        selected_reader_id: Fixed([2; 32]),
        compared_root_fingerprint: Fixed([3; 32]),
        requested_until_ms: Number(700),
    }
}

#[test]
fn canonical_create_commitment_matches_the_exact_internal_transcript() {
    let c = create();
    let account = Uuid::from_bytes([4; 16]);
    let origin = "https://example.test";
    let mut b = vec![1];
    b.extend(account.as_bytes());
    b.extend((origin.len() as u16).to_be_bytes());
    b.extend(origin.as_bytes());
    b.extend(c.create_request.0.as_bytes());
    b.extend(0_i64.to_be_bytes());
    b.push(0);
    b.extend([0; 16]);
    b.extend(0_i64.to_be_bytes());
    b.extend([0; 32]);
    b.extend([2; 32]);
    b.extend([3; 32]);
    b.extend(700_i64.to_be_bytes());
    assert_eq!(b.len(), 172 + origin.len());
    use sha2::{Digest, Sha256};
    assert!(
        c.commitment(account, origin)
            .is_ok_and(|n| n == <[u8; 32]>::from(Sha256::digest(b)))
    );
}

#[test]
fn every_original_create_identity_and_context_field_is_committed() {
    let c = create();
    let account = Uuid::from_bytes([4; 16]);
    let original = c.commitment(account, "https://example.test").unwrap();
    for c in [
        Create {
            create_request: Id(Uuid::from_bytes([5; 16])),
            ..c.clone()
        },
        Create {
            expected_revision: Number(1),
            ..c.clone()
        },
        Create {
            selected_reader_id: Fixed([6; 32]),
            ..c.clone()
        },
        Create {
            compared_root_fingerprint: Fixed([7; 32]),
            ..c.clone()
        },
        Create {
            requested_until_ms: Number(701),
            ..c.clone()
        },
        Create {
            prior: Prior::Active {
                authorization: Id(Uuid::from_bytes([8; 16])),
                generation: Number(1),
                digest: Fixed([9; 32]),
            },
            ..c.clone()
        },
    ] {
        assert!(c.commitment(account, "https://example.test").unwrap() != original);
    }
    assert!(
        c.commitment(Uuid::from_bytes([10; 16]), "https://example.test")
            .unwrap()
            != original
    );
    assert!(c.commitment(account, "https://other.example.test").unwrap() != original);
}

#[test]
fn raw_create_refuses_duplicates_aliases_nested_extras_and_null_unused_fields() {
    let good = serde_json::to_string(&create()).unwrap();
    assert!(parse::<Create>(good.as_bytes()).is_ok());
    for raw in [
        good.replacen(
            '{',
            "{\"create_request\":\"00000000-0000-0000-0000-000000000001\",",
            1,
        ),
        good.replace(
            "\"phase\":\"empty\"",
            "\"phase\":\"empty\",\"authorization\":null",
        ),
        good.replace(
            "\"phase\":\"empty\"",
            "\"phase\":\"empty\",\"generation\":\"1\"",
        ),
        good.replace(
            "\"phase\":\"empty\"",
            "\"phase\":\"empty\",\"phase\":\"empty\"",
        ),
        good.replacen('{', "{\"unknown\":true,", 1),
        format!("{good} {{}}"),
        good.replace("\"expected_revision\":\"0\"", "\"expected_revision\":null"),
    ] {
        assert!(parse::<Create>(raw.as_bytes()).is_err());
    }
    // Legible raw alias control stays in source, not an encoded fixture escape.
    let alias = good.replacen("\"create_request\"", r#""\u0063reate_request""#, 1);
    let duplicate = alias.replacen(
        '{',
        "{\"create_request\":\"00000000-0000-0000-0000-000000000001\",",
        1,
    );
    assert!(parse::<Create>(duplicate.as_bytes()).is_err());
}

#[test]
fn integer_uuid_and_byte_values_refuse_noncanonical_shapes() {
    for value in [
        json!(0),
        json!(-1),
        json!("-0"),
        json!("00"),
        json!("+1"),
        json!("1e1"),
        json!("1.0"),
        json!("9223372036854775808"),
    ] {
        assert!(serde_json::from_value::<Number>(value).is_err());
    }
    for value in [
        "00000000-0000-0000-0000-000000000000",
        "00000000000000000000000000000001",
        "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
    ] {
        assert!(serde_json::from_value::<Id>(json!(value)).is_err());
    }
    use base64::{Engine, engine::general_purpose::STANDARD};
    for value in [
        STANDARD.encode([0; 32]),
        STANDARD.encode([1; 31]),
        STANDARD.encode([1; 33]),
        STANDARD.encode([1; 32]).trim_end_matches('=').to_owned(),
    ] {
        assert!(serde_json::from_value::<Fixed<32>>(json!(value)).is_err());
    }
}

#[test]
fn status_query_has_one_positive_canonical_generation_only() {
    assert_eq!(status_query(Some("generation=1")).unwrap(), 1);
    assert_eq!(
        status_query(Some("generation=9223372036854775807")).unwrap(),
        i64::MAX
    );
    for q in [
        None,
        Some(""),
        Some("generation=0"),
        Some("generation=01"),
        Some("generation=%31"),
        Some("generation=1&generation=1"),
        Some("generation=1&other=2"),
    ] {
        assert!(status_query(q).is_err());
    }
}

#[test]
fn raw_body_caps_utf8_and_trailing_values_before_typed_ingress() {
    assert!(parse::<Create>(&[]).is_err());
    assert!(parse::<Create>(&[0xff]).is_err());
    assert!(parse::<Create>(&vec![b' '; MAX_BODY + 1]).is_err());
    let c = create();
    let text = serde_json::to_string_pretty(&c).unwrap();
    let parsed: Create = parse(text.as_bytes()).unwrap();
    assert!(parsed == c);
}

#[test]
fn serialized_unavailable_cannot_contain_an_effect_or_authority_field() {
    assert_eq!(
        encode(&ResultView::unavailable()).unwrap(),
        br#"{"kind":"unavailable"}"#
    );
    assert!(encode(&"x".repeat(MAX_RESPONSE)).is_err());
}

// Genuine registration/password-backed verification/login and public MFA
// enrollment. Root/manifest and issuer admission below are SYNTHETIC extant
// fixture assumptions, not a production genesis or no-reuse restore ceremony.
pub(crate) struct Owner {
    pub schema: crate::sealed_manifest_store::tests::Fixture,
    pub principal: crate::auth::SessionPrincipal,
    pub hasher: std::sync::Arc<crate::auth::TokenHasher>,
    pub cipher: std::sync::Arc<crate::auth::mfa::MfaCipher>,
    pub credentials: crate::auth::SessionCredentials,
    pub reader: [u8; 32],
    pub fingerprint: [u8; 32],
    pub pin: Vec<u8>,
    pub recovery: Vec<String>,
    // Only the genuinely enrolled synthetic test secret, never production input.
    totp_secret: zeroize::Zeroizing<String>,
}
pub(crate) const ORIGIN: &str = "https://owner.example.test";
impl Owner {
    pub(crate) async fn new(install: bool, seed: bool) -> Self {
        use crate::auth::{self, mfa};
        use p256::ecdsa::{Signature, signature::Signer};
        use sha2::{Digest, Sha256};
        let schema = crate::sealed_manifest_store::tests::Fixture::without_authority().await;
        assert_eq!(
            schema
                .db
                .query_one("SELECT current_schema()", &[])
                .await
                .unwrap()
                .get::<_, String>(0),
            schema.schema
        );
        // The maintained observer invitation fixture dependency is explicit.
        schema
            .db
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/053_observer_seat_invitations.sql"
            ))
            .await
            .unwrap();
        // Normal MFA enrollment updates the trusted-browser epoch. This
        // bounded fixture must install that dependency before enrolling.
        schema
            .db
            .batch_execute(include_str!(
                "../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"
            ))
            .await
            .unwrap();
        assert!(
            schema
                .db
                .query_one("SELECT to_regclass('seat_invitations') IS NOT NULL", &[])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        let hasher =
            std::sync::Arc::new(auth::TokenHasher::new(crate::test_keys::key(96)).unwrap());
        let cipher = std::sync::Arc::new(mfa::MfaCipher::new(crate::test_keys::key(97)).unwrap());
        let email = format!("contact-issuer-{}@example.test", Uuid::new_v4());
        let password = "synthetic issuer password";
        let mut db = schema.connect().await;
        let signup = auth::register(&mut db, &hasher, &email, password)
            .await
            .unwrap();
        assert!(
            auth::verify_email_with_password(
                &mut db,
                &hasher,
                &signup.verification_token,
                password
            )
            .await
            .unwrap()
        );
        let credentials = auth::login(&db, &hasher, &email, password).await.unwrap();
        let principal = auth::authenticate_session(&db, &hasher, &credentials.token)
            .await
            .unwrap();
        let enrollment = mfa::begin_enrollment(&mut db, &cipher, &principal, password)
            .await
            .unwrap();
        let code = totp_rs::Builder::new()
            .with_secret(totp_rs::Secret::try_from_base32(&enrollment.secret_base32).unwrap())
            .build()
            .unwrap()
            .generate_current()
            .to_string();
        let recovery = mfa::confirm_enrollment(&mut db, &cipher, &hasher, &principal, &code)
            .await
            .unwrap()
            .codes;
        let now: i64 = db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let account = principal.tenant.account_id();
        let mut pin = schema.pin.clone();
        pin[5..21].copy_from_slice(account.as_bytes());
        let mut manifest = schema.bytes[..151].to_vec();
        manifest[5..21].copy_from_slice(account.as_bytes());
        manifest[37..45].copy_from_slice(&(now as u64 - 1000).to_be_bytes());
        manifest[45..53].copy_from_slice(&(now as u64 + 3_600_000).to_be_bytes());
        manifest[150] = 2;
        for record in schema.bytes[151..schema.bytes.len() - 64]
            .chunks_exact(149)
            .filter(|r| r[0] == 2 || r[0] == 6)
        {
            let mut r = record.to_vec();
            r[132..140].copy_from_slice(&(now as u64 - 1000).to_be_bytes());
            r[140..148].copy_from_slice(&(now as u64 + 3_600_000).to_be_bytes());
            manifest.extend(r);
        }
        let digest = Sha256::digest(&manifest).to_vec();
        let signature: Signature = schema.root.sign(
            &[
                b"ZTSE/manifest/v2\0".as_slice(),
                &(manifest.len() as u32).to_be_bytes(),
                &manifest,
            ]
            .concat(),
        );
        manifest.extend(signature.normalize_s().to_bytes());
        let fingerprint =
            crate::sealed_root_enrollment::root_fingerprint(&pin, account.as_bytes()).unwrap();
        db.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest,version,semantic_digest,manifest,accepted_at_ms,last_verified_ms) VALUES($1,$2,$3,1,$4,1,$5,$6,$7,$7)",&[&account,&pin,&&fingerprint[..],&vec![0_u8;32],&digest,&manifest,&now]).await.unwrap();
        if install {
            db.batch_execute(include_str!(
                "../../../../protocol/v1/contact-reader-issuance-storage-proposal.sql"
            ))
            .await
            .unwrap();
            if seed {
                db.execute("INSERT INTO contact_reader_state(account_id,root_pin,root_fingerprint,trust_generation,allocation_generation,mutation_revision,last_mutation_ms,receipt_next_slot,phase) VALUES($1,$2,$3,1,0,0,$4,0,'EMPTY')",&[&account,&pin,&&fingerprint[..],&now]).await.unwrap();
            }
        }
        let reader = schema.readers[0].key_id;
        Self {
            schema,
            principal,
            hasher,
            cipher,
            credentials,
            reader,
            fingerprint,
            pin,
            recovery,
            totp_secret: zeroize::Zeroizing::new(enrollment.secret_base32.clone()),
        }
    }
    pub(crate) fn url(&self) -> String {
        let separator = if self.schema.url.contains('?') {
            '&'
        } else {
            '?'
        };
        format!(
            "{}{separator}options=-csearch_path%3D{}",
            self.schema.url, self.schema.schema
        )
    }
    pub(crate) async fn input(&self) -> Create {
        let mut db = self.schema.connect().await;
        let tx = db.transaction().await.unwrap();
        let a = store::load(&tx, self.principal.tenant.account_id(), false)
            .await
            .unwrap()
            .unwrap();
        let now = store::clock(&tx, a.state.last_ms).await.unwrap();
        tx.commit().await.unwrap();
        Create {
            create_request: Id(Uuid::new_v4()),
            expected_revision: Number(a.state.revision),
            prior: a.state.prior,
            selected_reader_id: Fixed(self.reader),
            compared_root_fingerprint: Fixed(self.fingerprint),
            requested_until_ms: Number(now + 120_000),
        }
    }
    pub(crate) async fn pending(&self, c: Create) -> PendingView {
        let value = lifecycle::create(
            &mut self.schema.connect().await,
            &self.hasher,
            &self.principal,
            ORIGIN,
            c,
        )
        .await
        .unwrap();
        match value {
            ResultView::Pending(p) => *p,
            _ => panic!("expected a newly allocated pending intent"),
        }
    }
    pub(crate) fn signed(&self, p: &PendingView) -> Vec<u8> {
        use p256::ecdsa::{Signature, signature::Signer};
        let unsigned = &p.unsigned.0;
        let signature: Signature = self.schema.root.sign(
            &[
                b"ZT/contact-reader/authorization/v1\0".as_slice(),
                &(unsigned.len() as u32).to_be_bytes(),
                unsigned,
            ]
            .concat(),
        );
        let mut bytes = unsigned.clone();
        bytes.extend(signature.normalize_s().to_bytes());
        bytes
    }
    fn completion(&self, p: &PendingView, index: usize) -> Complete {
        Complete {
            generation: p.generation,
            create_request: p.create_request,
            creation_expected_revision: p.creation_expected_revision,
            unsigned_digest: p.unsigned_digest,
            signed_statement: Packed(self.signed(p)),
            code: Code(zeroize::Zeroizing::new(self.recovery[index].clone())),
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine owner/MFA, synthetic extant issuer admission"]
async fn complete_installs_once_exact_replay_is_historical_and_changed_whole_bytes_conflict() {
    let f = Owner::new(true, true).await;
    let c = f.input().await;
    let p = f.pending(c.clone()).await;
    let duplicate = lifecycle::create(
        &mut f.schema.connect().await,
        &f.hasher,
        &f.principal,
        ORIGIN,
        c.clone(),
    )
    .await
    .unwrap();
    assert!(
        matches!(duplicate,ResultView::Pending(ref q) if q.authorization==p.authorization && q.unsigned.0==p.unsigned.0)
    );
    let result = lifecycle::complete(
        &mut f.schema.connect().await,
        &f.hasher,
        &f.cipher,
        &f.principal,
        ORIGIN,
        p.authorization.0,
        f.completion(&p, 0),
    )
    .await
    .unwrap();
    assert!(matches!(result,ResultView::Receipt(ref r) if r.kind=="historical_completed"));
    let account = f.principal.tenant.account_id();
    let row=f.schema.db.query_one("SELECT allocation_generation,mutation_revision,phase,current_statement FROM contact_reader_state WHERE account_id=$1",&[&account]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, String>(2)
        ),
        (1, 2, "ACTIVE".into())
    );
    assert_eq!(row.get::<_, Vec<u8>>(3), f.signed(&p));
    // Lose current root and MFA: exact completed replay remains public history.
    f.schema.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",&[&account]).await.unwrap();
    f.schema
        .db
        .execute(
            "UPDATE users SET mfa_enabled=false WHERE id=$1",
            &[&f.principal.user_id],
        )
        .await
        .unwrap();
    assert!(matches!(
        lifecycle::complete(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            f.completion(&p, 0)
        )
        .await
        .unwrap(),
        ResultView::Receipt(_)
    ));
    let mut changed = f.completion(&p, 0);
    let last = changed.signed_statement.0.len() - 1;
    changed.signed_statement.0[last] ^= 1;
    assert!(matches!(
        lifecycle::complete(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            changed
        )
        .await,
        Err(Error::Conflict)
    ));
    let mut original = c;
    original.requested_until_ms.0 += 1;
    assert!(matches!(
        lifecycle::lookup(
            &mut f.schema.connect().await,
            &f.principal,
            ORIGIN,
            Lookup {
                expected_input_digest: Fixed(original.commitment(account, ORIGIN).unwrap()),
                create: original
            }
        )
        .await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT count(*) FROM contact_reader_pending WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine factor failure budget and rollback"]
async fn invalid_factor_commits_only_maintained_budget_and_staged_owner_loss_rolls_back() {
    let f = Owner::new(true, true).await;
    let p = f.pending(f.input().await).await;
    let account = f.principal.tenant.account_id();
    let before:i64=f.schema.db.query_one("SELECT COALESCE(sum(attempts),0)::bigint FROM auth_abuse_counters WHERE scope LIKE 'mfa_step_up%'",&[]).await.unwrap().get(0);
    let mut invalid = f.completion(&p, 0);
    invalid.code = Code(zeroize::Zeroizing::new(format!("zrc_{}", "A".repeat(22))));
    assert!(matches!(
        lifecycle::complete(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            invalid
        )
        .await,
        Err(Error::Authentication(
            crate::auth::AuthError::InvalidCredentials
        ))
    ));
    let after:i64=f.schema.db.query_one("SELECT COALESCE(sum(attempts),0)::bigint FROM auth_abuse_counters WHERE scope LIKE 'mfa_step_up%'",&[]).await.unwrap().get(0);
    assert_eq!(after, before + 1);
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT mutation_revision FROM contact_reader_state WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT count(*) FROM contact_reader_pending WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.schema.db.batch_execute("CREATE FUNCTION contact_test_owner_loss() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE users SET mfa_enabled=false WHERE id IN (SELECT user_id FROM memberships WHERE account_id=NEW.account_id AND role='owner'); RETURN NEW; END $$; CREATE TRIGGER contact_test_owner_loss AFTER INSERT ON contact_reader_receipts FOR EACH ROW EXECUTE FUNCTION contact_test_owner_loss()").await.unwrap();
    assert!(
        lifecycle::complete(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            f.completion(&p, 0)
        )
        .await
        .is_err()
    );
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT mutation_revision FROM contact_reader_state WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT count(*) FROM contact_reader_receipts WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(
        f.schema
            .db
            .query_one(
                "SELECT mfa_enabled FROM users WHERE id=$1",
                &[&f.principal.user_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.schema.db.batch_execute("DROP TRIGGER contact_test_owner_loss ON contact_reader_receipts; DROP FUNCTION contact_test_owner_loss()").await.unwrap();
    assert!(
        lifecycle::complete(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            f.completion(&p, 0)
        )
        .await
        .is_ok()
    );
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; bounded pending/ring with genuine owner"]
async fn four_pending_refuse_fifth_without_counter_burn() {
    let f = Owner::new(true, true).await;
    let account = f.principal.tenant.account_id();
    let mut pending = Vec::new();
    for _ in 0..4 {
        pending.push(f.pending(f.input().await).await);
    }
    let fifth = f.input().await;
    assert!(matches!(
        lifecycle::create(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.principal,
            ORIGIN,
            fifth
        )
        .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT allocation_generation FROM contact_reader_state WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        4
    );
    for p in pending {
        lifecycle::cancel(
            &mut f.schema.connect().await,
            &f.principal,
            p.authorization.0,
            Cancel {
                generation: p.generation,
                create_request: p.create_request,
                unsigned_digest: p.unsigned_digest,
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT count(*) FROM contact_reader_receipts WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        4
    );
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual proposal catalog and synthetic extant state"]
async fn absent_partial_or_changed_schema_fails_closed() {
    let f = Owner::new(false, false).await;
    assert_eq!(
        export::state_only(&mut f.schema.connect().await, &f.principal)
            .await
            .unwrap(),
        br#"{"kind":"contact_reader_state","state":null}"#
    );
    let mut db = f.schema.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(!lifecycle::installed(&tx).await.unwrap());
    assert!(
        export::prepare_erase(&tx, f.principal.tenant.account_id())
            .await
            .unwrap()
            .erase()
            .await
            .unwrap()
            .is_empty()
    );
    tx.rollback().await.unwrap();
    f.schema
        .db
        .batch_execute(include_str!(
            "../../../../protocol/v1/contact-reader-issuance-storage-proposal.sql"
        ))
        .await
        .unwrap();
    assert_eq!(
        export::state_only(&mut f.schema.connect().await, &f.principal)
            .await
            .unwrap(),
        br#"{"kind":"contact_reader_state","state":null}"#
    );
    let tx = db.transaction().await.unwrap();
    tx.batch_execute(
        "ALTER TABLE contact_reader_pending DROP CONSTRAINT contact_reader_pending_bounds",
    )
    .await
    .unwrap();
    assert!(lifecycle::installed(&tx).await.is_err());
    tx.rollback().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.batch_execute("ALTER TABLE contact_reader_receipts ADD COLUMN unexpected text")
        .await
        .unwrap();
    assert!(lifecycle::installed(&tx).await.is_err());
    tx.rollback().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.batch_execute(
        "ALTER TABLE contact_reader_pending DISABLE TRIGGER contact_reader_pending_immutable",
    )
    .await
    .unwrap();
    assert!(lifecycle::installed(&tx).await.is_err());
    tx.rollback().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.batch_execute("CREATE OR REPLACE FUNCTION contact_reader_state_bounds_valid(account_id uuid,root_pin bytea,root_fingerprint bytea,trust_generation bigint,allocation_generation bigint,mutation_revision bigint,last_mutation_ms bigint,receipt_next_slot smallint,phase text,current_authorization uuid,current_generation bigint,current_statement_digest bytea,current_statement bytea) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $$ SELECT true $$").await.unwrap();
    assert!(lifecycle::installed(&tx).await.is_err());
    tx.rollback().await.unwrap();
    // A same-name UPDATE OF trigger omits ordinary mutations even when its
    // function is genuine. Both immutable transition triggers must cover all.
    for sql in [
        "DROP TRIGGER contact_reader_state_transition ON contact_reader_state; CREATE TRIGGER contact_reader_state_transition BEFORE UPDATE OF root_pin ON contact_reader_state FOR EACH ROW EXECUTE FUNCTION contact_reader_state_guard()",
        "DROP TRIGGER contact_reader_pending_immutable ON contact_reader_pending; CREATE TRIGGER contact_reader_pending_immutable BEFORE UPDATE OF origin ON contact_reader_pending FOR EACH ROW EXECUTE FUNCTION contact_reader_pending_guard()",
    ] {
        let tx = db.transaction().await.unwrap();
        tx.batch_execute(sql).await.unwrap();
        assert!(matches!(
            lifecycle::installed(&tx).await,
            Err(Error::Unavailable)
        ));
        tx.rollback().await.unwrap();
    }
    // Even a byte-identical same-name function in another namespace is not the
    // already validated function OID. Create/drop only an owned unique schema.
    let alternate = format!("contact_guard_{}", Uuid::new_v4().simple());
    let tx = db.transaction().await.unwrap();
    let body = include_str!("../../../../protocol/v1/contact-reader-issuance-storage-proposal.sql")
        .split("$state_guard$")
        .nth(1)
        .unwrap();
    tx.batch_execute(&format!("CREATE SCHEMA {alternate}; CREATE FUNCTION {alternate}.contact_reader_state_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $state_guard${body}$state_guard$; DROP TRIGGER contact_reader_state_transition ON contact_reader_state; CREATE TRIGGER contact_reader_state_transition BEFORE UPDATE ON contact_reader_state FOR EACH ROW EXECUTE FUNCTION {alternate}.contact_reader_state_guard()"))
        .await.unwrap();
    assert!(matches!(
        lifecycle::installed(&tx).await,
        Err(Error::Unavailable)
    ));
    tx.rollback().await.unwrap();
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; synthetic extant full-ring aggregate, genuine reduction"]
async fn full_receipt_ring_rotates_one_slot_without_unbounded_identity_growth() {
    use sha2::{Digest, Sha256};
    let f = Owner::new(true, false).await;
    let account = f.principal.tenant.account_id();
    let now: i64 = f
        .schema
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    // This is explicit preexisting admission/history fixture data. No production
    // seed method, budget reset or counter transition is being certified.
    let mut db = f.schema.connect().await;
    let tx = db.transaction().await.unwrap();
    tx.execute("INSERT INTO contact_reader_state(account_id,root_pin,root_fingerprint,trust_generation,allocation_generation,mutation_revision,last_mutation_ms,receipt_next_slot,phase) VALUES($1,$2,$3,1,32,64,$4,0,'EMPTY')",&[&account,&f.pin,&&f.fingerprint[..],&now]).await.unwrap();
    let mut first = None;
    for slot in 0_i16..32 {
        let authorization = Uuid::new_v4();
        let request = Uuid::new_v4();
        let generation = i64::from(slot) + 1;
        let expected = 2 * i64::from(slot);
        let c = Create {
            create_request: Id(request),
            expected_revision: Number(expected),
            prior: Prior::Empty {},
            selected_reader_id: Fixed(f.reader),
            compared_root_fingerprint: Fixed(f.fingerprint),
            requested_until_ms: Number(now + 120_000),
        };
        let commitment = c.commitment(account, ORIGIN).unwrap();
        let unsigned_digest: [u8; 32] = Sha256::digest(authorization.as_bytes()).into();
        tx.execute("INSERT INTO contact_reader_receipts(account_id,slot,\"authorization\",generation,create_request,create_input_digest,creation_expected_revision,unsigned_digest,terminal_kind,terminal_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'CANCELLED',$9)",&[&account,&slot,&authorization,&generation,&request,&&commitment[..],&expected,&&unsigned_digest[..],&now]).await.unwrap();
        if slot == 0 {
            first = Some((authorization, generation));
        }
    }
    tx.commit().await.unwrap();
    let p = f.pending(f.input().await).await;
    lifecycle::cancel(
        &mut f.schema.connect().await,
        &f.principal,
        p.authorization.0,
        Cancel {
            generation: p.generation,
            create_request: p.create_request,
            unsigned_digest: p.unsigned_digest,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT count(*) FROM contact_reader_receipts WHERE account_id=$1",
                &[&account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        32
    );
    let (first_id, first_generation) = first.unwrap();
    assert!(matches!(
        lifecycle::status(
            &mut f.schema.connect().await,
            &f.principal,
            first_id,
            first_generation
        )
        .await
        .unwrap(),
        ResultView::Unavailable { .. }
    ));
    let row=f.schema.db.query_one("SELECT allocation_generation,mutation_revision,receipt_next_slot FROM contact_reader_state WHERE account_id=$1",&[&account]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i16>(2)
        ),
        (33, 66, 1)
    );
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; synthetic MAX fixture, actual no-factor withdrawal"]
async fn maximum_revision_withdrawal_scrubs_whole_bytes_and_never_revives_identity() {
    let f = Owner::new(true, true).await;
    let p = f.pending(f.input().await).await;
    lifecycle::complete(
        &mut f.schema.connect().await,
        &f.hasher,
        &f.cipher,
        &f.principal,
        ORIGIN,
        p.authorization.0,
        f.completion(&p, 0),
    )
    .await
    .unwrap();
    let account = f.principal.tenant.account_id();
    let signed = f.signed(&p);
    let digest = store::hash(&signed);
    // Constraint-valid copied bytes still need signature/semantic validation.
    // Replace only inside an owned rollback transaction; no guard is disabled.
    let mut tampered = signed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let tampered_digest = store::hash(&tampered);
    let mut check = f.schema.connect().await;
    let tx = check.transaction().await.unwrap();
    let now = store::clock(&tx, 0).await.unwrap();
    tx.execute(
        "DELETE FROM contact_reader_state WHERE account_id=$1",
        &[&account],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO contact_reader_state(account_id,root_pin,root_fingerprint,trust_generation,allocation_generation,mutation_revision,last_mutation_ms,receipt_next_slot,phase,current_authorization,current_generation,current_statement_digest,current_statement) VALUES($1,$2,$3,1,1,2,$4,0,'ACTIVE',$5,1,$6,$7)",&[&account,&f.pin,&&f.fingerprint[..],&now,&p.authorization.0,&&tampered_digest[..],&tampered]).await.unwrap();
    assert!(store::load(&tx, account, false).await.is_err());
    tx.rollback().await.unwrap();
    // Reconstruct an explicitly synthetic already-exhausted admission fixture;
    // no production reset/restore or trigger bypass is added or claimed.
    let mut db = f.schema.connect().await;
    let tx = db.transaction().await.unwrap();
    let now = store::clock(&tx, 0).await.unwrap();
    tx.execute(
        "DELETE FROM contact_reader_state WHERE account_id=$1",
        &[&account],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO contact_reader_state(account_id,root_pin,root_fingerprint,trust_generation,allocation_generation,mutation_revision,last_mutation_ms,receipt_next_slot,phase,current_authorization,current_generation,current_statement_digest,current_statement) VALUES($1,$2,$3,1,$4,$4,$5,0,'ACTIVE',$6,1,$7,$8)",&[&account,&f.pin,&&f.fingerprint[..],&i64::MAX,&now,&p.authorization.0,&&digest[..],&signed]).await.unwrap();
    tx.commit().await.unwrap();
    f.schema
        .db
        .execute(
            "UPDATE users SET mfa_enabled=false WHERE id=$1",
            &[&f.principal.user_id],
        )
        .await
        .unwrap();
    f.schema.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",&[&account]).await.unwrap();
    let input = Withdraw {
        expected_revision: Number(i64::MAX),
        expected_authorization: p.authorization,
        expected_generation: p.generation,
        expected_digest: Fixed(digest),
    };
    assert!(
        matches!(lifecycle::withdraw(&mut f.schema.connect().await,&f.principal,input).await.unwrap(),ResultView::Withdraw(ref r)if r.kind=="withdrawn")
    );
    let row=f.schema.db.query_one("SELECT mutation_revision,phase,current_statement FROM contact_reader_state WHERE account_id=$1",&[&account]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), i64::MAX);
    assert_eq!(row.get::<_, String>(1), "WITHDRAWN");
    assert!(row.get::<_, Option<Vec<u8>>>(2).is_none());
    let repeat = Withdraw {
        expected_revision: Number(0),
        expected_authorization: p.authorization,
        expected_generation: p.generation,
        expected_digest: Fixed(digest),
    };
    assert!(
        matches!(lifecycle::withdraw(&mut f.schema.connect().await,&f.principal,repeat).await.unwrap(),ResultView::Withdraw(ref r)if r.kind=="already_withdrawn")
    );
    assert!(matches!(
        lifecycle::complete(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            f.completion(&p, 1)
        )
        .await
        .unwrap(),
        ResultView::Unavailable { .. }
    ));
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; same-Tx owned optional account erasure hook"]
async fn optional_child_first_erasure_rolls_back_with_later_failure_and_rejects_partial_schema() {
    let f = Owner::new(true, true).await;
    let p = f.pending(f.input().await).await;
    let account = f.principal.tenant.account_id();
    let mut db = f.schema.connect().await;
    let tx = db.transaction().await.unwrap();
    let prepared = export::prepare_erase(&tx, account).await.unwrap();
    let counts = prepared.erase().await.unwrap();
    assert_eq!(
        counts,
        vec![
            ("contact_reader_pending", 1),
            ("contact_reader_receipts", 0),
            ("contact_reader_state", 1)
        ]
    );
    assert!(tx.batch_execute("SELECT 1/0").await.is_err());
    tx.rollback().await.unwrap();
    assert!(matches!(
        lifecycle::status(
            &mut f.schema.connect().await,
            &f.principal,
            p.authorization.0,
            p.generation.0
        )
        .await
        .unwrap(),
        ResultView::Pending(_)
    ));
    let tx = db.transaction().await.unwrap();
    tx.batch_execute("ALTER TABLE contact_reader_receipts RENAME TO contact_test_receipts_hidden")
        .await
        .unwrap();
    assert!(export::prepare_erase(&tx, account).await.is_err());
    tx.rollback().await.unwrap();
    let tx = db.transaction().await.unwrap();
    export::prepare_erase(&tx, account)
        .await
        .unwrap()
        .erase()
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        export::state_only(&mut f.schema.connect().await, &f.principal)
            .await
            .unwrap(),
        br#"{"kind":"contact_reader_state","state":null}"#
    );
    assert!(
        lifecycle::create(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.principal,
            ORIGIN,
            Create {
                create_request: Id(Uuid::new_v4()),
                expected_revision: Number(0),
                prior: Prior::Empty {},
                selected_reader_id: Fixed(f.reader),
                compared_root_fingerprint: Fixed(f.fingerprint),
                requested_until_ms: Number(i64::MAX)
            }
        )
        .await
        .is_err()
    );
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; synthetic counter boundary, genuine create/complete"]
async fn create_reserves_revision_headroom_without_counter_burn_and_complete_can_reach_max() {
    let f = Owner::new(true, true).await;
    let account = f.principal.tenant.account_id();
    // These explicitly reconstructed extant fixtures test counter arithmetic;
    // they are neither an admitted production seed nor a restore operation.
    for (allocator, revision) in [(0, i64::MAX - 1), (i64::MAX, i64::MAX), (0, i64::MAX - 2)] {
        let mut db = f.schema.connect().await;
        let tx = db.transaction().await.unwrap();
        let now = store::clock(&tx, 0).await.unwrap();
        tx.execute(
            "DELETE FROM contact_reader_state WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap();
        tx.execute("INSERT INTO contact_reader_state(account_id,root_pin,root_fingerprint,trust_generation,allocation_generation,mutation_revision,last_mutation_ms,receipt_next_slot,phase) VALUES($1,$2,$3,1,$4,$5,$6,0,'EMPTY')", &[&account,&f.pin,&&f.fingerprint[..],&allocator,&revision,&now]).await.unwrap();
        tx.commit().await.unwrap();
        let c = f.input().await;
        if revision > i64::MAX - 2 {
            assert!(matches!(
                lifecycle::create(
                    &mut f.schema.connect().await,
                    &f.hasher,
                    &f.principal,
                    ORIGIN,
                    c
                )
                .await,
                Err(Error::Unavailable)
            ));
            let row=f.schema.db.query_one("SELECT allocation_generation,mutation_revision,(SELECT count(*) FROM contact_reader_pending WHERE account_id=$1) FROM contact_reader_state WHERE account_id=$1",&[&account]).await.unwrap();
            assert_eq!(
                (
                    row.get::<_, i64>(0),
                    row.get::<_, i64>(1),
                    row.get::<_, i64>(2)
                ),
                (allocator, revision, 0)
            );
        } else {
            let p = f.pending(c).await;
            assert_eq!(p.allocated_revision.0, i64::MAX - 1);
            assert!(matches!(
                lifecycle::complete(
                    &mut f.schema.connect().await,
                    &f.hasher,
                    &f.cipher,
                    &f.principal,
                    ORIGIN,
                    p.authorization.0,
                    f.completion(&p, 0)
                )
                .await
                .unwrap(),
                ResultView::Receipt(_)
            ));
            let row=f.schema.db.query_one("SELECT allocation_generation,mutation_revision,phase FROM contact_reader_state WHERE account_id=$1",&[&account]).await.unwrap();
            assert_eq!(
                (
                    row.get::<_, i64>(0),
                    row.get::<_, i64>(1),
                    row.get::<_, String>(2)
                ),
                (1, i64::MAX, "ACTIVE".into())
            );
            let public: serde_json::Value = serde_json::from_slice(
                &export::state_only(&mut f.schema.connect().await, &f.principal)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                public["state"]["current"]["mutation_revision"],
                i64::MAX.to_string()
            );
            assert!(public["state"]["signed_statement"].is_string());
        }
    }
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; real second session and stale prior, no concurrency"]
async fn historical_lookup_survives_session_change_but_first_completion_and_changed_prior_refuse() {
    let f = Owner::new(true, true).await;
    let c = f.input().await;
    let p = f.pending(c.clone()).await;
    let email: String = f
        .schema
        .db
        .query_one(
            "SELECT email FROM users WHERE id=$1",
            &[&f.principal.user_id],
        )
        .await
        .unwrap()
        .get(0);
    let mut db = f.schema.connect().await;
    assert!(matches!(
        crate::auth::login(&db, &f.hasher, &email, "synthetic issuer password").await,
        Err(crate::auth::AuthError::MfaRequired { account_id, user_id })
            if account_id == f.principal.tenant.account_id() && user_id == f.principal.user_id
    ));
    let challenge = crate::auth::mfa::begin_login_challenge(
        &db,
        &f.hasher,
        f.principal.tenant.account_id(),
        f.principal.user_id,
        "synthetic issuer password",
    )
    .await
    .unwrap();
    let login = crate::auth::mfa::complete_login(
        &mut db,
        Some(&f.cipher),
        &f.hasher,
        &challenge,
        &f.recovery[2],
    )
    .await
    .unwrap();
    let other = crate::auth::authenticate_session(&db, &f.hasher, &login.token)
        .await
        .unwrap();
    assert_ne!(other.session_id, f.principal.session_id);
    let lookup = Lookup {
        expected_input_digest: Fixed(
            c.commitment(f.principal.tenant.account_id(), ORIGIN)
                .unwrap(),
        ),
        create: c,
    };
    assert!(
        matches!(lifecycle::lookup(&mut db,&other,ORIGIN,lookup).await.unwrap(),ResultView::Pending(ref v) if v.authorization==p.authorization)
    );
    assert!(matches!(
        lifecycle::complete(
            &mut db,
            &f.hasher,
            &f.cipher,
            &other,
            ORIGIN,
            p.authorization.0,
            f.completion(&p, 0)
        )
        .await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT count(*) FROM contact_reader_pending WHERE account_id=$1",
                &[&f.principal.tenant.account_id()]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    // A second real intent shares EMPTY prior. Installing the first invalidates
    // that second positive completion, while historical inspection remains valid.
    let q = f.pending(f.input().await).await;
    lifecycle::complete(
        &mut db,
        &f.hasher,
        &f.cipher,
        &f.principal,
        ORIGIN,
        p.authorization.0,
        f.completion(&p, 0),
    )
    .await
    .unwrap();
    assert!(matches!(
        lifecycle::complete(
            &mut db,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            q.authorization.0,
            f.completion(&q, 1)
        )
        .await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        lifecycle::status(&mut db, &other, q.authorization.0, q.generation.0)
            .await
            .unwrap(),
        ResultView::Pending(_)
    ));
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT mutation_revision FROM contact_reader_state WHERE account_id=$1",
                &[&f.principal.tenant.account_id()]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        3
    );
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; account-scoped pending and receipt export cursors"]
async fn export_cursors_need_exact_visible_account_identity_and_never_infer_zero_state() {
    let f = Owner::new(true, true).await;
    let g = Owner::new(true, true).await;
    let p = f.pending(f.input().await).await;
    let foreign = g.pending(g.input().await).await;
    let own = format!("{}:{}", p.generation.0, p.authorization.0);
    let other = format!("{}:{}", foreign.generation.0, foreign.authorization.0);
    assert!(
        export::page(
            &mut f.schema.connect().await,
            &f.principal,
            Some(&own),
            None
        )
        .await
        .is_ok()
    );
    assert!(matches!(
        export::page(
            &mut f.schema.connect().await,
            &f.principal,
            Some(&other),
            None
        )
        .await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        export::page(
            &mut f.schema.connect().await,
            &f.principal,
            None,
            Some(&own)
        )
        .await,
        Err(Error::NotFound)
    ));
    lifecycle::cancel(
        &mut f.schema.connect().await,
        &f.principal,
        p.authorization.0,
        Cancel {
            generation: p.generation,
            create_request: p.create_request,
            unsigned_digest: p.unsigned_digest,
        },
    )
    .await
    .unwrap();
    assert!(
        export::page(
            &mut f.schema.connect().await,
            &f.principal,
            None,
            Some(&own)
        )
        .await
        .is_ok()
    );
    assert!(matches!(
        export::page(
            &mut f.schema.connect().await,
            &f.principal,
            Some(&own),
            None
        )
        .await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        export::page(
            &mut f.schema.connect().await,
            &f.principal,
            None,
            Some(&other)
        )
        .await,
        Err(Error::NotFound)
    ));
    let mut db = f.schema.connect().await;
    let tx = db.transaction().await.unwrap();
    export::prepare_erase(&tx, f.principal.tenant.account_id())
        .await
        .unwrap()
        .erase()
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        export::page(&mut db, &f.principal, None, Some(&own)).await,
        Err(Error::NotFound)
    ));
    assert_eq!(
        export::state_only(&mut db, &f.principal).await.unwrap(),
        br#"{"kind":"contact_reader_state","state":null}"#
    );
    g.schema.cleanup().await;
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; sequential final reducing-fence rollback control"]
async fn cancellation_rechecks_held_owner_after_last_write_and_rolls_back_lost_session() {
    let f = Owner::new(true, true).await;
    let p = f.pending(f.input().await).await;
    let account = f.principal.tenant.account_id();
    // This same-transaction, synthetic trigger controls an ordinary final-check
    // regression. It is not an authenticated concurrency/deadlock experiment.
    f.schema.db.batch_execute("CREATE FUNCTION contact_test_session_loss() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE sessions SET revoked_at=clock_timestamp() WHERE account_id=NEW.account_id; RETURN NEW; END $$; CREATE TRIGGER contact_test_session_loss AFTER INSERT ON contact_reader_receipts FOR EACH ROW EXECUTE FUNCTION contact_test_session_loss()").await.unwrap();
    let input = || Cancel {
        generation: p.generation,
        create_request: p.create_request,
        unsigned_digest: p.unsigned_digest,
    };
    assert!(matches!(
        lifecycle::cancel(
            &mut f.schema.connect().await,
            &f.principal,
            p.authorization.0,
            input()
        )
        .await,
        Err(Error::Authentication(crate::auth::AuthError::Unauthorized))
    ));
    let row=f.schema.db.query_one("SELECT mutation_revision,(SELECT count(*) FROM contact_reader_pending WHERE account_id=$1),(SELECT count(*) FROM contact_reader_receipts WHERE account_id=$1),(SELECT revoked_at IS NULL FROM sessions WHERE id=$2) FROM contact_reader_state WHERE account_id=$1",&[&account,&f.principal.session_id]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2),
            row.get::<_, bool>(3)
        ),
        (1, 1, 0, true)
    );
    f.schema.db.batch_execute("DROP TRIGGER contact_test_session_loss ON contact_reader_receipts; DROP FUNCTION contact_test_session_loss()").await.unwrap();
    assert!(
        matches!(lifecycle::cancel(&mut f.schema.connect().await,&f.principal,p.authorization.0,input()).await.unwrap(),ResultView::Receipt(ref r) if r.kind=="cancelled")
    );
    f.schema.cleanup().await;
}

// These sequential fixture-owned triggers are final-write controls, not an
// authenticated concurrency experiment. A sequence records the actual receipt
// write's clock independently of rollback; no auth/factor/source is fabricated.
async fn staged_completion_clock(f: &Owner) -> i64 {
    let row = f
        .schema
        .db
        .query_one(
            "SELECT last_value,is_called FROM contact_test_stage_ms",
            &[],
        )
        .await
        .unwrap();
    assert!(
        row.get::<_, bool>(1),
        "the actual final receipt write must have run"
    );
    row.get(0)
}
async fn actual_clock(f: &Owner) -> i64 {
    f.schema
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}
async fn assert_completion_rolled_back(f: &Owner, p: &PendingView) {
    let account = f.principal.tenant.account_id();
    let row = f.schema.db.query_one(
        "SELECT mutation_revision,phase,current_statement,(SELECT count(*) FROM contact_reader_pending WHERE account_id=$1 AND \"authorization\"=$2),(SELECT count(*) FROM contact_reader_receipts WHERE account_id=$1) FROM contact_reader_state WHERE account_id=$1",
        &[&account, &p.authorization.0],
    ).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), p.allocated_revision.0);
    assert_eq!(row.get::<_, String>(1), "EMPTY");
    assert!(row.get::<_, Option<Vec<u8>>>(2).is_none());
    assert_eq!(row.get::<_, i64>(3), 1);
    assert_eq!(row.get::<_, i64>(4), 0);
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; real post-write source refusal and rollback"]
async fn completion_rechecks_real_source_after_last_write_and_rolls_back_revocation() {
    let f = Owner::new(true, true).await;
    let p = f.pending(f.input().await).await;
    let account = f.principal.tenant.account_id();
    f.schema.db.batch_execute("CREATE SEQUENCE contact_test_stage_ms; CREATE FUNCTION contact_test_source_loss() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM setval('contact_test_stage_ms',floor(extract(epoch FROM clock_timestamp())*1000)::bigint,true); UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=NEW.account_id; RETURN NEW; END $$; CREATE TRIGGER contact_test_source_loss AFTER INSERT ON contact_reader_receipts FOR EACH ROW EXECUTE FUNCTION contact_test_source_loss()").await.unwrap();
    assert!(
        lifecycle::complete(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            f.completion(&p, 0),
        )
        .await
        .is_err()
    );
    assert!(staged_completion_clock(&f).await < p.until_ms.0);
    assert_completion_rolled_back(&f, &p).await;
    assert!(
        f.schema
            .db
            .query_one(
                "SELECT revoked_at IS NULL FROM sealed_manifest_authorities WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.schema.db.batch_execute("DROP TRIGGER contact_test_source_loss ON contact_reader_receipts; DROP FUNCTION contact_test_source_loss()").await.unwrap();
    // The consumed recovery factor also rolled back: the exact factor is usable.
    assert!(
        lifecycle::complete(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            f.completion(&p, 0),
        )
        .await
        .is_ok()
    );
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual clock crosses requested deadline after write"]
async fn completion_rechecks_actual_deadline_after_last_write_and_rolls_back() {
    let f = Owner::new(true, true).await;
    let mut c = f.input().await;
    c.requested_until_ms = Number(actual_clock(&f).await + 4_000);
    let p = f.pending(c).await;
    // Bounded sleep occurs only after the actual last receipt write. No clock
    // injection, changed deadline, or shared statement-timeout override is used.
    f.schema.db.batch_execute(&format!("CREATE SEQUENCE contact_test_stage_ms; CREATE FUNCTION contact_test_deadline_crossing() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM setval('contact_test_stage_ms',floor(extract(epoch FROM clock_timestamp())*1000)::bigint,true); PERFORM pg_sleep(GREATEST(0,({}::double precision-extract(epoch FROM clock_timestamp())*1000)/1000)); RETURN NEW; END $$; CREATE TRIGGER contact_test_deadline_crossing AFTER INSERT ON contact_reader_receipts FOR EACH ROW EXECUTE FUNCTION contact_test_deadline_crossing()", p.until_ms.0 + 50)).await.unwrap();
    assert!(
        actual_clock(&f).await < p.until_ms.0 - 500,
        "setup missed its real deadline; refuse a vacuous control"
    );
    assert!(matches!(
        lifecycle::complete(
            &mut f.schema.connect().await,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            f.completion(&p, 0),
        )
        .await,
        Err(Error::Conflict)
    ));
    assert!(staged_completion_clock(&f).await < p.until_ms.0);
    assert!(actual_clock(&f).await >= p.until_ms.0);
    assert_completion_rolled_back(&f, &p).await;
    assert!(f.schema.db.query_one(
        "SELECT count(*) FROM owner_mfa_recovery_codes WHERE account_id=$1 AND used_at IS NOT NULL",
        &[&f.principal.tenant.account_id()],
    ).await.unwrap().get::<_, i64>(0) == 0);
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine enrolled TOTP expires only after final write"]
async fn completion_rechecks_consumed_totp_current_at_after_last_write_and_rolls_back() {
    let f = Owner::new(true, true).await;
    let p = f.pending(f.input().await).await;
    let account = f.principal.tenant.account_id();
    let prior_step: i64 = f
        .schema
        .db
        .query_one(
            "SELECT last_accepted_step FROM owner_mfa WHERE account_id=$1 AND user_id=$2",
            &[&account, &f.principal.user_id],
        )
        .await
        .unwrap()
        .get(0);
    // Select the next genuinely generated step, then await its final valid
    // previous-step window on the real DB clock. Enrollment's step stays spent.
    let selected_step = prior_step + 1;
    let boundary = (selected_step + 2) * 30_000;
    let totp = totp_rs::Builder::new()
        .with_secret(totp_rs::Secret::try_from_base32(&f.totp_secret).unwrap())
        .build()
        .unwrap();
    let code = totp.generate(selected_step as u64 * 30).to_string();
    let mut input = f.completion(&p, 0);
    input.code = Code(zeroize::Zeroizing::new(code));
    f.schema.db.batch_execute(&format!("CREATE SEQUENCE contact_test_stage_ms; CREATE SEQUENCE contact_test_factor_step; CREATE FUNCTION contact_test_factor_crossing() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM setval('contact_test_stage_ms',floor(extract(epoch FROM clock_timestamp())*1000)::bigint,true); PERFORM setval('contact_test_factor_step',(SELECT last_accepted_step FROM owner_mfa WHERE account_id=NEW.account_id AND user_id=(SELECT user_id FROM memberships WHERE account_id=NEW.account_id AND role='owner')),true); PERFORM pg_sleep(GREATEST(0,({}::double precision-extract(epoch FROM clock_timestamp())*1000)/1000)); RETURN NEW; END $$; CREATE TRIGGER contact_test_factor_crossing AFTER INSERT ON contact_reader_receipts FOR EACH ROW EXECUTE FUNCTION contact_test_factor_crossing()", boundary + 50)).await.unwrap();
    let now = actual_clock(&f).await;
    let wait = boundary - 2_500 - now;
    assert!(
        (0..=90_000).contains(&wait),
        "fixture did not reach a usable bounded TOTP window"
    );
    let mut db = f.schema.connect().await;
    tokio::time::sleep(std::time::Duration::from_millis(wait as u64)).await;
    let before = actual_clock(&f).await;
    assert!(
        before >= boundary - 30_000 && before < boundary - 1_000,
        "refuse missed-window controls before calling the genuine completion"
    );
    assert!(p.until_ms.0 > boundary + 5_000);
    assert!(matches!(
        lifecycle::complete(
            &mut db,
            &f.hasher,
            &f.cipher,
            &f.principal,
            ORIGIN,
            p.authorization.0,
            input,
        )
        .await,
        Err(Error::Conflict)
    ));
    let staged = staged_completion_clock(&f).await;
    assert!(staged >= boundary - 30_000 && staged < boundary);
    let consumed = f
        .schema
        .db
        .query_one(
            "SELECT last_value,is_called FROM contact_test_factor_step",
            &[],
        )
        .await
        .unwrap();
    assert!(consumed.get::<_, bool>(1));
    assert_eq!(consumed.get::<_, i64>(0), selected_step);
    let after = actual_clock(&f).await;
    assert!(after >= boundary && after < p.until_ms.0);
    assert_completion_rolled_back(&f, &p).await;
    assert_eq!(
        f.schema
            .db
            .query_one(
                "SELECT last_accepted_step FROM owner_mfa WHERE account_id=$1 AND user_id=$2",
                &[&account, &f.principal.user_id],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        prior_step
    );
    assert!(
        f.schema
            .db
            .query_one(
                "SELECT revoked_at IS NULL FROM sealed_manifest_authorities WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.schema.cleanup().await;
}
