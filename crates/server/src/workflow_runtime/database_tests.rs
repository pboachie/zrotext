// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::{self, SessionPrincipal, TokenHasher, mfa},
    http_owner_conversations::{
        activation::tests::{activate, pending},
        context::{self, wire},
    },
    sealed_connector_registry as registry,
    sealed_manifest_store::{self, tests::Fixture},
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Argon2, PasswordHasher};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PASSWORD: &str = "synthetic-workflow-password";
struct Case {
    f: Fixture,
    owner: SessionPrincipal,
    hasher: TokenHasher,
    cipher: mfa::MfaCipher,
    factor: String,
    request: GrantRequest,
    header: wire::Header,
}
fn digest(domain: &[u8], value: &str) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&crate::test_keys::key(84)).unwrap();
    mac.update(domain);
    mac.update(&[0]);
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().into()
}
impl Case {
    async fn new() -> Self {
        let (mut f, owner, s) = pending().await;
        activate(&f, &s).await;
        for sql in [include_str!(
            "../../../../deploy/compose/migrations/078_workflow_integration_authority.sql"
        )] {
            f.db.batch_execute(sql).await.unwrap();
        }
        let now: i64 =
            f.db.query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        // Advance the real signed manifest chain with a distinct role-3 key.
        f.advance();
        let key = SigningKey::generate_from_rng(&mut rand::rng());
        let point = key.verifying_key().to_sec1_point(false);
        let id: [u8; 32] =
            Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], point.as_bytes()].concat())
                .into();
        let mut record = vec![3];
        record.extend(id);
        record.extend(point.as_bytes());
        record.extend([0; 32]);
        record.extend(8u16.to_be_bytes());
        record.extend((now - 1000).to_be_bytes());
        record.extend((now + 120000).to_be_bytes());
        record.push(1);
        f.bytes.splice(300..300, record);
        f.bytes[150] = 4;
        f.resign();
        let mut client = f.connect().await;
        let tx = client.transaction().await.unwrap();
        let mut admission = sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
            .await
            .unwrap();
        admission.context(&f.wanted()).await.unwrap();
        drop(admission);
        tx.commit().await.unwrap();
        let hash = Argon2::default()
            .hash_password(PASSWORD.as_bytes())
            .unwrap()
            .to_string();
        f.db.execute(
            "UPDATE users SET password_hash=$2,mfa_enabled=true WHERE id=$1",
            &[&owner.user_id, &hash],
        )
        .await
        .unwrap();
        let cipher_key = crate::test_keys::key(89);
        let cipher = mfa::MfaCipher::new(cipher_key.clone()).unwrap();
        let nonce = rand::random::<[u8; 12]>();
        let secret = rand::random::<[u8; 20]>();
        let aad = [
            b"zrotext-owner-totp-v1".as_slice(),
            f.account.as_bytes(),
            owner.user_id.as_bytes(),
        ]
        .concat();
        let encrypted = Aes256Gcm::new_from_slice(&cipher_key)
            .unwrap()
            .encrypt(
                &Nonce::try_from(nonce.as_slice()).unwrap(),
                Payload {
                    msg: &secret,
                    aad: &aad,
                },
            )
            .unwrap();
        f.db.execute("INSERT INTO owner_mfa(account_id,user_id,secret_nonce,secret_ciphertext,enabled_at) VALUES($1,$2,$3,$4,clock_timestamp())",&[&f.account,&owner.user_id,&nonce.as_slice(),&encrypted]).await.unwrap();
        let hasher = TokenHasher::new(crate::test_keys::key(84)).unwrap();
        let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let hash = digest(b"session-v1", &token);
        f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",&[&Uuid::new_v4(),&f.account,&owner.user_id,&hash.as_slice(),&vec![4u8;32]]).await.unwrap();
        let second = auth::authenticate_session(&f.db, &hasher, &token)
            .await
            .unwrap();
        let ticket = registry::propose(
            &mut f.connect().await,
            &hasher,
            &owner,
            registry::RegistrationRequest {
                display_name: "synthetic-workflow-reader".into(),
                key_point: point.as_bytes().try_into().unwrap(),
                grants: vec![registry::GrantRequest {
                    kind: registry::GrantKind::Read { directions: 8 },
                    line_id: f.line,
                    conversation_restriction: vec![s.interval],
                    expires_ms: (now + 60000) as u64,
                }],
                expires_ms: (now + 60000) as u64,
            },
        )
        .await
        .unwrap();
        registry::approve(
            &mut f.connect().await,
            &hasher,
            &second,
            ticket.connector_id,
        )
        .await
        .unwrap();
        let row=f.db.query_one("SELECT generation,version,semantic_digest FROM sealed_manifest_authorities WHERE account_id=$1",&[&f.account]).await.unwrap();
        let header = wire::Header {
            kind: 1,
            account: f.account,
            device: f.device,
            line: f.line,
            interval: s.interval,
            context: Uuid::new_v4(),
            binding_generation: 1,
            revision: 1,
            expires_ms: now + 60000,
            trust_generation: row.get(0),
            manifest_version: row.get(1),
            peer_digest: Sha256::digest(s.peer.as_bytes()).into(),
            reader: s.reader,
            manifest_digest: row.get::<_, Vec<u8>>(2).try_into().unwrap(),
        };
        let mut envelope = header.aad().unwrap();
        envelope.extend(point.as_bytes());
        envelope.extend(33u32.to_be_bytes());
        envelope.extend([88; 33]);
        context::write(&mut f.connect().await, &owner, Uuid::new_v4(), 0, &envelope)
            .await
            .unwrap();
        let contact = Uuid::new_v4();
        f.db.execute(
            "INSERT INTO contacts(id,account_id,recipient_e164) VALUES($1,$2,$3)",
            &[&contact, &f.account, &s.peer],
        )
        .await
        .unwrap();
        let factor = format!("zrc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()));
        let hash = digest(
            b"mfa-recovery-v1",
            &format!("{}:{}:{factor}", f.account, owner.user_id),
        );
        f.db.execute(
            "INSERT INTO owner_mfa_recovery_codes(account_id,user_id,code_hash) VALUES($1,$2,$3)",
            &[&f.account, &owner.user_id, &hash.as_slice()],
        )
        .await
        .unwrap();
        let request = GrantRequest {
            connector: ticket.connector_id,
            context: header.context,
            contact,
            purpose: Purpose::Operational,
            permissions: Permissions::new(&[Operation::ContextMetadata]).unwrap(),
            signer: None,
            expires_ms: now + 30000,
            content_envelope: None,
        };
        Self {
            f,
            owner,
            hasher,
            cipher,
            factor,
            request,
            header,
        }
    }
    async fn issue(&self) -> Result<IssuedCredential, auth::AuthError> {
        issue_grant(
            &mut self.f.connect().await,
            &self.owner,
            &self.hasher,
            &self.cipher,
            PASSWORD,
            &self.factor,
            &self.request,
        )
        .await
    }
    async fn projection(&self) -> Vec<u8> {
        let reader: Vec<u8>=self.f.db.query_one("SELECT key_id FROM connector_registrations WHERE account_id=$1 AND connector_id=$2", &[&self.f.account,&self.request.connector]).await.unwrap().get(0);
        let mut header = self.header.clone();
        header.reader = reader.try_into().unwrap();
        let ephemeral = SigningKey::generate_from_rng(&mut rand::rng());
        let mut envelope = header.aad().unwrap();
        envelope.extend(ephemeral.verifying_key().to_sec1_point(false).as_bytes());
        // Opaque storage fixture; real role-3 HPKE is tested in the SDK.
        envelope.extend(33u32.to_be_bytes());
        envelope.extend([99; 33]);
        envelope
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn owner_mfa_grant_allows_exact_metadata_without_content_or_send_authority() {
    let case = Case::new().await;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    assert!(principal.require(Operation::ContextContent).is_err());
    assert!(principal.require(Operation::Send).is_err());
    let request = Uuid::new_v4();
    let header = read_context_metadata(
        &mut case.f.connect().await,
        &principal,
        request,
        case.header.context,
    )
    .await
    .unwrap();
    assert_eq!(header, case.header);
    assert_eq!(
        read_context_metadata(
            &mut case.f.connect().await,
            &principal,
            request,
            case.header.context
        )
        .await
        .unwrap(),
        header
    );
    let count: i64 = case
        .f
        .db
        .query_one("SELECT count(*) FROM workflow_integration_access", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    assert!(
        read_context_metadata(
            &mut case.f.connect().await,
            &principal,
            request,
            Uuid::new_v4()
        )
        .await
        .is_err()
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn grants_cannot_widen_and_withdrawal_invalidates_an_already_authenticated_reader() {
    let case = Case::new().await;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    assert_eq!(
        case.f
            .db
            .execute(
                "UPDATE workflow_integration_grants SET permissions=6 WHERE grant_id=$1",
                &[&issued.grant_id]
            )
            .await
            .unwrap_err()
            .code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    revoke_grant(&mut case.f.connect().await, &case.owner, issued.grant_id)
        .await
        .unwrap();
    assert!(
        authenticate(&case.f.db, &case.hasher, &issued.token)
            .await
            .is_err()
    );
    assert!(
        read_context_metadata(
            &mut case.f.connect().await,
            &principal,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_err()
    );
    let count: i64 = case
        .f
        .db
        .query_one("SELECT count(*) FROM workflow_integration_access", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn grant_withdrawal_remains_available_after_manifest_revocation_and_mfa_disable() {
    let case = Case::new().await;
    let issued = case.issue().await.unwrap();
    case.f.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1", &[&case.f.account]).await.unwrap();
    case.f
        .db
        .execute(
            "UPDATE users SET mfa_enabled=false WHERE id=$1",
            &[&case.owner.user_id],
        )
        .await
        .unwrap();
    revoke_grant(&mut case.f.connect().await, &case.owner, issued.grant_id)
        .await
        .unwrap();
    let revoked: bool = case
        .f
        .db
        .query_one(
            "SELECT revoked_ms IS NOT NULL FROM workflow_integration_grants WHERE grant_id=$1",
            &[&issued.grant_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(revoked);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn contact_scope_mismatch_creates_no_grant_and_does_not_consume_owner_factor() {
    let mut case = Case::new().await;
    let original = case.request.contact;
    let wrong = Uuid::new_v4();
    case.f
        .db
        .execute(
            "INSERT INTO contacts(id,account_id,recipient_e164) VALUES($1,$2,'+13')",
            &[&wrong, &case.f.account],
        )
        .await
        .unwrap();
    case.request.contact = wrong;
    assert!(matches!(
        case.issue().await,
        Err(auth::AuthError::Forbidden)
    ));
    let counts=case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_integration_grants), (SELECT count(*) FROM owner_mfa_recovery_codes WHERE used_at IS NULL)",&[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 1);
    case.request.contact = original;
    assert!(case.issue().await.is_ok());
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn content_permission_without_a_separate_envelope_never_returns_archive_ciphertext() {
    let mut case = Case::new().await;
    case.request.permissions = Permissions::new(&[Operation::ContextContent]).unwrap();
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    assert!(
        read_context_content(
            &mut case.f.connect().await,
            &principal,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_err()
    );
    let count: i64 = case
        .f
        .db
        .query_one("SELECT count(*) FROM workflow_integration_access", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn content_only_grant_returns_its_owner_declared_projection_and_cannot_rehydrate_it() {
    let mut case = Case::new().await;
    case.request.permissions = Permissions::new(&[Operation::ContextContent]).unwrap();
    let archive: Vec<u8> = case
        .f
        .db
        .query_one(
            "SELECT envelope FROM workflow_context_versions WHERE context_id=$1",
            &[&case.header.context],
        )
        .await
        .unwrap()
        .get(0);
    case.request.content_envelope = Some(archive.clone());
    assert!(matches!(
        case.issue().await,
        Err(auth::AuthError::Forbidden)
    ));
    let projection = case.projection().await;
    assert_ne!(projection, archive);
    case.request.content_envelope = Some(projection.clone());
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    assert!(
        read_context_metadata(
            &mut case.f.connect().await,
            &principal,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_err()
    );
    let request = Uuid::new_v4();
    assert_eq!(
        read_context_content(
            &mut case.f.connect().await,
            &principal,
            request,
            case.header.context
        )
        .await
        .unwrap(),
        projection
    );
    case.f
        .db
        .execute(
            "UPDATE workflow_connector_context_envelopes SET envelope=NULL WHERE grant_id=$1",
            &[&issued.grant_id],
        )
        .await
        .unwrap();
    assert!(
        read_context_content(
            &mut case.f.connect().await,
            &principal,
            request,
            case.header.context
        )
        .await
        .is_err()
    );
    assert_eq!(
        case.f
            .db
            .execute(
                "UPDATE workflow_connector_context_envelopes SET envelope=$2 WHERE grant_id=$1",
                &[&issued.grant_id, &projection]
            )
            .await
            .unwrap_err()
            .code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    let count: i64 = case
        .f
        .db
        .query_one("SELECT count(*) FROM workflow_integration_access", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn interval_withdrawal_refuses_content_before_retention_scrubs_either_representation() {
    let mut case = Case::new().await;
    case.request.permissions = Permissions::new(&[Operation::ContextContent]).unwrap();
    case.request.content_envelope = Some(case.projection().await);
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    crate::http_owner_conversations::activation::close(
        &mut case.f.connect().await,
        &case.owner,
        case.header.interval,
        true,
    )
    .await
    .unwrap();
    let retained: bool=case.f.db.query_one("SELECT envelope IS NOT NULL FROM workflow_connector_context_envelopes WHERE grant_id=$1", &[&issued.grant_id]).await.unwrap().get(0);
    assert!(retained);
    assert!(
        read_context_content(
            &mut case.f.connect().await,
            &principal,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_err()
    );
    let count: i64 = case
        .f
        .db
        .query_one("SELECT count(*) FROM workflow_integration_access", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn integration_takeout_pages_access_without_exporting_credentials() {
    let case = Case::new().await;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut client = case.f.connect().await;
    for _ in 0..21 {
        read_context_metadata(&mut client, &principal, Uuid::new_v4(), case.header.context)
            .await
            .unwrap();
    }
    let first = lifecycle::export(&mut client, &case.owner, [None; 3])
        .await
        .unwrap();
    assert_eq!(first.grants.items.len(), 1);
    assert!(first.grants.items[0].get("credential_hash").is_none());
    assert!(
        !serde_json::to_string(&first)
            .unwrap()
            .contains(issued.token.as_str())
    );
    assert_eq!(first.access.items.len(), 20);
    let cursor = first.access.next_cursor.unwrap();
    let last = lifecycle::export(&mut client, &case.owner, [None, None, Some(cursor)])
        .await
        .unwrap();
    assert_eq!(last.access.items.len(), 1);
    assert!(last.access.next_cursor.is_none());
    assert!(matches!(
        lifecycle::export(&mut client, &case.owner, [Some(Uuid::new_v4()), None, None]).await,
        Err(crate::http_owner_conversations::ConversationError::NotFound)
    ));
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn withdrawn_projection_is_scrubbed_once_and_erasure_preserves_source_context() {
    let mut case = Case::new().await;
    case.request.permissions = Permissions::new(&[Operation::ContextContent]).unwrap();
    let projection = case.projection().await;
    case.request.content_envelope = Some(projection.clone());
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut client = case.f.connect().await;
    read_context_content(&mut client, &principal, Uuid::new_v4(), case.header.context)
        .await
        .unwrap();
    revoke_grant(&mut client, &case.owner, issued.grant_id)
        .await
        .unwrap();
    assert_eq!(lifecycle::prune(&mut client, 1).await.unwrap(), 1);
    assert_eq!(lifecycle::prune(&mut client, 1).await.unwrap(), 0);
    let exported = lifecycle::export(&mut client, &case.owner, [None; 3])
        .await
        .unwrap();
    assert_eq!(exported.envelopes.items.len(), 1);
    assert!(exported.envelopes.items[0]["envelope_hex"].is_null());
    assert!(
        !serde_json::to_string(&exported).unwrap().contains(
            &projection
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    );
    let tx = client.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &case.owner)
        .await
        .unwrap();
    lifecycle::erase_context(&tx, case.owner.tenant.account_id(), case.header.context)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let erased = lifecycle::export(&mut client, &case.owner, [None; 3])
        .await
        .unwrap();
    assert!(
        erased.grants.items.is_empty()
            && erased.envelopes.items.is_empty()
            && erased.access.items.is_empty()
    );
    let exists: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM workflow_contexts WHERE id=$1)",
            &[&case.header.context],
        )
        .await
        .unwrap()
        .get(0);
    assert!(exists);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn contact_erasure_removes_bound_grants_without_touching_other_contacts() {
    let case = Case::new().await;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut client = case.f.connect().await;
    read_context_metadata(&mut client, &principal, Uuid::new_v4(), case.header.context)
        .await
        .unwrap();
    let tx = client.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &case.owner)
        .await
        .unwrap();
    lifecycle::erase_contact(&tx, case.owner.tenant.account_id(), Uuid::new_v4())
        .await
        .unwrap();
    let retained: i64 = tx
        .query_one("SELECT count(*) FROM workflow_integration_grants", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(retained, 1);
    lifecycle::erase_contact(&tx, case.owner.tenant.account_id(), case.request.contact)
        .await
        .unwrap();
    assert_eq!(
        tx.execute(
            "DELETE FROM contacts WHERE account_id=$1 AND id=$2",
            &[&case.owner.tenant.account_id(), &case.request.contact]
        )
        .await
        .unwrap(),
        1
    );
    tx.commit().await.unwrap();
    assert!(
        read_context_metadata(&mut client, &principal, Uuid::new_v4(), case.header.context)
            .await
            .is_err()
    );
    assert!(
        lifecycle::export(&mut client, &case.owner, [None; 3])
            .await
            .unwrap()
            .grants
            .items
            .is_empty()
    );
    case.f.cleanup().await;
}
