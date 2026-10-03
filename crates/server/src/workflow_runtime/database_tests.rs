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
use zeroize::Zeroizing;

mod grant_http;
mod grant_origin;

mod scope_expiry;
pub(super) struct Case {
    pub(super) f: Fixture,
    pub(super) owner: SessionPrincipal,
    pub(super) hasher: TokenHasher,
    pub(super) reader_key: SigningKey,
    cipher: mfa::MfaCipher,
    password: Zeroizing<String>,
    factor: String,
    pub(super) request: GrantRequest,
    pub(super) header: wire::Header,
    pub(super) outbound: Option<SigningKey>,
    pub(super) phone_reader: Option<[u8; 32]>,
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn proposal_and_metadata_read_cannot_reuse_each_others_request_identity() {
    for proposal_first in [false, true] {
        let mut case = Case::with_signer(Some(120000)).await;
        case.request.permissions =
            Permissions::new(&[Operation::Propose, Operation::ContextMetadata]).unwrap();
        let issued = case.issue().await.unwrap();
        let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
            .await
            .unwrap();
        let descriptor = case.descriptor().await;
        let request = Uuid::new_v4();
        if proposal_first {
            propose_action(
                &mut case.f.connect().await,
                &principal,
                request,
                descriptor.clone(),
            )
            .await
            .unwrap();
            assert!(matches!(
                read_context_metadata(
                    &mut case.f.connect().await,
                    &principal,
                    request,
                    case.header.context
                )
                .await,
                Err(auth::AuthError::Conflict)
            ));
            read_context_metadata(
                &mut case.f.connect().await,
                &principal,
                Uuid::new_v4(),
                case.header.context,
            )
            .await
            .unwrap();
        } else {
            read_context_metadata(
                &mut case.f.connect().await,
                &principal,
                request,
                case.header.context,
            )
            .await
            .unwrap();
            assert!(matches!(
                propose_action(
                    &mut case.f.connect().await,
                    &principal,
                    request,
                    descriptor.clone()
                )
                .await,
                Err(auth::AuthError::Conflict)
            ));
            let actions: i64 = case
                .f
                .db
                .query_one("SELECT count(*) FROM workflow_actions", &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(
                actions, 0,
                "the conflicting proposal must roll back its action"
            );
            propose_action(
                &mut case.f.connect().await,
                &principal,
                Uuid::new_v4(),
                descriptor,
            )
            .await
            .unwrap();
        }
        let row = case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_integration_access),(SELECT count(*) FROM workflow_actions),(SELECT count(*) FROM messages)", &[]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 2);
        assert_eq!(row.get::<_, i64>(1), 1);
        assert_eq!(row.get::<_, i64>(2), 0);
        case.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn dispatcher_proposes_exact_content_using_the_returned_source_digest_without_a_database_read()
 {
    use super::contracts::{ContextRequest, ProposalRequest, Request, Response};
    let mut case = Case::with_signer(Some(120000)).await;
    case.request.permissions =
        Permissions::new(&[Operation::ContextMetadata, Operation::Propose]).unwrap();
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    case.f.db.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'operational','grant','manual_entry',clock_timestamp(),$4)", &[&Uuid::new_v4(),&case.f.account,&case.request.contact,&case.owner.user_id]).await.unwrap();
    let Response::ContextMetadata(metadata) = call(
        &mut case.f.connect().await,
        &principal,
        Request::ContextMetadata(ContextRequest {
            request_id: Uuid::new_v4(),
            context_id: case.header.context,
        }),
    )
    .await
    .unwrap() else {
        panic!("dispatcher must return the selected source metadata")
    };
    // Identity and selected purpose are client configuration; the content digest
    // and version come solely from the actual scoped service response.
    let descriptor = context::decisions::Descriptor {
        account_id: case.f.account.to_string(),
        action_id: Uuid::new_v4().to_string(),
        revision: 1,
        line_id: case.f.line.to_string(),
        recipient_id: case.request.contact.to_string(),
        purpose_id: Purpose::Operational.action_id().to_string(),
        content_ref: metadata.context_id.to_string(),
        content_version: metadata.revision,
        content_digest: metadata.source_content_digest,
        not_before: 0,
        expires_at: metadata.expires_at_ms / 1000,
        timezone: "UTC".into(),
        window_id: IMMEDIATE_WINDOW_ID.into(),
        routine_id: Uuid::new_v4().to_string(),
        authority_generation: 1,
        commitment: "informational".into(),
    };
    let request = Uuid::new_v4();
    let Response::Action(action) = call(
        &mut case.f.connect().await,
        &principal,
        Request::Propose(ProposalRequest {
            request_id: request,
            descriptor: descriptor.clone(),
        }),
    )
    .await
    .unwrap() else {
        panic!("dispatcher must return the proposed action")
    };
    assert_eq!(action.phase, context::decisions::model::Phase::Proposed);
    assert_eq!(action.key, descriptor.key().unwrap());
    let mut changed = descriptor;
    changed.action_id = Uuid::new_v4().to_string();
    changed.routine_id = Uuid::new_v4().to_string();
    let replacement = if changed.content_digest.starts_with('0') {
        "1"
    } else {
        "0"
    };
    changed.content_digest.replace_range(..1, replacement);
    assert!(
        call(
            &mut case.f.connect().await,
            &principal,
            Request::Propose(ProposalRequest {
                request_id: Uuid::new_v4(),
                descriptor: changed
            })
        )
        .await
        .is_err()
    );
    let row = case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_actions),(SELECT count(*) FROM messages),(SELECT count(*) FROM workflow_integration_access)", &[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 2);
    case.f.cleanup().await;
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
    pub(super) async fn new() -> Self {
        Self::with_signer(None).await
    }
    pub(super) async fn with_signer(signer_lifetime: Option<i64>) -> Self {
        Self::with_fixture_lifetimes(signer_lifetime, false, 60000, 30000).await
    }
    pub(super) async fn with_signer_aligned(
        signer_lifetime: Option<i64>,
        future_window: bool,
    ) -> Self {
        Self::with_fixture_lifetimes(signer_lifetime, future_window, 60000, 30000).await
    }
    // Preserve the bounded multi-process routine fixture's original lifetimes.
    pub(super) async fn for_customer_routine(signer_lifetime: Option<i64>) -> Self {
        Self::with_fixture_lifetimes(signer_lifetime, false, 120000, 90000).await
    }
    async fn with_fixture_lifetimes(
        signer_lifetime: Option<i64>,
        future_window: bool,
        authority_lifetime: i64,
        grant_lifetime: i64,
    ) -> Self {
        let password = Zeroizing::new(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let hash = Argon2::default()
            .hash_password(password.as_bytes())
            .unwrap()
            .to_string();
        let (mut f, owner, s) = pending().await;
        activate(&f, &s).await;

        // Prepare storage and the password before aligning the actual clock.
        // Only then mint the signed context/key lifetimes used by this test.
        if future_window {
            let started = tokio::time::Instant::now();
            loop {
                let second: i32 = f.db.query_one(
                    "SELECT floor(extract(second FROM clock_timestamp() AT TIME ZONE 'UTC'))::integer",
                    &[],
                ).await.unwrap().get(0);
                if (5..=35).contains(&second) {
                    break;
                }
                assert!(started.elapsed() < std::time::Duration::from_secs(31));
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
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
        let mut outbound = None;
        let signer = signer_lifetime.map(|lifetime| {
            let key = SigningKey::generate_from_rng(&mut rand::rng());
            let point = key.verifying_key().to_sec1_point(false);
            let id: [u8; 32] =
                Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[1, 1], point.as_bytes()].concat())
                    .into();
            let mut record = vec![5];
            record.extend(id);
            record.extend(point.as_bytes());
            record.extend([0; 16]);
            record.extend(f.line.as_bytes());
            record.extend(1u16.to_be_bytes());
            record.extend((now - 1000).to_be_bytes());
            record.extend((now + lifetime).to_be_bytes());
            record.push(1);
            f.bytes.splice(598..598, record);
            f.bytes[150] = 5;
            outbound = Some(key);
            id
        });
        // A real signed role-1 phone receiver is required for outbound wraps;
        // direction 4 does not widen the existing inbound archive reader set.
        let phone_reader = signer.map(|_| {
            let key = SigningKey::generate_from_rng(&mut rand::rng());
            let point = key.verifying_key().to_sec1_point(false);
            let id: [u8; 32] =
                Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], point.as_bytes()].concat())
                    .into();
            let mut record = vec![1];
            record.extend(id);
            record.extend(point.as_bytes());
            record.extend(f.device.as_bytes());
            record.extend(f.line.as_bytes());
            record.extend(4u16.to_be_bytes());
            record.extend((now - 1000).to_be_bytes());
            record.extend((now + 120000).to_be_bytes());
            record.push(1);
            f.bytes.splice(151..151, record);
            f.bytes[150] = 6;
            id
        });
        f.resign();
        let mut client = f.connect().await;
        let tx = client.transaction().await.unwrap();
        let mut admission = sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
            .await
            .unwrap();
        admission.context(&f.wanted()).await.unwrap();
        drop(admission);
        tx.commit().await.unwrap();
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
                grants: {
                    let mut grants = vec![registry::GrantRequest {
                        kind: registry::GrantKind::Read { directions: 8 },
                        line_id: f.line,
                        conversation_restriction: vec![s.interval],
                        expires_ms: (now + authority_lifetime) as u64,
                    }];
                    if signer.is_some() {
                        grants.push(registry::GrantRequest {
                            kind: registry::GrantKind::Send,
                            line_id: f.line,
                            conversation_restriction: vec![],
                            expires_ms: (now + authority_lifetime) as u64,
                        });
                    }
                    grants
                },
                expires_ms: (now + authority_lifetime) as u64,
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
            expires_ms: now + authority_lifetime,
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
            signer,
            expires_ms: now + grant_lifetime,
            content_envelope: None,
        };
        Self {
            f,
            owner,
            hasher,
            cipher,
            password,
            factor,
            request,
            header,
            outbound,
            phone_reader,
            reader_key: key,
        }
    }
    pub(super) async fn descriptor(
        &self,
    ) -> crate::http_owner_conversations::context::decisions::Descriptor {
        use crate::http_owner_conversations::context::decisions;
        let bytes: Vec<u8> = self
            .f
            .db
            .query_one(
                "SELECT envelope FROM workflow_context_versions WHERE context_id=$1",
                &[&self.header.context],
            )
            .await
            .unwrap()
            .get(0);
        self.f.db.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'operational','grant','manual_entry',clock_timestamp(),$4)", &[&Uuid::new_v4(),&self.f.account,&self.request.contact,&self.owner.user_id]).await.unwrap();
        decisions::Descriptor {
            account_id: self.f.account.to_string(),
            action_id: Uuid::new_v4().to_string(),
            revision: 1,
            line_id: self.header.line.to_string(),
            recipient_id: self.request.contact.to_string(),
            purpose_id: "00000000-0000-0000-0000-000000000002".into(),
            content_ref: self.header.context.to_string(),
            content_digest: decisions::descriptor::hex(&Sha256::digest(bytes)),
            content_version: 1,
            not_before: 0,
            expires_at: self.header.expires_ms / 1000,
            timezone: "UTC".into(),
            window_id: "exact-window".into(),
            routine_id: Uuid::new_v4().to_string(),
            authority_generation: 1,
            commitment: "informational".into(),
        }
    }
    pub(super) async fn issue(&self) -> Result<IssuedCredential, auth::AuthError> {
        issue_grant(
            &mut self.f.connect().await,
            &self.owner,
            &self.hasher,
            &self.cipher,
            &self.password,
            &self.factor,
            &self.request,
        )
        .await
    }
    pub(super) async fn fresh_factor(&mut self) -> String {
        self.factor = format!("zrc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()));
        let hash = digest(
            b"mfa-recovery-v1",
            &format!("{}:{}:{}", self.f.account, self.owner.user_id, self.factor),
        );
        self.f.db.execute("INSERT INTO owner_mfa_recovery_codes(account_id,user_id,code_hash) VALUES($1,$2,$3)", &[&self.f.account,&self.owner.user_id,&hash.as_slice()]).await.unwrap();
        self.factor.clone()
    }
    pub(super) fn password(&self) -> &str {
        self.password.as_str()
    }
    pub(super) async fn issue_another(&mut self) -> IssuedCredential {
        self.fresh_factor().await;
        self.issue().await.unwrap()
    }
    pub(super) async fn projection(&self) -> Vec<u8> {
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
    pub(super) async fn bind_message(
        &mut self,
        approved: context::decisions::ActionState,
        dispatch: Uuid,
    ) -> (context::decisions::ActionState, Uuid) {
        self.try_bind_message(approved, dispatch).await.unwrap()
    }
    pub(super) async fn try_bind_message(
        &mut self,
        approved: context::decisions::ActionState,
        dispatch: Uuid,
    ) -> Result<(context::decisions::ActionState, Uuid), crate::sealed_outbound::AdmitError> {
        let factor = format!("zrc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()));
        let hash = digest(
            b"mfa-recovery-v1",
            &format!("{}:{}:{factor}", self.f.account, self.owner.user_id),
        );
        self.f.db.execute("INSERT INTO owner_mfa_recovery_codes(account_id,user_id,code_hash) VALUES($1,$2,$3)", &[&self.f.account,&self.owner.user_id,&hash.as_slice()]).await.unwrap();
        let credential = auth::account::create_api_key_with_proof(
            &mut self.f.connect().await,
            Some(&self.cipher),
            &self.hasher,
            &self.owner,
            &self.password,
            Some(&factor),
            auth::account::ApiKeyRequest {
                scopes: &[auth::Scope::MessagesSend],
                bound_device_id: Some(self.f.device),
                lifetime: auth::ApiKeyLifetime::Unspecified,
            },
        )
        .await
        .unwrap();
        let api = auth::authenticate_api_key(&self.f.db, &self.hasher, &credential.token)
            .await
            .unwrap();
        self.f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',1000) ON CONFLICT(account_id,metric) DO NOTHING", &[&self.f.account]).await.unwrap();
        let now: i64 = self
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let message = Uuid::new_v4();
        let original_signer = self.f.signer;
        let original_key = self.f.event_signer.clone();
        let original_readers = self.f.readers.clone();
        self.f.signer = self.request.signer.unwrap();
        self.f.event_signer = self.outbound.clone().unwrap();
        self.f.readers = vec![
            crate::sealed_envelope::ExpectedRecipient {
                role: 1,
                key_id: self.phone_reader.unwrap(),
            },
            crate::sealed_envelope::ExpectedRecipient {
                role: 2,
                key_id: self.header.reader,
            },
        ];
        let descriptor = {
            let tx = self.f.db.transaction().await.unwrap();
            let descriptor = context::decisions::store::descriptor(&tx, approved.key)
                .await
                .unwrap();
            tx.rollback().await.unwrap();
            descriptor
        };
        let lifetime = (descriptor.expires_at_ms().unwrap() - now - 1).min(30000);
        assert!(
            lifetime > 0,
            "owner binding must precede the exact action deadline"
        );
        let bytes = crate::sealed_outbound::tests::envelope(&self.f, message, now, lifetime);
        self.f.signer = original_signer;
        self.f.event_signer = original_key;
        self.f.readers = original_readers;
        crate::sealed_outbound::admit_candidate02_with_limit(
            &mut self.f.connect().await,
            &api,
            &self.hasher,
            crate::sealed_outbound::WriterContext {
                site_id: "manifest-test",
                deployment_epoch: 1,
                billing_enabled: true,
            },
            &bytes,
            Some(1),
        )
        .await?;
        let bound = context::decisions::bind_message(
            &mut self.f.connect().await,
            &self.owner,
            Uuid::new_v4(),
            approved.record_version,
            approved.key,
            context::decisions::store::RenderedBinding {
                message_id: message,
                dispatch_id: dispatch,
                message_digest: context::decisions::descriptor::hex(&Sha256::digest(bytes)),
            },
        )
        .await
        .unwrap();
        Ok((bound, message))
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

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn contact_metadata_authority_does_not_inherit_context_or_connector_read_permissions() {
    let mut case = Case::new().await;
    case.request.permissions = Permissions::new(&[Operation::ContactRead]).unwrap();
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    case.f.db.execute("UPDATE connector_grants SET revoked_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE account_id=$1 AND kind='read'", &[&case.f.account]).await.unwrap();
    let mut client = case.f.connect().await;
    let request = Uuid::new_v4();
    for _ in 0..2 {
        let contact = read_contact(&mut client, &principal, request, case.header.context)
            .await
            .unwrap();
        assert_eq!(contact.contact_id, case.request.contact);
        assert_eq!(contact.purpose, "operational");
        assert_eq!(contact.peer_digest, case.header.peer_digest);
        assert!(!serde_json::to_string(&contact).unwrap().contains("+12"));
    }
    assert!(
        read_context_metadata(&mut client, &principal, Uuid::new_v4(), case.header.context)
            .await
            .is_err()
    );
    assert!(
        read_context_content(&mut client, &principal, Uuid::new_v4(), case.header.context)
            .await
            .is_err()
    );
    assert!(
        read_contact(&mut client, &principal, Uuid::new_v4(), Uuid::new_v4())
            .await
            .is_err()
    );
    assert!(
        read_contact(&mut client, &principal, Uuid::nil(), case.header.context)
            .await
            .is_err()
    );
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM workflow_integration_access WHERE operation=1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn transaction_scope_rechecks_a_withdrawal_after_its_constructor() {
    let case = Case::new().await;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut client = case.f.connect().await;
    let tx = client.transaction().await.unwrap();
    let mut permit = scope::lock_scope(
        &tx,
        &principal,
        case.header.context,
        Operation::ContextMetadata,
    )
    .await
    .unwrap();
    tx.execute("UPDATE workflow_integration_grants SET revoked_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE grant_id=$1", &[&issued.grant_id]).await.unwrap();
    assert!(matches!(
        permit.recheck().await,
        Err(auth::AuthError::Forbidden)
    ));
    drop(permit);
    tx.rollback().await.unwrap();
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn status_only_grant_reads_current_owner_action_without_approval_or_content_authority() {
    use crate::http_owner_conversations::context::decisions::{self, model::Decision};
    let mut case = Case::new().await;
    case.request.permissions = Permissions::new(&[Operation::Status]).unwrap();
    let descriptor = case.descriptor().await;
    let mut client = case.f.connect().await;
    let state = decisions::register(&mut client, &case.owner, Uuid::new_v4(), descriptor)
        .await
        .unwrap();
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let request = Uuid::new_v4();
    let actual = read_action_status(
        &mut client,
        &principal,
        request,
        case.header.context,
        state.key.action_id,
    )
    .await
    .unwrap();
    assert_eq!(actual.key, state.key);
    assert_eq!(actual.phase, decisions::model::Phase::Proposed);
    let canceled = decisions::decide(
        &mut client,
        &case.owner,
        Uuid::new_v4(),
        state.record_version,
        state.key,
        Decision::Cancel,
    )
    .await
    .unwrap();
    let actual = read_action_status(
        &mut client,
        &principal,
        request,
        case.header.context,
        state.key.action_id,
    )
    .await
    .unwrap();
    assert_eq!(actual.record_version, canceled.record_version);
    assert_eq!(actual.phase, decisions::model::Phase::Cancelled);
    assert!(
        read_contact(&mut client, &principal, Uuid::new_v4(), case.header.context)
            .await
            .is_err()
    );
    assert!(
        read_context_metadata(&mut client, &principal, Uuid::new_v4(), case.header.context)
            .await
            .is_err()
    );
    assert!(
        read_action_status(
            &mut client,
            &principal,
            Uuid::new_v4(),
            case.header.context,
            Uuid::new_v4()
        )
        .await
        .is_err()
    );
    revoke_grant(&mut client, &case.owner, issued.grant_id)
        .await
        .unwrap();
    assert!(
        read_action_status(
            &mut client,
            &principal,
            request,
            case.header.context,
            state.key.action_id
        )
        .await
        .is_err()
    );
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM workflow_integration_access WHERE operation=16",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn transaction_scope_rechecks_device_and_connector_key_revocation() {
    let case = Case::new().await;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut client = case.f.connect().await;
    for sql in [
        "UPDATE devices SET revoked_at=clock_timestamp() WHERE account_id=$1",
        "UPDATE connector_keys SET retired_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE account_id=$1",
    ] {
        let tx = client.transaction().await.unwrap();
        let mut permit = scope::lock_scope(
            &tx,
            &principal,
            case.header.context,
            Operation::ContextMetadata,
        )
        .await
        .unwrap();
        tx.execute(sql, &[&case.f.account]).await.unwrap();
        assert!(matches!(
            permit.recheck().await,
            Err(auth::AuthError::Forbidden)
        ));
        drop(permit);
        tx.rollback().await.unwrap();
    }
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn integration_proposal_retries_share_action_ledger_and_require_separate_owner_approval() {
    use crate::http_owner_conversations::context::decisions::{
        self,
        model::{Decision, Phase},
    };
    let mut case = Case::with_signer(Some(120000)).await;
    case.request.permissions = Permissions::new(&[Operation::Propose]).unwrap();
    let descriptor = case.descriptor().await;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut client = case.f.connect().await;
    let request = Uuid::new_v4();
    let first = propose_action(&mut client, &principal, request, descriptor.clone())
        .await
        .unwrap();
    let retry = propose_action(&mut client, &principal, request, descriptor.clone())
        .await
        .unwrap();
    assert_eq!(first.key, retry.key);
    assert_eq!(first.phase, Phase::Proposed);
    let facts = client.query_one("SELECT (SELECT count(*) FROM workflow_actions),(SELECT count(*) FROM workflow_action_mutations),actor_kind,actor_grant_id,actor_user_id FROM workflow_action_mutations", &[]).await.unwrap();
    assert_eq!(facts.get::<_, i64>(0), 1);
    assert_eq!(facts.get::<_, i64>(1), 1);
    assert_eq!(facts.get::<_, String>(2), "integration");
    assert_eq!(facts.get::<_, Uuid>(3), issued.grant_id);
    assert_eq!(facts.get::<_, Option<Uuid>>(4), None);
    let origin: Uuid = client
        .query_one("SELECT integration_origin_grant FROM workflow_actions", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(origin, issued.grant_id);
    assert!(
        client
            .execute(
                "UPDATE workflow_actions SET integration_origin_grant=NULL",
                &[]
            )
            .await
            .is_err()
    );
    assert!(client.execute("UPDATE workflow_action_mutations SET actor_kind='owner',actor_user_id=$1,actor_grant_id=NULL", &[&case.owner.user_id]).await.is_err());
    let mut changed = descriptor.clone();
    changed.commitment = "sensitive".into();
    assert!(matches!(
        propose_action(&mut client, &principal, request, changed).await,
        Err(auth::AuthError::Conflict)
    ));
    for operation in [
        Operation::ContactRead,
        Operation::ContextMetadata,
        Operation::ContextContent,
        Operation::Status,
        Operation::Schedule,
        Operation::Send,
    ] {
        assert!(principal.require(operation).is_err());
    }
    let approved = decisions::decide(
        &mut client,
        &case.owner,
        Uuid::new_v4(),
        first.record_version,
        first.key,
        Decision::Approve,
    )
    .await
    .unwrap();
    assert_eq!(approved.phase, Phase::Approved);
    assert!(
        client
            .query_one(
                "SELECT workflow_action_origin_current($1,$2)",
                &[&case.f.account, &first.key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let takeout = decisions::lifecycle::export(&mut client, &case.owner, [None; 7])
        .await
        .unwrap();
    let proposal = takeout
        .mutations
        .items
        .iter()
        .find(|item| item["actor_kind"] == "integration")
        .unwrap();
    assert_eq!(proposal["actor_grant_id"], issued.grant_id.to_string());
    assert!(proposal["actor_user_id"].is_null());
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    revoke_grant(&mut client, &case.owner, issued.grant_id)
        .await
        .unwrap();
    assert!(
        !client
            .query_one(
                "SELECT workflow_action_origin_current($1,$2)",
                &[&case.f.account, &first.key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(
        propose_action(&mut client, &principal, request, descriptor)
            .await
            .is_err()
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn integration_proposals_reject_scope_changes_and_replay_after_owner_takeover() {
    use crate::http_owner_conversations::context::decisions;
    let mut case = Case::with_signer(Some(120000)).await;
    case.request.permissions = Permissions::new(&[Operation::Propose]).unwrap();
    let descriptor = case.descriptor().await;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut client = case.f.connect().await;
    for field in 0..6 {
        let mut wrong = descriptor.clone();
        match field {
            0 => wrong.account_id = Uuid::new_v4().to_string(),
            1 => wrong.line_id = Uuid::new_v4().to_string(),
            2 => wrong.recipient_id = Uuid::new_v4().to_string(),
            3 => wrong.purpose_id = "00000000-0000-0000-0000-000000000001".into(),
            4 => wrong.content_version = 2,
            _ => wrong.content_digest = decisions::descriptor::hex(&[0; 32]),
        }
        assert!(
            propose_action(&mut client, &principal, Uuid::new_v4(), wrong)
                .await
                .is_err()
        );
    }
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM workflow_actions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let request = Uuid::new_v4();
    propose_action(&mut client, &principal, request, descriptor.clone())
        .await
        .unwrap();
    decisions::takeover(
        &mut client,
        &case.owner,
        Uuid::new_v4(),
        case.header.context,
    )
    .await
    .unwrap();
    assert!(
        propose_action(&mut client, &principal, request, descriptor.clone())
            .await
            .is_err()
    );
    let mut next = descriptor;
    next.action_id = Uuid::new_v4().to_string();
    assert!(
        propose_action(&mut client, &principal, Uuid::new_v4(), next)
            .await
            .is_err()
    );
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM workflow_actions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn workflow_grant_cannot_outlive_verified_role_five_signer_or_consume_factor_on_refusal() {
    let mut case = Case::with_signer(Some(45000)).await;
    case.request.permissions = Permissions::new(&[Operation::Propose]).unwrap();
    case.request.expires_ms = case.header.expires_ms - 1000;
    assert!(case.issue().await.is_err());
    let counts=case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_integration_grants),(SELECT count(*) FROM owner_mfa_recovery_codes WHERE used_at IS NULL)",&[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 1);
    case.request.expires_ms = case.header.expires_ms - 30000;
    assert!(case.issue().await.is_ok());
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn sql_origin_fence_requires_live_grant_creator_context_and_current_key_authority() {
    let mut case = Case::with_signer(Some(120000)).await;
    case.request.permissions = Permissions::new(&[Operation::Propose]).unwrap();
    let descriptor = case.descriptor().await;
    let issued = case.issue().await.unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut client = case.f.connect().await;
    let action = propose_action(&mut client, &principal, Uuid::new_v4(), descriptor)
        .await
        .unwrap();
    assert!(
        client
            .query_one(
                "SELECT workflow_action_origin_current($1,$2)",
                &[&case.f.account, &action.key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    for change in [
        "UPDATE devices SET revoked_at=clock_timestamp()",
        "UPDATE connector_keys SET retired_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second'",
        "UPDATE users SET mfa_enabled=false",
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp()",
        "UPDATE workflow_contexts SET purged_at=clock_timestamp()",
    ] {
        let tx = client.transaction().await.unwrap();
        tx.batch_execute(change).await.unwrap();
        assert!(
            !tx.query_one(
                "SELECT workflow_action_origin_current($1,$2)",
                &[&case.f.account, &action.key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0),
            "{change}"
        );
        tx.rollback().await.unwrap();
    }
    assert!(
        !client
            .query_one(
                "SELECT workflow_action_origin_current($1,$2)",
                &[&Uuid::new_v4(), &action.key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(
        !client
            .query_one(
                "SELECT workflow_integration_grant_current($1,$2,$3,64)",
                &[&case.f.account, &issued.grant_id, &action.key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(
        client
            .query_one(
                "SELECT workflow_action_origin_current($1,$2)",
                &[&case.f.account, &action.key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let tx = client.transaction().await.unwrap();
    lifecycle::erase_contact(&tx, case.f.account, case.request.contact)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        !client
            .query_one(
                "SELECT workflow_action_origin_current($1,$2)",
                &[&case.f.account, &action.key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(
        client
            .query_one("SELECT integration_origin_grant FROM workflow_actions", &[])
            .await
            .unwrap()
            .get::<_, Uuid>(0),
        issued.grant_id
    );
    case.f.cleanup().await;
}
