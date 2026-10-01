// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::{ApiPrincipal, TokenHasher},
    sealed_envelope::ExpectedRecipient,
    sealed_manifest_store,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};

pub(crate) struct Case {
    pub(crate) base: super::super::super::tests::Case,
    pub(crate) descriptor: Descriptor,
    pub(crate) contact: Uuid,
    pub(crate) outbound: SigningKey,
    pub(crate) outbound_id: [u8; 32],
    pub(crate) phone_reader: [u8; 32],
    pub(crate) api: ApiPrincipal,
    pub(crate) hasher: TokenHasher,
    enrollment: SigningKey,
}
impl Case {
    pub(crate) async fn new() -> Self {
        let mut base = super::super::super::tests::Case::new().await;
        let f = &mut base.f;
        f.advance();
        f.bytes.truncate(f.bytes.len() - 64);
        f.bytes[150] += 2;
        let mut outbound = None;
        let mut outbound_id = [0; 32];
        let mut phone_reader = [0; 32];
        let now = activation::now(&f.connect().await.transaction().await.unwrap())
            .await
            .unwrap();
        for (role, scope) in [(1, 4u16), (5, 1u16)] {
            let key = SigningKey::generate_from_rng(&mut rand::rng());
            let point = key.verifying_key().to_sec1_point(false);
            let algorithm = if role == 1 { [0, 16] } else { [1, 1] };
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
            f.bytes.extend(f.line.as_bytes());
            f.bytes.extend(scope.to_be_bytes());
            f.bytes.extend(((now - 1000) as u64).to_be_bytes());
            f.bytes.extend(((now + 240000) as u64).to_be_bytes());
            f.bytes.push(1);
            if role == 1 {
                phone_reader = id;
            } else {
                outbound_id = id;
                outbound = Some(key);
            }
        }
        f.bytes.extend([0; 64]);
        // Manifest leaf records have a canonical role/key order.
        let mut leaves: Vec<Vec<u8>> = f.bytes[151..f.bytes.len() - 64]
            .chunks_exact(149)
            .map(|v| v.to_vec())
            .collect();
        leaves.sort_by(|a, b| a[..33].cmp(&b[..33]));
        f.bytes.truncate(151);
        for leaf in leaves {
            f.bytes.extend(leaf);
        }
        f.bytes.extend([0; 64]);
        f.resign();
        let mut db = f.connect().await;
        let tx = db.transaction().await.unwrap();
        let mut admission = sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
            .await
            .unwrap();
        admission.context(&f.wanted()).await.unwrap();
        drop(admission);
        tx.commit().await.unwrap();
        let row=f.db.query_one("SELECT version,semantic_digest FROM sealed_manifest_authorities WHERE account_id=$1",&[&f.account]).await.unwrap();
        base.h.manifest_version = row.get(0);
        base.h.manifest_digest = row.get::<_, Vec<u8>>(1).try_into().unwrap();
        let bytes = base.bytes();
        super::super::super::write(
            &mut base.f.connect().await,
            &base.owner,
            Uuid::new_v4(),
            0,
            &bytes,
        )
        .await
        .unwrap();
        let f = &base.f;
        let contact = Uuid::new_v4();
        f.db.execute(
            "INSERT INTO contacts(id,account_id,recipient_e164) VALUES($1,$2,$3)",
            &[&contact, &f.account, &base.s.peer],
        )
        .await
        .unwrap();
        f.db.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'transactional','grant','manual_entry',clock_timestamp(),$4)",&[&Uuid::new_v4(),&f.account,&contact,&base.owner.user_id]).await.unwrap();
        let descriptor = Descriptor {
            account_id: f.account.to_string(),
            action_id: Uuid::new_v4().to_string(),
            revision: 1,
            line_id: f.line.to_string(),
            recipient_id: contact.to_string(),
            purpose_id: "00000000-0000-0000-0000-000000000001".into(),
            content_ref: base.h.context.to_string(),
            content_digest: super::super::descriptor::hex(&Sha256::digest(bytes)),
            content_version: 1,
            not_before: now / 1000,
            expires_at: (now / 1000) + 90,
            timezone: "UTC".into(),
            window_id: "exact-window".into(),
            routine_id: Uuid::new_v4().to_string(),
            authority_generation: 1,
            commitment: "informational".into(),
        };
        let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let pepper = crate::test_keys::key(76);
        let mut mac = Hmac::<Sha256>::new_from_slice(&pepper).unwrap();
        mac.update(b"api-key-v1\0");
        mac.update(token.as_bytes());
        let hash = mac.finalize().into_bytes().to_vec();
        f.db.execute("INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id) VALUES($1,$2,$3,$4,$5,ARRAY['messages:send'],$6)",&[&Uuid::new_v4(),&f.account,&base.owner.user_id,&&token[4..16],&hash,&f.device]).await.unwrap();
        f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',1000)",&[&f.account]).await.unwrap();
        let hasher = TokenHasher::new(pepper).unwrap();
        let api = crate::auth::authenticate_api_key(&f.db, &hasher, &token)
            .await
            .unwrap();
        let enrollment = SigningKey::generate_from_rng(&mut rand::rng());
        let point = enrollment.verifying_key().to_sec1_point(false);
        let fingerprint = Sha256::digest(point.as_bytes());
        f.db.execute(
            "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
            &[&f.device, &point.as_bytes(), &fingerprint.as_slice()],
        )
        .await
        .unwrap();
        Self {
            base,
            descriptor,
            contact,
            outbound: outbound.unwrap(),
            outbound_id,
            phone_reader,
            api,
            hasher,
            enrollment,
        }
    }
    pub(crate) async fn propose(&self, d: Descriptor) -> ActionState {
        register(
            &mut self.base.f.connect().await,
            &self.base.owner,
            Uuid::new_v4(),
            d,
        )
        .await
        .unwrap()
    }
    pub(crate) async fn approved(&self) -> ActionState {
        let p = self.propose(self.descriptor.clone()).await;
        decide(
            &mut self.base.f.connect().await,
            &self.base.owner,
            Uuid::new_v4(),
            1,
            p.key,
            Decision::Approve,
        )
        .await
        .unwrap()
    }
    pub(crate) async fn capture(&self, sequence: u64) -> Uuid {
        let event = Uuid::new_v4();
        crate::http_owner_conversations::activation::tests::capture(
            &self.base.f,
            &self.base.s,
            event,
            sequence,
            self.base.s.peer.as_bytes(),
        )
        .await
        .unwrap();
        event
    }
    pub(crate) async fn cleanup(self) {
        self.base.cleanup().await;
    }
    pub(crate) async fn bind(&mut self, approved: ActionState) -> ActionState {
        let message = Uuid::new_v4();
        let f = &mut self.base.f;
        let now = activation::now(&f.connect().await.transaction().await.unwrap())
            .await
            .unwrap();
        let original_signer = f.signer;
        let original_key = f.event_signer.clone();
        let original_readers = f.readers.clone();
        f.signer = self.outbound_id;
        f.event_signer = self.outbound.clone();
        f.readers = vec![
            ExpectedRecipient {
                role: 1,
                key_id: self.phone_reader,
            },
            ExpectedRecipient {
                role: 2,
                key_id: self.base.h.reader,
            },
        ];
        let mut bytes = crate::sealed_outbound::tests::envelope(f, message, now, 60000);
        bytes[74..82].copy_from_slice(&(self.base.h.manifest_version as u64).to_be_bytes());
        crate::sealed_outbound::tests::signed(f, &mut bytes);
        f.signer = original_signer;
        f.event_signer = original_key;
        f.readers = original_readers;
        crate::sealed_outbound::admit_candidate02_with_limit(
            &mut f.connect().await,
            &self.api,
            &self.hasher,
            crate::sealed_outbound::WriterContext {
                site_id: "manifest-test",
                deployment_epoch: 1,
                billing_enabled: true,
            },
            &bytes,
            Some(1),
        )
        .await
        .unwrap();
        let binding = store::RenderedBinding {
            message_id: message,
            dispatch_id: Uuid::new_v4(),
            message_digest: super::super::descriptor::hex(&Sha256::digest(bytes)),
        };
        bind_message(
            &mut f.connect().await,
            &self.base.owner,
            Uuid::new_v4(),
            approved.record_version,
            approved.key,
            binding,
        )
        .await
        .unwrap()
    }
    pub(crate) async fn dispatch(&self, key: ActionKey) -> Uuid {
        let row=self.base.f.db.query_one("SELECT message_id,dispatch_id FROM workflow_message_links WHERE account_id=$1 AND action_id=$2 AND revision=$3",&[&key.account_id,&key.action_id,&key.revision]).await.unwrap();
        let message: Uuid = row.get(0);
        let dispatch: Uuid = row.get(1);
        let mut db = self.base.f.connect().await;
        let tx = db.transaction().await.unwrap();
        let mut permit = lock_approved(&tx, &self.base.owner, key).await.unwrap();
        permit.mark_dispatching(message, dispatch).await.unwrap();
        drop(permit);
        tx.commit().await.unwrap();
        message
    }
    pub(crate) async fn grant(
        &self,
    ) -> Result<Option<crate::sealed_dispatch::wire::GrantFrame>, crate::sealed_dispatch::Error>
    {
        let f = &self.base.f;
        f.db.batch_execute("UPDATE deployment_authority SET dispatch_enabled=true")
            .await
            .unwrap();
        let session = zrotext_delivery_store::SessionRecord {
            account_id: f.account,
            device_id: f.device,
            site_id: "manifest-test".into(),
            instance_id: "fixture".into(),
            epoch: 1,
            deployment_epoch: 1,
        };
        let ready = crate::sealed_dispatch::wire::Ready {
            grant_version: 1,
            connection_epoch: 1,
            line_id: f.line,
            binding_generation: 1,
            reader_key_id: URL_SAFE_NO_PAD.encode(self.phone_reader),
        };
        let policy = crate::alpha_policy::AlphaPolicy::parse(
            Some("true"),
            Some(&f.account.to_string()),
            Some("+12"),
        )
        .unwrap();
        crate::sealed_dispatch::grant(&mut f.connect().await, &session, &ready, &policy).await
    }
    pub(crate) async fn fetch(
        &self,
        frame: crate::sealed_dispatch::wire::GrantFrame,
    ) -> Result<Vec<u8>, crate::sealed_dispatch::Error> {
        let signature: Signature = self
            .enrollment
            .sign(&crate::sealed_dispatch::wire::fetch_transcript(&frame).unwrap());
        let input = crate::sealed_dispatch::wire::Fetch {
            grant: frame,
            signature_der: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        };
        let f = &self.base.f;
        let policy = crate::alpha_policy::AlphaPolicy::parse(
            Some("true"),
            Some(&f.account.to_string()),
            Some("+12"),
        )
        .unwrap();
        crate::sealed_dispatch::fetch(&mut f.connect().await, &input, "manifest-test", 1, &policy)
            .await
    }
}
