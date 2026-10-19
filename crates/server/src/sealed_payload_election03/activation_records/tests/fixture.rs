// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine auth/MFA, enrolled device, root and registered-v2 ceremonies on the
//! stock runtime grants. Only the claimed lease/Android observation are seeded;
//! this fixture does not claim a real socket, phone, hardware reader or SIM.
use super::*;
use crate::{
    auth, enrollment, http_owner_conversations::sealed_line_setup::registration as setup,
    inbound::InboundSession, sealed_root_ceremony as root,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
    pkcs8::EncodePublicKey,
};
use sha2::{Digest, Sha256};

pub(crate) struct Case {
    pub db: Fixture,
    pub principal: auth::SessionPrincipal,
    pub device: Uuid,
    pub line: Uuid,
    pub registration: Uuid,
    pub challenge: crate::sealed_inbound::line_activation::LineChallenge,
    pub device_statement: Vec<u8>,
    pub device_der: Vec<u8>,
    pub owner_statement: Vec<u8>,
    pub owner_der: Vec<u8>,
    pub hasher: std::sync::Arc<auth::TokenHasher>,
    pub cipher: std::sync::Arc<auth::mfa::MfaCipher>,
    pub password: String,
    pub credentials: auth::SessionCredentials,
    pub recovery: Vec<String>,
    pub root_key: SigningKey,
    pub phone_key: SigningKey,
    pub approval_key: SigningKey,
    pub pin: [u8; 94],
}
impl Case {
    pub(crate) async fn new() -> Self {
        let mut db = Fixture::runtime().await;
        crate::payload_profile_v2_receipts::require(&db.reader)
            .await
            .unwrap();
        let hasher = std::sync::Arc::new(
            auth::TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap(),
        );
        let cipher = std::sync::Arc::new(
            auth::mfa::MfaCipher::new(rand::random::<[u8; 32]>().to_vec()).unwrap(),
        );
        let password = format!("synthetic-owner-{}", Uuid::new_v4().simple());
        let account = auth::register(
            &mut db.reader,
            &hasher,
            "activation-owner@example.test",
            &password,
        )
        .await
        .unwrap();
        assert!(
            auth::verify_email(&mut db.reader, &hasher, &account.verification_token)
                .await
                .unwrap()
        );
        let session = auth::login(
            &db.reader,
            &hasher,
            "activation-owner@example.test",
            &password,
        )
        .await
        .unwrap();
        let principal = auth::authenticate_session(&db.reader, &hasher, &session.token)
            .await
            .unwrap();
        let mfa = auth::mfa::begin_enrollment(&mut db.reader, &cipher, &principal, &password)
            .await
            .unwrap();
        let code = totp_rs::Builder::new()
            .with_secret(totp_rs::Secret::try_from_base32(&mfa.secret_base32).unwrap())
            .build()
            .unwrap()
            .generate_current()
            .to_string();
        let recovery =
            auth::mfa::confirm_enrollment(&mut db.reader, &cipher, &hasher, &principal, &code)
                .await
                .unwrap()
                .codes;
        let root_key = SigningKey::generate_from_rng(&mut rand::rng());
        let pin: [u8; 94] = [
            b"ZTRP\x02".as_slice(),
            account.account_id.as_bytes(),
            &1u64.to_be_bytes(),
            root_key.verifying_key().to_sec1_point(false).as_bytes(),
        ]
        .concat()
        .try_into()
        .unwrap();
        let issued = root::issue_challenge(&mut db.reader, &hasher, &principal, ORIGIN, pin)
            .await
            .unwrap();
        let signature: Signature = root_key.sign(&issued.unsigned);
        root::complete_genesis(
            &mut db.reader,
            &hasher,
            &cipher,
            &principal,
            ORIGIN,
            root::Completion {
                unsigned: &issued.unsigned,
                signature: &signature.normalize_s().to_bytes(),
                factor: &recovery[0],
            },
        )
        .await
        .unwrap();
        let phone_key = SigningKey::generate_from_rng(&mut rand::rng());
        let approval_key = SigningKey::generate_from_rng(&mut rand::rng());
        let enrollment_hasher =
            enrollment::EnrollmentHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
        let ticket = enrollment::create_pairing(
            &db.reader,
            &enrollment_hasher,
            &principal,
            "synthetic original phone",
        )
        .await
        .unwrap();
        let public = phone_key.verifying_key().to_public_key_der().unwrap();
        let claim = enrollment::claim_pairing(
            &mut db.reader,
            &enrollment_hasher,
            ticket.id,
            &ticket.token,
            public.as_bytes(),
        )
        .await
        .unwrap();
        let phone_point = phone_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let paired_fingerprint: [u8; 32] = Sha256::digest(&phone_point).into();
        let unsigned = enrollment::enrollment_challenge_bytes(
            account.account_id,
            ticket.id,
            &paired_fingerprint,
            &claim.challenge_nonce,
        );
        let proof: Signature = phone_key.sign(&unsigned);
        assert!(
            enrollment::prove_pairing_key(
                &mut db.reader,
                &enrollment_hasher,
                ticket.id,
                &claim.challenge_nonce,
                proof.to_der().as_bytes()
            )
            .await
            .unwrap()
        );
        let device = enrollment::approve_pairing(
            &mut db.reader,
            &principal,
            ticket.id,
            &claim.comparison_code,
            &claim.key_fingerprint,
        )
        .await
        .unwrap();
        // This synthetic claimed lease isolates the original-capture boundary.
        // The separate socket tests establish the real handshake/claim path.
        db.reader
            .execute(
                "INSERT INTO public.sites(site_id) VALUES('activation-test')",
                &[],
            )
            .await
            .unwrap();
        db.reader.execute("INSERT INTO public.device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,deployment_epoch,lease_until,line_activation_version) VALUES($1,$2,'activation-test','fixture',1,1,clock_timestamp()+interval '10 minutes',2)", &[&device,&account.account_id]).await.unwrap();
        let line = Uuid::new_v4();
        let statement = setup::issue(
            &mut db.reader,
            &principal,
            ORIGIN,
            setup::Selection {
                device,
                line,
                generation: 1,
                root_fingerprint: zrotext_root_material::sealed_root_enrollment::root_fingerprint(
                    &pin,
                    account.account_id.as_bytes(),
                )
                .unwrap(),
                paired_fingerprint,
                approval_point: approval_key
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                connection_epoch: 1,
                deployment_epoch: 1,
                site_id: "activation-test".into(),
                instance_id: "fixture".into(),
            },
        )
        .await
        .unwrap();
        let registration = Uuid::from_bytes(statement.scope().challenge);
        let unsigned = zrotext_root_material::line_key_registration::encode(&statement).unwrap();
        let root_sig: Signature = root_key.sign(&unsigned);
        let approval_sig: Signature = approval_key.sign(&unsigned);
        setup::complete(
            &mut db.reader,
            &principal,
            ORIGIN,
            &hasher,
            &cipher,
            registration,
            setup::Completion {
                unsigned: &unsigned,
                root_signature: &root_sig.normalize_s().to_bytes(),
                approval_signature: &approval_sig.normalize_s().to_bytes(),
                factor: &recovery[1],
            },
        )
        .await
        .unwrap();
        let lease = InboundSession {
            account_id: account.account_id,
            device_id: device,
            site_id: "activation-test",
            instance_id: "fixture",
            connection_epoch: 1,
            deployment_epoch: 1,
        };
        let challenge = run::open(
            &mut db.reader,
            &principal,
            line,
            device,
            run::Purpose::Sealed,
            registration,
            Some(registration),
        )
        .await
        .unwrap()
        .tuple;
        let mut observation = [0u8; 121];
        observation[..2].copy_from_slice(&35u16.to_be_bytes());
        observation[2..4].copy_from_slice(&2u16.to_be_bytes());
        observation[4..8].copy_from_slice(&1i32.to_be_bytes());
        observation[8] = 2;
        for at in [9, 25, 49, 73] {
            observation[at..at + 16].copy_from_slice(Uuid::new_v4().as_bytes());
        }
        observation[65..73].copy_from_slice(&1i64.to_be_bytes());
        observation[89..].fill(7);
        let declared = v2::ObservationV2::decode(&observation).unwrap();
        let device_statement =
            v2::device_statement(v2::PurposeV2::Sealed, &challenge, &declared).unwrap();
        let proof: Signature = phone_key.sign(&device_statement.bytes());
        let device_der = proof.to_der().as_bytes().to_vec();
        assert!(
            run::record_device_proof(
                &mut db.reader,
                lease,
                run::Purpose::Sealed,
                challenge.id,
                &observation,
                &device_der
            )
            .await
            .unwrap()
        );
        let owner_statement = v2::owner_statement(&device_statement, &device_der)
            .unwrap()
            .bytes();
        let signature: Signature = approval_key.sign(&owner_statement);
        Self {
            db,
            principal,
            device,
            line,
            registration,
            challenge,
            device_statement: device_statement.bytes(),
            device_der,
            owner_statement,
            owner_der: signature.to_der().as_bytes().to_vec(),
            hasher,
            cipher,
            password,
            credentials: session,
            recovery,
            root_key,
            phone_key,
            approval_key,
            pin,
        }
    }
    pub(crate) fn lease(&self) -> InboundSession<'static> {
        InboundSession {
            account_id: self.principal.tenant.account_id(),
            device_id: self.device,
            site_id: "activation-test",
            instance_id: "fixture",
            connection_epoch: 1,
            deployment_epoch: 1,
        }
    }
    pub(crate) async fn approve(&mut self) {
        run::approve(
            &mut self.db.reader,
            &self.principal,
            self.line,
            self.challenge.id,
            run::Purpose::Sealed,
            &self.owner_der,
        )
        .await
        .unwrap();
    }
    pub(super) async fn locator(&self) -> Locator {
        Locator { account:self.principal.tenant.account_id(), binding:self.db.reader.query_one(
            "SELECT binding_id FROM public.payload_profile_v2_activation_receipts WHERE account_id=$1 AND challenge_id=$2",
            &[&self.principal.tenant.account_id(),&self.challenge.id]).await.unwrap().get(0),selected_reader_key_id:[9;32] }
    }
}
