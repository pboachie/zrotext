// SPDX-License-Identifier: AGPL-3.0-only
//! Tests for the dormant connector registration and key lifecycle. The
//! PostgreSQL-backed tests share the fixture style of the sealed manifest
//! store: one disposable schema per test, real prerequisite migrations,
//! synthetic identities only. Manifest bytes are built exactly like
//! `sealed_manifest_store` fixtures, plus role-3 integration records.

use super::*;
use crate::auth;
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
use sha2::{Digest, Sha256};
use tokio_postgres::NoTls;

fn token_digest(pepper: &[u8], domain: &[u8], token: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(pepper).unwrap();
    mac.update(domain);
    mac.update(&[0]);
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().into()
}

fn key_id(role: u8, point: &[u8]) -> [u8; 32] {
    let algorithm: [u8; 2] = if role <= 3 { [0, 16] } else { [1, 1] };
    Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &algorithm, point].concat()).into()
}

/// One manifest role record (pre-serialization). All points are synthetic.
struct RoleRecord {
    role: u8,
    point: [u8; 65],
    scope: u16,
    device: [u8; 16],
    line: [u8; 16],
}

fn point_bytes(key: &SigningKey) -> [u8; 65] {
    key.verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn random_point() -> [u8; 65] {
    point_bytes(&SigningKey::generate_from_rng(&mut rand::rng()))
}

/// Minimal manifest builder matching the candidate-02 wire format used by
/// `sealed_manifest_store` fixtures; records are emitted in (role, id) order.
fn build_manifest(
    account: &Uuid,
    generation: u64,
    version: u64,
    now: i64,
    anchor: [u8; 32],
    root: &SigningKey,
    roles: &[RoleRecord],
) -> Vec<u8> {
    let root_point = root.verifying_key().to_sec1_point(false);
    let mut bytes = b"ZTMA\x02".to_vec();
    bytes.extend(account.as_bytes());
    bytes.extend(generation.to_be_bytes());
    bytes.extend(version.to_be_bytes());
    bytes.extend((now as u64 - 1_000).to_be_bytes());
    bytes.extend((now as u64 + 300_000).to_be_bytes());
    bytes.extend(anchor);
    bytes.extend(root_point.as_bytes());
    bytes.push(roles.len() as u8);
    let mut records: Vec<(u8, [u8; 32], &RoleRecord)> = roles
        .iter()
        .map(|r| (r.role, key_id(r.role, &r.point), r))
        .collect();
    records.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    for (_, _, record) in records {
        bytes.push(record.role);
        bytes.extend(key_id(record.role, &record.point));
        bytes.extend(record.point);
        bytes.extend(record.device);
        bytes.extend(record.line);
        bytes.extend(record.scope.to_be_bytes());
        bytes.extend((now as u64 - 2_000).to_be_bytes());
        bytes.extend((now as u64 + 400_000).to_be_bytes());
        bytes.push(1);
    }
    bytes.extend([0; 64]);
    let n = bytes.len() - 64;
    let signature: Signature = root.sign(
        &[
            b"ZTSE/manifest/v2\0".as_slice(),
            &(n as u32).to_be_bytes(),
            &bytes[..n],
        ]
        .concat(),
    );
    bytes[n..].copy_from_slice(&signature.normalize_s().to_bytes());
    bytes
}

fn pin_for(account: &Uuid, generation: u64, root: &SigningKey) -> Vec<u8> {
    let mut pin = b"ZTRP\x02".to_vec();
    pin.extend(account.as_bytes());
    pin.extend(generation.to_be_bytes());
    pin.extend(root.verifying_key().to_sec1_point(false).as_bytes());
    pin
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub(crate) struct Fixture {
    pub(crate) url: String,
    pub(crate) schema: String,
    pub(crate) db: Client,
    pub(crate) account: Uuid,
    pub(crate) line: Uuid,
    pub(crate) other_line: Uuid,
    pub(crate) root: SigningKey,
    pub(crate) pin: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    /// (synthetic signing key, manifest role-3 scope) pairs.
    pub(crate) integration: Vec<(SigningKey, u16)>,
    pub(crate) hasher: TokenHasher,
    pub(crate) proposer_token: String,
    pub(crate) approver_token: String,
}

impl Fixture {
    /// Default fixture: three integration keys with scopes (12, 12, 4).
    pub(crate) async fn new() -> Self {
        let scopes = [12u16, 12, 4];
        let integration = scopes
            .iter()
            .map(|scope| (SigningKey::generate_from_rng(&mut rand::rng()), *scope))
            .collect();
        Self::with_integration(integration).await
    }

    pub(crate) async fn with_integration(integration: Vec<(SigningKey, u16)>) -> Self {
        let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL").expect("disposable test database");
        let (db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("connector_registry_{}", Uuid::new_v4().simple());
        db.batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
        // Real prerequisite migrations, not a permissive substitute schema
        // (the same set the sealed manifest store fixture applies).
        for sql in [
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
            include_str!("../../../../deploy/compose/migrations/019_line_activation_contract.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/020_enrollment_retention_indexes.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
            include_str!("../../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
            ),
            include_str!(
                "../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/025_account_recovery.sql"),
            include_str!("../../../../deploy/compose/migrations/026_data_retention.sql"),
            include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
            include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
            include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
            include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
            include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
            include_str!("../../../../deploy/compose/migrations/032_line_opt_out_events.sql"),
            include_str!("../../../../deploy/compose/migrations/033_sms_line_binding_scope.sql"),
            include_str!("../../../../deploy/compose/migrations/034_delivery_sweep_index.sql"),
            include_str!("../../../../deploy/compose/migrations/035_sms_owner_key_ceremony.sql"),
            include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/037_sms_line_activation_exchange.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/040_radio_evidence_index.sql"),
            include_str!("../../../../deploy/compose/migrations/041_device_preconditions.sql"),
            include_str!("../../../../deploy/compose/migrations/042_sealed_manifest_authority.sql"),
            include_str!("../../../../deploy/compose/migrations/043_sealed_candidate_inbound.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/044_sealed_root_role_reservations.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/045_sealed_outbound_queue.sql"),
            include_str!("../../../../deploy/compose/migrations/046_sealed_root_ceremonies.sql"),
            include_str!("../../../../deploy/compose/migrations/067_connector_registration.sql"),
        ] {
            // Mirror the migrator's autocommit index preparation.
            if sql.contains("CREATE FUNCTION messages_in_flight_index_ready") {
                db.batch_execute("CREATE INDEX CONCURRENTLY messages_in_flight_updated ON messages(updated_at,id) WHERE state IN ('claimed','submitting','submitted')").await.unwrap();
            }
            if sql.contains("CREATE FUNCTION message_events_radio_evidence_index_ready") {
                db.batch_execute("CREATE INDEX CONCURRENTLY message_events_attempt_evidence ON message_events(attempt_id,evidence_code)").await.unwrap();
            }
            db.batch_execute(sql).await.unwrap();
        }
        let account = Uuid::new_v4();
        let line = Uuid::new_v4();
        let other_line = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        for l in [line, other_line] {
            db.execute(
                "INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) \
             VALUES($1,$2,'active',now(),1,1)",
                &[&l, &account],
            )
            .await
            .unwrap();
        }
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let pin = pin_for(&account, 1, &root);
        let now: i64 = db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let mut roles = vec![
            RoleRecord {
                role: 2,
                point: random_point(),
                scope: 12,
                device: [0; 16],
                line: [0; 16],
            },
            RoleRecord {
                role: 4,
                point: random_point(),
                scope: 2,
                device: [7; 16],
                line: *line.as_bytes(),
            },
            RoleRecord {
                role: 6,
                point: point_bytes(&root.clone()),
                scope: 0,
                device: [0; 16],
                line: [0; 16],
            },
        ];
        for (key, scope) in &integration {
            roles.push(RoleRecord {
                role: 3,
                point: point_bytes(key),
                scope: *scope,
                device: [0; 16],
                line: [0; 16],
            });
        }
        let bytes = build_manifest(&account, 1, 1, now, [0; 32], &root, &roles);
        let fingerprint =
            Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), &pin].concat()).to_vec();
        let digest = Sha256::digest(&bytes[..bytes.len() - 64]).to_vec();
        db.execute(
            "INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) \
         VALUES($1,$2,$3,1,$4)",
            &[&account, &pin, &fingerprint, &vec![0u8; 32]],
        )
        .await
        .unwrap();
        db.execute(
            "UPDATE sealed_manifest_authorities SET version=1,semantic_digest=$2,manifest=$3, \
         accepted_at_ms=$4,last_verified_ms=$4 WHERE account_id=$1",
            &[&account, &digest, &bytes, &now],
        )
        .await
        .unwrap();
        // Owner with MFA and two live sessions: one proposes, one approves.
        let user = Uuid::new_v4();
        let pepper = rand::random::<[u8; 32]>().to_vec();
        let hasher = TokenHasher::new(pepper.clone()).unwrap();
        db.execute(
            "INSERT INTO users(id,email,password_hash,email_verified_at,mfa_enabled) \
         VALUES($1,$2,'synthetic',now(),true)",
            &[&user, &format!("{}@example.test", user.simple())],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&account, &user],
        )
        .await
        .unwrap();
        let mut proposer_token = String::new();
        let mut approver_token = String::new();
        for token_slot in [&mut proposer_token, &mut approver_token] {
            let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
            *token_slot = token.clone();
            let hash = token_digest(&pepper, b"session-v1", &token);
            db.execute(
                "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) \
             VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
                &[
                    &Uuid::new_v4(),
                    &account,
                    &user,
                    &&hash[..],
                    &&vec![0u8; 32][..],
                ],
            )
            .await
            .unwrap();
        }
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
        db.execute(
            "INSERT INTO owner_mfa(account_id,user_id,secret_nonce,secret_ciphertext,enabled_at) \
         VALUES($1,$2,$3,$4,now())",
            &[&account, &user, &&nonce[..], &ciphertext],
        )
        .await
        .unwrap();
        Self {
            url,
            schema,
            db,
            account,
            line,
            other_line,
            root,
            pin,
            bytes,
            integration,
            hasher,
            proposer_token,
            approver_token,
        }
    }

    pub(crate) async fn connect(&self) -> Client {
        let (db, connection) = tokio_postgres::connect(&self.url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        db.batch_execute(&format!(
            "SET search_path TO {}; SET statement_timeout='10s'",
            self.schema
        ))
        .await
        .unwrap();
        db
    }

    pub(crate) async fn proposer(&self) -> SessionPrincipal {
        auth::authenticate_session(&self.db, &self.hasher, &self.proposer_token)
            .await
            .unwrap()
    }

    pub(crate) async fn approver(&self) -> SessionPrincipal {
        auth::authenticate_session(&self.db, &self.hasher, &self.approver_token)
            .await
            .unwrap()
    }

    /// The owner-management budget is shared; long scenarios reset the
    /// synthetic counters between lifecycle calls to stay under the burst.
    pub(crate) async fn reset_budget(&self) {
        self.db
            .execute("DELETE FROM auth_abuse_counters", &[])
            .await
            .unwrap();
    }

    pub(crate) fn integration_point(&self, index: usize) -> [u8; 65] {
        point_bytes(&self.integration[index].0.clone())
    }

    pub(crate) fn integration_key_id(&self, index: usize) -> [u8; 32] {
        key_id(3, &self.integration_point(index))
    }

    /// Replace the authority with `bytes` under `pin`/`generation`, modeling
    /// what an accepted ceremony plus admission leaves in storage.
    pub(crate) async fn accept_manifest(
        &self,
        bytes: &[u8],
        generation: i64,
        anchor: &[u8],
        pin: &[u8],
    ) {
        let digest = Sha256::digest(&bytes[..bytes.len() - 64]).to_vec();
        let fingerprint = Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), pin].concat()).to_vec();
        self.db
            .execute(
                "DELETE FROM sealed_manifest_authorities WHERE account_id=$1",
                &[&self.account],
            )
            .await
            .unwrap();
        self.db
            .execute(
                "INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest, \
             version,semantic_digest,manifest,accepted_at_ms,last_verified_ms) \
             VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$8)",
                &[
                    &self.account,
                    &pin,
                    &fingerprint,
                    &generation,
                    &anchor,
                    &digest,
                    &bytes,
                    &(now_ms() as i64),
                ],
            )
            .await
            .unwrap();
    }

    /// Advance the accepted chain: same generation, next version.
    pub(crate) async fn advance_manifest(&mut self) {
        let digest: [u8; 32] = Sha256::digest(&self.bytes[..self.bytes.len() - 64]).into();
        let version = u64::from_be_bytes(self.bytes[29..37].try_into().unwrap());
        self.bytes[29..37].copy_from_slice(&(version + 1).to_be_bytes());
        self.bytes[53..85].copy_from_slice(&digest);
        let n = self.bytes.len() - 64;
        let signature: Signature = self.root.sign(
            &[
                b"ZTSE/manifest/v2\0".as_slice(),
                &(n as u32).to_be_bytes(),
                &self.bytes[..n],
            ]
            .concat(),
        );
        self.bytes[n..].copy_from_slice(&signature.normalize_s().to_bytes());
        let new_digest = Sha256::digest(&self.bytes[..n]).to_vec();
        self.db
            .execute(
                "UPDATE sealed_manifest_authorities SET version=$2,semantic_digest=$3,manifest=$4, \
             accepted_at_ms=$5,last_verified_ms=$5 WHERE account_id=$1",
                &[
                    &self.account,
                    &(version as i64 + 1),
                    &new_digest,
                    &self.bytes,
                    &(now_ms() as i64),
                ],
            )
            .await
            .unwrap();
    }

    /// Root rotation: a fresh generation with a new root, same role points,
    /// so an unchanged connector key is still listed but its stored binding
    /// generation is stale.
    pub(crate) async fn rotate_generation(&mut self) {
        let new_root = SigningKey::generate_from_rng(&mut rand::rng());
        let generation = 2u64;
        let now: i64 = self
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let mut roles = vec![
            RoleRecord {
                role: 2,
                point: random_point(),
                scope: 12,
                device: [0; 16],
                line: [0; 16],
            },
            RoleRecord {
                role: 4,
                point: random_point(),
                scope: 2,
                device: [7; 16],
                line: *self.line.as_bytes(),
            },
            RoleRecord {
                role: 6,
                point: point_bytes(&new_root),
                scope: 0,
                device: [0; 16],
                line: [0; 16],
            },
        ];
        for (key, scope) in &self.integration {
            roles.push(RoleRecord {
                role: 3,
                point: point_bytes(key),
                scope: *scope,
                device: [0; 16],
                line: [0; 16],
            });
        }
        let old_digest: Vec<u8> = self
            .db
            .query_one(
                "SELECT semantic_digest FROM sealed_manifest_authorities WHERE account_id=$1",
                &[&self.account],
            )
            .await
            .unwrap()
            .get(0);
        let bytes = build_manifest(
            &self.account,
            generation,
            1,
            now,
            old_digest.clone().try_into().unwrap(),
            &new_root,
            &roles,
        );
        let pin = pin_for(&self.account, generation, &new_root);
        self.root = new_root;
        self.pin = pin.clone();
        self.bytes = bytes.clone();
        self.accept_manifest(&bytes, generation as i64, &old_digest, &pin)
            .await;
    }

    pub(crate) async fn cleanup(self) {
        self.db
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

/// A read+send request on the fixture's primary line, expiring in an hour.
fn default_request(f: &Fixture, point: [u8; 65]) -> RegistrationRequest {
    let expires = now_ms() + 3_600_000;
    RegistrationRequest {
        display_name: "synthetic-connector".into(),
        key_point: point,
        grants: vec![
            GrantRequest {
                kind: GrantKind::Read {
                    directions: READ_BOTH,
                },
                line_id: f.line,
                conversation_restriction: vec![],
                expires_ms: expires,
            },
            GrantRequest {
                kind: GrantKind::Send,
                line_id: f.line,
                conversation_restriction: vec![],
                expires_ms: expires,
            },
        ],
        expires_ms: expires,
    }
}

async fn registered_connector(f: &Fixture, index: usize) -> RegistrationTicket {
    registered_connector_with(f, index, default_request(f, f.integration_point(index))).await
}

async fn registered_connector_with(
    f: &Fixture,
    index: usize,
    request: RegistrationRequest,
) -> RegistrationTicket {
    let proposer = f.proposer().await;
    let approver = f.approver().await;
    let ticket = propose(&mut f.connect().await, &f.hasher, &proposer, request)
        .await
        .unwrap();
    approve(
        &mut f.connect().await,
        &f.hasher,
        &approver,
        ticket.connector_id,
    )
    .await
    .unwrap();
    assert_eq!(
        ticket.key_id,
        f.integration_key_id(index),
        "the ticket must carry the manifest role-3 key id"
    );
    ticket
}

fn rejected_reason(error: RegistryError) -> &'static str {
    match error {
        RegistryError::Rejected(reason) => reason,
        other => panic!("expected a rejection, got {other}"),
    }
}

// Pure bound checks: no database needed.

#[test]
fn grant_directions_are_limited_to_manifest_reader_bits() {
    for directions in [0u16, 1, 2, 3, 5, 16, 12 | 16] {
        let request = GrantRequest {
            kind: GrantKind::Read { directions },
            line_id: Uuid::new_v4(),
            conversation_restriction: vec![],
            expires_ms: 1,
        };
        assert_eq!(
            rejected_reason(validate_grant_bounds(&request).unwrap_err()),
            "read directions"
        );
    }
    for directions in [READ_OUTBOUND, READ_INBOUND, READ_BOTH] {
        let request = GrantRequest {
            kind: GrantKind::Read { directions },
            line_id: Uuid::new_v4(),
            conversation_restriction: vec![],
            expires_ms: 1,
        };
        validate_grant_bounds(&request).unwrap();
    }
}

#[test]
fn send_grants_cannot_smuggle_conversation_or_reader_bits() {
    let request = GrantRequest {
        kind: GrantKind::Send,
        line_id: Uuid::new_v4(),
        conversation_restriction: vec![Uuid::new_v4()],
        expires_ms: 1,
    };
    assert_eq!(
        rejected_reason(validate_grant_bounds(&request).unwrap_err()),
        "send grants are line-scoped only"
    );
    assert_eq!(GrantKind::Send.directions(), 0);
    assert_eq!(
        GrantKind::Read {
            directions: READ_BOTH
        }
        .directions(),
        READ_BOTH as i16
    );
}

#[test]
fn conversation_restrictions_are_bounded() {
    let ids: Vec<Uuid> = (0..=MAX_CONVERSATION_RESTRICTION)
        .map(|_| Uuid::new_v4())
        .collect();
    let request = GrantRequest {
        kind: GrantKind::Read {
            directions: READ_BOTH,
        },
        line_id: Uuid::new_v4(),
        conversation_restriction: ids,
        expires_ms: 1,
    };
    assert_eq!(
        rejected_reason(validate_grant_bounds(&request).unwrap_err()),
        "conversation restriction size"
    );
}

// PostgreSQL-backed lifecycle tests.

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn registration_requires_pending_then_independent_approval() {
    let f = Fixture::new().await;
    let proposer = f.proposer().await;
    let approver = f.approver().await;
    let mut db = f.connect().await;
    let request = default_request(&f, f.integration_point(0));
    let ticket = propose(&mut db, &f.hasher, &proposer, request)
        .await
        .unwrap();
    assert_eq!(ticket.manifest_generation, 1);
    // Pending registrations authorize nothing.
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &ticket.key_id,
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "unknown or inactive connector"
    );
    // The proposing session cannot approve its own proposal.
    assert_eq!(
        rejected_reason(
            approve(
                &mut f.connect().await,
                &f.hasher,
                &proposer,
                ticket.connector_id
            )
            .await
            .unwrap_err()
        ),
        "independent approval session required"
    );
    approve(&mut db, &f.hasher, &approver, ticket.connector_id)
        .await
        .unwrap();
    // Approval replays fail: the registration is no longer pending.
    assert_eq!(
        rejected_reason(
            approve(&mut db, &f.hasher, &approver, ticket.connector_id)
                .await
                .unwrap_err()
        ),
        "registration not pending"
    );
    let views = list_registrations(&mut db, &proposer).await.unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].state, RegistrationState::Active);
    assert_eq!(views[0].grants.len(), 2);
    assert!(views[0].approved_ms.is_some());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn reader_wrap_requires_live_read_grant_for_line_direction_and_conversation() {
    let f = Fixture::new().await;
    let ticket = registered_connector(&f, 0).await;
    let mut db = f.connect().await;
    // Ungranted lines deny both gates.
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut db,
                f.account,
                &ticket.key_id,
                f.other_line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "no live grant for line/kind"
    );
    assert_eq!(
        rejected_reason(
            authorize_send(&mut db, f.account, &ticket.key_id, f.other_line)
                .await
                .unwrap_err()
        ),
        "no live grant for line/kind"
    );
    // The granted line and both directions succeed, and sends are separate.
    authorize_reader_wrap(
        &mut db,
        f.account,
        &ticket.key_id,
        f.line,
        None,
        READ_OUTBOUND,
    )
    .await
    .unwrap();
    authorize_reader_wrap(
        &mut db,
        f.account,
        &ticket.key_id,
        f.line,
        None,
        READ_INBOUND,
    )
    .await
    .unwrap();
    authorize_send(&mut db, f.account, &ticket.key_id, f.line)
        .await
        .unwrap();
    // A read grant restricted to explicit conversations denies everything
    // outside that set, including requests that name no conversation.
    let conversation = Uuid::new_v4();
    let mut restricted = default_request(&f, f.integration_point(1));
    restricted.grants.truncate(1);
    restricted.grants[0].conversation_restriction = vec![conversation];
    let restricted = registered_connector_with(&f, 1, restricted).await;
    let mut db = f.connect().await;
    authorize_reader_wrap(
        &mut db,
        f.account,
        &restricted.key_id,
        f.line,
        Some(conversation),
        READ_BOTH,
    )
    .await
    .unwrap();
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &restricted.key_id,
                f.line,
                Some(Uuid::new_v4()),
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "conversation outside grant restriction"
    );
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &restricted.key_id,
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "conversation required by grant restriction"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn authorization_is_account_scoped_and_unknown_keys_write_nothing() {
    let f = Fixture::new().await;
    let ticket = registered_connector(&f, 0).await;
    let mut db = f.connect().await;
    // A different account has no such connector: fail closed, no journal row.
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut db,
                Uuid::new_v4(),
                &ticket.key_id,
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "unknown or inactive connector"
    );
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &[9u8; 32],
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "unknown or inactive connector"
    );
    let events: i64 =
        f.db.query_one(
            "SELECT count(*) FROM connector_audit_events WHERE account_id=$1",
            &[&f.account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(events, 2, "only propose and approve are journaled so far");
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn read_grants_cannot_be_wider_than_the_manifest_scope() {
    let f = Fixture::new().await;
    let proposer = f.proposer().await;
    // Integration key 2 carries outbound-only scope (4).
    let mut request = default_request(&f, f.integration_point(2));
    request.grants.truncate(1);
    let mut narrower = request.clone();
    if let GrantKind::Read { directions } = &mut narrower.grants[0].kind {
        *directions = READ_INBOUND;
    }
    let mut db = f.connect().await;
    assert_eq!(
        rejected_reason(
            propose(&mut db, &f.hasher, &proposer, narrower)
                .await
                .unwrap_err()
        ),
        "read grant wider than manifest scope"
    );
    if let GrantKind::Read { directions } = &mut request.grants[0].kind {
        *directions = READ_OUTBOUND;
    }
    propose(&mut db, &f.hasher, &proposer, request)
        .await
        .unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn registration_refuses_non_integration_points_and_device_key_aliasing() {
    let f = Fixture::new().await;
    let proposer = f.proposer().await;
    let mut db = f.connect().await;
    // The account root pin is the owner role-6 point: it can never register
    // as an integration reader.
    let root_point: [u8; 65] = f.pin[29..94].try_into().unwrap();
    let request = default_request(&f, root_point);
    assert_eq!(
        rejected_reason(
            propose(&mut db, &f.hasher, &proposer, request)
                .await
                .unwrap_err()
        ),
        "integration reader authority"
    );
    // A valid integration point that is also an enrolled device key aliases
    // a device identity and is refused even though the manifest lists it.
    let device_key = SigningKey::generate_from_rng(&mut rand::rng());
    let point: [u8; 65] = point_bytes(&device_key);
    let device = Uuid::new_v4();
    f.db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
        &[&device, &f.account],
    )
    .await
    .unwrap();
    f.db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&device, &f.account, &&point[..], &vec![5u8; 32]],
    ).await.unwrap();
    let alias = Fixture::with_integration(vec![(device_key, READ_BOTH)]).await;
    let alias_proposer = alias.proposer().await;
    let alias_request = default_request(&alias, point);
    assert_eq!(
        rejected_reason(
            propose(
                &mut alias.connect().await,
                &alias.hasher,
                &alias_proposer,
                alias_request
            )
            .await
            .unwrap_err()
        ),
        "key point aliases device/owner key"
    );
    alias.cleanup().await;
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn key_rotation_retires_the_old_point_and_refuses_any_reuse() {
    let f = Fixture::new().await;
    let approver = f.approver().await;
    let ticket = registered_connector(&f, 0).await;
    let mut db = f.connect().await;
    // Rotating to the same point is not a rotation.
    assert_eq!(
        rejected_reason(
            rotate_key(
                &mut db,
                &f.hasher,
                &approver,
                ticket.connector_id,
                f.integration_point(0)
            )
            .await
            .unwrap_err()
        ),
        "rotation must use a new key"
    );
    let rotated = rotate_key(
        &mut db,
        &f.hasher,
        &approver,
        ticket.connector_id,
        f.integration_point(1),
    )
    .await
    .unwrap();
    assert_ne!(rotated.key_id, ticket.key_id);
    // The retired key authorizes nothing anymore.
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &ticket.key_id,
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "unknown or inactive connector"
    );
    authorize_reader_wrap(
        &mut f.connect().await,
        f.account,
        &rotated.key_id,
        f.line,
        None,
        READ_BOTH,
    )
    .await
    .unwrap();
    // The retired point can neither rotate back nor register again.
    assert_eq!(
        rejected_reason(
            rotate_key(
                &mut f.connect().await,
                &f.hasher,
                &approver,
                ticket.connector_id,
                f.integration_point(0)
            )
            .await
            .unwrap_err()
        ),
        "key point already used in account"
    );
    let proposer = f.proposer().await;
    let request = default_request(&f, f.integration_point(0));
    assert_eq!(
        rejected_reason(
            propose(&mut f.connect().await, &f.hasher, &proposer, request)
                .await
                .unwrap_err()
        ),
        "key point already used in account"
    );
    let retired: i64 =
        f.db.query_one(
            "SELECT count(*) FROM connector_keys WHERE account_id=$1 AND retired_ms IS NOT NULL",
            &[&f.account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(retired, 1);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn rotation_refuses_a_new_scope_narrower_than_held_grants() {
    let f = Fixture::new().await;
    let approver = f.approver().await;
    // Connector over key 0 (scope 12) holds a BOTH-direction read grant.
    let ticket = registered_connector(&f, 0).await;
    let mut db = f.connect().await;
    // Key 2 is outbound-only (scope 4): rotating would narrow authority.
    assert_eq!(
        rejected_reason(
            rotate_key(
                &mut db,
                &f.hasher,
                &approver,
                ticket.connector_id,
                f.integration_point(2)
            )
            .await
            .unwrap_err()
        ),
        "rotation narrower than held read grants"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn revocation_fences_grants_and_reports_outstanding_work() {
    let f = Fixture::new().await;
    let approver = f.approver().await;
    let ticket = registered_connector(&f, 0).await;
    let mut db = f.connect().await;
    authorize_send(&mut db, f.account, &ticket.key_id, f.line)
        .await
        .unwrap();
    let summary = revoke(
        &mut db,
        &f.hasher,
        &approver,
        ticket.connector_id,
        "synthetic key-loss drill",
    )
    .await
    .unwrap();
    assert_eq!(summary.grants_stopped, 2);
    assert_eq!(summary.send_authorizations, 1);
    // Every gate fails closed after revocation.
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &ticket.key_id,
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "unknown or inactive connector"
    );
    assert_eq!(
        rejected_reason(
            authorize_send(&mut f.connect().await, f.account, &ticket.key_id, f.line)
                .await
                .unwrap_err()
        ),
        "unknown or inactive connector"
    );
    assert_eq!(
        rejected_reason(
            rotate_key(
                &mut f.connect().await,
                &f.hasher,
                &approver,
                ticket.connector_id,
                f.integration_point(1)
            )
            .await
            .unwrap_err()
        ),
        "registration not active"
    );
    // A revoked key cannot be resurrected by re-registering its point.
    let proposer = f.proposer().await;
    let request = default_request(&f, f.integration_point(0));
    assert_eq!(
        rejected_reason(
            propose(&mut f.connect().await, &f.hasher, &proposer, request)
                .await
                .unwrap_err()
        ),
        "key point already used in account"
    );
    // Recovery is a fresh registration with a brand-new key.
    let fresh = default_request(&f, f.integration_point(1));
    let fresh_ticket = propose(&mut f.connect().await, &f.hasher, &proposer, fresh)
        .await
        .unwrap();
    approve(
        &mut f.connect().await,
        &f.hasher,
        &approver,
        fresh_ticket.connector_id,
    )
    .await
    .unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn approval_refuses_advanced_and_forked_manifests() {
    let mut f = Fixture::new().await;
    let proposer = f.proposer().await;
    let approver = f.approver().await;
    let request = default_request(&f, f.integration_point(0));
    let ticket = propose(&mut f.connect().await, &f.hasher, &proposer, request)
        .await
        .unwrap();
    // The accepted manifest advanced (version 2) while the proposal waited.
    f.advance_manifest().await;
    assert_eq!(
        rejected_reason(
            approve(
                &mut f.connect().await,
                &f.hasher,
                &approver,
                ticket.connector_id
            )
            .await
            .unwrap_err()
        ),
        "manifest changed since proposal; propose again"
    );
    // A fresh proposal under the advanced chain approves normally.
    f.reset_budget().await;
    let request = default_request(&f, f.integration_point(1));
    let ticket = propose(&mut f.connect().await, &f.hasher, &proposer, request)
        .await
        .unwrap();
    approve(
        &mut f.connect().await,
        &f.hasher,
        &approver,
        ticket.connector_id,
    )
    .await
    .unwrap();
    assert_eq!(ticket.manifest_version, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn authorization_and_rotation_refuse_incompatible_generations() {
    let mut f = Fixture::new().await;
    let approver = f.approver().await;
    let ticket = registered_connector(&f, 0).await;
    // Root rotation replaced the manifest generation even though the same
    // integration key is present: every stored binding is now stale.
    f.rotate_generation().await;
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &ticket.key_id,
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "manifest generation changed; re-register"
    );
    assert_eq!(
        rejected_reason(
            rotate_key(
                &mut f.connect().await,
                &f.hasher,
                &approver,
                ticket.connector_id,
                f.integration_point(1)
            )
            .await
            .unwrap_err()
        ),
        "manifest generation changed; re-register"
    );
    let denied: i64 = f
        .db
        .query_one(
            "SELECT count(*) FROM connector_audit_events WHERE account_id=$1 AND action='reader_wrap_denied'",
            &[&f.account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(denied, 1, "the stale-generation denial is audited");
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn expired_registrations_and_grants_fail_closed() {
    let f = Fixture::new().await;
    let proposer = f.proposer().await;
    let approver = f.approver().await;
    // A short-lived registration and an even shorter-lived read grant.
    let mut request = default_request(&f, f.integration_point(0));
    request.expires_ms = now_ms() + 8_000;
    request.grants.truncate(1);
    request.grants[0].expires_ms = now_ms() + 3_000;
    let ticket = propose(&mut f.connect().await, &f.hasher, &proposer, request)
        .await
        .unwrap();
    approve(
        &mut f.connect().await,
        &f.hasher,
        &approver,
        ticket.connector_id,
    )
    .await
    .unwrap();
    let mut db = f.connect().await;
    authorize_reader_wrap(&mut db, f.account, &ticket.key_id, f.line, None, READ_BOTH)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(3_500)).await;
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &ticket.key_id,
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "no live grant for line/kind"
    );
    tokio::time::sleep(std::time::Duration::from_millis(5_000)).await;
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &ticket.key_id,
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "registration expired"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn revoked_lines_deny_authorization() {
    let f = Fixture::new().await;
    let ticket = registered_connector(&f, 0).await;
    f.db.execute(
        "UPDATE phone_lines SET state='revoked' WHERE account_id=$1 AND id=$2",
        &[&f.account, &f.line],
    )
    .await
    .unwrap();
    assert_eq!(
        rejected_reason(
            authorize_reader_wrap(
                &mut f.connect().await,
                f.account,
                &ticket.key_id,
                f.line,
                None,
                READ_BOTH
            )
            .await
            .unwrap_err()
        ),
        "line not active"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn registration_shape_is_bounded() {
    let f = Fixture::new().await;
    let proposer = f.proposer().await;
    let mut db = f.connect().await;
    // Too many grants in one request.
    let mut many = default_request(&f, f.integration_point(0));
    for _ in 0..MAX_GRANTS_PER_REGISTRATION {
        many.grants.push(GrantRequest {
            kind: GrantKind::Send,
            line_id: f.line,
            conversation_restriction: vec![],
            expires_ms: many.expires_ms,
        });
    }
    assert_eq!(
        rejected_reason(
            propose(&mut db, &f.hasher, &proposer, many)
                .await
                .unwrap_err()
        ),
        "registration shape"
    );
    // Grants cannot outlive their registration.
    let mut outlives = default_request(&f, f.integration_point(0));
    outlives.grants.truncate(1);
    outlives.grants[0].expires_ms = outlives.expires_ms + 1;
    assert_eq!(
        rejected_reason(
            propose(&mut db, &f.hasher, &proposer, outlives)
                .await
                .unwrap_err()
        ),
        "grant outlives registration"
    );
    // The ninety-day registration bound.
    let mut long = default_request(&f, f.integration_point(0));
    long.expires_ms += MAX_LIFETIME_MS;
    assert_eq!(
        rejected_reason(
            propose(&mut db, &f.hasher, &proposer, long)
                .await
                .unwrap_err()
        ),
        "registration expiry bound"
    );
    // Grants require an active line of the same account.
    let mut wrong_line = default_request(&f, f.integration_point(0));
    wrong_line.grants.truncate(1);
    wrong_line.grants[0].line_id = Uuid::new_v4();
    assert_eq!(
        rejected_reason(
            propose(&mut db, &f.hasher, &proposer, wrong_line)
                .await
                .unwrap_err()
        ),
        "grant line not active"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn accounts_hold_at_most_eight_live_connectors() {
    let integration: Vec<(SigningKey, u16)> = (0..9)
        .map(|_| (SigningKey::generate_from_rng(&mut rand::rng()), READ_BOTH))
        .collect();
    let f = Fixture::with_integration(integration).await;
    let proposer = f.proposer().await;
    let mut db = f.connect().await;
    for index in 0..MAX_CONNECTORS_PER_ACCOUNT {
        let request = default_request(&f, f.integration_point(index as usize));
        propose(&mut db, &f.hasher, &proposer, request)
            .await
            .unwrap();
        f.reset_budget().await;
    }
    let request = default_request(&f, f.integration_point(8));
    assert_eq!(
        rejected_reason(
            propose(&mut db, &f.hasher, &proposer, request)
                .await
                .unwrap_err()
        ),
        "connector limit reached"
    );
    // Revoked connectors do not count against the bound.
    let approver = f.approver().await;
    let first: Uuid = f
        .db
        .query_one(
            "SELECT connector_id FROM connector_registrations WHERE account_id=$1 ORDER BY proposed_ms LIMIT 1",
            &[&f.account],
        )
        .await
        .unwrap()
        .get(0);
    revoke(&mut db, &f.hasher, &approver, first, "synthetic cleanup")
        .await
        .unwrap();
    let request = default_request(&f, f.integration_point(8));
    assert!(
        propose(&mut db, &f.hasher, &proposer, request)
            .await
            .is_ok()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn rejected_proposals_cannot_be_approved_or_reproposed_verbatim() {
    let f = Fixture::new().await;
    let proposer = f.proposer().await;
    let approver = f.approver().await;
    let mut db = f.connect().await;
    let request = default_request(&f, f.integration_point(0));
    let ticket = propose(&mut db, &f.hasher, &proposer, request.clone())
        .await
        .unwrap();
    reject(
        &mut db,
        &f.hasher,
        &approver,
        ticket.connector_id,
        "synthetic change of mind",
    )
    .await
    .unwrap();
    assert_eq!(
        rejected_reason(
            approve(&mut db, &f.hasher, &approver, ticket.connector_id)
                .await
                .unwrap_err()
        ),
        "registration not pending"
    );
    assert_eq!(
        rejected_reason(
            reject(&mut db, &f.hasher, &approver, ticket.connector_id, "again")
                .await
                .unwrap_err()
        ),
        "registration not pending"
    );
    // The rejected identity's key history still blocks the same point.
    assert_eq!(
        rejected_reason(
            propose(&mut db, &f.hasher, &proposer, request)
                .await
                .unwrap_err()
        ),
        "key point already used in account"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn access_records_export_and_erase_after_revocation_only() {
    let f = Fixture::new().await;
    let approver = f.approver().await;
    let ticket = registered_connector(&f, 0).await;
    let mut db = f.connect().await;
    authorize_reader_wrap(&mut db, f.account, &ticket.key_id, f.line, None, READ_BOTH)
        .await
        .unwrap();
    // Denials of a known connector are access records too.
    let _ = authorize_reader_wrap(
        &mut f.connect().await,
        f.account,
        &ticket.key_id,
        f.other_line,
        None,
        READ_BOTH,
    )
    .await;
    let proposer = f.proposer().await;
    // Erase refuses a still-live connector.
    assert_eq!(
        rejected_reason(
            erase_access_records(
                &mut f.connect().await,
                &f.hasher,
                &proposer,
                ticket.connector_id
            )
            .await
            .unwrap_err()
        ),
        "revoke before erasing access records"
    );
    let export = export_access_records(&mut f.connect().await, &proposer)
        .await
        .unwrap();
    let actions: Vec<&str> = export.records.iter().map(|r| r.action.as_str()).collect();
    assert!(actions.contains(&"proposed"));
    assert!(actions.contains(&"approved"));
    assert!(actions.contains(&"reader_wrap_authorized"));
    assert!(actions.contains(&"reader_wrap_denied"));
    assert_eq!(export.registrations[0].key_id, ticket.key_id);
    // Exports carry no key points or content, only identifiers and reasons.
    assert!(export.records.iter().all(|r| !r.reason.is_empty()));
    revoke(
        &mut f.connect().await,
        &f.hasher,
        &approver,
        ticket.connector_id,
        "synthetic erasure drill",
    )
    .await
    .unwrap();
    let erased = erase_access_records(
        &mut f.connect().await,
        &f.hasher,
        &proposer,
        ticket.connector_id,
    )
    .await
    .unwrap();
    assert!(erased.audit_events >= 4);
    let after = export_access_records(&mut f.connect().await, &proposer)
        .await
        .unwrap();
    // Only the erasure marker (and markers written after the erase) remain.
    assert!(
        after
            .records
            .iter()
            .all(|r| r.action == "erased" || r.action == "revoked")
    );
    assert!(after.records.iter().any(|r| r.action == "erased"));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn audit_and_grant_history_cannot_be_rewritten_and_erasure_cascades() {
    let f = Fixture::new().await;
    registered_connector(&f, 0).await;
    // Rewriting history is fenced at the storage layer.
    for sql in [
        "UPDATE connector_audit_events SET reason='rewritten'",
        "UPDATE connector_grants SET expires_ms=expires_ms+1000",
        "UPDATE connector_grants SET kind='send' WHERE kind='read'",
    ] {
        let result = f.db.execute(sql, &[]).await;
        assert!(
            result.is_err(),
            "storage must reject rewriting connector history: {sql}"
        );
    }
    let truncated = f.db.execute("TRUNCATE connector_audit_events", &[]).await;
    assert!(truncated.is_err());
    // Deleting the registration cascades keys, grants and audit rows, the
    // same rows account erasure removes through the accounts cascade.
    f.db.execute(
        "DELETE FROM connector_registrations WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    for table in [
        "connector_registrations",
        "connector_keys",
        "connector_grants",
        "connector_audit_events",
    ] {
        let rows: i64 =
            f.db.query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&f.account],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(rows, 0, "{table} must cascade with the registration");
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn grants_survive_as_history_after_revocation_and_stop_authorizing() {
    let f = Fixture::new().await;
    let approver = f.approver().await;
    let ticket = registered_connector(&f, 0).await;
    let mut db = f.connect().await;
    revoke(
        &mut db,
        &f.hasher,
        &approver,
        ticket.connector_id,
        "synthetic",
    )
    .await
    .unwrap();
    let views = list_registrations(&mut db, &f.proposer().await)
        .await
        .unwrap();
    assert_eq!(views[0].state, RegistrationState::Revoked);
    assert_eq!(views[0].grants.len(), 2);
    assert!(views[0].grants.iter().all(|g| g.revoked_ms.is_some()));
    // The next registration of a different key is unaffected.
    let ticket = registered_connector(&f, 1).await;
    authorize_reader_wrap(
        &mut f.connect().await,
        f.account,
        &ticket.key_id,
        f.line,
        None,
        READ_BOTH,
    )
    .await
    .unwrap();
    f.cleanup().await;
}
