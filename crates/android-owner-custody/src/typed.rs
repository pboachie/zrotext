// SPDX-License-Identifier: AGPL-3.0-only
//! Typed Android owner ceremonies using unchanged root-material codecs.
//! Expected scopes originate in trusted composition, separately from proposals.

use crate::{
    custody,
    signing::{Authority, OperationHandle, SigningError, TimeAnchor},
};
use p256::{NonZeroScalar, SecretKey, elliptic_curve::Generate};
use rand::{TryCryptoRng, TryRng, rngs::SysRng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;
use zrotext_root_material::{
    archive_backup::{self, ArchiveIdentity, ArchiveRecoverySecret, ArchiveSecret},
    archive_init, conversation_activation as activation, conversation_genesis as genesis,
    conversation_refresh as refresh, line_key_registration as line, recovery_kit,
    root_backup::{self, ExpectedIdentity, RootSecret},
    sealed_root_enrollment,
};

pub const MAX_EXPECTED: usize = 4096;
pub const MAX_PROPOSAL: usize = refresh::MAX_PROPOSAL;

fn valid_identity(identity: &ExpectedIdentity) -> Result<(), SigningError> {
    if identity.account_id == [0; 16]
        || identity.root_fingerprint == [0; 32]
        || identity.origin.len() > 512
        || !sealed_root_enrollment::canonical_origin(&identity.origin)
    {
        return Err(SigningError::InvalidInput);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    LineRegistration = 1,
    ArchiveCreation = 2,
    Genesis = 3,
    Activation = 4,
    Refresh = 5,
}
impl TryFrom<i32> for OperationKind {
    type Error = SigningError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::LineRegistration),
            2 => Ok(Self::ArchiveCreation),
            3 => Ok(Self::Genesis),
            4 => Ok(Self::Activation),
            5 => Ok(Self::Refresh),
            _ => Err(SigningError::InvalidInput),
        }
    }
}

struct Hex<const N: usize>([u8; N]);
fn field<T: Into<U>, U>(value: T) -> U {
    value.into()
}
impl<const N: usize> From<Hex<N>> for [u8; N] {
    fn from(value: Hex<N>) -> Self {
        value.0
    }
}
impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() != N * 2 {
            return Err(serde::de::Error::custom("public expectation rejected"));
        }
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        let mut result = [0; N];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            result[index] = digit(pair[0])
                .zip(digit(pair[1]))
                .map(|(a, b)| a * 16 + b)
                .ok_or_else(|| serde::de::Error::custom("public expectation rejected"))?;
        }
        Ok(Self(result))
    }
}

macro_rules! scope_wire {
    ($wire:ident => $module:ident::$scope:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $wire { $($field: $ty),* }
        impl $wire { fn into_scope(self) -> $module::$scope { $module::$scope { $($field: field(self.$field)),* } } }
    };
}
scope_wire!(LineScope => line::Scope {
    account: Hex<16>, user: Hex<16>, owner_session: Hex<16>, device: Hex<16>, line: Hex<16>,
    next_generation: u64, challenge: Hex<16>, nonce: Hex<32>, issued_ms: u64, expires_ms: u64,
    approval_fingerprint: Hex<32>, paired_signing_fingerprint: Hex<32>, connection_epoch: u64,
    deployment_epoch: u64, site_id: String, instance_id: String, origin: String,
});
scope_wire!(GenesisScope => genesis::Scope {
    account: Hex<16>, session: Hex<16>, device: Hex<16>, line: Hex<16>, device_signing_fingerprint: Hex<32>,
    generation: u64, peer: String, origin: String, fingerprint: Hex<32>, issued_ms: u64, expires_ms: u64,
});
scope_wire!(ActivationScope => activation::Scope {
    account: Hex<16>, session: Hex<16>, device: Hex<16>, line: Hex<16>, line_generation: u64,
    peer: String, origin: String, fingerprint: Hex<32>, predecessor_version: u64,
    predecessor_digest: Hex<32>, phone_reader: Hex<32>, archive_reader: Hex<32>, phone_signer: Hex<32>, issued_ms: u64,
});
scope_wire!(RefreshScope => refresh::Scope {
    account: Hex<16>, session: Hex<16>, interval: Hex<16>, device: Hex<16>, line: Hex<16>, line_generation: u64,
    peer: String, origin: String, fingerprint: Hex<32>, predecessor_version: u64,
    predecessor_digest: Hex<32>, phone_reader: Hex<32>, archive_reader: Hex<32>, signer: Hex<32>, point: Hex<65>, until_ms: u64,
});
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LineInput {
    scope: LineScope,
    root_pin: Hex<94>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveInput {
    root_pin: Hex<94>,
    operation_id: Hex<16>,
    issued_ms: u64,
    expires_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisInput {
    scope: GenesisScope,
    root_pin: Hex<94>,
    phone_reader: Hex<65>,
    archive_reader: Hex<65>,
    phone_signer: Hex<65>,
    archive_backup_sha256: Hex<32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationInput {
    scope: ActivationScope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshInput {
    scope: RefreshScope,
}

enum Expected {
    Line(line::Expected),
    Archive {
        root_pin: [u8; 94],
        operation_id: [u8; 16],
        issued_ms: u64,
        expires_ms: u64,
    },
    Genesis {
        expected: genesis::Expected,
        archive_digest: [u8; 32],
    },
    Activation(activation::Expected),
    Refresh(refresh::Expected),
}
fn parse_expected(
    kind: OperationKind,
    bytes: &[u8],
    identity: &ExpectedIdentity,
) -> Result<Expected, SigningError> {
    if bytes.is_empty() || bytes.len() > MAX_EXPECTED {
        return Err(SigningError::InvalidInput);
    }
    fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, SigningError> {
        serde_json::from_slice(bytes).map_err(|_| SigningError::InvalidInput)
    }
    Ok(match kind {
        OperationKind::LineRegistration => {
            let v: LineInput = parse(bytes)?;
            Expected::Line(line::Expected {
                identity: identity.clone(),
                scope: v.scope.into_scope(),
                root_pin: v.root_pin.0,
            })
        }
        OperationKind::ArchiveCreation => {
            let v: ArchiveInput = parse(bytes)?;
            Expected::Archive {
                root_pin: v.root_pin.0,
                operation_id: v.operation_id.0,
                issued_ms: v.issued_ms,
                expires_ms: v.expires_ms,
            }
        }
        OperationKind::Genesis => {
            let v: GenesisInput = parse(bytes)?;
            Expected::Genesis {
                expected: genesis::Expected {
                    identity: identity.clone(),
                    scope: v.scope.into_scope(),
                    root_pin: v.root_pin.0,
                    phone_reader: v.phone_reader.0,
                    archive_reader: v.archive_reader.0,
                    phone_signer: v.phone_signer.0,
                },
                archive_digest: v.archive_backup_sha256.0,
            }
        }
        OperationKind::Activation => {
            let v: ActivationInput = parse(bytes)?;
            Expected::Activation(activation::Expected {
                identity: identity.clone(),
                scope: v.scope.into_scope(),
            })
        }
        OperationKind::Refresh => {
            let v: RefreshInput = parse(bytes)?;
            Expected::Refresh(refresh::Expected {
                identity: identity.clone(),
                scope: v.scope.into_scope(),
            })
        }
    })
}

fn check_context(
    expected: &Expected,
    identity: &ExpectedIdentity,
    authority: &Authority,
) -> Result<(), SigningError> {
    if [
        authority.account_id,
        authority.user_id,
        authority.session_id,
    ]
    .contains(&[0; 16])
        || authority.account_id != identity.account_id
    {
        return Err(SigningError::ContextRejected);
    }
    let matches = match expected {
        Expected::Line(e) => {
            e.scope.account == authority.account_id
                && e.scope.user == authority.user_id
                && e.scope.owner_session == authority.session_id
        }
        Expected::Archive {
            root_pin,
            operation_id,
            ..
        } => {
            *operation_id != [0; 16]
                && sealed_root_enrollment::root_fingerprint(root_pin, &identity.account_id).ok()
                    == Some(identity.root_fingerprint)
        }
        Expected::Genesis { expected: e, .. } => {
            e.scope.account == authority.account_id && e.scope.session == authority.session_id
        }
        Expected::Activation(e) => {
            e.scope.account == authority.account_id && e.scope.session == authority.session_id
        }
        Expected::Refresh(e) => {
            e.scope.account == authority.account_id && e.scope.session == authority.session_id
        }
    };
    if !matches {
        return Err(SigningError::ContextRejected);
    }
    Ok(())
}

fn inspect(expected: &Expected, proposal: &[u8], now: u64) -> Result<(), SigningError> {
    let rejected = |_| SigningError::ContextRejected;
    match expected {
        Expected::Line(e) => {
            let p = line::decode(proposal).map_err(rejected)?;
            line::inspect(&p, e, now).map_err(rejected)?;
        }
        Expected::Archive {
            issued_ms,
            expires_ms,
            ..
        } => {
            if !proposal.is_empty()
                || *issued_ms == 0
                || *expires_ms > i64::MAX as u64
                || expires_ms
                    .checked_sub(*issued_ms)
                    .is_none_or(|v| v == 0 || v > 300_000)
                || now < *issued_ms
                || now >= *expires_ms
            {
                return Err(SigningError::TimeRejected);
            }
        }
        Expected::Genesis {
            expected: e,
            archive_digest,
        } => {
            if *archive_digest == [0; 32] {
                return Err(SigningError::ContextRejected);
            }
            let p = genesis::decode(proposal).map_err(|_| SigningError::InvalidInput)?;
            genesis::inspect(&p, e, now).map_err(|_| SigningError::ContextRejected)?;
        }
        Expected::Activation(e) => {
            let p = activation::decode(proposal).map_err(|_| SigningError::InvalidInput)?;
            activation::inspect(&p, e, now).map_err(|_| SigningError::ContextRejected)?;
        }
        Expected::Refresh(e) => {
            let p = refresh::decode(proposal).map_err(|_| SigningError::InvalidInput)?;
            refresh::inspect(&p, e, now).map_err(|_| SigningError::ContextRejected)?;
        }
    }
    Ok(())
}

pub struct CreatedArchive {
    pub encrypted_backup: Vec<u8>,
    pub public_receipt: Vec<u8>,
    pub recovery: Zeroizing<[u8; 32]>,
    pub archive_id: [u8; 32],
    pub archive_point: [u8; 65],
}
pub enum TypedOutput {
    Public(Vec<Vec<u8>>),
    Archive(CreatedArchive),
}

fn archive_identity(root: &ExpectedIdentity, point: [u8; 65]) -> ArchiveIdentity {
    ArchiveIdentity {
        account_id: root.account_id,
        origin: root.origin.clone(),
        root_fingerprint: root.root_fingerprint,
        generation: 1,
        archive_id: Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], &point].concat()).into(),
        archive_point: point,
    }
}

/// Fresh retained archive material, separate from the owner-root token. Both
/// AEAD tags and the decrypted actual point/key ID must match independent intent.
pub fn check_archive_recovery(
    encrypted: &[u8],
    recovery: &[u8],
    expected_root: &ExpectedIdentity,
    archive_id: &[u8; 32],
    point: &[u8; 65],
) -> Result<(), SigningError> {
    valid_identity(expected_root)?;
    if encrypted.len() > 845 || recovery.len() != 32 || recovery == [0; 32] {
        return Err(SigningError::InvalidInput);
    }
    let expected = archive_identity(expected_root, *point);
    if expected.archive_id != *archive_id {
        return Err(SigningError::ContextRejected);
    }
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(recovery);
    let restored = archive_backup::open(encrypted, &ArchiveRecoverySecret::new(secret), &expected)
        .map_err(|_| SigningError::RecoveryRejected)?;
    drop(restored);
    Ok(())
}

fn create_archive(root: &ExpectedIdentity, pin: &[u8; 94]) -> Result<CreatedArchive, SigningError> {
    create_archive_with_rng(root, pin, &mut SysRng)
}
fn create_archive_with_rng<R: TryCryptoRng>(
    root: &ExpectedIdentity,
    pin: &[u8; 94],
    rng: &mut R,
) -> Result<CreatedArchive, SigningError> {
    valid_identity(root)?;
    if sealed_root_enrollment::root_fingerprint(pin, &root.account_id).ok()
        != Some(root.root_fingerprint)
    {
        return Err(SigningError::ContextRejected);
    }
    let scalar = Zeroizing::new(
        NonZeroScalar::try_generate_from_rng(rng).map_err(|_| SigningError::Unavailable)?,
    );
    let key = SecretKey::from(&*scalar);
    let encoded = Zeroizing::new(key.to_bytes());
    let mut raw = Zeroizing::new([0; 32]);
    raw.copy_from_slice(&encoded);
    let archive = ArchiveSecret::new(raw).map_err(|_| SigningError::Unavailable)?;
    drop(encoded);
    drop(key);
    drop(scalar);
    let mut recovery = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(recovery.as_mut_slice())
        .map_err(|_| SigningError::Unavailable)?;
    if *recovery == [0; 32] {
        return Err(SigningError::Unavailable);
    }
    let prepared = archive_init::prepare(archive, ArchiveRecoverySecret::new(recovery), root, pin)
        .map_err(|_| SigningError::Unavailable)?;
    let mut output_recovery = Zeroizing::new([0; 32]);
    output_recovery.copy_from_slice(prepared.recovery_bytes());
    Ok(CreatedArchive {
        encrypted_backup: prepared.encrypted_backup().to_vec(),
        public_receipt: prepared.public_receipt(),
        recovery: output_recovery,
        archive_id: prepared.identity().archive_id,
        archive_point: prepared.identity().archive_point,
    })
}

fn perform(
    expected: &Expected,
    proposal: &[u8],
    root: &RootSecret,
    identity: &ExpectedIdentity,
    archive_backup: &[u8],
    archive_recovery: &[u8],
    now: u64,
) -> Result<TypedOutput, SigningError> {
    if !matches!(expected, Expected::Genesis { .. })
        && (!archive_backup.is_empty() || !archive_recovery.is_empty())
    {
        return Err(SigningError::InvalidInput);
    }
    Ok(match expected {
        Expected::Line(e) => {
            let p = line::decode(proposal).map_err(|_| SigningError::InvalidInput)?;
            let signature = line::inspect(&p, e, now)
                .and_then(|v| v.sign(root, now))
                .map_err(|_| SigningError::ContextRejected)?;
            TypedOutput::Public(vec![signature.to_vec()])
        }
        Expected::Archive { root_pin, .. } => {
            TypedOutput::Archive(create_archive(identity, root_pin)?)
        }
        Expected::Genesis {
            expected: e,
            archive_digest,
        } => {
            if <[u8; 32]>::from(Sha256::digest(archive_backup)) != *archive_digest {
                return Err(SigningError::RecoveryRejected);
            }
            let archive = archive_identity(identity, e.archive_reader);
            check_archive_recovery(
                archive_backup,
                archive_recovery,
                identity,
                &archive.archive_id,
                &archive.archive_point,
            )?;
            let p = genesis::decode(proposal).map_err(|_| SigningError::InvalidInput)?;
            let signed = genesis::inspect(&p, e, now)
                .and_then(|v| v.sign(root, now))
                .map_err(|_| SigningError::ContextRejected)?;
            TypedOutput::Public(vec![signed])
        }
        Expected::Activation(e) => {
            let p = activation::decode(proposal).map_err(|_| SigningError::InvalidInput)?;
            TypedOutput::Public(vec![
                activation::sign(root, &p, e, now).map_err(|_| SigningError::ContextRejected)?,
            ])
        }
        Expected::Refresh(e) => {
            let p = refresh::decode(proposal).map_err(|_| SigningError::InvalidInput)?;
            TypedOutput::Public(vec![
                refresh::sign(root, &p, e, now).map_err(|_| SigningError::ContextRejected)?,
            ])
        }
    })
}

struct Operation {
    expected: Expected,
    expected_json: Vec<u8>,
    proposal: Vec<u8>,
    backup: Vec<u8>,
    card: Vec<u8>,
    identity: ExpectedIdentity,
    authority: Authority,
    anchor: TimeAnchor,
    opened: u64,
    cancelled: Arc<AtomicBool>,
}
#[derive(Default)]
struct Registry {
    pending: HashMap<OperationHandle, Operation>,
    active: HashMap<OperationHandle, Arc<AtomicBool>>,
    replay: HashSet<[u8; 32]>,
}
#[derive(Default)]
pub struct TypedService {
    registry: Mutex<Registry>,
}

impl TypedService {
    #[expect(
        clippy::too_many_arguments,
        reason = "proposal, independent expectation, kit and authenticated authority are distinct"
    )]
    pub fn open(
        &self,
        kind: OperationKind,
        proposal: &[u8],
        expected_json: &[u8],
        backup: &[u8],
        card: &[u8],
        identity: &ExpectedIdentity,
        authority: Authority,
        anchor: TimeAnchor,
        now: u64,
    ) -> Result<OperationHandle, SigningError> {
        valid_identity(identity)?;
        if proposal.len() > MAX_PROPOSAL || backup.len() > 748 || card.len() > 645 {
            return Err(SigningError::InvalidInput);
        }
        let expected = parse_expected(kind, expected_json, identity)?;
        check_context(&expected, identity, &authority)?;
        let (lower, upper) = anchor.bounds(now)?;
        inspect(&expected, proposal, lower)?;
        inspect(&expected, proposal, upper)?;
        root_backup::validate_public_header(backup, identity)
            .map_err(|_| SigningError::ContextRejected)?;
        recovery_kit::decode_public_card(card, identity, &Sha256::digest(backup).into())
            .map_err(|_| SigningError::ContextRejected)?;
        // Canonical proposals already have exact framing. Expected JSON layout
        // or hex case must never permit a reviewed proposal to reopen.
        let replay_input: &[u8] = match &expected {
            Expected::Archive { operation_id, .. } => operation_id,
            _ => proposal,
        };
        let replay = Sha256::digest(
            [
                &[kind as u8],
                authority.account_id.as_slice(),
                &authority.user_id,
                &authority.session_id,
                replay_input,
            ]
            .concat(),
        )
        .into();
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        if registry.active.len() >= 8
            || registry.replay.len() >= 256
            || registry.replay.contains(&replay)
        {
            return Err(SigningError::Unavailable);
        }
        let handle = (0..8)
            .find_map(|_| {
                let mut random = [0; 8];
                SysRng.try_fill_bytes(&mut random).ok()?;
                let handle =
                    OperationHandle::from_u64(u64::from_be_bytes(random) & i64::MAX as u64).ok()?;
                (!registry.active.contains_key(&handle)).then_some(handle)
            })
            .ok_or(SigningError::Unavailable)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        registry.replay.insert(replay);
        registry.active.insert(handle, cancelled.clone());
        registry.pending.insert(
            handle,
            Operation {
                expected,
                expected_json: expected_json.to_vec(),
                proposal: proposal.to_vec(),
                backup: backup.to_vec(),
                card: card.to_vec(),
                identity: identity.clone(),
                authority,
                anchor,
                opened: now,
                cancelled,
            },
        );
        Ok(handle)
    }
    pub fn review(&self, handle: OperationHandle) -> Result<Vec<Vec<u8>>, SigningError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        let operation = registry
            .pending
            .get(&handle)
            .ok_or(SigningError::Unavailable)?;
        Ok(vec![
            operation.proposal.clone(),
            operation.expected_json.clone(),
        ])
    }
    pub fn execute(
        &self,
        handle: OperationHandle,
        root_token: &[u8],
        archive_backup: &[u8],
        archive_recovery: &[u8],
        authority: &Authority,
        mut elapsed: impl FnMut() -> Result<u64, SigningError>,
    ) -> Result<TypedOutput, SigningError> {
        self.execute_with_output(
            handle,
            root_token,
            archive_backup,
            archive_recovery,
            authority,
            &mut (),
            |_| elapsed(),
            |_, v| Ok(v),
            |_, _| {},
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "bounded recovery inputs and cleanup for secret output are separate"
    )]
    pub(crate) fn execute_with_output<C, T>(
        &self,
        handle: OperationHandle,
        root_token: &[u8],
        archive_backup: &[u8],
        archive_recovery: &[u8],
        authority: &Authority,
        context: &mut C,
        mut elapsed: impl FnMut(&mut C) -> Result<u64, SigningError>,
        output: impl FnOnce(&mut C, TypedOutput) -> Result<T, SigningError>,
        discard: impl FnOnce(&mut C, T),
    ) -> Result<T, SigningError> {
        let operation = self
            .registry
            .lock()
            .map_err(|_| SigningError::Unavailable)?
            .pending
            .remove(&handle)
            .ok_or(SigningError::Unavailable)?;
        let result = (|| {
            if root_token.len() != 79 || archive_backup.len() > 845 || archive_recovery.len() > 32 {
                return Err(SigningError::InvalidInput);
            }
            if operation.cancelled.load(Ordering::SeqCst) || *authority != operation.authority {
                return Err(SigningError::ContextRejected);
            }
            let now = elapsed(context)?;
            if now < operation.opened {
                return Err(SigningError::TimeRejected);
            }
            let (lower, upper) = operation.anchor.bounds(now)?;
            inspect(&operation.expected, &operation.proposal, lower)?;
            inspect(&operation.expected, &operation.proposal, upper)?;
            let root = custody::recover(
                &operation.backup,
                &operation.card,
                root_token,
                &operation.identity,
            )
            .map_err(|_| SigningError::RecoveryRejected)?;
            if operation.cancelled.load(Ordering::SeqCst) {
                return Err(SigningError::Unavailable);
            }
            let artifact = perform(
                &operation.expected,
                &operation.proposal,
                &root,
                &operation.identity,
                archive_backup,
                archive_recovery,
                upper,
            )?;
            drop(root);
            let prepared = output(context, artifact)?;
            // A panic after Java secret output allocation still needs the
            // adapter's explicit cleanup, before the outer JNI boundary runs.
            let validation = (|| {
                // Keep the final clock/context sample and publication in one
                // registry critical section, including time spent acquiring it.
                let mut registry = self
                    .registry
                    .lock()
                    .map_err(|_| SigningError::Unavailable)?;
                // The guard lives outside this unwind boundary, so a clock
                // callback panic cannot poison it or block lifecycle cleanup.
                let checked = catch_unwind(AssertUnwindSafe(|| {
                    let completed = elapsed(context)?;
                    if completed < now {
                        return Err(SigningError::TimeRejected);
                    }
                    let (lower, upper) = operation.anchor.bounds(completed)?;
                    inspect(&operation.expected, &operation.proposal, lower)?;
                    inspect(&operation.expected, &operation.proposal, upper)?;
                    if operation.cancelled.load(Ordering::SeqCst)
                        || registry.active.remove(&handle).is_none()
                    {
                        return Err(SigningError::Unavailable);
                    }
                    Ok(())
                }));
                drop(registry);
                checked.unwrap_or_else(|_| {
                    self.close_all();
                    Err(SigningError::Unavailable)
                })
            })();
            if let Err(error) = validation {
                discard(context, prepared);
                return Err(error);
            }
            Ok(prepared)
        })();
        if result.is_err() {
            operation.cancelled.store(true, Ordering::SeqCst);
            if let Ok(mut registry) = self.registry.lock() {
                registry.active.remove(&handle);
            }
        }
        result
    }
    pub fn close(&self, handle: OperationHandle) {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(cancelled) = registry.active.remove(&handle) {
                cancelled.store(true, Ordering::SeqCst);
            }
            registry.pending.remove(&handle);
        }
    }
    pub fn close_all(&self) {
        if let Ok(mut registry) = self.registry.lock() {
            for cancelled in registry.active.values() {
                cancelled.store(true, Ordering::SeqCst);
            }
            registry.active.clear();
            registry.pending.clear();
        }
    }
}
impl Drop for TypedService {
    fn drop(&mut self) {
        self.close_all();
    }
}

#[cfg(test)]
mod tests;
