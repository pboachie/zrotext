// SPDX-License-Identifier: AGPL-3.0-only
//! Isolated review-workspace custody: one exact approval and fresh recovery.
//!
//! This trusted-input component does not authenticate a server or a broker. The
//! Android sibling obtains this DISTINCT context from the current app-owned
//! same-origin review session. Ordinary owner-session authority is never accepted.
//! Wire enrollment/custody formats and ordinary signing policy are unchanged.

use crate::custody;
use rand::{TryRng, rngs::SysRng};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zrotext_root_material::{
    root_backup::ExpectedIdentity,
    root_unlock::custody::{ReviewedCustody, Signatures},
    sealed_root_enrollment::{self, Challenge},
};

const MAX_OPERATIONS: usize = 8;
const MAX_CHALLENGES: usize = 256;
use crate::signing::{SigningError, TimeAnchor};

/// Current authenticated isolated review context, captured independently of the
/// proposed enrollment. No cookie, password, private locator or root secret.
/// This is not an ordinary signing::Authority or database authorization proof.
#[derive(Clone, PartialEq, Eq)]
pub struct ReviewAuthority {
    pub realm: [u8; 16],
    pub database_commitment: [u8; 32],
    pub config_commitment: [u8; 32],
    pub config_revision: u64,
    pub origin: String,
    pub account_id: [u8; 16],
    pub owner_user_id: [u8; 16],
    pub review_owner_session_id: [u8; 16],
    pub broker_principal_id: [u8; 16],
    pub credential_id: [u8; 16],
    pub credential_revision: u64,
    pub broker_session_id: [u8; 16],
    pub authentication_event_id: [u8; 16],
    pub issued_ms: u64,
    pub absolute_expiry_ms: u64,
    pub idle_deadline_ms: u64,
    /// Local browser/context lifecycle epoch. A cancelled context cannot revive.
    pub context_epoch: u64,
}

/// Opaque random positive handle. It carries no root or reusable signing power.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReviewHandle(u64);

impl ReviewHandle {
    pub fn as_u64(self) -> u64 {
        self.0
    }
    pub fn from_u64(value: u64) -> Result<Self, SigningError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(SigningError::Unavailable);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ReplayKey {
    realm: [u8; 16],
    database: [u8; 32],
    account: [u8; 16],
    user: [u8; 16],
    session: [u8; 16],
    challenge: [u8; 16],
}

struct Operation {
    reviewed: ReviewedCustody,
    unsigned: Vec<u8>,
    backup: Vec<u8>,
    card: Vec<u8>,
    expected: ExpectedIdentity,
    authority: ReviewAuthority,
    anchor: TimeAnchor,
    opened_elapsed_ms: u64,
    cancelled: Arc<AtomicBool>,
}

#[derive(Default)]
struct Registry {
    pending: HashMap<ReviewHandle, Operation>,
    active: HashMap<ReviewHandle, Arc<AtomicBool>>,
    // Never evict within the process: a cancelled/failed approval cannot reopen.
    // Server one-time challenge consumption remains necessary across restarts.
    reviewed_challenges: HashSet<ReplayKey>,
}

#[derive(Default)]
pub struct ReviewSigningService {
    registry: Mutex<Registry>,
}

fn check_authority(challenge: &Challenge, authority: &ReviewAuthority) -> Result<(), SigningError> {
    let identities = [
        authority.realm,
        authority.account_id,
        authority.owner_user_id,
        authority.review_owner_session_id,
        authority.broker_principal_id,
        authority.credential_id,
        authority.broker_session_id,
        authority.authentication_event_id,
    ];
    if identities.contains(&[0; 16])
        || authority.database_commitment == [0; 32]
        || authority.config_commitment == [0; 32]
        || authority.config_revision == 0
        || authority.config_revision > i64::MAX as u64
        || authority.credential_revision == 0
        || authority.credential_revision > i64::MAX as u64
        || authority.context_epoch == 0
        || authority.context_epoch > i64::MAX as u64
        || !sealed_root_enrollment::canonical_origin(&authority.origin)
        || challenge.origin != authority.origin
        || challenge.account_id != authority.account_id
        || challenge.user_id != authority.owner_user_id
        || challenge.session_id != authority.review_owner_session_id
    {
        return Err(SigningError::ContextRejected);
    }
    Ok(())
}

fn check_time(
    challenge: &Challenge,
    authority: &ReviewAuthority,
    anchor: TimeAnchor,
    now: u64,
) -> Result<u64, SigningError> {
    let (lower, upper) = anchor.bounds(now)?;
    if authority.issued_ms == 0
        || authority.absolute_expiry_ms > i64::MAX as u64
        || authority.idle_deadline_ms > authority.absolute_expiry_ms
        || lower < authority.issued_ms
        || upper >= authority.idle_deadline_ms
        || lower < challenge.issued_ms
        || upper >= challenge.expires_ms
    {
        return Err(SigningError::TimeRejected);
    }
    Ok(upper)
}

impl ReviewSigningService {
    /// Review only the canonical typed enrollment challenge plus exact encrypted
    /// custody publication. No arbitrary bytes, arbitrary transcript or signer.
    #[expect(
        clippy::too_many_arguments,
        reason = "separate independent identity, session and time are required"
    )]
    pub fn open_custody(
        &self,
        unsigned: &[u8],
        backup: &[u8],
        card: &[u8],
        expected: &ExpectedIdentity,
        bundle_id: &[u8; 16],
        authority: ReviewAuthority,
        anchor: TimeAnchor,
        now_elapsed_ms: u64,
    ) -> Result<ReviewHandle, SigningError> {
        let challenge =
            sealed_root_enrollment::parse(unsigned).map_err(|_| SigningError::InvalidInput)?;
        check_authority(&challenge, &authority)?;
        let upper = check_time(&challenge, &authority, anchor, now_elapsed_ms)?;
        let reviewed = ReviewedCustody::inspect(unsigned, backup, card, expected, bundle_id, upper)
            .map_err(|_| SigningError::ContextRejected)?;
        let replay = ReplayKey {
            realm: authority.realm,
            database: authority.database_commitment,
            account: authority.account_id,
            user: authority.owner_user_id,
            session: authority.review_owner_session_id,
            challenge: challenge.challenge_id,
        };
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        if registry.active.len() >= MAX_OPERATIONS
            || registry.reviewed_challenges.len() >= MAX_CHALLENGES
            || registry.reviewed_challenges.contains(&replay)
        {
            return Err(SigningError::Unavailable);
        }
        let handle = (0..8)
            .find_map(|_| {
                let mut bytes = [0; 8];
                SysRng.try_fill_bytes(&mut bytes).ok()?;
                let value = u64::from_be_bytes(bytes) & i64::MAX as u64;
                let handle = ReviewHandle::from_u64(value).ok()?;
                (!registry.active.contains_key(&handle)).then_some(handle)
            })
            .ok_or(SigningError::Unavailable)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        registry.reviewed_challenges.insert(replay);
        registry.active.insert(handle, cancelled.clone());
        registry.pending.insert(
            handle,
            Operation {
                reviewed,
                unsigned: unsigned.to_vec(),
                backup: backup.to_vec(),
                card: card.to_vec(),
                expected: expected.clone(),
                authority,
                anchor,
                opened_elapsed_ms: now_elapsed_ms,
                cancelled,
            },
        );
        Ok(handle)
    }

    /// Exact immutable public bytes used by the native typed review.
    pub fn review(&self, handle: ReviewHandle) -> Result<Vec<u8>, SigningError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        let operation = registry
            .pending
            .get(&handle)
            .ok_or(SigningError::Unavailable)?;
        Ok(operation.unsigned.clone())
    }

    /// Consumes approval before recovery, even on a wrong token or switched
    /// session. Time is sampled again after the recovered root has been dropped.
    /// The clock callback only supplies elapsed time; it receives no secret.
    pub fn sign(
        &self,
        handle: ReviewHandle,
        recovery_token: &[u8],
        current_authority: &ReviewAuthority,
        mut elapsed_realtime: impl FnMut() -> Result<u64, SigningError>,
    ) -> Result<Signatures, SigningError> {
        self.sign_with_public_output(
            handle,
            recovery_token,
            current_authority,
            &mut (),
            |_| elapsed_realtime(),
            |_, signatures| Ok(signatures),
        )
    }

    /// The JNI adapter builds public output before the final fresh-time and
    /// cancellation checks, so an allocation/GC pause cannot extend expiry.
    /// This adapter receives signatures only, after the native root is dropped.
    pub(crate) fn sign_with_public_output<C, T>(
        &self,
        handle: ReviewHandle,
        recovery_token: &[u8],
        current_authority: &ReviewAuthority,
        context: &mut C,
        mut elapsed_realtime: impl FnMut(&mut C) -> Result<u64, SigningError>,
        output: impl FnOnce(&mut C, Signatures) -> Result<T, SigningError>,
    ) -> Result<T, SigningError> {
        let operation = self
            .registry
            .lock()
            .map_err(|_| SigningError::Unavailable)?
            .pending
            .remove(&handle)
            .ok_or(SigningError::Unavailable)?;
        let result = (|| {
            if operation.cancelled.load(Ordering::SeqCst)
                || *current_authority != operation.authority
            {
                return Err(SigningError::ContextRejected);
            }
            let now = elapsed_realtime(context)?;
            if now < operation.opened_elapsed_ms {
                return Err(SigningError::TimeRejected);
            }
            let challenge = sealed_root_enrollment::parse(&operation.unsigned)
                .map_err(|_| SigningError::InvalidInput)?;
            let upper = check_time(&challenge, &operation.authority, operation.anchor, now)?;
            let root = custody::recover(
                &operation.backup,
                &operation.card,
                recovery_token,
                &operation.expected,
            )
            .map_err(|_| SigningError::RecoveryRejected)?;
            if operation.cancelled.load(Ordering::SeqCst) {
                return Err(SigningError::Unavailable);
            }
            let signatures = operation
                .reviewed
                .sign(&root, upper)
                .map_err(|_| SigningError::ContextRejected)?;
            drop(root);
            let public_output = output(context, signatures)?;
            // Acquire the publication lock before the final time sample: the
            // lock wait itself must not extend approval past its deadline.
            // A close that wins this lock prevents output; replay remains burned.
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| SigningError::Unavailable)?;
            let completed = elapsed_realtime(context)?;
            if completed < now {
                return Err(SigningError::TimeRejected);
            }
            check_time(
                &challenge,
                &operation.authority,
                operation.anchor,
                completed,
            )?;
            if operation.cancelled.load(Ordering::SeqCst)
                || registry.active.remove(&handle).is_none()
            {
                return Err(SigningError::Unavailable);
            }
            Ok(public_output)
        })();
        if result.is_err() {
            operation.cancelled.store(true, Ordering::SeqCst);
            if let Ok(mut registry) = self.registry.lock() {
                registry.active.remove(&handle);
            }
        }
        result
    }

    pub fn close(&self, handle: ReviewHandle) {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(cancelled) = registry.active.remove(&handle) {
                cancelled.store(true, Ordering::SeqCst);
            }
            registry.pending.remove(&handle);
        }
    }

    /// Lifecycle loss, authority withdrawal or session replacement. No root is
    /// cached; a process restart naturally starts with an empty handle registry.
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

impl Drop for ReviewSigningService {
    fn drop(&mut self) {
        self.close_all();
    }
}

#[cfg(test)]
mod tests;
