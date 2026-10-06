// SPDX-License-Identifier: AGPL-3.0-only
//! One exact enrollment/custody approval, fresh recovery, and no unlocked lease.

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
const MAX_AGE_MS: u64 = 300_000;
const MAX_UNCERTAINTY_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SigningError {
    #[error("owner custody input rejected")]
    InvalidInput,
    #[error("owner custody identity or session rejected")]
    ContextRejected,
    #[error("owner custody time rejected")]
    TimeRejected,
    #[error("owner custody approval unavailable")]
    Unavailable,
    #[error("owner custody recovery rejected")]
    RecoveryRejected,
}

/// Obtained from the current authenticated owner session, independently of the
/// imported public proposal. This native layer does not establish authentication.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Authority {
    pub account_id: [u8; 16],
    pub user_id: [u8; 16],
    pub session_id: [u8; 16],
}

/// Authenticated server time, recorded against Android elapsedRealtime (which
/// includes device sleep). Uncertainty is a conservative bound, not clock skew
/// permission. A wall clock or downloaded proposal is not an authenticated anchor.
#[derive(Clone, Copy)]
pub struct TimeAnchor {
    pub authenticated_server_ms: u64,
    pub authenticated_elapsed_ms: u64,
    pub uncertainty_ms: u64,
}

impl TimeAnchor {
    pub(crate) fn bounds(self, elapsed_ms: u64) -> Result<(u64, u64), SigningError> {
        let elapsed = elapsed_ms
            .checked_sub(self.authenticated_elapsed_ms)
            .ok_or(SigningError::TimeRejected)?;
        if self.authenticated_server_ms == 0
            || self.authenticated_server_ms > i64::MAX as u64
            || self.uncertainty_ms > MAX_UNCERTAINTY_MS
            || elapsed > MAX_AGE_MS
        {
            return Err(SigningError::TimeRejected);
        }
        let center = self
            .authenticated_server_ms
            .checked_add(elapsed)
            .ok_or(SigningError::TimeRejected)?;
        let lower = center
            .checked_sub(self.uncertainty_ms)
            .ok_or(SigningError::TimeRejected)?;
        let upper = center
            .checked_add(self.uncertainty_ms)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(SigningError::TimeRejected)?;
        Ok((lower, upper))
    }
}

/// Opaque random positive handle. It carries no root or reusable signing power.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationHandle(u64);

impl OperationHandle {
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
    authority: Authority,
    anchor: TimeAnchor,
    opened_elapsed_ms: u64,
    cancelled: Arc<AtomicBool>,
}

#[derive(Default)]
struct Registry {
    pending: HashMap<OperationHandle, Operation>,
    active: HashMap<OperationHandle, Arc<AtomicBool>>,
    // Never evict within the process: a cancelled/failed approval cannot reopen.
    // Server one-time challenge consumption remains necessary across restarts.
    reviewed_challenges: HashSet<ReplayKey>,
}

#[derive(Default)]
pub struct SigningService {
    registry: Mutex<Registry>,
}

fn check_authority(challenge: &Challenge, authority: &Authority) -> Result<(), SigningError> {
    if authority.account_id == [0; 16]
        || authority.user_id == [0; 16]
        || authority.session_id == [0; 16]
        || challenge.account_id != authority.account_id
        || challenge.user_id != authority.user_id
        || challenge.session_id != authority.session_id
    {
        return Err(SigningError::ContextRejected);
    }
    Ok(())
}

fn check_time(challenge: &Challenge, anchor: TimeAnchor, now: u64) -> Result<u64, SigningError> {
    let (lower, upper) = anchor.bounds(now)?;
    if lower < challenge.issued_ms || upper >= challenge.expires_ms {
        return Err(SigningError::TimeRejected);
    }
    Ok(upper)
}

impl SigningService {
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
        authority: Authority,
        anchor: TimeAnchor,
        now_elapsed_ms: u64,
    ) -> Result<OperationHandle, SigningError> {
        let challenge =
            sealed_root_enrollment::parse(unsigned).map_err(|_| SigningError::InvalidInput)?;
        check_authority(&challenge, &authority)?;
        let upper = check_time(&challenge, anchor, now_elapsed_ms)?;
        let reviewed = ReviewedCustody::inspect(unsigned, backup, card, expected, bundle_id, upper)
            .map_err(|_| SigningError::ContextRejected)?;
        let replay = ReplayKey {
            account: authority.account_id,
            user: authority.user_id,
            session: authority.session_id,
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
                let handle = OperationHandle::from_u64(value).ok()?;
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
    pub fn review(&self, handle: OperationHandle) -> Result<Vec<u8>, SigningError> {
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
        handle: OperationHandle,
        recovery_token: &[u8],
        current_authority: &Authority,
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
        handle: OperationHandle,
        recovery_token: &[u8],
        current_authority: &Authority,
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
            let upper = check_time(&challenge, operation.anchor, now)?;
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
            check_time(&challenge, operation.anchor, completed)?;
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

    pub fn close(&self, handle: OperationHandle) {
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

impl Drop for SigningService {
    fn drop(&mut self) {
        self.close_all();
    }
}

#[cfg(test)]
mod tests;
