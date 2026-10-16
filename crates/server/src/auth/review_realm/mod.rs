// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted review-realm component. Supplied deployment/database observations
//! are NOT authenticated here. No value in this module activates startup,
//! provisions a workspace, verifies email, consumes MFA or authorizes HTTP/DB
//! effects. A future adapter must establish actual isolation and re-read durable
//! identity/credential/challenge state under the action's writer fence.

use super::password_work;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Public identity commitments, not key material or evidence of key custody.
#[derive(Clone, PartialEq, Eq)]
pub struct DeploymentIdentity {
    pub realm_id: Uuid,
    pub database_id: Uuid,
    pub canonical_origin: String,
    pub deployment_fingerprint: [u8; 32],
    /// Auth token, enrollment token, reauthentication, grant and MFA keys,
    /// respectively. Fixed slots avoid accepting an incomplete key inventory.
    pub key_fingerprints: [[u8; 32]; 5],
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ComponentError {
    #[error("review component identity is incomplete or noncanonical")]
    InvalidIdentity,
    #[error("review component expected/observed isolation mismatch")]
    IsolationMismatch,
    #[error("review component overlaps a production identity")]
    ProductionOverlap,
    #[error("review component requires an exact review workspace binding")]
    InvalidBinding,
    #[error("review component time is stale or regressed")]
    InvalidTime,
    #[error("review component password verification refused")]
    PasswordRejected,
}

fn nonzero(bytes: &[u8; 32]) -> bool {
    bytes.iter().any(|b| *b != 0)
}

fn time(value: u64) -> Result<(), ComponentError> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(ComponentError::InvalidTime);
    }
    Ok(())
}

impl DeploymentIdentity {
    fn validate(&self) -> Result<(), ComponentError> {
        let origin =
            url::Url::parse(&self.canonical_origin).map_err(|_| ComponentError::InvalidIdentity)?;
        if self.realm_id.is_nil()
            || self.database_id.is_nil()
            || self.canonical_origin.len() > 512
            || origin.scheme() != "https"
            || origin.origin().ascii_serialization() != self.canonical_origin
            || !origin.username().is_empty()
            || origin.password().is_some()
            || !nonzero(&self.deployment_fingerprint)
            || self.key_fingerprints.iter().any(|key| !nonzero(key))
            || self
                .key_fingerprints
                .iter()
                .enumerate()
                .any(|(i, key)| self.key_fingerprints[..i].contains(key))
        {
            return Err(ComponentError::InvalidIdentity);
        }
        Ok(())
    }
}

/// Owned structural snapshot only. Its name deliberately does not promise that
/// an operator actually connected to an isolated database or inspected keys.
/// No constructor or method mounts or changes ordinary authentication policy.
pub struct UnactivatedReviewRealm {
    identity: DeploymentIdentity,
    observed_at_ms: u64,
}

impl UnactivatedReviewRealm {
    /// Compare complete supplied observations with expected pins and a nonempty
    /// production inventory. Actual marker/endpoint/certificate/key provenance
    /// and deployment-enforced containment remain the future adapter's job.
    pub fn compare_supplied_observations(
        expected: DeploymentIdentity,
        observed: DeploymentIdentity,
        production: &[DeploymentIdentity],
        observed_at_ms: u64,
    ) -> Result<Self, ComponentError> {
        expected.validate()?;
        observed.validate()?;
        time(observed_at_ms)?;
        if production.is_empty() {
            return Err(ComponentError::InvalidIdentity);
        }
        if expected != observed {
            return Err(ComponentError::IsolationMismatch);
        }
        for other in production {
            other.validate()?;
            if expected.realm_id == other.realm_id
                || expected.database_id == other.database_id
                || expected.canonical_origin == other.canonical_origin
                || expected.deployment_fingerprint == other.deployment_fingerprint
                || expected
                    .key_fingerprints
                    .iter()
                    .any(|key| other.key_fingerprints.contains(key))
            {
                return Err(ComponentError::ProductionOverlap);
            }
        }
        Ok(Self {
            identity: expected,
            observed_at_ms,
        })
    }

    fn bind(
        &self,
        policy: &IdentityPolicy,
        request: &ReauthenticationRequest,
        now_ms: u64,
    ) -> Result<(), ComponentError> {
        request.scope.validate()?;
        let IdentityPolicy::ReviewWorkspace(scope) = policy else {
            return Err(ComponentError::InvalidBinding);
        };
        if scope != &request.scope
            || scope.realm_id != self.identity.realm_id
            || scope.database_id != self.identity.database_id
            || request.challenge_id.is_nil()
            || !nonzero(&request.statement_digest)
        {
            return Err(ComponentError::InvalidBinding);
        }
        time(request.issued_at_ms)?;
        time(request.expires_at_ms)?;
        time(now_ms)?;
        if now_ms < self.observed_at_ms
            || request.issued_at_ms > now_ms
            || now_ms >= request.expires_at_ms
        {
            return Err(ComponentError::InvalidTime);
        }
        Ok(())
    }

    /// Real bounded password work against a captured, supplied verifier. This
    /// proves only that check, not that the verifier/revision is current in DB.
    /// All request/scalar/hash values are owned before the verifier can await.
    /// Login is never accepted as a replacement for this operation-bound check.
    pub async fn check_password(
        &self,
        policy: IdentityPolicy,
        request: ReauthenticationRequest,
        credential: CredentialSnapshot,
        password: &str,
        now_ms: u64,
    ) -> Result<PasswordCheckProof, ComponentError> {
        self.bind(&policy, &request, now_ms)?;
        if credential.realm_id != self.identity.realm_id
            || credential.database_id != self.identity.database_id
            || credential.credential_id != request.scope.broker_credential_id
            || credential.revision != request.scope.credential_revision
        {
            return Err(ComponentError::InvalidBinding);
        }
        password_work::verify(password, Some(credential.verifier.to_string()))
            .await
            .map_err(|_| ComponentError::PasswordRejected)?;
        Ok(PasswordCheckProof {
            identity: self.identity.clone(),
            request,
            checked_at_ms: now_ms,
        })
    }
}

/// Workspace identity comes from an authenticated adapter, not from imported
/// proposals or the shared broker's own normal account membership.
#[derive(Clone, PartialEq, Eq)]
pub struct WorkspaceScope {
    pub realm_id: Uuid,
    pub database_id: Uuid,
    pub account_id: Uuid,
    pub owner_user_id: Uuid,
    pub owner_session_id: Uuid,
    pub broker_authentication_event: Uuid,
    pub broker_credential_id: Uuid,
    pub credential_revision: u64,
}

impl WorkspaceScope {
    fn validate(&self) -> Result<(), ComponentError> {
        if [
            self.realm_id,
            self.database_id,
            self.account_id,
            self.owner_user_id,
            self.owner_session_id,
            self.broker_authentication_event,
            self.broker_credential_id,
        ]
        .iter()
        .any(Uuid::is_nil)
            || self.credential_revision == 0
            || self.credential_revision > i64::MAX as u64
        {
            return Err(ComponentError::InvalidBinding);
        }
        Ok(())
    }
}

/// Explicit policy alternatives; no boolean exempts ordinary owners from MFA.
pub enum IdentityPolicy {
    Ordinary,
    ReviewWorkspace(WorkspaceScope),
}

/// Component operation kinds only: no route, transcript or wire allocation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReviewOperation {
    RootCustodyEnrollment,
    LineOwnerKeyRegistration,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReauthenticationRequest {
    pub scope: WorkspaceScope,
    pub operation: ReviewOperation,
    pub challenge_id: Uuid,
    pub statement_digest: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Supplied verifier, not authenticated DB state. No Debug/Serialize/projection
/// exposes its hash, and the owned copy is zeroized on drop.
///
/// ```compile_fail
/// use zrotext_server::auth::review_realm::CredentialSnapshot;
/// fn diagnostic<T: std::fmt::Debug>() {}
/// diagnostic::<CredentialSnapshot>();
/// ```
pub struct CredentialSnapshot {
    realm_id: Uuid,
    database_id: Uuid,
    credential_id: Uuid,
    revision: u64,
    verifier: Zeroizing<String>,
}

impl CredentialSnapshot {
    pub fn capture_supplied_verifier(
        realm: &UnactivatedReviewRealm,
        credential_id: Uuid,
        revision: u64,
        verifier: String,
    ) -> Result<Self, ComponentError> {
        let verifier = Zeroizing::new(verifier);
        if credential_id.is_nil()
            || revision == 0
            || revision > i64::MAX as u64
            || verifier.is_empty()
            || verifier.len() > 1024
        {
            return Err(ComponentError::InvalidIdentity);
        }
        Ok(Self {
            realm_id: realm.identity.realm_id,
            database_id: realm.identity.database_id,
            credential_id,
            revision,
            verifier,
        })
    }
}

/// Unforgeable within safe Rust, component-only evidence. Deliberately neither
/// Debug nor Serialize. It is NOT MFA, durable one-use consumption, a live DB
/// read, session creation, startup activation, consent, or permission to commit.
///
/// ```compile_fail
/// use zrotext_server::auth::review_realm::PasswordCheckProof;
/// fn diagnostic<T: std::fmt::Debug>() {}
/// diagnostic::<PasswordCheckProof>();
/// ```
///
/// Safe callers cannot supply the private proof fields:
///
/// ```compile_fail
/// use zrotext_server::auth::review_realm::PasswordCheckProof;
/// let proof = PasswordCheckProof { identity: todo!(), request: todo!(), checked_at_ms: 1 };
/// ```
pub struct PasswordCheckProof {
    identity: DeploymentIdentity,
    request: ReauthenticationRequest,
    checked_at_ms: u64,
}

impl PasswordCheckProof {
    /// Recheck exact structural context and nonregressing comparison time. This
    /// method is intentionally repeatable: it makes NO replay-ledger claim.
    /// A future durable consumer must atomically re-read and consume its actual
    /// challenge/revision/permission; this check cannot replace that transaction.
    pub fn check_exact_binding(
        &self,
        realm: &UnactivatedReviewRealm,
        policy: &IdentityPolicy,
        request: &ReauthenticationRequest,
        now_ms: u64,
    ) -> Result<(), ComponentError> {
        realm.bind(policy, request, now_ms)?;
        if self.identity != realm.identity || self.request != *request {
            return Err(ComponentError::InvalidBinding);
        }
        if now_ms < self.checked_at_ms {
            return Err(ComponentError::InvalidTime);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
