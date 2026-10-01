// SPDX-License-Identifier: AGPL-3.0-only
//! Adapter interfaces for external writer fencing and epoch authority
//! (issue #647).
//!
//! `MULTI-LOCATION.md` ("Three fences, not one sticky session") separates the
//! *database authority fence* — the `sites` row the executor already sets
//! through [`crate::executor::WriterAuthority`] — from *external host
//! fencing*: stopping the old writer's PostgreSQL host through an independent,
//! authenticated authority so a stale process cannot accept mutations or
//! restart as a writer. SQL site-row fencing cannot provide that, and
//! automatic promotion must not rely on internal substitutes. This module
//! defines the bounded adapter interfaces for both halves of that external
//! contract:
//!
//! * [`FenceAuthority`] fences a host under an opaque [`FenceToken`] —
//!   idempotently, because a re-fence under the token of the same promotion
//!   intent is a success, never a second fence — and reports whether a fence
//!   holds. There is deliberately **no unfence operation**: the executor has
//!   no operation that reverses a fence, and an external fence is released
//!   only by an operator acting on the external authority, never
//!   automatically (never disable fencing to regain availability).
//! * [`ExternalEpochAnchor`] extends the epoch-anchor contract of
//!   [`crate::anchor`] with the confirmation concept: an anchor that is
//!   *confirmed* by its external authority names the highest epoch that
//!   authority anchored, and only a confirmed anchor may authorize anything.
//!   It fuses "is it confirmed?" and "at which epoch?" into one
//!   [`ExternalEpochAnchor::confirmed_epoch`] call so no window exists
//!   between the two answers.
//!
//! Both traits are deliberately **object safe and refusal-only**: they have no
//! error channel, because an absent, unconfirmed, timed-out or partitioned
//! authority is a *refusal*, never an error a caller could misread as
//! success. Implementations fold every transport failure, timeout and
//! internal disagreement into the `Unconfirmed`-shaped outcomes. That is the
//! issue's "refusal (not error-and-continue)" rule made unrepresentable to
//! bypass. The timeout contract: every operation returns within a bound the
//! implementation enforces itself (the PostgreSQL adapter rides the port's
//! existing operation ceiling); a timeout surfaces as `Unconfirmed`, never as
//! a hang. Implementations backed by a replicated or partitionable authority
//! must refuse when their replicas disagree — picking one side of a partition
//! would fabricate a confirmed fence.
//!
//! This build ships exactly one production implementation, the fail-closed
//! [`NoopFenceAuthority`]: no external fencing backend exists yet, so the
//! wiring exists but every fence is refused and no promotion can pass the
//! external-fence precondition. A real backend (for example an authenticated
//! command executor against a watchdog) is deliberately deferred; the
//! interface is the contract later increments implement. The in-repo
//! [`crate::anchor::MemoryEpochAnchor`] and the test-only
//! [`MemoryFenceAuthority`] exist for the contract's semantics corpus.

#[cfg(test)]
use std::sync::{Arc, Mutex};

/// The opaque identity of one external host-fencing action. The executor
/// derives it deterministically from the promotion epoch a fence protects, so
/// retries and restarts replay the *same* token and the fence stays
/// idempotent, while a genuinely different promotion (a different epoch)
/// yields a different token and can never silently take over another
/// promotion's fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FenceToken(u64);

impl FenceToken {
    /// The fence identity of the promotion under `epoch`.
    pub const fn for_promotion(epoch: u64) -> Self {
        Self(epoch)
    }
}

/// Result of asking an external authority to fence one host.
///
/// Every refusal is fail-closed: the caller must not proceed with whatever
/// the fence protected, and may only retry with identical parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostFenceOutcome {
    /// The authority fenced the host under this token in this call. The
    /// return itself is the confirmation; a successful fence is durable
    /// before the authority answers.
    Fenced { token: FenceToken },
    /// The host was already fenced under the same token: the idempotent
    /// success of an earlier identical fence (a retry or a restart replay).
    AlreadyFenced { token: FenceToken },
    /// The host is fenced under a different token — another promotion's
    /// fence holds. The existing fence is never overwritten; this caller must
    /// not proceed. Clearing it is a manual operator action on the external
    /// authority.
    RefusedCompetingFence { holder: FenceToken },
    /// The authority is absent, unconfirmed, timed out or partitioned: the
    /// fence could not be established or observed, so nothing may rely on
    /// it. Uncertain fencing is a refusal, never a pass.
    RefusedUnconfirmed,
}

/// What an external authority currently reports about one host's fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceStatus {
    /// The host is fenced under this token and the authority confirms it.
    Fenced { token: FenceToken },
    /// The authority confirms the host is not fenced.
    Unfenced,
    /// The authority could not confirm the host's state at all — absent,
    /// timed out, or partitioned. Uncertainty is not evidence; it never
    /// counts as fenced or unfenced.
    Unconfirmed,
}

/// The external host-fencing port. Operations are bounded (see the module
/// documentation's timeout contract), authenticated by the implementation's
/// own authority credentials, and idempotent under an identical
/// [`FenceToken`].
///
/// Deliberately absent: any unfence operation. Reversing an external fence is
/// a manual operator action on the external authority, never an automated
/// one; the failover design never disables fencing to regain availability.
pub trait FenceAuthority {
    /// Idempotently fence `host_site_id` under `token`. Re-fencing a host
    /// already fenced under the same token succeeds
    /// ([`HostFenceOutcome::AlreadyFenced`]); a host fenced under a different
    /// token is refused, never re-fenced.
    fn fence_host(&mut self, host_site_id: &str, token: FenceToken) -> HostFenceOutcome;

    /// Whether a fence currently holds for `host_site_id`. The executor
    /// requires [`FenceStatus::Fenced`] with *its own* token before any
    /// promotion; every other answer — including [`FenceStatus::Unconfirmed`]
    /// — refuses the promotion.
    fn fence_status(&mut self, host_site_id: &str) -> FenceStatus;
}

/// The fail-closed production default: no external fencing backend is
/// configured, so every operation refuses. This is the failover lane's
/// established pattern (the abstaining probe source): the wiring exists, and
/// an absent authority is never a confirmed fence — so with this backend no
/// promotion can ever pass the external-fence precondition, which is exactly
/// the safe state until a real backend lands.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopFenceAuthority;

impl FenceAuthority for NoopFenceAuthority {
    fn fence_host(&mut self, _host_site_id: &str, _token: FenceToken) -> HostFenceOutcome {
        HostFenceOutcome::RefusedUnconfirmed
    }

    fn fence_status(&mut self, _host_site_id: &str) -> FenceStatus {
        FenceStatus::Unconfirmed
    }
}

/// The reading of one external epoch-anchor query: the highest epoch the
/// external authority has anchored, when that authority confirms it.
///
/// [`AnchorReading::Unconfirmed`] covers the absent, partitioned, timed-out
/// and internally-disagreeing authority: a refusal, never a value. Promotion
/// requires a confirmed anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorReading {
    /// The authority confirms it anchored exactly this epoch (the highest it
    /// ever anchored; implementations never regress it).
    Confirmed { epoch: u64 },
    /// The authority could not confirm an anchored epoch. Nothing may be
    /// authorized on top of an unconfirmed anchor.
    Unconfirmed,
}

/// Result of witnessing a promotion into an external anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorRecord {
    /// The anchor durably recorded the promotion under `new_epoch`.
    Recorded,
    /// Refused: the anchor stays at `anchored_epoch` and only moves strictly
    /// forward. The refusal names the anchored epoch so a caller can tell a
    /// backward/equal record from an unapplied one.
    Refused { anchored_epoch: u64 },
    /// Refused: the authority was absent or unconfirmed, so nothing was
    /// recorded.
    RefusedUnconfirmed,
}

/// The external epoch-authority port: the [`crate::anchor::EpochAnchor`]
/// contract (monotonic anchored epoch, refuses non-forward promotions) plus
/// the confirmation concept issue #647 requires.
///
/// * [`Self::confirmed_epoch`] never regresses for a given authority and
///   answers both "confirmed?" and "at which epoch?" in one call;
/// * [`Self::record_promotion`] refuses an epoch at or below the anchored one
///   — the anchor only moves strictly forward — and a successful record is
///   durable before it answers.
///
/// Witness discipline for implementations that back the *writer database
/// itself* (the PostgreSQL adapter): record only promotions the authority row
/// already serves. The anchor never becomes a second writer of the epoch;
/// recording verifies, it does not write.
pub trait ExternalEpochAnchor {
    /// The highest epoch the external authority anchored, when confirmed.
    fn confirmed_epoch(&mut self) -> AnchorReading;

    /// Anchor that a promotion under `new_epoch` was applied; refuses
    /// non-forward epochs and unconfirmed authorities.
    fn record_promotion(&mut self, new_epoch: u64) -> AnchorRecord;
}

/// The executor's two external adapters bundled as one injectable gate. Each
/// port is boxed behind its object-safe trait, so the executor stays
/// two-generic over its observation source and writer authority while the
/// concrete adapters (the test fakes, the PostgreSQL anchor, the refusing
/// default) are chosen at wiring time — never defaulted, never absent: a
/// [`crate::executor::FailoverExecutor`] cannot be built without external
/// fencing adapters, and the shipped combination pairs a real anchor with
/// [`NoopFenceAuthority`] so promotion stays impossible until a real fence
/// backend exists.
pub struct ExternalFencing {
    fence: Box<dyn FenceAuthority>,
    anchor: Box<dyn ExternalEpochAnchor>,
}

impl ExternalFencing {
    /// Bundle a fence authority and an epoch anchor as the executor's
    /// external gate.
    pub fn new(
        fence: impl FenceAuthority + 'static,
        anchor: impl ExternalEpochAnchor + 'static,
    ) -> Self {
        Self {
            fence: Box::new(fence),
            anchor: Box::new(anchor),
        }
    }

    /// The external fence status for one host.
    pub(crate) fn fence_status(&mut self, host_site_id: &str) -> FenceStatus {
        self.fence.fence_status(host_site_id)
    }

    /// Idempotently fence one host under `token`.
    pub(crate) fn fence_host(&mut self, host_site_id: &str, token: FenceToken) -> HostFenceOutcome {
        self.fence.fence_host(host_site_id, token)
    }

    /// The confirmed anchored epoch, if the authority confirms one.
    pub(crate) fn confirmed_epoch(&mut self) -> AnchorReading {
        self.anchor.confirmed_epoch()
    }

    /// Witness an applied promotion; best-effort by contract (the anchor is a
    /// witness that may lag, never a gate that leads — see the executor's
    /// promotion binding).
    pub(crate) fn record_promotion(&mut self, new_epoch: u64) -> AnchorRecord {
        self.anchor.record_promotion(new_epoch)
    }
}

/// Test-only in-memory fence backend implementing exactly the
/// [`FenceAuthority`] contract, with fault seams for the corpus: the state is
/// shared behind an `Arc`, so a test keeps a clone that observes and injects
/// faults into the very adapter an executor holds.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct MemoryFenceAuthority {
    state: Arc<Mutex<MemoryFenceState>>,
}

#[cfg(test)]
#[derive(Default)]
struct MemoryFenceState {
    fences: std::collections::HashMap<String, FenceToken>,
    /// Every operation answers unconfirmed while set (an absent or
    /// partitioned authority).
    unconfirmed: bool,
    /// How many `fence_host` calls apply the fence in the backend but answer
    /// `RefusedUnconfirmed`: a lost acknowledgment. The fence itself held, so
    /// the idempotent retry observes `AlreadyFenced`.
    drop_acknowledgments: usize,
    calls: Vec<(String, FenceToken)>,
}

#[cfg(test)]
impl MemoryFenceAuthority {
    /// Every operation refuses: the authority is absent.
    pub(crate) fn mark_unconfirmed(&self) {
        self.state.lock().expect("fence state").unconfirmed = true;
    }

    /// Install a foreign fence, as another promoter would have.
    pub(crate) fn pre_fence(&self, host_site_id: &str, holder: FenceToken) {
        self.state
            .lock()
            .expect("fence state")
            .fences
            .insert(host_site_id.to_owned(), holder);
    }

    /// Let the next `n` fence applications lose their acknowledgment.
    pub(crate) fn drop_acknowledgments(&self, count: usize) {
        self.state.lock().expect("fence state").drop_acknowledgments = count;
    }

    /// The `(host, token)` pairs `fence_host` was called with.
    pub(crate) fn fence_calls(&self) -> Vec<(String, FenceToken)> {
        self.state.lock().expect("fence state").calls.clone()
    }

    /// The token currently fencing one host, if any.
    pub(crate) fn held_by(&self, host_site_id: &str) -> Option<FenceToken> {
        self.state
            .lock()
            .expect("fence state")
            .fences
            .get(host_site_id)
            .copied()
    }
}

#[cfg(test)]
impl FenceAuthority for MemoryFenceAuthority {
    fn fence_status(&mut self, host_site_id: &str) -> FenceStatus {
        let state = self.state.lock().expect("fence state");
        if state.unconfirmed {
            return FenceStatus::Unconfirmed;
        }
        state
            .fences
            .get(host_site_id)
            .map(|token| FenceStatus::Fenced { token: *token })
            .unwrap_or(FenceStatus::Unfenced)
    }

    fn fence_host(&mut self, host_site_id: &str, token: FenceToken) -> HostFenceOutcome {
        let mut state = self.state.lock().expect("fence state");
        state.calls.push((host_site_id.to_owned(), token));
        if state.unconfirmed {
            return HostFenceOutcome::RefusedUnconfirmed;
        }
        match state.fences.get(host_site_id) {
            Some(existing) if *existing == token => HostFenceOutcome::AlreadyFenced { token },
            Some(existing) => HostFenceOutcome::RefusedCompetingFence { holder: *existing },
            None => {
                state.fences.insert(host_site_id.to_owned(), token);
                if state.drop_acknowledgments > 0 {
                    state.drop_acknowledgments -= 1;
                    // The fence applied; only the acknowledgment was lost.
                    return HostFenceOutcome::RefusedUnconfirmed;
                }
                HostFenceOutcome::Fenced { token }
            }
        }
    }
}
