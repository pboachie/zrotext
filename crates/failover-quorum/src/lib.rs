// SPDX-License-Identifier: AGPL-3.0-only
//! Decision model for independent-quorum automatic writer failover.
//!
//! Increments of the automatic-failover design in
//! `docs/MULTI-LOCATION.md` ("Automatic failover needs an independent
//! decision") implemented by this crate:
//!
//! * [`policy`] parses the `FAILOVER_QUORUM_ENABLED` /
//!   `FAILOVER_QUORUM_MEMBERS` environment contract. Disabled is the default
//!   and the disabled policy never reads further configuration.
//! * [`decision`] holds the quorum-observation types and the
//!   [`decision::FailoverController`] promotion-decision state machine with
//!   its failure-scenario tests, plus the restorable subset of its state.
//! * [`executor`] is the controller loop: it gathers member observations
//!   through a pluggable source, runs decision rounds and applies the
//!   emitted decisions to the authoritative writer database through an
//!   injected [`executor::WriterAuthority`] port — fencing the old writer's
//!   site, bumping `deployment_authority.epoch` to exactly the decided epoch
//!   (never backward, never twice, never past an unfenced writer), enabling
//!   the promoted site and forcing dispatch paused — with a durable
//!   write-ahead journal so restarts resume instead of re-applying.
//! * [`store`] is the durable consensus store the executor reads rounds
//!   from: a membership record plus one append-only journal file per member
//!   under a configurable directory, with store-assigned contiguous
//!   sequences, per-record identities (spoofing fails the load) and the
//!   decision model's freshness window. Corruption, truncation, membership
//!   changes mid-flight and concurrent appends all fail closed — an `Err`
//!   store or a poisoned one serves only empty rounds, so the controller
//!   loses quorum and holds. [`store::StoreObservationSource`] adapts it to
//!   the executor's observation seam without touching the rounds.
//! * [`anchor`] defines the interface for anchoring the operational epoch to
//!   a future external authority (monotonic, refuses backward promotions).
//!   It is an interface only: this build ships a test implementation and no
//!   external anchoring.
//! * [`observe`] forms one member's quorum report per round from raw probe
//!   outcomes — the reporter half of the member-reporting transport — with
//!   fail-closed rules for member-local probe faults.
//!
//! What this crate deliberately does **not** do yet: it listens on no
//! network and runs no consensus service — no transport carries member
//! reports into the store, so in production the store stays empty and every
//! round fails closed — it observes no database itself, it does not stop or
//! reseed PostgreSQL hosts (external watchdog integration), the epoch anchor
//! has no real implementation, and the store journals are never rotated or
//! compacted; later increments per the implementation-status notes in
//! `docs/MULTI-LOCATION.md`.

pub mod anchor;
pub mod decision;
pub mod executor;
pub mod observe;
pub mod policy;
pub mod store;

#[cfg(test)]
mod executor_tests;
#[cfg(test)]
mod tests;
