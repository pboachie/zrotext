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
//!
//! What this crate deliberately does **not** do yet: it talks to no quorum or
//! consensus store and observes no database itself (the executor's default
//! in-process source contributes no reports until real members exist), it
//! does not stop or reseed PostgreSQL hosts (external watchdog integration),
//! and the operational epoch is not yet anchored to an external authority —
//! later increments per the implementation-status notes in
//! `docs/MULTI-LOCATION.md`.

pub mod decision;
pub mod executor;
pub mod policy;

#[cfg(test)]
mod executor_tests;
#[cfg(test)]
mod tests;
