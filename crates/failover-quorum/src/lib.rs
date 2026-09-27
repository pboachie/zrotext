// SPDX-License-Identifier: AGPL-3.0-only
//! Decision model for independent-quorum automatic writer failover.
//!
//! First increment of the automatic-failover design in
//! `docs/MULTI-LOCATION.md` ("Automatic failover needs an independent
//! decision"). This crate is a pure, I/O-free model:
//!
//! * [`policy`] parses the `FAILOVER_QUORUM_ENABLED` /
//!   `FAILOVER_QUORUM_MEMBERS` environment contract. Disabled is the default
//!   and the disabled policy never reads further configuration.
//! * [`decision`] holds the quorum-observation types and the
//!   [`decision::FailoverController`] promotion-decision state machine with
//!   its failure-scenario tests.
//!
//! What this crate deliberately does **not** do yet: it runs no controller
//! loop, talks to no quorum or consensus store, observes no database, and
//! executes no fencing. Applying a [`decision::Decision`] — writing the site
//! fence, stopping the old writer's PostgreSQL, promoting the standby and
//! bumping `deployment_authority.epoch` — is the executor's job and a later
//! increment, as is anchoring the epoch to an external authority.

pub mod decision;
pub mod policy;

#[cfg(test)]
mod tests;
