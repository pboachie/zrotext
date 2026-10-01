// SPDX-License-Identifier: AGPL-3.0-only
//! Interface for anchoring the operational epoch to an external authority.
//!
//! `MULTI-LOCATION.md` ("Site-aware contracts") requires that the operational
//! epoch is anchored to an external authority once automatic failover is
//! introduced: a writer restored from backup, or a stale process pinned to an
//! old epoch, must not be able to serve an epoch the deployment never
//! granted. This module defines that contract only. There is deliberately no
//! production implementation in this build — no network listener, no external
//! service dependency — so an [`EpochAnchor`] can never silently become a
//! second, weaker authority; the in-repo [`MemoryEpochAnchor`] exists for
//! tests of the contract's semantics.
//!
//! Implementations must be monotonic: [`EpochAnchor::anchored_epoch`] never
//! regresses, and [`EpochAnchor::record_promotion`] refuses an epoch at or
//! below the anchored one, so the anchor can only ever move the bound
//! forward. The executor binding of that contract lives in
//! [`crate::fence::ExternalEpochAnchor`] (the confirmation concept) and in the
//! executor itself: a promotion must name an epoch strictly above the
//! confirmed anchored one — except the idempotent completion replay, which
//! the authority must already serve — and a restore whose confirmed anchor is
//! ahead of the authority row (a database restored from an older backup)
//! fails closed.

/// The future external authority for the operational epoch. The contract:
///
/// * [`Self::anchored_epoch`] returns the highest epoch the authority has
///   anchored; it must never regress, including across the authority's own
///   restarts;
/// * [`Self::record_promotion`] anchors that a promotion under `new_epoch`
///   was decided. It must refuse (`Err`) any epoch at or below the currently
///   anchored one — the anchor only moves forward — and a successful record
///   must be durable before it returns.
pub trait EpochAnchor {
    type Error;

    /// The highest anchored deployment epoch.
    fn anchored_epoch(&mut self) -> Result<u64, Self::Error>;

    /// Anchor a promotion under `new_epoch`; refuses epochs that do not move
    /// strictly above the anchored one.
    fn record_promotion(&mut self, new_epoch: u64) -> Result<(), Self::Error>;
}

/// In-repo test implementation of [`EpochAnchor`] and
/// [`crate::fence::ExternalEpochAnchor`] — not a production authority.
/// Monotonic in memory, refuses backward and equal promotions. The state is
/// shared behind an `Arc`, so a test keeps a clone that observes and injects
/// faults into the very anchor an executor holds across a simulated restart.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct MemoryEpochAnchor {
    state: std::sync::Arc<std::sync::Mutex<MemoryAnchorState>>,
}

#[cfg(test)]
#[derive(Default)]
struct MemoryAnchorState {
    anchored_epoch: u64,
    /// Every read answers unconfirmed while set (an absent or partitioned
    /// authority).
    unconfirmed: bool,
    /// Refuse every record while set: the authority cannot witness.
    refuse_records: bool,
}

#[cfg(test)]
impl MemoryEpochAnchor {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Every read answers unconfirmed: the authority is absent.
    pub(crate) fn mark_unconfirmed(&self) {
        self.state.lock().expect("anchor state").unconfirmed = true;
    }

    /// Refuse every record (the authority cannot witness promotions).
    pub(crate) fn refuse_records(&self) {
        self.state.lock().expect("anchor state").refuse_records = true;
    }

    /// Pre-seed the anchored epoch, as an authority that witnessed earlier
    /// promotions would report.
    pub(crate) fn seed(&self, epoch: u64) {
        self.state.lock().expect("anchor state").anchored_epoch = epoch;
    }
}

#[cfg(test)]
impl EpochAnchor for MemoryEpochAnchor {
    type Error = &'static str;

    fn anchored_epoch(&mut self) -> Result<u64, Self::Error> {
        Ok(self.state.lock().expect("anchor state").anchored_epoch)
    }

    fn record_promotion(&mut self, new_epoch: u64) -> Result<(), Self::Error> {
        let mut state = self.state.lock().expect("anchor state");
        if new_epoch <= state.anchored_epoch {
            return Err("the anchored epoch only moves strictly forward");
        }
        state.anchored_epoch = new_epoch;
        Ok(())
    }
}

#[cfg(test)]
impl crate::fence::ExternalEpochAnchor for MemoryEpochAnchor {
    fn confirmed_epoch(&mut self) -> crate::fence::AnchorReading {
        let state = self.state.lock().expect("anchor state");
        if state.unconfirmed {
            return crate::fence::AnchorReading::Unconfirmed;
        }
        crate::fence::AnchorReading::Confirmed {
            epoch: state.anchored_epoch,
        }
    }

    fn record_promotion(&mut self, new_epoch: u64) -> crate::fence::AnchorRecord {
        let mut state = self.state.lock().expect("anchor state");
        if state.unconfirmed || state.refuse_records {
            return crate::fence::AnchorRecord::RefusedUnconfirmed;
        }
        if new_epoch <= state.anchored_epoch {
            return crate::fence::AnchorRecord::Refused {
                anchored_epoch: state.anchored_epoch,
            };
        }
        state.anchored_epoch = new_epoch;
        crate::fence::AnchorRecord::Recorded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_anchor_records_and_serves_anchored_epochs() {
        let mut anchor = MemoryEpochAnchor::new();
        assert_eq!(EpochAnchor::anchored_epoch(&mut anchor).unwrap(), 0);
        EpochAnchor::record_promotion(&mut anchor, 7).unwrap();
        assert_eq!(EpochAnchor::anchored_epoch(&mut anchor).unwrap(), 7);
        EpochAnchor::record_promotion(&mut anchor, 12).unwrap();
        assert_eq!(EpochAnchor::anchored_epoch(&mut anchor).unwrap(), 12);
    }

    #[test]
    fn memory_anchor_refuses_backward_and_equal_promotions() {
        let mut anchor = MemoryEpochAnchor::new();
        EpochAnchor::record_promotion(&mut anchor, 5).unwrap();
        assert!(
            EpochAnchor::record_promotion(&mut anchor, 5).is_err(),
            "equal is refused"
        );
        assert!(
            EpochAnchor::record_promotion(&mut anchor, 4).is_err(),
            "backward is refused"
        );
        assert_eq!(
            EpochAnchor::anchored_epoch(&mut anchor).unwrap(),
            5,
            "a refused record never moves the anchored epoch"
        );
        EpochAnchor::record_promotion(&mut anchor, 6).unwrap();
        assert_eq!(EpochAnchor::anchored_epoch(&mut anchor).unwrap(), 6);
    }

    #[test]
    fn external_anchor_confirms_and_refuses_non_forward_records() {
        use crate::fence::ExternalEpochAnchor;
        let mut anchor = MemoryEpochAnchor::new();
        anchor.seed(5);
        assert_eq!(
            anchor.confirmed_epoch(),
            crate::fence::AnchorReading::Confirmed { epoch: 5 }
        );
        assert_eq!(
            crate::fence::ExternalEpochAnchor::record_promotion(&mut anchor, 5),
            crate::fence::AnchorRecord::Refused { anchored_epoch: 5 },
            "equal is refused"
        );
        assert_eq!(
            crate::fence::ExternalEpochAnchor::record_promotion(&mut anchor, 4),
            crate::fence::AnchorRecord::Refused { anchored_epoch: 5 },
            "backward is refused"
        );
        anchor.mark_unconfirmed();
        assert_eq!(
            anchor.confirmed_epoch(),
            crate::fence::AnchorReading::Unconfirmed
        );
        assert_eq!(
            crate::fence::ExternalEpochAnchor::record_promotion(&mut anchor, 6),
            crate::fence::AnchorRecord::RefusedUnconfirmed,
            "an absent authority records nothing"
        );
    }

    #[test]
    fn clones_share_one_anchor_state() {
        use crate::fence::ExternalEpochAnchor;
        // A clone shares the state: the executor's adapter and the test's
        // handle observe one authority across a simulated restart.
        let mut handle = MemoryEpochAnchor::new();
        let mut boxed_adapter = handle.clone();
        assert_eq!(
            crate::fence::ExternalEpochAnchor::record_promotion(&mut boxed_adapter, 9),
            crate::fence::AnchorRecord::Recorded
        );
        assert_eq!(
            handle.confirmed_epoch(),
            crate::fence::AnchorReading::Confirmed { epoch: 9 },
            "the executor-side record is visible through the retained handle"
        );
    }
}
