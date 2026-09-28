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
//! forward. Callers (a later executor increment) are expected to refuse a
//! promotion whose epoch is not strictly above the anchored epoch, and to
//! seed their epoch memory from the anchor on restore.

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

/// In-repo test implementation of [`EpochAnchor`] — not a production
/// authority. Monotonic in memory, refuses backward and equal promotions.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryEpochAnchor {
    anchored_epoch: u64,
}

#[cfg(test)]
impl MemoryEpochAnchor {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl EpochAnchor for MemoryEpochAnchor {
    type Error = &'static str;

    fn anchored_epoch(&mut self) -> Result<u64, Self::Error> {
        Ok(self.anchored_epoch)
    }

    fn record_promotion(&mut self, new_epoch: u64) -> Result<(), Self::Error> {
        if new_epoch <= self.anchored_epoch {
            return Err("the anchored epoch only moves strictly forward");
        }
        self.anchored_epoch = new_epoch;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_anchor_records_and_serves_anchored_epochs() {
        let mut anchor = MemoryEpochAnchor::new();
        assert_eq!(anchor.anchored_epoch().unwrap(), 0);
        anchor.record_promotion(7).unwrap();
        assert_eq!(anchor.anchored_epoch().unwrap(), 7);
        anchor.record_promotion(12).unwrap();
        assert_eq!(anchor.anchored_epoch().unwrap(), 12);
    }

    #[test]
    fn memory_anchor_refuses_backward_and_equal_promotions() {
        let mut anchor = MemoryEpochAnchor::new();
        anchor.record_promotion(5).unwrap();
        assert!(anchor.record_promotion(5).is_err(), "equal is refused");
        assert!(anchor.record_promotion(4).is_err(), "backward is refused");
        assert_eq!(
            anchor.anchored_epoch().unwrap(),
            5,
            "a refused record never moves the anchored epoch"
        );
        anchor.record_promotion(6).unwrap();
        assert_eq!(anchor.anchored_epoch().unwrap(), 6);
    }
}
