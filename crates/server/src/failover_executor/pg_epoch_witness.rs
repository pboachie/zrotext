// SPDX-License-Identifier: AGPL-3.0-only
//! In-process high-water for a same-database epoch witness, not durable custody.
use zrotext_failover_quorum::fence::{AnchorReading, AnchorRecord};

#[derive(Default)]
pub(super) struct EpochWitness {
    highest: u64,
}

impl EpochWitness {
    pub(super) fn observe(&mut self, served: u64) -> AnchorReading {
        self.highest = self.highest.max(served);
        AnchorReading::Confirmed {
            epoch: self.highest,
        }
    }

    pub(super) fn record(&mut self, served: u64, requested: u64) -> AnchorRecord {
        let previous = self.highest;
        self.highest = self.highest.max(served);
        if requested == served && requested > previous {
            AnchorRecord::Recorded
        } else {
            AnchorRecord::Refused {
                anchored_epoch: self.highest,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observations_keep_the_high_water_after_a_database_rollback() {
        let mut witness = EpochWitness::default();
        assert_eq!(witness.observe(7), AnchorReading::Confirmed { epoch: 7 });
        assert_eq!(witness.observe(4), AnchorReading::Confirmed { epoch: 7 });
        assert_eq!(witness.observe(9), AnchorReading::Confirmed { epoch: 9 });
    }
    #[test]
    fn only_a_forward_exactly_served_promotion_is_recorded() {
        let mut witness = EpochWitness::default();
        witness.observe(4);
        assert_eq!(
            witness.record(4, 5),
            AnchorRecord::Refused { anchored_epoch: 4 }
        );
        assert_eq!(witness.record(5, 5), AnchorRecord::Recorded);
        assert_eq!(
            witness.record(5, 5),
            AnchorRecord::Refused { anchored_epoch: 5 }
        );
        assert_eq!(
            witness.record(5, 4),
            AnchorRecord::Refused { anchored_epoch: 5 }
        );
        assert_eq!(
            witness.record(4, 4),
            AnchorRecord::Refused { anchored_epoch: 5 }
        );
    }
    #[test]
    fn ahead_database_observation_never_records_an_older_requested_epoch() {
        let mut witness = EpochWitness::default();
        witness.observe(4);
        assert_eq!(
            witness.record(7, 6),
            AnchorRecord::Refused { anchored_epoch: 7 }
        );
        assert_eq!(witness.observe(5), AnchorReading::Confirmed { epoch: 7 });
        assert_eq!(witness.record(8, 8), AnchorRecord::Recorded);
    }
}
