// SPDX-License-Identifier: AGPL-3.0-only
//! Content-free per-connection totals for the opt-in
//! `ZT_DEVICE_STREAM_DIAGNOSTIC=1` markers.
//!
//! Per-heartbeat markers stop after [`HEARTBEAT_MARKER_CAP`] heartbeats, which
//! is about two hours at the 30-second cadence. A long liveness run still needs
//! the whole connection's heartbeat count and worst gap, so the close marker
//! carries those totals. Markers never include device IDs, frames or content;
//! `scripts/liveness_report.py` parses exactly this grammar.

use std::time::{Duration, Instant};

/// Per-heartbeat markers emitted per connection before they are suppressed.
pub(super) const HEARTBEAT_MARKER_CAP: u32 = 256;

pub(super) struct StreamTally {
    started: Instant,
    heartbeats: u64,
    max_gap_ms: u128,
    markers_emitted: u32,
}

impl StreamTally {
    pub(super) fn new(started: Instant) -> Self {
        Self {
            started,
            heartbeats: 0,
            max_gap_ms: 0,
            markers_emitted: 0,
        }
    }

    /// Records one accepted, acknowledged heartbeat. Returns whether a
    /// per-heartbeat marker may still be emitted for this connection.
    pub(super) fn record_heartbeat(&mut self, since_prior_accepted_ms: u128) -> bool {
        self.heartbeats = self.heartbeats.saturating_add(1);
        self.max_gap_ms = self.max_gap_ms.max(since_prior_accepted_ms);
        if self.markers_emitted < HEARTBEAT_MARKER_CAP {
            self.markers_emitted += 1;
            true
        } else {
            false
        }
    }

    pub(super) fn heartbeat_line(
        connection_epoch: i64,
        since_prior_accepted_ms: u128,
        handling_ms: u128,
    ) -> String {
        format!(
            "ZTDeviceStream heartbeat_ack connection_epoch={connection_epoch} \
             since_prior_accepted_ms={since_prior_accepted_ms} handling_ms={handling_ms}"
        )
    }

    pub(super) fn close_line(
        &self,
        close_reason: &str,
        connection_epoch: i64,
        since_heartbeat: Duration,
        now: Instant,
    ) -> String {
        format!(
            "ZTDeviceStream close_reason={close_reason} connection_epoch={connection_epoch} \
             since_heartbeat_ms={} heartbeats={} max_gap_ms={} connected_ms={}",
            since_heartbeat.as_millis(),
            self.heartbeats,
            self.max_gap_ms,
            now.saturating_duration_since(self.started).as_millis()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_line_carries_totals_past_the_marker_cap() {
        let start = Instant::now();
        let mut tally = StreamTally::new(start);
        let mut markers = 0;
        for beat in 0..300u128 {
            // One late heartbeat in the suppressed tail must still count.
            let gap = if beat == 290 { 41_250 } else { 30_000 };
            if tally.record_heartbeat(gap) {
                markers += 1;
            }
        }
        assert_eq!(markers, HEARTBEAT_MARKER_CAP);
        let line = tally.close_line(
            "heartbeat_deadline",
            7,
            Duration::from_millis(45_500),
            start + Duration::from_secs(9_045),
        );
        assert_eq!(
            line,
            "ZTDeviceStream close_reason=heartbeat_deadline connection_epoch=7 \
             since_heartbeat_ms=45500 heartbeats=300 max_gap_ms=41250 connected_ms=9045000"
        );
    }

    #[test]
    fn close_line_without_heartbeats_reports_zero_totals() {
        let start = Instant::now();
        let tally = StreamTally::new(start);
        assert_eq!(
            tally.close_line("superseded", 3, Duration::from_millis(12), start),
            "ZTDeviceStream close_reason=superseded connection_epoch=3 \
             since_heartbeat_ms=12 heartbeats=0 max_gap_ms=0 connected_ms=0"
        );
    }

    #[test]
    fn heartbeat_line_keeps_the_documented_grammar() {
        assert_eq!(
            StreamTally::heartbeat_line(2, 30_004, 3),
            "ZTDeviceStream heartbeat_ack connection_epoch=2 since_prior_accepted_ms=30004 handling_ms=3"
        );
    }
}
