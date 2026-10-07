// SPDX-License-Identifier: AGPL-3.0-only
//! Conservative local exposure accounting candidate. A reservation is not
//! permission to execute: the caller must independently retain exact action,
//! consent, recipient, reader and route authority through the effect boundary.

use thiserror::Error;

/// Integer exposure units, independent of any currency or public price.
/// Operator policy fixes their meaning for one immutable policy version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExposureUnits(i64);

impl ExposureUnits {
    pub fn new(value: i64) -> Result<Self, ExposureError> {
        if value <= 0 {
            return Err(ExposureError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }

    /// Round each independently priced input/output component upward. Both
    /// maximums and rates come from authenticated immutable server policy,
    /// never from a prompt, browser estimate or unbounded provider response.
    pub fn model_maximum(
        input_limit: i64,
        output_limit: i64,
        input_units_per_thousand: i64,
        output_units_per_thousand: i64,
        fixed_units: i64,
    ) -> Result<Self, ExposureError> {
        if input_limit < 0
            || output_limit <= 0
            || input_units_per_thousand < 0
            || output_units_per_thousand <= 0
            || fixed_units < 0
        {
            return Err(ExposureError::Invalid);
        }
        let component = |limit: i64, rate: i64| {
            i128::from(limit)
                .checked_mul(i128::from(rate))
                .and_then(|value| value.checked_add(999))
                .map(|value| value / 1000)
                .ok_or(ExposureError::Overflow)
        };
        let value = component(input_limit, input_units_per_thousand)?
            .checked_add(component(output_limit, output_units_per_thousand)?)
            .and_then(|value| value.checked_add(i128::from(fixed_units)))
            .ok_or(ExposureError::Overflow)?;
        Self::new(i64::try_from(value).map_err(|_| ExposureError::Overflow)?)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExposureError {
    #[error("exposure policy or request is invalid")]
    Invalid,
    #[error("exposure bound overflow")]
    Overflow,
    #[error("exposure limit exceeded")]
    Limit,
}

/// Pending and unknown outcomes remain part of liability. No clock or worker
/// lease expiry reduces this amount; only authoritative terminal settlement
/// can release an unused remainder.
pub fn projected_liability(
    finalized: i64,
    outstanding: i64,
    requested: ExposureUnits,
    hard_cap: i64,
) -> Result<i64, ExposureError> {
    if finalized < 0 || outstanding < 0 || hard_cap < 0 {
        return Err(ExposureError::Invalid);
    }
    let projected = finalized
        .checked_add(outstanding)
        .and_then(|value| value.checked_add(requested.get()))
        .ok_or(ExposureError::Overflow)?;
    if projected > hard_cap {
        return Err(ExposureError::Limit);
    }
    Ok(projected)
}

/// Result of one scope's integer admission decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    /// Finalized plus outstanding plus this request; never above the hard cap.
    pub projected: i64,
    /// True when `projected` reaches the soft threshold. A warning never
    /// widens the hard cap and carries no authority to spend.
    pub soft_warning: bool,
}

/// Single decision shared by every scope and the deployment aggregate. Policy
/// rows must satisfy `0 <= soft <= hard`; a violated invariant fails closed
/// instead of silently disabling the warning or the refusal.
pub fn admit(
    finalized: i64,
    outstanding: i64,
    requested: ExposureUnits,
    soft: i64,
    hard: i64,
) -> Result<Admission, ExposureError> {
    if soft < 0 || soft > hard {
        return Err(ExposureError::Invalid);
    }
    let projected = projected_liability(finalized, outstanding, requested, hard)?;
    Ok(Admission {
        projected,
        soft_warning: projected >= soft,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractional_components_round_up_independently() {
        assert_eq!(
            ExposureUnits::model_maximum(1, 1, 1, 1, 3).unwrap().get(),
            5
        );
        assert_eq!(
            ExposureUnits::model_maximum(1000, 1001, 2, 3, 0)
                .unwrap()
                .get(),
            6
        );
    }

    #[test]
    fn unbounded_or_overflowing_model_cost_is_refused() {
        assert_eq!(
            ExposureUnits::model_maximum(1, 0, 1, 1, 0),
            Err(ExposureError::Invalid)
        );
        assert_eq!(
            ExposureUnits::model_maximum(i64::MAX, i64::MAX, i64::MAX, i64::MAX, 0),
            Err(ExposureError::Overflow)
        );
    }

    #[test]
    fn unknown_outcomes_consume_the_last_unit() {
        let one = ExposureUnits::new(1).unwrap();
        assert_eq!(projected_liability(4, 5, one, 10), Ok(10));
        assert_eq!(
            projected_liability(4, 6, one, 10),
            Err(ExposureError::Limit)
        );
        assert_eq!(
            projected_liability(i64::MAX, 0, one, i64::MAX),
            Err(ExposureError::Overflow)
        );
    }

    fn units(value: i64) -> ExposureUnits {
        ExposureUnits::new(value).unwrap()
    }

    #[test]
    fn soft_threshold_warns_at_equality_and_hard_cap_admits_exact_fit() {
        assert!(!admit(2, 2, units(1), 6, 10).unwrap().soft_warning);
        assert!(admit(2, 3, units(1), 6, 10).unwrap().soft_warning);
        let last = admit(4, 5, units(1), 6, 10).unwrap();
        assert_eq!((last.projected, last.soft_warning), (10, true));
        assert_eq!(admit(4, 5, units(2), 6, 10), Err(ExposureError::Limit));
    }

    #[test]
    fn inverted_or_negative_thresholds_fail_closed() {
        assert_eq!(admit(0, 0, units(1), 11, 10), Err(ExposureError::Invalid));
        assert_eq!(admit(0, 0, units(1), -1, 10), Err(ExposureError::Invalid));
        assert_eq!(admit(0, 0, units(1), 0, -1), Err(ExposureError::Invalid));
    }

    #[test]
    fn rollover_drops_finalized_usage_but_keeps_older_outstanding_liability() {
        // Previous period: 8 finalized + 1 unknown. New period sums only the
        // finalized units of its own interval, plus all outstanding liability.
        let next = admit(0, 1, units(9), 5, 10).unwrap();
        assert_eq!(next.projected, 10);
        assert_eq!(admit(0, 1, units(10), 5, 10), Err(ExposureError::Limit));
    }

    #[test]
    fn model_maximum_edges_reject_negative_and_overflowing_fixed_components() {
        assert_eq!(
            ExposureUnits::model_maximum(-1, 1, 1, 1, 0),
            Err(ExposureError::Invalid)
        );
        assert_eq!(
            ExposureUnits::model_maximum(1, 1, 1, 1, -1),
            Err(ExposureError::Invalid)
        );
        assert_eq!(
            ExposureUnits::model_maximum(1, 1, 1, 1, i64::MAX),
            Err(ExposureError::Overflow)
        );
        assert_eq!(
            ExposureUnits::model_maximum(0, 1000, 0, 1, 0)
                .unwrap()
                .get(),
            1
        );
    }
}
