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
}
