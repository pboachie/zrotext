// SPDX-License-Identifier: AGPL-3.0-only
//! Recipient-local window resolution for the dormant encrypted scheduler.
//! PostgreSQL owns the IANA timezone database. Missing, nonexistent and
//! ambiguous civil time never silently selects an execution instant.

use tokio_postgres::GenericClient;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug)]
pub struct LocalWindow<'a> {
    pub date: &'a str,
    pub timezone: Option<&'a str>,
    pub opens_minute: u16,
    pub closes_minute: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewReason {
    UnknownTimezone,
    NonexistentCivilTime,
    AmbiguousCivilTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Ready { opens_at_ms: i64, closes_at_ms: i64 },
    OwnerReview(ReviewReason),
}

/// Timing only: WithinWindow never grants approval, render, send or radio access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timing {
    Expired,
    OwnerReview(ReviewReason),
    WaitingUntil(i64),
    MissedWindow,
    WithinWindow,
}

/// Expiry wins even when timing/rendering cannot otherwise progress. Pacing
/// does not move a deadline or turn a missed window into a retry instruction.
pub fn timing(
    now_ms: i64,
    not_before_ms: i64,
    expires_at_ms: i64,
    pacing_until_ms: i64,
    resolution: Resolution,
) -> Result<Timing, WindowError> {
    if now_ms < 0 || not_before_ms < 0 || expires_at_ms <= not_before_ms || pacing_until_ms < 0 {
        return Err(WindowError::Invalid);
    }
    if now_ms >= expires_at_ms {
        return Ok(Timing::Expired);
    }
    let (opens_at_ms, closes_at_ms) = match resolution {
        Resolution::Ready {
            opens_at_ms,
            closes_at_ms,
        } => (opens_at_ms, closes_at_ms),
        Resolution::OwnerReview(reason) => return Ok(Timing::OwnerReview(reason)),
    };
    if opens_at_ms < 0 || closes_at_ms <= opens_at_ms {
        return Err(WindowError::Invalid);
    }
    let earliest = opens_at_ms.max(not_before_ms).max(pacing_until_ms);
    let latest = closes_at_ms.min(expires_at_ms);
    if now_ms >= latest || earliest >= latest {
        return Ok(Timing::MissedWindow);
    }
    if now_ms < earliest {
        return Ok(Timing::WaitingUntil(earliest));
    }
    Ok(Timing::WithinWindow)
}

#[derive(Debug, thiserror::Error)]
pub enum WindowError {
    #[error("invalid recipient window")]
    Invalid,
    #[error("recipient window storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}

impl WindowError {
    pub(crate) fn calendar(error: tokio_postgres::Error) -> Self {
        match error.code() {
            Some(code)
                if code == &tokio_postgres::error::SqlState::INVALID_DATETIME_FORMAT
                    || code == &tokio_postgres::error::SqlState::DATETIME_FIELD_OVERFLOW =>
            {
                Self::Invalid
            }
            _ => Self::Database(error),
        }
    }
}

/// Resolve an immutable local window, including a window across midnight.
/// Both boundaries must have exactly one UTC interpretation. The bounded
/// timezone-offset enumeration includes minute-resolution transitions and
/// second-resolution offsets; candidates are checked against the exact local
/// value, rather than relying on PostgreSQL's preferred overlap interpretation.
pub async fn resolve<C: GenericClient + Sync>(
    db: &C,
    window: LocalWindow<'_>,
) -> Result<Resolution, WindowError> {
    if window.date.len() != 10
        || !window.date.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
        || window.opens_minute >= 1440
        || window.closes_minute >= 1440
        || window.opens_minute == window.closes_minute
    {
        return Err(WindowError::Invalid);
    }
    let Some(zone) = window.timezone.filter(|z| !z.is_empty() && z.len() <= 128) else {
        return Ok(Resolution::OwnerReview(ReviewReason::UnknownTimezone));
    };
    if db
        .query_opt("SELECT name FROM pg_timezone_names WHERE name=$1", &[&zone])
        .await?
        .is_none()
    {
        return Ok(Resolution::OwnerReview(ReviewReason::UnknownTimezone));
    }
    let open = i32::from(window.opens_minute);
    let close = i32::from(window.closes_minute);
    let overnight = i32::from(window.closes_minute < window.opens_minute);
    let rows = db.query(
        "WITH endpoints(label,local_time) AS (VALUES \
           (0,$1::text::date + $2::integer * interval '1 minute'), \
           (1,$1::text::date + $3::integer * interval '1 minute' + $5::integer * interval '1 day')), \
         candidates AS (SELECT DISTINCT e.label,e.local_time, \
           (e.local_time AT TIME ZONE 'UTC') - \
           ((s AT TIME ZONE $4) - (s AT TIME ZONE 'UTC')) AS instant \
           FROM endpoints e CROSS JOIN LATERAL generate_series( \
             (e.local_time AT TIME ZONE $4) - interval '48 hours', \
             (e.local_time AT TIME ZONE $4) + interval '48 hours', \
             interval '1 minute') AS s), \
         valid AS (SELECT label,instant FROM candidates WHERE instant AT TIME ZONE $4=local_time) \
         SELECT e.label,count(v.instant)::bigint, \
           (extract(epoch FROM min(v.instant))*1000)::bigint \
         FROM endpoints e LEFT JOIN valid v ON v.label=e.label GROUP BY e.label ORDER BY e.label",
        &[&window.date,&open,&close,&zone,&overnight],
    ).await.map_err(WindowError::calendar)?;
    if rows.iter().any(|r| r.get::<_, i64>(1) == 0) {
        return Ok(Resolution::OwnerReview(ReviewReason::NonexistentCivilTime));
    }
    if rows.iter().any(|r| r.get::<_, i64>(1) != 1) {
        return Ok(Resolution::OwnerReview(ReviewReason::AmbiguousCivilTime));
    }
    let opens_at_ms = rows[0]
        .get::<_, Option<i64>>(2)
        .ok_or(WindowError::Invalid)?;
    let closes_at_ms = rows[1]
        .get::<_, Option<i64>>(2)
        .ok_or(WindowError::Invalid)?;
    if opens_at_ms >= closes_at_ms {
        return Err(WindowError::Invalid);
    }
    Ok(Resolution::Ready {
        opens_at_ms,
        closes_at_ms,
    })
}
