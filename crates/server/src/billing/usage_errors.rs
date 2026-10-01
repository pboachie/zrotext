// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted TEST meter-error verifier. Missing thin-event mode requires a
//! trusted retrieval bridge; this candidate never guesses mode or calls Stripe.
use super::{BillingError, verify_raw_payload};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_postgres::Client;
use uuid::Uuid;
use zrotext_delivery_store::billable::{MeterErrorObservation, UsageError, record_meter_error};

pub struct VerifiedMeterError {
    observation: MeterErrorObservation,
}

pub fn verify_meter_error(
    body: &[u8],
    signature: &str,
    secret: &str,
    now: i64,
) -> Result<VerifiedMeterError, BillingError> {
    verify_raw_payload(body, signature, secret, now)?;
    let value: Value = serde_json::from_slice(body).map_err(|_| BillingError::InvalidEvent)?;
    if value["object"] != "v2.core.event"
        || value["livemode"] != false
        || !matches!(
            value["type"].as_str(),
            Some("v1.billing.meter.error_report_triggered" | "v1.billing.meter.no_meter_found")
        )
        || !value["account"].is_null()
        || !value["context"].is_null()
        || value["related_object"]["type"] != "billing.meter"
    {
        return Err(BillingError::InvalidEvent);
    }
    let event_id = thin_id(&value["id"], "evt_")?.to_owned();
    let meter_id = thin_id(&value["related_object"]["id"], "mtr_")?.to_owned();
    let start =
        utc_milliseconds(&value["data"]["validation_start"]).ok_or(BillingError::InvalidEvent)?;
    let end =
        utc_milliseconds(&value["data"]["validation_end"]).ok_or(BillingError::InvalidEvent)?;
    if end < start {
        return Err(BillingError::InvalidEvent);
    }
    Ok(VerifiedMeterError {
        observation: MeterErrorObservation {
            event_id,
            meter_id,
            validation_start: start,
            validation_end: end,
            body_digest: Sha256::digest(body).into(),
        },
    })
}

fn thin_id<'a>(value: &'a Value, prefix: &str) -> Result<&'a str, BillingError> {
    let id = value.as_str().ok_or(BillingError::InvalidEvent)?;
    if id.len() <= prefix.len()
        || id.len() > 100
        || !id.starts_with(prefix)
        || !id[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(BillingError::InvalidEvent);
    }
    Ok(id)
}

// Closed provider shape, preserving milliseconds rather than guessing local
// timezone or accepting PostgreSQL's permissive free-form date parser.
fn utc_milliseconds(value: &Value) -> Option<i64> {
    let s = value.as_str()?;
    if !s.is_ascii()
        || s.len() != 24
        || &s[4..5] != "-"
        || &s[7..8] != "-"
        || &s[10..11] != "T"
        || &s[13..14] != ":"
        || &s[16..17] != ":"
        || &s[19..20] != "."
        || &s[23..] != "Z"
        || !s
            .bytes()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19 | 23) || b.is_ascii_digit())
    {
        return None;
    }
    let y = s[..4].parse::<i64>().ok()?;
    let m = s[5..7].parse::<usize>().ok()?;
    let d = s[8..10].parse::<i64>().ok()?;
    let h = s[11..13].parse::<i64>().ok()?;
    let min = s[14..16].parse::<i64>().ok()?;
    let sec = s[17..19].parse::<i64>().ok()?;
    let ms = s[20..23].parse::<i64>().ok()?;
    if y < 1970
        || !(1..=12).contains(&m)
        || h > 23
        || min > 59
        || sec > 59
        || h < 0
        || min < 0
        || sec < 0
        || !(0..=999).contains(&ms)
    {
        return None;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mut lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if leap {
        lengths[1] = 29;
    }
    if d < 1 || d > lengths[m - 1] {
        return None;
    }
    let leaps = |year: i64| year / 4 - year / 100 + year / 400;
    let days =
        365 * (y - 1970) + leaps(y - 1) - leaps(1969) + lengths[..m - 1].iter().sum::<i64>() + d
            - 1;
    Some(((days * 24 + h) * 60 + min) * 60_000 + sec * 1000 + ms)
}

/// Opaque in-process continuation, scoped by the verified event's meter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorCursor {
    account: Uuid,
    policy_version: i64,
}

/// Bounded policy-keyset fanout for a verified platform TEST event. Caller
/// supplies no tenant/meter/customer pointer. Each mapping is rechecked by the
/// local ledger; a continuation means ingestion is not complete.
pub async fn ingest_page(
    client: &mut Client,
    event: &VerifiedMeterError,
    after: Option<ErrorCursor>,
) -> Result<Option<ErrorCursor>, UsageError> {
    let account = after.map(|c| c.account);
    let version = after.map(|c| c.policy_version);
    let rows=client.query("SELECT account_id,policy_version FROM billing_usage_test_policies WHERE mode='test' AND meter_id=$1 AND ($2::uuid IS NULL OR (account_id,policy_version)>($2,$3::bigint)) ORDER BY account_id,policy_version LIMIT 101",&[&event.observation.meter_id,&account,&version]).await?;
    let more = rows.len() > 100;
    let mut last = None;
    for row in rows.iter().take(100) {
        let account: Uuid = row.get(0);
        let policy_version: i64 = row.get(1);
        record_meter_error(client, account, policy_version, &event.observation).await?;
        last = Some(ErrorCursor {
            account,
            policy_version,
        });
    }
    Ok(if more { last } else { None })
}

#[cfg(test)]
mod tests;
