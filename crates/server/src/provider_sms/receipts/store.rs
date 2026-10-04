// SPDX-License-Identifier: AGPL-3.0-only
use super::Error;
use crate::provider_sms::{Attempt, MAX_EVENTS, ReceiptFact, VerifiedReceipt};
use std::collections::BTreeMap;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;
use zrotext_domain::MessageState;

pub(super) fn state_name(state: MessageState) -> Result<&'static str, Error> {
    Ok(match state {
        MessageState::Submitting => "submitting",
        MessageState::Unknown => "unknown",
        MessageState::Submitted => "submitted",
        MessageState::DeliveryUnknown => "delivery_unconfirmed",
        MessageState::Delivered => "delivered",
        MessageState::Failed => "failed",
        _ => return Err(Error::Inconsistent),
    })
}
fn state(value: &str) -> Result<MessageState, Error> {
    Ok(match value {
        "submitting" => MessageState::Submitting,
        "unknown" => MessageState::Unknown,
        "submitted" => MessageState::Submitted,
        "delivery_unconfirmed" => MessageState::DeliveryUnknown,
        "delivered" => MessageState::Delivered,
        "failed" => MessageState::Failed,
        _ => return Err(Error::Inconsistent),
    })
}
pub(super) fn fact_name(fact: ReceiptFact) -> &'static str {
    match fact {
        ReceiptFact::CarrierSubmitted => "carrier_submitted",
        ReceiptFact::Delivered => "delivered",
        ReceiptFact::DeliveryUnconfirmed => "delivery_unconfirmed",
        ReceiptFact::SendingFailed => "sending_failed",
        ReceiptFact::DeliveryFailed => "delivery_failed",
        ReceiptFact::Unrecognized => "unrecognized",
    }
}
fn fact(value: &str) -> Result<ReceiptFact, Error> {
    Ok(match value {
        "carrier_submitted" => ReceiptFact::CarrierSubmitted,
        "delivered" => ReceiptFact::Delivered,
        "delivery_unconfirmed" => ReceiptFact::DeliveryUnconfirmed,
        "sending_failed" => ReceiptFact::SendingFailed,
        "delivery_failed" => ReceiptFact::DeliveryFailed,
        "unrecognized" => ReceiptFact::Unrecognized,
        _ => return Err(Error::Inconsistent),
    })
}

pub(super) async fn rehydrate(
    tx: &Transaction<'_>,
    row: &Row,
    event: &VerifiedReceipt,
) -> Result<(Attempt, i64), Error> {
    let attempt_id: Uuid = row.try_get(0).map_err(|_| Error::Inconsistent)?;
    let current = state(
        &row.try_get::<_, String>(1)
            .map_err(|_| Error::Inconsistent)?,
    )?;
    let delivery_failed: bool = row.try_get(2).map_err(|_| Error::Inconsistent)?;
    let count: i16 = row.try_get(3).map_err(|_| Error::Inconsistent)?;
    let version: i64 = row.try_get(4).map_err(|_| Error::Inconsistent)?;
    let digest: Vec<u8> = row.try_get(5).map_err(|_| Error::Inconsistent)?;
    if digest.as_slice() != event.request.digest() {
        return Err(Error::Evidence(
            crate::provider_sms::Rejection::RequestConflict,
        ));
    }
    if attempt_id.is_nil()
        || !(0..=MAX_EVENTS as i16).contains(&count)
        || version < i64::from(count)
        || event.request.route.revision == 0
        || (delivery_failed
            && !matches!(
                current,
                MessageState::Submitted | MessageState::DeliveryUnknown
            ))
    {
        return Err(Error::Inconsistent);
    }
    let rows = tx
        .query(
            "SELECT event_id,semantic_digest,fact,state_version FROM provider_receipt_events \
        WHERE account_id=$1 AND attempt_id=$2 ORDER BY state_version LIMIT 65",
            &[&event.request.route.account, &attempt_id],
        )
        .await
        .map_err(|_| Error::Database)?;
    if rows.len() != count as usize {
        return Err(Error::Inconsistent);
    }
    let mut events = BTreeMap::new();
    let mut delivered = false;
    let mut failed = false;
    let mut negative_delivery = false;
    let mut positive_carrier = false;
    let mut unconfirmed = false;
    let mut previous_version = 0;
    for row in rows {
        let identity: Uuid = row.try_get(0).map_err(|_| Error::Inconsistent)?;
        let digest: Vec<u8> = row.try_get(1).map_err(|_| Error::Inconsistent)?;
        let digest: [u8; 32] = digest.try_into().map_err(|_| Error::Inconsistent)?;
        let fact = fact(
            &row.try_get::<_, String>(2)
                .map_err(|_| Error::Inconsistent)?,
        )?;
        let event_version: i64 = row.try_get(3).map_err(|_| Error::Inconsistent)?;
        if identity.is_nil()
            || event_version <= previous_version
            || event_version > version
            || events.insert(identity, digest).is_some()
        {
            return Err(Error::Inconsistent);
        }
        previous_version = event_version;
        delivered |= fact == ReceiptFact::Delivered;
        failed |= fact == ReceiptFact::SendingFailed;
        negative_delivery |= fact == ReceiptFact::DeliveryFailed;
        positive_carrier |= matches!(
            fact,
            ReceiptFact::CarrierSubmitted
                | ReceiptFact::Delivered
                | ReceiptFact::DeliveryUnconfirmed
                | ReceiptFact::DeliveryFailed
        );
        unconfirmed |= fact == ReceiptFact::DeliveryUnconfirmed;
    }
    if delivered != (current == MessageState::Delivered)
        || failed != (current == MessageState::Failed)
        || negative_delivery != delivery_failed
        || (positive_carrier
            != matches!(
                current,
                MessageState::Submitted | MessageState::DeliveryUnknown | MessageState::Delivered
            ))
        || (current == MessageState::DeliveryUnknown && !unconfirmed)
    {
        return Err(Error::Inconsistent);
    }
    Ok((
        Attempt {
            request: event.request.clone(),
            attempt_id,
            state: current,
            provider_id: Some(event.message_id),
            events,
            delivery_failed,
        },
        version,
    ))
}
