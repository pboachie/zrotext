// SPDX-License-Identifier: AGPL-3.0-only
//! Local HTTP assertions and metadata projections, never allocation authority.
use super::super::{contracts, model};
use crate::http_owner_conversations::ConversationError;
use serde::{Deserialize, Deserializer, Serialize, de};
use std::{fmt, marker::PhantomData};
use uuid::Uuid;

struct MapOnly<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for ObjectVisitor<T> {
            type Value = MapOnly<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed JSON object")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map)).map(MapOnly)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

pub(super) fn canonical_uuid(value: &str) -> Result<Uuid, ConversationError> {
    let uuid = Uuid::parse_str(value).map_err(|_| ConversationError::Invalid)?;
    if uuid.is_nil() || value != uuid.hyphenated().to_string() {
        return Err(ConversationError::Invalid);
    }
    Ok(uuid)
}

struct CanonicalUuid(Uuid);

impl<'de> Deserialize<'de> for CanonicalUuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UuidVisitor;
        impl de::Visitor<'_> for UuidVisitor {
            type Value = CanonicalUuid;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical nonnil UUID string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                canonical_uuid(value)
                    .map(CanonicalUuid)
                    .map_err(|_| E::custom("invalid UUID assertion"))
            }
        }
        deserializer.deserialize_str(UuidVisitor)
    }
}

struct PositiveDecimal(i64);

impl<'de> Deserialize<'de> for PositiveDecimal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DecimalVisitor;
        impl de::Visitor<'_> for DecimalVisitor {
            type Value = PositiveDecimal;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical positive decimal i64 string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                let bytes = value.as_bytes();
                if bytes.is_empty()
                    || bytes.len() > 19
                    || !(b'1'..=b'9').contains(&bytes[0])
                    || !bytes.iter().all(u8::is_ascii_digit)
                {
                    return Err(E::custom("invalid deadline assertion"));
                }
                value
                    .parse::<i64>()
                    .map(PositiveDecimal)
                    .map_err(|_| E::custom("invalid deadline assertion"))
            }
        }
        deserializer.deserialize_str(DecimalVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInput {
    context_id: CanonicalUuid,
    revision: i64,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    request_id: CanonicalUuid,
    opening_id: CanonicalUuid,
    capacity: i16,
    description: MapOnly<SourceInput>,
    decision_deadline_ms: PositiveDecimal,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct CreateInput(MapOnly<CreateBody>);

impl CreateInput {
    pub(super) fn into_request(self) -> Result<contracts::Create, ConversationError> {
        let MapOnly(body) = self.0;
        let source = body.description.0;
        let request = contracts::Create {
            request_id: body.request_id.0,
            opening_id: body.opening_id.0,
            capacity: body.capacity,
            description: contracts::Source {
                context_id: source.context_id.0,
                revision: source.revision,
                digest: source.digest,
            },
            decision_deadline_ms: body.decision_deadline_ms.0,
        };
        if !request.validate() {
            return Err(ConversationError::Invalid);
        }
        Ok(request)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyStatus {}

pub(super) struct StatusInput;

impl<'de> Deserialize<'de> for StatusInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        MapOnly::<EmptyStatus>::deserialize(deserializer).map(|_| Self)
    }
}

#[derive(Serialize)]
pub(super) struct Created {
    account_id: Uuid,
    request_id: Uuid,
    outcome: Outcome,
}

#[derive(Serialize)]
struct Outcome {
    receipt: Receipt,
    applied: bool,
    recorded: bool,
}

#[derive(Serialize)]
pub(super) struct Status {
    account_id: Uuid,
    receipt: Receipt,
}

#[derive(Serialize)]
struct Opening {
    opening_id: Uuid,
    definition_version: String,
    state_version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Open,
    Closed,
    Cancelled,
}

#[derive(Serialize)]
struct Receipt {
    opening: Opening,
    offer: Option<()>,
    allocation_id: Option<()>,
    allocation_version: Option<()>,
    phase: Phase,
    pending: String,
    confirmed: String,
}

fn project(opening: Uuid, receipt: model::Receipt) -> Result<Receipt, ConversationError> {
    if opening.is_nil()
        || receipt.opening.opening_id != opening
        || receipt.opening.definition_version <= 0
        || receipt.opening.state_version <= 0
        || receipt.offer.is_some()
        || receipt.allocation_id.is_some()
        || receipt.allocation_version.is_some()
        || !(0..=i64::from(contracts::MAX_CAPACITY)).contains(&receipt.pending)
        || !(0..=i64::from(contracts::MAX_CAPACITY)).contains(&receipt.confirmed)
        || receipt.pending + receipt.confirmed > i64::from(contracts::MAX_CAPACITY)
    {
        return Err(ConversationError::Unavailable);
    }
    let phase = match receipt.phase.as_str() {
        "open" => Phase::Open,
        "closed" => Phase::Closed,
        "cancelled" => Phase::Cancelled,
        _ => return Err(ConversationError::Unavailable),
    };
    Ok(Receipt {
        opening: Opening {
            opening_id: opening,
            definition_version: receipt.opening.definition_version.to_string(),
            state_version: receipt.opening.state_version.to_string(),
        },
        offer: None,
        allocation_id: None,
        allocation_version: None,
        phase,
        pending: receipt.pending.to_string(),
        confirmed: receipt.confirmed.to_string(),
    })
}

pub(super) fn created(
    account: Uuid,
    request: Uuid,
    opening: Uuid,
    outcome: model::Outcome,
) -> Result<Created, ConversationError> {
    if account.is_nil() || request.is_nil() || !outcome.recorded {
        return Err(ConversationError::Unavailable);
    }
    Ok(Created {
        account_id: account,
        request_id: request,
        outcome: Outcome {
            receipt: project(opening, outcome.receipt)?,
            applied: outcome.applied,
            recorded: true,
        },
    })
}

pub(super) fn status(
    account: Uuid,
    opening: Uuid,
    receipt: model::Receipt,
) -> Result<Status, ConversationError> {
    if account.is_nil() {
        return Err(ConversationError::Unavailable);
    }
    Ok(Status {
        account_id: account,
        receipt: project(opening, receipt)?,
    })
}

#[cfg(test)]
mod tests;
