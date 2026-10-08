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
struct OpeningKeyBody {
    opening_id: CanonicalUuid,
    definition_version: PositiveDecimal,
    state_version: PositiveDecimal,
}

impl OpeningKeyBody {
    fn into_contract(self) -> contracts::OpeningKey {
        contracts::OpeningKey {
            opening_id: self.opening_id.0,
            definition_version: self.definition_version.0,
            state_version: self.state_version.0,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferKeyBody {
    offer_id: CanonicalUuid,
    state_version: PositiveDecimal,
}

impl OfferKeyBody {
    fn into_contract(self) -> contracts::OfferKey {
        contracts::OfferKey {
            offer_id: self.offer_id.0,
            state_version: self.state_version.0,
        }
    }
}

fn source_contract(input: SourceInput) -> contracts::Source {
    contracts::Source {
        context_id: input.context_id.0,
        revision: input.revision,
        digest: input.digest,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferBody {
    request_id: CanonicalUuid,
    opening: MapOnly<OpeningKeyBody>,
    offer_id: CanonicalUuid,
    contact_id: CanonicalUuid,
    purpose: contracts::Purpose,
    source: MapOnly<SourceInput>,
    expires_ms: PositiveDecimal,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct OfferInput(MapOnly<OfferBody>);

impl OfferInput {
    pub(super) fn into_request(self) -> Result<contracts::Offer, ConversationError> {
        let MapOnly(body) = self.0;
        let request = contracts::Offer {
            request_id: body.request_id.0,
            opening: body.opening.0.into_contract(),
            offer_id: body.offer_id.0,
            contact_id: body.contact_id.0,
            purpose: body.purpose,
            source: source_contract(body.source.0),
            expires_ms: body.expires_ms.0,
        };
        if !request.validate() {
            return Err(ConversationError::Invalid);
        }
        Ok(request)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReserveBody {
    request_id: CanonicalUuid,
    opening: MapOnly<OpeningKeyBody>,
    offer: MapOnly<OfferKeyBody>,
    allocation_id: CanonicalUuid,
    event_id: CanonicalUuid,
    event_digest: String,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct ReserveInput(MapOnly<ReserveBody>);

impl ReserveInput {
    pub(super) fn into_request(self) -> Result<contracts::Reserve, ConversationError> {
        let MapOnly(body) = self.0;
        let request = contracts::Reserve {
            request_id: body.request_id.0,
            opening: body.opening.0.into_contract(),
            offer: body.offer.0.into_contract(),
            allocation_id: body.allocation_id.0,
            event_id: body.event_id.0,
            event_digest: body.event_digest,
        };
        if !request.validate() {
            return Err(ConversationError::Invalid);
        }
        Ok(request)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllocationMutationBody {
    request_id: CanonicalUuid,
    opening: MapOnly<OpeningKeyBody>,
    allocation_id: CanonicalUuid,
    allocation_version: PositiveDecimal,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct AllocationMutationInput(MapOnly<AllocationMutationBody>);

impl AllocationMutationInput {
    pub(super) fn into_request(self) -> Result<contracts::AllocationMutation, ConversationError> {
        let MapOnly(body) = self.0;
        let request = contracts::AllocationMutation {
            request_id: body.request_id.0,
            opening: body.opening.0.into_contract(),
            allocation_id: body.allocation_id.0,
            allocation_version: body.allocation_version.0,
        };
        if !request.validate() {
            return Err(ConversationError::Invalid);
        }
        Ok(request)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpeningMutationBody {
    request_id: CanonicalUuid,
    opening: MapOnly<OpeningKeyBody>,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct OpeningMutationInput(MapOnly<OpeningMutationBody>);

impl OpeningMutationInput {
    pub(super) fn into_request(self) -> Result<contracts::OpeningMutation, ConversationError> {
        let MapOnly(body) = self.0;
        let request = contracts::OpeningMutation {
            request_id: body.request_id.0,
            opening: body.opening.0.into_contract(),
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

#[derive(Serialize)]
pub(super) struct Mutated {
    account_id: Uuid,
    request_id: Uuid,
    outcome: MutationOutcome,
}

#[derive(Serialize)]
struct MutationOutcome {
    receipt: MutationReceipt,
    applied: bool,
    recorded: bool,
}

#[derive(Serialize)]
struct MutationReceipt {
    opening: Opening,
    offer_id: Option<String>,
    offer_version: Option<String>,
    allocation_id: Option<String>,
    allocation_version: Option<String>,
    phase: Phase,
    pending: String,
    confirmed: String,
}

/// Mutations legitimately carry offer and allocation identities, unlike the
/// create/status projection; every other closed-metadata invariant is shared.
fn mutation_receipt(
    opening: Uuid,
    receipt: model::Receipt,
) -> Result<MutationReceipt, ConversationError> {
    if opening.is_nil()
        || receipt.opening.opening_id != opening
        || receipt.opening.definition_version <= 0
        || receipt.opening.state_version <= 0
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
    let offer = receipt.offer;
    if offer.is_some_and(|key| key.offer_id.is_nil() || key.state_version <= 0)
        || receipt.allocation_id.is_some_and(|id| id.is_nil())
        || receipt
            .allocation_version
            .is_some_and(|version| version <= 0)
    {
        return Err(ConversationError::Unavailable);
    }
    Ok(MutationReceipt {
        opening: Opening {
            opening_id: opening,
            definition_version: receipt.opening.definition_version.to_string(),
            state_version: receipt.opening.state_version.to_string(),
        },
        offer_id: offer.map(|key| key.offer_id.to_string()),
        offer_version: offer.map(|key| key.state_version.to_string()),
        allocation_id: receipt.allocation_id.map(|id| id.to_string()),
        allocation_version: receipt
            .allocation_version
            .map(|version| version.to_string()),
        phase,
        pending: receipt.pending.to_string(),
        confirmed: receipt.confirmed.to_string(),
    })
}

pub(super) fn mutated(
    account: Uuid,
    request: Uuid,
    opening: Uuid,
    outcome: model::Outcome,
) -> Result<Mutated, ConversationError> {
    if account.is_nil() || request.is_nil() || !outcome.recorded {
        return Err(ConversationError::Unavailable);
    }
    Ok(Mutated {
        account_id: account,
        request_id: request,
        outcome: MutationOutcome {
            receipt: mutation_receipt(opening, outcome.receipt)?,
            applied: outcome.applied,
            recorded: true,
        },
    })
}

#[cfg(test)]
mod tests;
