// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    contact,
    contracts::{AllocationMutation, Offer, OfferKey, OpeningKey, Reserve, Source},
    model::{Outcome, next_version},
    source, store,
};
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{
        self as owner_context, ConversationError, activation,
        context::decisions::responses::source as reply_source,
    },
    sealed_manifest_store::outbound::lock_current,
};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

struct Opening {
    source: Source,
    deadline: i64,
    capacity: i16,
}
async fn opening(
    tx: &Transaction<'_>,
    account: Uuid,
    key: OpeningKey,
    lock: bool,
) -> Result<Opening, ConversationError> {
    let sql = if lock {
        "SELECT definition_version,state_version,phase,description_context_id,description_revision,description_digest,decision_deadline_ms,capacity FROM workflow_openings WHERE account_id=$1 AND id=$2 FOR UPDATE"
    } else {
        "SELECT definition_version,state_version,phase,description_context_id,description_revision,description_digest,decision_deadline_ms,capacity FROM workflow_openings WHERE account_id=$1 AND id=$2"
    };
    let row = tx
        .query_opt(sql, &[&account, &key.opening_id])
        .await?
        .ok_or(ConversationError::NotFound)?;
    if row.get::<_, i64>(0) != key.definition_version
        || row.get::<_, i64>(1) != key.state_version
        || row.get::<_, String>(2) != "open"
    {
        return Err(ConversationError::Conflict);
    }
    Ok(Opening {
        source: Source {
            context_id: row
                .get::<_, Option<Uuid>>(3)
                .ok_or(ConversationError::Forbidden)?,
            revision: row
                .get::<_, Option<i64>>(4)
                .ok_or(ConversationError::Forbidden)?,
            digest: hex(&row
                .get::<_, Option<Vec<u8>>>(5)
                .ok_or(ConversationError::Forbidden)?),
        },
        deadline: row
            .get::<_, Option<i64>>(6)
            .ok_or(ConversationError::Forbidden)?,
        capacity: row.get(7),
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
async fn bump(
    tx: &Transaction<'_>,
    account: Uuid,
    key: OpeningKey,
) -> Result<OpeningKey, ConversationError> {
    let state_version =
        next_version(key.state_version, false).ok_or(ConversationError::Conflict)?;
    tx.execute(
        "UPDATE workflow_openings SET state_version=$3 WHERE account_id=$1 AND id=$2",
        &[&account, &key.opening_id, &state_version],
    )
    .await?;
    Ok(OpeningKey {
        state_version,
        ..key
    })
}

pub async fn offer(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Offer,
) -> Result<Outcome, ConversationError> {
    if !request.validate() {
        return Err(ConversationError::Invalid);
    }
    let account = owner.tenant.account_id();
    let digest = store::digest(account, 2, &request)?;
    let tx = store::begin(client).await?;
    let mut authority = lock_current(&tx, account).await?;
    owner_context::lock_owner(&tx, owner).await?;
    if let Some(receipt) = store::replay(&tx, account, request.request_id, &digest).await? {
        owner_context::fresh_owner(&tx, owner).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(Outcome {
            receipt,
            applied: false,
            recorded: true,
        });
    }
    store::ordinary_capacity(&tx, account).await?;
    let opening_data = opening(&tx, account, request.opening, false).await?;
    let description = source::check(&tx, owner, &mut authority, &opening_data.source).await?;
    let selected = source::check(&tx, owner, &mut authority, &request.source).await?;
    let (episode, consent_deadline) = contact::check(
        &tx,
        selected.header(),
        request.contact_id,
        request.purpose.as_str(),
    )
    .await?;
    opening(&tx, account, request.opening, true).await?;
    let now = activation::now(&tx).await?;
    let deadline = opening_data
        .deadline
        .min(description.deadline_ms())
        .min(selected.deadline_ms())
        .min(consent_deadline.unwrap_or(i64::MAX));
    if request.expires_ms > deadline || now >= request.expires_ms {
        return Err(ConversationError::Forbidden);
    }
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM workflow_opening_offers WHERE account_id=$1 AND opening_id=$2",
            &[&account, &request.opening.opening_id],
        )
        .await?
        .get(0);
    if count >= 256 {
        return Err(ConversationError::Conflict);
    }
    let inserted=tx.execute("INSERT INTO workflow_opening_offers(account_id,id,opening_id,opening_definition_version,state_version,phase,contact_identity,current_contact_id,purpose,consent_episode_id,context_id,context_revision,context_digest,issued_ms,expires_ms,created_by_user,created_session) VALUES($1,$2,$3,$4,1,'active',$5,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(account_id,id) DO NOTHING", &[&account,&request.offer_id,&request.opening.opening_id,&request.opening.definition_version,&request.contact_id,&request.purpose.as_str(),&episode,&request.source.context_id,&request.source.revision,&super::decode(&request.source.digest)?,&now,&request.expires_ms,&owner.user_id,&owner.session_id]).await?;
    if inserted != 1 {
        return Err(ConversationError::Conflict);
    }
    let key = bump(&tx, account, request.opening).await?;
    let mut receipt = store::status(&tx, account, key, "active".into()).await?;
    receipt.offer = Some(OfferKey {
        offer_id: request.offer_id,
        state_version: 1,
    });
    store::record(
        &tx,
        owner,
        store::Mutation {
            request: request.request_id,
            operation: 2,
            subject_kind: 2,
            subject: request.offer_id,
            digest: &digest,
            receipt: &receipt,
            charged: true,
        },
    )
    .await?;
    description.recheck(&mut authority).await?;
    selected.recheck(&mut authority).await?;
    if contact::check(
        &tx,
        selected.header(),
        request.contact_id,
        request.purpose.as_str(),
    )
    .await?
    .0 != episode
        || activation::now(&tx).await? >= request.expires_ms
    {
        return Err(ConversationError::Forbidden);
    }
    owner_context::fresh_owner(&tx, owner).await?;
    drop(authority);
    tx.commit().await?;
    Ok(Outcome {
        receipt,
        applied: true,
        recorded: true,
    })
}

struct BoundOffer {
    source: Source,
    contact: Uuid,
    purpose: String,
    episode: Uuid,
    issued: i64,
    expires: i64,
    version: i64,
}
async fn bound_offer(
    tx: &Transaction<'_>,
    account: Uuid,
    opening: OpeningKey,
    key: OfferKey,
    lock: bool,
) -> Result<BoundOffer, ConversationError> {
    let sql = if lock {
        "SELECT state_version,phase,binding_scrubbed,opening_definition_version,context_id,context_revision,context_digest,contact_identity,purpose,consent_episode_id,issued_ms,expires_ms FROM workflow_opening_offers WHERE account_id=$1 AND opening_id=$2 AND id=$3 FOR UPDATE"
    } else {
        "SELECT state_version,phase,binding_scrubbed,opening_definition_version,context_id,context_revision,context_digest,contact_identity,purpose,consent_episode_id,issued_ms,expires_ms FROM workflow_opening_offers WHERE account_id=$1 AND opening_id=$2 AND id=$3"
    };
    let row = tx
        .query_opt(sql, &[&account, &opening.opening_id, &key.offer_id])
        .await?
        .ok_or(ConversationError::NotFound)?;
    if row.get::<_, i64>(0) != key.state_version
        || row.get::<_, String>(1) != "active"
        || row.get::<_, bool>(2)
        || row.get::<_, i64>(3) != opening.definition_version
    {
        return Err(ConversationError::Conflict);
    }
    Ok(BoundOffer {
        source: Source {
            context_id: row
                .get::<_, Option<Uuid>>(4)
                .ok_or(ConversationError::Forbidden)?,
            revision: row
                .get::<_, Option<i64>>(5)
                .ok_or(ConversationError::Forbidden)?,
            digest: hex(&row
                .get::<_, Option<Vec<u8>>>(6)
                .ok_or(ConversationError::Forbidden)?),
        },
        contact: row
            .get::<_, Option<Uuid>>(7)
            .ok_or(ConversationError::Forbidden)?,
        purpose: row
            .get::<_, Option<String>>(8)
            .ok_or(ConversationError::Forbidden)?,
        episode: row
            .get::<_, Option<Uuid>>(9)
            .ok_or(ConversationError::Forbidden)?,
        issued: row
            .get::<_, Option<i64>>(10)
            .ok_or(ConversationError::Forbidden)?,
        expires: row
            .get::<_, Option<i64>>(11)
            .ok_or(ConversationError::Forbidden)?,
        version: row.get(0),
    })
}

pub async fn reserve(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Reserve,
) -> Result<Outcome, ConversationError> {
    if !request.validate() {
        return Err(ConversationError::Invalid);
    }
    let account = owner.tenant.account_id();
    let digest = store::digest(account, 3, &request)?;
    let tx = store::begin(client).await?;
    let mut authority = lock_current(&tx, account).await?;
    owner_context::lock_owner(&tx, owner).await?;
    if let Some(receipt) = store::replay(&tx, account, request.request_id, &digest).await? {
        owner_context::fresh_owner(&tx, owner).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(Outcome {
            receipt,
            applied: false,
            recorded: true,
        });
    }
    store::ordinary_capacity(&tx, account).await?;
    let opening_data = opening(&tx, account, request.opening, false).await?;
    let offer = bound_offer(&tx, account, request.opening, request.offer, false).await?;
    let description = source::check(&tx, owner, &mut authority, &opening_data.source).await?;
    let selected = source::check(&tx, owner, &mut authority, &offer.source).await?;
    if contact::check(&tx, selected.header(), offer.contact, &offer.purpose)
        .await?
        .0
        != offer.episode
    {
        return Err(ConversationError::Forbidden);
    }
    opening(&tx, account, request.opening, true).await?;
    bound_offer(&tx, account, request.opening, request.offer, true).await?;
    expire_pending(&tx, account, request.opening.opening_id).await?;
    let event =
        reply_source::verify(&tx, &mut authority, selected.header(), request.event_id).await?;
    let deadline = offer
        .expires
        .min(opening_data.deadline)
        .min(description.deadline_ms())
        .min(selected.deadline_ms());
    if !timely(&event, offer.issued, deadline, activation::now(&tx).await?)
        || hex(&event.envelope_digest) != request.event_digest
    {
        return Err(ConversationError::Forbidden);
    }
    let (pending, confirmed) = store::counts(&tx, account, request.opening.opening_id).await?;
    if pending + confirmed >= i64::from(opening_data.capacity) {
        return Err(ConversationError::Conflict);
    }
    let mut response = Sha256::new();
    response.update(b"ZT/opening-response-use/v1\0");
    response.update(account.as_bytes());
    response.update(request.event_id.as_bytes());
    let response = response.finalize().to_vec();
    let inserted=tx.execute("INSERT INTO workflow_opening_allocations(account_id,id,opening_id,offer_id,offer_state_version,contact_identity,event_id,event_digest,response_use_digest,observed_ms,accepted_ms,decision_deadline_ms,phase,state_version,reserved_by_user,reserved_session) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',1,$13,$14) ON CONFLICT DO NOTHING", &[&account,&request.allocation_id,&request.opening.opening_id,&request.offer.offer_id,&offer.version,&offer.contact,&request.event_id,&super::decode(&request.event_digest)?,&response,&event.observed_ms,&event.accepted_ms,&deadline,&owner.user_id,&owner.session_id]).await?;
    if inserted != 1 {
        return Err(ConversationError::Conflict);
    }
    let key = bump(&tx, account, request.opening).await?;
    let mut receipt = store::status(&tx, account, key, "pending".into()).await?;
    receipt.offer = Some(request.offer);
    receipt.allocation_id = Some(request.allocation_id);
    receipt.allocation_version = Some(1);
    store::record(
        &tx,
        owner,
        store::Mutation {
            request: request.request_id,
            operation: 3,
            subject_kind: 3,
            subject: request.allocation_id,
            digest: &digest,
            receipt: &receipt,
            charged: true,
        },
    )
    .await?;
    description.recheck(&mut authority).await?;
    selected.recheck(&mut authority).await?;
    if contact::check(&tx, selected.header(), offer.contact, &offer.purpose)
        .await?
        .0
        != offer.episode
        || !timely(&event, offer.issued, deadline, activation::now(&tx).await?)
    {
        return Err(ConversationError::Forbidden);
    }
    owner_context::fresh_owner(&tx, owner).await?;
    drop(authority);
    tx.commit().await?;
    Ok(Outcome {
        receipt,
        applied: true,
        recorded: true,
    })
}

fn timely(event: &reply_source::VerifiedSource, issued: i64, deadline: i64, now: i64) -> bool {
    event.observed_ms >= issued
        && event.accepted_ms >= issued
        && event.observed_ms <= event.accepted_ms
        && event.accepted_ms <= now
        && event.observed_ms < deadline
        && event.accepted_ms < deadline
        && now < deadline
}
pub(super) async fn expire_pending(
    tx: &Transaction<'_>,
    account: Uuid,
    opening: Uuid,
) -> Result<(), ConversationError> {
    tx.query("SELECT id FROM workflow_opening_allocations WHERE account_id=$1 AND opening_id=$2 ORDER BY id FOR UPDATE", &[&account,&opening]).await?;
    tx.execute("UPDATE workflow_opening_allocations SET phase='expired',state_version=CASE WHEN state_version=9223372036854775807 THEN state_version ELSE state_version+1 END WHERE account_id=$1 AND opening_id=$2 AND phase='pending' AND decision_deadline_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint", &[&account,&opening]).await?;
    Ok(())
}

/// The owner declares the business meaning after client-local decryption.
/// Neither delivery nor ciphertext/provenance itself implies confirmation.
pub async fn confirm(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: AllocationMutation,
) -> Result<Outcome, ConversationError> {
    if !request.validate() {
        return Err(ConversationError::Invalid);
    }
    let account = owner.tenant.account_id();
    let digest = store::digest(account, 4, &request)?;
    let tx = store::begin(client).await?;
    let mut authority = lock_current(&tx, account).await?;
    owner_context::lock_owner(&tx, owner).await?;
    if let Some(receipt) = store::replay(&tx, account, request.request_id, &digest).await? {
        owner_context::fresh_owner(&tx, owner).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(Outcome {
            receipt,
            applied: false,
            recorded: true,
        });
    }
    store::ordinary_capacity(&tx, account).await?;
    let row=tx.query_opt("SELECT offer_id,offer_state_version,event_id,event_digest,state_version,phase,binding_scrubbed,decision_deadline_ms,observed_ms,accepted_ms FROM workflow_opening_allocations WHERE account_id=$1 AND opening_id=$2 AND id=$3", &[&account,&request.opening.opening_id,&request.allocation_id]).await?.ok_or(ConversationError::NotFound)?;
    if row.get::<_, i64>(4) != request.allocation_version
        || row.get::<_, String>(5) != "pending"
        || row.get::<_, bool>(6)
    {
        return Err(ConversationError::Conflict);
    }
    let offer_key = OfferKey {
        offer_id: row
            .get::<_, Option<Uuid>>(0)
            .ok_or(ConversationError::Forbidden)?,
        state_version: row
            .get::<_, Option<i64>>(1)
            .ok_or(ConversationError::Forbidden)?,
    };
    let event_id = row
        .get::<_, Option<Uuid>>(2)
        .ok_or(ConversationError::Forbidden)?;
    let event_digest = row
        .get::<_, Option<Vec<u8>>>(3)
        .ok_or(ConversationError::Forbidden)?;
    let deadline = row
        .get::<_, Option<i64>>(7)
        .ok_or(ConversationError::Forbidden)?;
    let observed = row
        .get::<_, Option<i64>>(8)
        .ok_or(ConversationError::Forbidden)?;
    let accepted = row
        .get::<_, Option<i64>>(9)
        .ok_or(ConversationError::Forbidden)?;
    let opening_data = opening(&tx, account, request.opening, false).await?;
    let offer = bound_offer(&tx, account, request.opening, offer_key, false).await?;
    let description = source::check(&tx, owner, &mut authority, &opening_data.source).await?;
    let selected = source::check(&tx, owner, &mut authority, &offer.source).await?;
    if contact::check(&tx, selected.header(), offer.contact, &offer.purpose)
        .await?
        .0
        != offer.episode
    {
        return Err(ConversationError::Forbidden);
    }
    opening(&tx, account, request.opening, true).await?;
    bound_offer(&tx, account, request.opening, offer_key, true).await?;
    tx.query_opt("SELECT id FROM workflow_opening_allocations WHERE account_id=$1 AND id=$2 AND phase='pending' AND state_version=$3 FOR UPDATE", &[&account,&request.allocation_id,&request.allocation_version]).await?.ok_or(ConversationError::Conflict)?;
    let event = reply_source::verify(&tx, &mut authority, selected.header(), event_id).await?;
    if event.envelope_digest.as_slice() != event_digest
        || event.observed_ms != observed
        || event.accepted_ms != accepted
        || !timely(&event, offer.issued, deadline, activation::now(&tx).await?)
    {
        return Err(ConversationError::Forbidden);
    }
    let version =
        next_version(request.allocation_version, false).ok_or(ConversationError::Conflict)?;
    tx.execute("UPDATE workflow_opening_allocations SET phase='confirmed',state_version=$3,confirmed_by_user=$4,confirmed_session=$5,confirmed_ms=$6 WHERE account_id=$1 AND id=$2", &[&account,&request.allocation_id,&version,&owner.user_id,&owner.session_id,&activation::now(&tx).await?]).await?;
    let key = bump(&tx, account, request.opening).await?;
    let mut receipt = store::status(&tx, account, key, "confirmed".into()).await?;
    receipt.offer = Some(offer_key);
    receipt.allocation_id = Some(request.allocation_id);
    receipt.allocation_version = Some(version);
    store::record(
        &tx,
        owner,
        store::Mutation {
            request: request.request_id,
            operation: 4,
            subject_kind: 3,
            subject: request.allocation_id,
            digest: &digest,
            receipt: &receipt,
            charged: true,
        },
    )
    .await?;
    description.recheck(&mut authority).await?;
    selected.recheck(&mut authority).await?;
    if contact::check(&tx, selected.header(), offer.contact, &offer.purpose)
        .await?
        .0
        != offer.episode
        || !timely(&event, offer.issued, deadline, activation::now(&tx).await?)
    {
        return Err(ConversationError::Forbidden);
    }
    owner_context::fresh_owner(&tx, owner).await?;
    drop(authority);
    tx.commit().await?;
    Ok(Outcome {
        receipt,
        applied: true,
        recorded: true,
    })
}
