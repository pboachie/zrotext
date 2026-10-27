// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated device-reported permanent pre-entry closure, not OS attestation.
use super::{history::*, *};
use crate::conversation_effect03::{NoSubmitCore03, NoSubmitRecord03, SubmitCommand03, wire};
use crate::sealed_manifest03 as crypto;
use tokio_postgres::Row;

fn record_submit(record: &NoSubmitRecord03) -> Result<SubmitCommand03> {
    let r = record.bytes();
    let mut bytes = Vec::with_capacity(153);
    bytes.extend(&r[..80]);
    bytes.extend(&r[96..128]);
    bytes.extend(&r[160..192]);
    bytes.extend(&r[192..201]);
    let command = SubmitCommand03::decode(&bytes).map_err(|_| Error::Unsupported)?;
    if command.digest().map_err(|_| Error::Unsupported)?.as_slice() != &r[128..160] {
        return Err(Error::Conflict);
    }
    Ok(command)
}
async fn retained_record(
    tx: &Transaction<'_>,
    scope: &Scope03,
    held: &HeldHistory03<'_, '_>,
    closure: Uuid,
) -> Result<NoSubmitRecord03> {
    let row = tx.query_opt(
        "SELECT * FROM public.conversation_profile03_closure_records WHERE account_id=$1 AND closure_id=$2",
        &[&scope.session.account_id,&closure],
    ).await?.ok_or(Error::NotFound)?;
    let record = NoSubmitRecord03::decode(&row.try_get::<_, Vec<u8>>("record")?)
        .map_err(|_| Error::Unsupported)?;
    if row.try_get::<_, Uuid>("attempt_id")? != held.original.grant.ids[2]
        || row.try_get::<_, Vec<u8>>("record_sha256")?.as_slice()
            != record.digest().map_err(|_| Error::Unsupported)?
        || &record.bytes()[80..96] != closure.as_bytes()
    {
        return Err(Error::Conflict);
    }
    let command = record_submit(&record)?;
    held.original.command(&command)?;
    let submitted=tx.query_opt(
        "SELECT * FROM public.conversation_profile03_submits WHERE account_id=$1 AND attempt_id=$2",
        &[&scope.session.account_id,&held.original.grant.ids[2]],
    ).await?;
    if let Some(submitted) = submitted {
        let (accepted, _) = super::status::accepted_submit(&submitted, &held.original)?;
        if accepted.bytes() != command.bytes() {
            return Err(Error::Conflict);
        }
    } else if record.bytes()[201] == 1 {
        // ACK-authorized is possible only AFTER the actual server committed
        // this original submit. Reserved also covers a lost first ACK or no
        // committed submit; neither case permits another platform entry.
        return Err(Error::Conflict);
    }
    Ok(record)
}
fn challenge_core(
    row: &Row,
    original: &Original03,
    record: &NoSubmitRecord03,
) -> Result<NoSubmitCore03> {
    let core = NoSubmitCore03::decode(&row.try_get::<_, Vec<u8>>("core")?)
        .map_err(|_| Error::Unsupported)?;
    core.matches_record(record).map_err(|_| Error::Conflict)?;
    let ids = core.identities();
    let n = core.numbers();
    let hashes = core.digests();
    if ids[6] != *row.try_get::<_, Uuid>("proof_request_id")?.as_bytes()
        || ids[7] != *row.try_get::<_, Uuid>("challenge_id")?.as_bytes()
        || ids[0] != *original.grant.ids[0].as_bytes()
        || ids[1] != *original.grant.ids[7].as_bytes()
        || ids[3] != *original.grant.ids[1].as_bytes()
        || ids[4] != *original.grant.ids[2].as_bytes()
        || n[0] != original.grant.numbers[2]
        || n[1] != original.grant.numbers[3]
        || n[4] != original.grant.numbers[1]
        || n[5] > u64::from(original.grant.frame()?.claims().segment_count)
        || n[8] != positive(row.try_get("issued_ms")?)?
        || n[9] != positive(row.try_get("expires_ms")?)?
        || hashes[0] != original.fetch
        || hashes[2] != original.session
        || hashes[4] != original.key
        || hashes[5] != crypto::sha(&row.try_get::<_, Vec<u8>>("nonce")?)
        || row.try_get::<_, Vec<u8>>("core_sha256")?.as_slice() != crypto::sha(core.bytes())
        || row
            .try_get::<_, Vec<u8>>("proof_device_session_digest")?
            .as_slice()
            != hashes[3]
    {
        return Err(Error::Conflict);
    }
    Ok(core)
}
fn fresh(core: &NoSubmitCore03, held: &HeldHistory03<'_, '_>, scope: &Scope03) -> Result<()> {
    let n = core.numbers();
    if n[2] != u64::try_from(scope.session.connection_epoch).map_err(|_| Error::Authentication)?
        || n[3] != u64::try_from(scope.deployment).map_err(|_| Error::Authentication)?
        || core.digests()[3] != held.proof_session
        || held.now_ms() < n[8]
        || held.now_ms() >= n[9]
        || n[9] > held.lease_end
    {
        return Err(Error::Expired);
    }
    Ok(())
}
async fn challenge_json(tx: &Transaction<'_>, row: &Row) -> Result<serde_json::Value> {
    let previous: Option<Uuid> = row.try_get("previous_challenge_id")?;
    let predecessor = if let Some(previous) = previous {
        let p=tx.query_one(
            "SELECT * FROM public.conversation_profile03_closure_challenges WHERE account_id=$1 AND challenge_id=$2",
            &[&row.try_get::<_,Uuid>("account_id")?,&previous],
        ).await?;
        let next: Uuid = row.try_get("challenge_id")?;
        let closed = p
            .try_get::<_, Option<i64>>("closed_unaccepted_ms")?
            .ok_or(Error::Conflict)?;
        if p.try_get::<_, Uuid>("closure_id")? != row.try_get::<_, Uuid>("closure_id")?
            || p.try_get::<_, Option<Uuid>>("superseded_by_challenge_id")? != Some(next)
            || closed != row.try_get::<_, i64>("issued_ms")?
            || closed < p.try_get::<_, i64>("expires_ms")?
            || p.try_get::<_, Vec<u8>>("core_sha256")?.as_slice()
                != crypto::sha(&p.try_get::<_, Vec<u8>>("core")?)
        {
            return Err(Error::Conflict);
        }
        serde_json::json!({"challenge_id":previous,"core_sha256":B.encode(p.try_get::<_,Vec<u8>>("core_sha256")?),"closed_ms":positive(closed)?.to_string(),"superseded_by_challenge_id":next})
    } else {
        serde_json::Value::Null
    };
    Ok(serde_json::json!({
        "proof_request_id":row.try_get::<_,Uuid>("proof_request_id")?,
        "closure_id":row.try_get::<_,Uuid>("closure_id")?,
        "challenge_id":row.try_get::<_,Uuid>("challenge_id")?,
        "core":B.encode(row.try_get::<_,Vec<u8>>("core")?),
        "nonce":B.encode(row.try_get::<_,Vec<u8>>("nonce")?),
        "closed_predecessor":predecessor
    }))
}
fn receipt_json(
    row: &Row,
    core: &NoSubmitCore03,
    original: &Original03,
) -> Result<serde_json::Value> {
    let raw = row.try_get::<_, Vec<u8>>("signature")?;
    core.verify_candidate_signature(&original.point, &raw)
        .map_err(|_| Error::Authentication)?;
    let accepted = positive(row.try_get("accepted_ms")?)?;
    if row.try_get::<_, Vec<u8>>("core")?.as_slice() != core.bytes()
        || row.try_get::<_, Vec<u8>>("core_sha256")?.as_slice() != crypto::sha(core.bytes())
        || row.try_get::<_, Vec<u8>>("signature_sha256")?.as_slice() != crypto::sha(&raw)
        || accepted < core.numbers()[8]
        || accepted >= core.numbers()[9]
    {
        return Err(Error::Conflict);
    }
    Ok(serde_json::json!({
        "challenge_id":row.try_get::<_,Uuid>("challenge_id")?,
        "core_sha256":B.encode(crypto::sha(core.bytes())),
        "signature_sha256":B.encode(crypto::sha(&raw)),
        "accepted_ms":accepted.to_string(),"disposition":"closed_no_rearm"
    }))
}

pub(super) async fn challenge(
    tx: &Transaction<'_>,
    scope: &Scope03,
    request: &wire::Challenge03,
) -> Result<serde_json::Value> {
    let mut held = HeldHistory03::lock(tx, scope, request.attempt_id).await?;
    let record = request
        .candidate_record(
            scope.session.account_id,
            scope.session.device_id,
            &held.original.session,
        )
        .map_err(|_| Error::Conflict)?;
    held.original.command(&record_submit(&record)?)?;
    // This existence check is AFTER the same exclusive account/anchor locks
    // taken by every factory. It is only a new-versus-history classification;
    // the actual SQL factory independently enforces the immutable command.
    let prior=tx.query_opt(
        "SELECT 1 FROM public.conversation_profile03_closure_challenges WHERE account_id=$1 AND proof_request_id=$2",
        &[&scope.session.account_id,&request.proof_request_id],
    ).await?.is_some();
    let bytes = &record.bytes()[..];
    let [a, b, c, d, e, f] = scope.sql_actor();
    let rows=tx.query(
        "SELECT * FROM public.conversation_profile03_effect_closure_challenge($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[a,b,c,d,e,f,&request.proof_request_id,&bytes,&request.previous_challenge_id],
    ).await?;
    if rows.len() != 1 {
        return Err(Error::Conflict);
    }
    let row = &rows[0];
    let stored = retained_record(tx, scope, &held, request.closure_id).await?;
    if stored.bytes() != record.bytes() {
        return Err(Error::Conflict);
    }
    let core = challenge_core(row, &held.original, &stored)?;
    if core.identities()[6] != *request.proof_request_id.as_bytes()
        || core.identities()[5] != *request.closure_id.as_bytes()
    {
        return Err(Error::Conflict);
    }
    let value = challenge_json(tx, row).await?;
    held.revalidate(scope).await?;
    if !prior {
        fresh(&core, &held, scope)?;
    }
    let mut object = value.as_object().ok_or(Error::Unsupported)?.clone();
    object.insert("v".into(), serde_json::json!(1));
    object.insert(
        "type".into(),
        serde_json::json!("payload_profile_no_submit_challenge03"),
    );
    object.insert(
        "connection_epoch".into(),
        serde_json::json!(scope.session.connection_epoch),
    );
    Ok(serde_json::Value::Object(object))
}

pub(super) async fn accept(
    tx: &Transaction<'_>,
    scope: &Scope03,
    request: &wire::Proof03,
) -> Result<serde_json::Value> {
    let attempt = Uuid::from_bytes(request.core.identities()[4]);
    let mut held = HeldHistory03::lock(tx, scope, attempt).await?;
    let record = retained_record(tx, scope, &held, request.closure_id).await?;
    let row=tx.query_opt(
        "SELECT * FROM public.conversation_profile03_closure_challenges WHERE account_id=$1 AND proof_request_id=$2",
        &[&scope.session.account_id,&request.proof_request_id],
    ).await?.ok_or(Error::NotFound)?;
    let core = challenge_core(&row, &held.original, &record)?;
    if core.bytes() != request.core.bytes()
        || core.identities()[7] != *request.challenge_id.as_bytes()
        || core.identities()[5] != *request.closure_id.as_bytes()
        || row
            .try_get::<_, Option<i64>>("closed_unaccepted_ms")?
            .is_some()
    {
        return Err(Error::Conflict);
    }
    core.verify_candidate_signature(&held.original.point, &request.signature)
        .map_err(|_| Error::Authentication)?;
    let prior=tx.query_opt(
        "SELECT * FROM public.conversation_profile03_closure_receipts WHERE account_id=$1 AND closure_id=$2",
        &[&scope.session.account_id,&request.closure_id],
    ).await?;
    held.revalidate(scope).await?;
    if prior.is_none() {
        fresh(&core, &held, scope)?;
    }
    let bytes = &request.core.bytes()[..];
    let signature = &request.signature[..];
    let [a, b, c, d, e, f] = scope.sql_actor();
    let rows=tx.query(
        "SELECT * FROM public.conversation_profile03_effect_closure_accept($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[a,b,c,d,e,f,&request.proof_request_id,&bytes,&signature],
    ).await?;
    if rows.len() != 1 {
        return Err(Error::Conflict);
    }
    let accepted = &rows[0];
    if accepted.try_get::<_, Vec<u8>>("signature")?.as_slice() != request.signature
        || accepted.try_get::<_, Uuid>("proof_request_id")? != request.proof_request_id
        || accepted.try_get::<_, Uuid>("challenge_id")? != request.challenge_id
        || accepted.try_get::<_, Uuid>("closure_id")? != request.closure_id
    {
        return Err(Error::Conflict);
    }
    let receipt = receipt_json(accepted, &core, &held.original)?;
    held.revalidate(scope).await?;
    if prior.is_none() {
        fresh(&core, &held, scope)?;
    }
    Ok(serde_json::json!({
        "v":1,"type":"payload_profile_no_submit_ack03","connection_epoch":scope.session.connection_epoch,
        "proof_request_id":request.proof_request_id,"closure_id":request.closure_id,
        "challenge_id":request.challenge_id,"message_id":held.original.grant.ids[1],"attempt_id":attempt,
        "submit_command_sha256":B.encode(core.digests()[1]),"closure_record_sha256":B.encode(core.digests()[6]),
        "accepted_ms":receipt.get("accepted_ms").ok_or(Error::Unsupported)?,"disposition":"closed_no_rearm"
    }))
}

pub(super) async fn status(
    tx: &Transaction<'_>,
    scope: &Scope03,
    request: &wire::ProofStatus03,
) -> Result<serde_json::Value> {
    let mut held = HeldHistory03::lock(tx, scope, request.attempt_id).await?;
    if held.original.grant.ids[1] != request.message_id {
        return Err(Error::Conflict);
    }
    let row=tx.query_opt(
        "SELECT * FROM public.conversation_profile03_closure_challenges WHERE account_id=$1 AND proof_request_id=$2",
        &[&scope.session.account_id,&request.proof_request_id],
    ).await?;
    let (status, challenge, receipt) = if let Some(row) = row {
        let record = retained_record(tx, scope, &held, request.closure_id).await?;
        let core = challenge_core(&row, &held.original, &record)?;
        if core.identities()[5] != *request.closure_id.as_bytes()
            || core.digests()[1] != request.submit_sha256
            || core.digests()[6] != request.record_sha256
        {
            return Err(Error::Conflict);
        }
        let challenge = challenge_json(tx, &row).await?;
        if row.try_get::<_,Option<i64>>("closed_unaccepted_ms")?.is_some() {
            ("superseded",challenge,serde_json::Value::Null)
        } else if let Some(receipt)=tx.query_opt(
            "SELECT * FROM public.conversation_profile03_closure_receipts WHERE account_id=$1 AND closure_id=$2 AND proof_request_id=$3 AND challenge_id=$4",
            &[&scope.session.account_id,&request.closure_id,&request.proof_request_id,&Uuid::from_bytes(core.identities()[7])],
        ).await? {
            ("accepted",challenge,receipt_json(&receipt,&core,&held.original)?)
        } else { ("challenged",challenge,serde_json::Value::Null) }
    } else {
        (
            "not_found",
            serde_json::Value::Null,
            serde_json::Value::Null,
        )
    };
    held.revalidate(scope).await?;
    Ok(serde_json::json!({
        "v":1,"type":"payload_profile_no_submit_status03","connection_epoch":scope.session.connection_epoch,
        "request_id":request.request_id,"proof_request_id":request.proof_request_id,"closure_id":request.closure_id,
        "message_id":request.message_id,"attempt_id":request.attempt_id,
        "submit_command_sha256":B.encode(request.submit_sha256),"closure_record_sha256":B.encode(request.record_sha256),
        "status":status,"challenge":challenge,"receipt":receipt
    }))
}
