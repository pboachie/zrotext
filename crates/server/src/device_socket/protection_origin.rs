// SPDX-License-Identifier: AGPL-3.0-only
//! Ordinary authenticated setup control, independent of line/profile negotiation.
use super::*;
use crate::device_protection::{Association, CandidateProof, ProofCore};
use crate::sealed_inbound::line_activation::v2_runtime::object_body;
use tokio_postgres::{Row, Transaction};

object_body! {struct Open{v:u8,r#type:String,connection_epoch:i64,setup_id:String,opening_id:String,command_id:String}}
object_body! {struct Attempt{v:u8,r#type:String,connection_epoch:i64,setup_id:String,opening_id:String,command_id:String,proof_request_id:String,association:String,aes_probe:String,previous_attempt_id:serde_json::Value,previous_core_sha256:serde_json::Value,previous_bundle_sha256:serde_json::Value}}
object_body! {struct Accept{v:u8,r#type:String,connection_epoch:i64,setup_id:String,opening_id:String,command_id:String,proof_request_id:String,attempt_id:String,bundle:String}}
object_body! {struct Status{v:u8,r#type:String,connection_epoch:i64,request_id:String,setup_id:String,opening_id:String,command_id:String,proof_request_id:serde_json::Value}}

pub(super) struct Incoming {
    raw: String,
    kind: Kind,
}
#[derive(Clone, Copy)]
enum Kind {
    Open,
    Attempt,
    Accept,
    Status,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Open => "protection_origin_open",
            Self::Attempt => "protection_origin_proof_open",
            Self::Accept => "protection_origin_proof",
            Self::Status => "protection_origin_status_request",
        }
    }
}
pub(super) fn parse(raw: &str) -> Result<Option<Incoming>, ()> {
    // Only a routing projection. Full closed parsing follows the separately
    // committed authenticated request debit, including malformed proof inputs.
    #[derive(Deserialize)]
    struct Route {
        r#type: String,
    }
    let mut decoder = serde_json::Deserializer::from_str(raw);
    let route: Route =
        crate::sealed_inbound::line_activation::v2_runtime::decode_object(&mut decoder)
            .map_err(|_| ())?;
    decoder.end().map_err(|_| ())?;
    let kind = match route.r#type.as_str() {
        "protection_origin_open" => Kind::Open,
        "protection_origin_proof_open" => Kind::Attempt,
        "protection_origin_proof" => Kind::Accept,
        "protection_origin_status_request" => Kind::Status,
        _ => return Ok(None),
    };
    if raw.len() > MAX_FRAME_BYTES {
        return Err(());
    }
    Ok(Some(Incoming {
        raw: raw.to_owned(),
        kind,
    }))
}
fn id(s: &str) -> Result<Uuid, ()> {
    let id = Uuid::parse_str(s).map_err(|_| ())?;
    if id.is_nil() || id.to_string() != s {
        return Err(());
    }
    Ok(id)
}
fn binary<const N: usize>(s: &str) -> Result<[u8; N], ()> {
    let raw = URL_SAFE_NO_PAD.decode(s).map_err(|_| ())?;
    if URL_SAFE_NO_PAD.encode(&raw) != s {
        return Err(());
    }
    raw.try_into().map_err(|_| ())
}
fn nullable_id(v: &serde_json::Value) -> Result<Option<Uuid>, ()> {
    if v.is_null() {
        Ok(None)
    } else {
        id(v.as_str().ok_or(())?).map(Some)
    }
}
fn nullable_hash(v: &serde_json::Value) -> Result<Option<Vec<u8>>, ()> {
    if v.is_null() {
        Ok(None)
    } else {
        binary::<32>(v.as_str().ok_or(())?).map(|v| Some(v.to_vec()))
    }
}
fn header(v: u8, tag: &str, kind: Kind, epoch: i64, actor: actor::SocketActor) -> Result<(), ()> {
    if v != 1 || tag != kind.name() || epoch != actor.session().connection_epoch {
        return Err(());
    }
    Ok(())
}
fn json_id(row: &Row, name: &str) -> Result<String, ()> {
    Ok(row.try_get::<_, Uuid>(name).map_err(|_| ())?.to_string())
}
fn json_bytes(row: &Row, name: &str) -> Result<String, ()> {
    Ok(URL_SAFE_NO_PAD.encode(row.try_get::<_, Vec<u8>>(name).map_err(|_| ())?))
}
fn json_time(row: &Row, name: &str) -> Result<String, ()> {
    let t = row.try_get::<_, i64>(name).map_err(|_| ())?;
    if t <= 0 {
        return Err(());
    }
    Ok(t.to_string())
}

async fn lock(
    tx: &Transaction<'_>,
    actor: actor::SocketActor,
    state: &DeviceSocketState,
) -> Result<(), ()> {
    crate::device_protection_storage::require(tx)
        .await
        .map_err(|_| ())?;
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'").await.map_err(|_|())?;
    // The absent-original recovery proof depends on a fresh post-claim
    // snapshot. Structural SQL may support other isolation levels; this
    // authenticated control port deliberately requires READ COMMITTED.
    if tx
        .query_one("SHOW transaction_isolation", &[])
        .await
        .map_err(|_| ())?
        .try_get::<_, String>(0)
        .map_err(|_| ())?
        != "read committed"
    {
        return Err(());
    }
    let s = actor.session();
    tx.query_one(
        "SELECT public.device_protection_lock($1,$2,$3,$4,$5,$6)",
        &[
            &s.account_id,
            &s.device_id,
            &state.site_id,
            &state.instance_id,
            &s.connection_epoch,
            &state.deployment_epoch,
        ],
    )
    .await
    .map_err(|_| ())?;
    // SQL locks establish current rows; only this separately verified witness
    // proves which enrolled point actually authenticated this socket.
    let point = tx
        .query_one(
            "SELECT signing_key_sec1 FROM public.device_keys WHERE account_id=$1 AND device_id=$2",
            &[&s.account_id, &s.device_id],
        )
        .await
        .map_err(|_| ())?
        .try_get::<_, Vec<u8>>(0)
        .map_err(|_| ())?;
    if !actor.proof().matches_point(&point) {
        return Err(());
    }
    Ok(())
}
async fn opening(
    tx: &Transaction<'_>,
    actor: actor::SocketActor,
    state: &DeviceSocketState,
    scope: [Uuid; 3],
    origin: &[u8; 32],
) -> Result<Option<Row>, ()> {
    let s = actor.session();
    let row=tx.query_opt("SELECT * FROM public.device_protection_origins WHERE account_id=$1 AND device_id=$2 AND setup_id=$3 AND opening_id=$4 AND command_id=$5",&[&s.account_id,&s.device_id,&scope[0],&scope[1],&scope[2]]).await.map_err(|_|())?;
    if let Some(row) = &row {
        if !actor.proof().matches_point(
            &row.try_get::<_, Vec<u8>>("enrolled_point")
                .map_err(|_| ())?,
        ) || row
            .try_get::<_, Vec<u8>>("enrolled_key_id")
            .map_err(|_| ())?
            .as_slice()
            != actor.proof().signing_key_id()
            || row
                .try_get::<_, Vec<u8>>("origin_digest")
                .map_err(|_| ())?
                .as_slice()
                != origin
        {
            return Err(());
        }
    }
    // Keep full actor/retirement checks after every possibly waiting lookup.
    lock(tx, actor, state).await?;
    Ok(row)
}
fn opening_json(row: &Row) -> Result<serde_json::Value, ()> {
    Ok(
        serde_json::json!({"account_id":json_id(row,"account_id")?,"device_id":json_id(row,"device_id")?,"source_pairing_id":json_id(row,"source_pairing_id")?,"origin_digest":json_bytes(row,"origin_digest")?,"enrolled_point":json_bytes(row,"enrolled_point")?,"enrolled_key_id":json_bytes(row,"enrolled_key_id")?,"opening_nonce":json_bytes(row,"opening_nonce")?,"created_ms":json_time(row,"created_ms")?,"pairing_created_ms":json_time(row,"pairing_created_ms")?,"pairing_claimed_ms":json_time(row,"pairing_claimed_ms")?,"pairing_approved_ms":json_time(row,"pairing_approved_ms")?,"pairing_expires_ms":json_time(row,"pairing_expires_ms")?}),
    )
}
fn receipt_json(row: &Row) -> Result<serde_json::Value, ()> {
    Ok(
        serde_json::json!({"association_sha256":json_bytes(row,"association_sha256")?,"core_sha256":json_bytes(row,"core_sha256")?,"bundle_sha256":json_bytes(row,"bundle_sha256")?,"accepted_ms":json_time(row,"accepted_ms")?}),
    )
}
async fn challenge_json(tx: &Transaction<'_>, row: &Row) -> Result<serde_json::Value, ()> {
    let previous: Option<Uuid> = row.try_get("previous_attempt_id").map_err(|_| ())?;
    let closed = if let Some(previous) = previous {
        let p=tx.query_one("SELECT * FROM public.device_protection_attempts WHERE account_id=$1 AND attempt_id=$2",&[&row.try_get::<_,Uuid>("account_id").map_err(|_|())?,&previous]).await.map_err(|_|())?;
        serde_json::json!({"proof_request_id":json_id(&p,"proof_request_id")?,"attempt_id":previous,"core_sha256":json_bytes(&p,"core_sha256")?,"bundle_sha256":p.try_get::<_,Option<Vec<u8>>>("closed_bundle_sha256").map_err(|_|())?.map(|v|URL_SAFE_NO_PAD.encode(v)),"closed_ms":json_time(&p,"closed_ms")?})
    } else {
        serde_json::Value::Null
    };
    Ok(
        serde_json::json!({"proof_request_id":json_id(row,"proof_request_id")?,"attempt_id":json_id(row,"attempt_id")?,"core":json_bytes(row,"core")?,"nonce":json_bytes(row,"nonce")?,"closed_predecessor":closed}),
    )
}
async fn verify_receipt(
    tx: &Transaction<'_>,
    actor: actor::SocketActor,
    row: &Row,
) -> Result<(), ()> {
    let account = row.try_get::<_, Uuid>("account_id").map_err(|_| ())?;
    let opening = row.try_get::<_, Uuid>("opening_id").map_err(|_| ())?;
    let association=tx.query_one("SELECT association FROM public.device_protection_associations WHERE account_id=$1 AND opening_id=$2",&[&account,&opening]).await.map_err(|_|())?.try_get::<_,Vec<u8>>(0).map_err(|_|())?;
    let association = Association::decode(&association).map_err(|_| ())?;
    let bundle = row.try_get::<_, Vec<u8>>("bundle").map_err(|_| ())?;
    let proof = CandidateProof::verify(&bundle, actor.proof().signing_point(), &association)
        .map_err(|_| ())?;
    let accepted = row.try_get::<_, i64>("accepted_ms").map_err(|_| ())?;
    proof
        .core()
        .fresh(u64::try_from(accepted).map_err(|_| ())?)
        .map_err(|_| ())?;
    if row
        .try_get::<_, Vec<u8>>("association_sha256")
        .map_err(|_| ())?
        .as_slice()
        != association.digest()
        || row
            .try_get::<_, Vec<u8>>("core_sha256")
            .map_err(|_| ())?
            .as_slice()
            != crate::sealed_manifest03::sha(proof.core().bytes())
        || row
            .try_get::<_, Vec<u8>>("bundle_sha256")
            .map_err(|_| ())?
            .as_slice()
            != proof.digest()
    {
        return Err(());
    }
    Ok(())
}
fn scope(setup: &str, opening: &str, command: &str) -> Result<[Uuid; 3], ()> {
    Ok([id(setup)?, id(opening)?, id(command)?])
}

// This request admission commits separately, even if later closed parsing,
// signatures or the business command refuse. No owner credential is invented.
async fn admit<C: runtime_db::NativeConnection>(
    db: &mut C,
    state: &DeviceSocketState,
    actor: actor::SocketActor,
    kind: Kind,
) -> Result<(), ()> {
    let admission = runtime_db::begin_native(db).await.map_err(|_| ())?;
    lock(&admission, actor, state).await?;
    let allowed = abuse_limits::consume_device_protection(
        &admission,
        &state.auth_hasher,
        actor.proof(),
        !matches!(kind, Kind::Status),
    )
    .await
    .map_err(|_| ())?;
    lock(&admission, actor, state).await?;
    admission.commit().await.map_err(|_| ())?;
    if allowed { Ok(()) } else { Err(()) }
}

pub(super) async fn dispatch(
    socket: &mut WebSocket,
    state: &DeviceSocketState,
    actor: actor::SocketActor,
    origin: [u8; 32],
    frame: Incoming,
) -> Option<()> {
    if state.draining.load(Ordering::Acquire) {
        return None;
    }
    let mut db = runtime_db::connect_device(&state.database_url).await.ok()?;
    admit(&mut db, state, actor, frame.kind).await.ok()?;
    let tx = db.native_transaction().await.ok()?;
    lock(&tx, actor, state).await.ok()?;
    let (reply, deadline) = apply(&tx, state, actor, &origin, frame).await.ok()?;
    lock(&tx, actor, state).await.ok()?;
    if let Some(deadline) = deadline {
        let now=tx.query_one("SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",&[]).await.ok()?.get::<_,i64>(0);
        if now <= 0 || u64::try_from(now).ok()? >= deadline {
            return None;
        }
    }
    tx.commit().await.ok()?;
    let raw = reply.to_string();
    if raw.len() > MAX_FRAME_BYTES {
        return None;
    }
    socket.send(Message::Text(raw.into())).await.ok()?;
    Some(())
}

async fn apply(
    tx: &Transaction<'_>,
    state: &DeviceSocketState,
    actor: actor::SocketActor,
    origin: &[u8; 32],
    frame: Incoming,
) -> Result<(serde_json::Value, Option<u64>), ()> {
    let s = actor.session();
    let kind = frame.kind;
    match kind {
        Kind::Open => {
            let b: Open = serde_json::from_str(&frame.raw).map_err(|_| ())?;
            header(b.v, &b.r#type, kind, b.connection_epoch, actor)?;
            let ids = scope(&b.setup_id, &b.opening_id, &b.command_id)?;
            let row = tx
                .query_one(
                    "SELECT * FROM public.device_protection_open($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                    &[
                        &s.account_id,
                        &s.device_id,
                        &state.site_id,
                        &state.instance_id,
                        &s.connection_epoch,
                        &state.deployment_epoch,
                        &ids[0],
                        &ids[1],
                        &ids[2],
                        &&origin[..],
                    ],
                )
                .await
                .map_err(|_| ())?;
            let retained = opening(tx, actor, state, ids, origin).await?.ok_or(())?;
            if json_id(&row, "opening_id")? != json_id(&retained, "opening_id")? {
                return Err(());
            }
            Ok((
                serde_json::json!({"v":1,"type":"protection_origin_opened","connection_epoch":s.connection_epoch,"setup_id":ids[0],"opening_id":ids[1],"command_id":ids[2],"opening":opening_json(&retained)?}),
                None,
            ))
        }
        Kind::Attempt => {
            let b: Attempt = serde_json::from_str(&frame.raw).map_err(|_| ())?;
            header(b.v, &b.r#type, kind, b.connection_epoch, actor)?;
            let ids = scope(&b.setup_id, &b.opening_id, &b.command_id)?;
            let request = id(&b.proof_request_id)?;
            let original = opening(tx, actor, state, ids, origin).await?.ok_or(())?;
            let association =
                Association::decode(&binary::<329>(&b.association)?).map_err(|_| ())?;
            let aes = binary::<120>(&b.aes_probe)?;
            association
                .matches_provider_claims(
                    &original
                        .try_get::<_, Vec<u8>>("opening_nonce")
                        .map_err(|_| ())?,
                    &aes,
                )
                .map_err(|_| ())?;
            let expected = [
                s.account_id,
                s.device_id,
                ids[0],
                ids[1],
                ids[2],
                original
                    .try_get::<_, Uuid>("source_pairing_id")
                    .map_err(|_| ())?,
            ];
            if association
                .identities()
                .iter()
                .zip(expected)
                .any(|(a, b)| a != b.as_bytes())
                || &association.digests()[0] != origin
                || &association.digests()[1] != actor.proof().signing_key_id()
            {
                return Err(());
            }
            let previous = nullable_id(&b.previous_attempt_id)?;
            let prior_core = nullable_hash(&b.previous_core_sha256)?;
            let prior_bundle = nullable_hash(&b.previous_bundle_sha256)?;
            if previous.is_some() != prior_core.is_some()
                || previous.is_none() && prior_bundle.is_some()
            {
                return Err(());
            }
            let prior=tx.query_opt("SELECT 1 FROM public.device_protection_attempts WHERE account_id=$1 AND opening_id=$2 AND proof_request_id=$3",&[&s.account_id,&ids[1],&request]).await.map_err(|_|())?.is_some();
            let row=tx.query_one("SELECT * FROM public.device_protection_attempt($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",&[&s.account_id,&s.device_id,&state.site_id,&state.instance_id,&s.connection_epoch,&state.deployment_epoch,&ids[0],&ids[1],&ids[2],&request,&&association.bytes()[..],&&aes[..],&previous,&prior_core,&prior_bundle]).await.map_err(|_|())?;
            let core = ProofCore::decode(&row.try_get::<_, Vec<u8>>("core").map_err(|_| ())?)
                .map_err(|_| ())?;
            if core.association().bytes() != association.bytes() {
                return Err(());
            }
            core.matches_nonce(&row.try_get::<_, Vec<u8>>("nonce").map_err(|_| ())?)
                .map_err(|_| ())?;
            let challenge = challenge_json(tx, &row).await?;
            lock(tx, actor, state).await?;
            let now=tx.query_one("SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",&[]).await.map_err(|_|())?.get::<_,i64>(0);
            if !prior {
                core.fresh(u64::try_from(now).map_err(|_| ())?)
                    .map_err(|_| ())?;
            }
            Ok((
                serde_json::json!({"v":1,"type":"protection_origin_proof_challenge","connection_epoch":s.connection_epoch,"setup_id":ids[0],"opening_id":ids[1],"command_id":ids[2],"proof_request_id":request,"attempt_id":challenge["attempt_id"],"core":challenge["core"],"nonce":challenge["nonce"],"closed_predecessor":challenge["closed_predecessor"]}),
                if prior { None } else { Some(core.expires_ms()) },
            ))
        }
        Kind::Accept => {
            let b: Accept = serde_json::from_str(&frame.raw).map_err(|_| ())?;
            header(b.v, &b.r#type, kind, b.connection_epoch, actor)?;
            let ids = scope(&b.setup_id, &b.opening_id, &b.command_id)?;
            let request = id(&b.proof_request_id)?;
            let attempt = id(&b.attempt_id)?;
            opening(tx, actor, state, ids, origin).await?.ok_or(())?;
            let association=tx.query_one("SELECT association FROM public.device_protection_associations WHERE account_id=$1 AND opening_id=$2",&[&s.account_id,&ids[1]]).await.map_err(|_|())?.try_get::<_,Vec<u8>>(0).map_err(|_|())?;
            let association = Association::decode(&association).map_err(|_| ())?;
            let bundle = binary::<521>(&b.bundle)?;
            let proof =
                CandidateProof::verify(&bundle, actor.proof().signing_point(), &association)
                    .map_err(|_| ())?;
            if proof.core().attempt_id() != attempt.as_bytes() {
                return Err(());
            }
            let row=tx.query_one("SELECT * FROM public.device_protection_accept($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",&[&s.account_id,&s.device_id,&state.site_id,&state.instance_id,&s.connection_epoch,&state.deployment_epoch,&ids[0],&ids[1],&ids[2],&request,&attempt,&&proof.bytes()[..]]).await.map_err(|_|())?;
            verify_receipt(tx, actor, &row).await?;
            Ok((
                serde_json::json!({"v":1,"type":"protection_origin_accepted","connection_epoch":s.connection_epoch,"setup_id":ids[0],"opening_id":ids[1],"command_id":ids[2],"proof_request_id":request,"attempt_id":attempt,"receipt":receipt_json(&row)?}),
                None,
            ))
        }
        Kind::Status => {
            let b: Status = serde_json::from_str(&frame.raw).map_err(|_| ())?;
            header(b.v, &b.r#type, kind, b.connection_epoch, actor)?;
            let ids = scope(&b.setup_id, &b.opening_id, &b.command_id)?;
            let request = id(&b.request_id)?;
            let proof_request = nullable_id(&b.proof_request_id)?;
            let original = opening(tx, actor, state, ids, origin).await?;
            let mut status = "not_found";
            let mut open = serde_json::Value::Null;
            let mut challenge = serde_json::Value::Null;
            let mut receipt = serde_json::Value::Null;
            if let Some(original) = original {
                if let Some(proof_request) = proof_request {
                    if let Some(attempt)=tx.query_opt("SELECT * FROM public.device_protection_attempts WHERE account_id=$1 AND opening_id=$2 AND proof_request_id=$3",&[&s.account_id,&ids[1],&proof_request]).await.map_err(|_|())?{
                        open=opening_json(&original)?;challenge=challenge_json(tx,&attempt).await?;
                        let accepted=tx.query_opt("SELECT * FROM public.device_protection_receipts WHERE account_id=$1 AND opening_id=$2 AND proof_request_id=$3",&[&s.account_id,&ids[1],&proof_request]).await.map_err(|_|())?;
                        if let Some(accepted)=accepted{verify_receipt(tx,actor,&accepted).await?;status="accepted";receipt=receipt_json(&accepted)?;}else{status=if attempt.try_get::<_,Option<i64>>("closed_ms").map_err(|_|())?.is_some(){"superseded"}else{"challenged"};}
                    }
                } else {
                    status = "opened";
                    open = opening_json(&original)?;
                }
            }
            Ok((
                serde_json::json!({"v":1,"type":"protection_origin_status","connection_epoch":s.connection_epoch,"request_id":request,"setup_id":ids[0],"opening_id":ids[1],"command_id":ids[2],"proof_request_id":proof_request,"status":status,"opening":open,"challenge":challenge,"receipt":receipt}),
                None,
            ))
        }
    }
}

#[cfg(test)]
mod pg_tests;
#[cfg(test)]
mod tests;
