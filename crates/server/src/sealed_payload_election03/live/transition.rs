// SPDX-License-Identifier: AGPL-3.0-only
//! Held real transitions. The caller owns the transaction and must roll it back
//! on every refusal; one consumed factor never authorizes a later transaction.
use super::*;
use crate::sealed_manifest03 as crypto;
use crate::sealed_payload_election03::{self as election, adapter_contract, owner_records};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use uuid::Uuid;

async fn ready(tx: &Transaction<'_>) -> Result<()> {
    crate::payload_profile_elections::require(tx)
        .await
        .map_err(|_| Error::Unavailable)
}

pub(super) async fn exclusive(tx: &Transaction<'_>, owner: &Owner<'_, '_, '_>) -> Result<()> {
    if !owner.uses(tx) {
        return Err(Error::Authentication);
    }
    let who = owner.selector();
    // Genuine authentication already retained authority-before-account SHARE
    // witnesses. Upgrade with NOWAIT/try rather than waiting behind another
    // holder which might itself be waiting for this transaction's witnesses.
    tx.query_opt("SELECT account_id FROM public.sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR UPDATE NOWAIT",&[&who.account]).await?.ok_or(Error::Unsupported)?;
    let key = adapter_contract::account_fence_key(who.account.as_bytes())
        .map_err(|_| Error::Unsupported)?;
    if !tx
        .query_one("SELECT pg_catalog.pg_try_advisory_xact_lock($1)", &[&key])
        .await?
        .try_get::<_, bool>(0)?
    {
        return Err(Error::Conflict);
    }
    let row=tx.query_opt("SELECT state,selection_epoch FROM public.payload_profile_account_anchors WHERE account_id=$1 FOR UPDATE NOWAIT",&[&who.account]).await?.ok_or(Error::Unsupported)?;
    if row.try_get::<_, String>(0)? != "live"
        || u64::try_from(row.try_get::<_, i64>(1)?).ok() != Some(owner.epoch())
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub async fn bootstrap(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    line: Uuid,
    origin: &str,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let mut current = state02::Current02::lock(tx, &Owner::Ordinary(owner), line, origin).await?;
    current
        .context
        .revalidate()
        .await
        .map_err(|_| Error::Unavailable)?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    current.checked_ms = clock(
        tx,
        current
            .checked_ms
            .max(owner.checked_at_ms())
            .max(current.context.checked_primary_ms()),
    )
    .await?;
    if current.checked_ms
        >= owner
            .session_deadline_ms()
            .min(current.context.lease_deadline_ms())
            .min(current.selected.expires_ms)
    {
        return Err(Error::Expired);
    }
    Ok(current.projection(&Owner::Ordinary(owner)))
}

pub async fn status(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    line: Uuid,
) -> Result<Reservation> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) || opening.is_nil() || line.is_nil() {
        return Err(Error::Authentication);
    }
    let who = owner.selected_identity();
    let r = Reservation::read(tx, who.account, opening)
        .await?
        .ok_or(Error::NotFound)?;
    if r.user != who.user || r.line != line || r.core[400..432] != *owner.origin_digest() {
        return Err(Error::NotFound);
    }
    // Historical recovery may use a newly authenticated session of the same
    // original owner. It returns only the immutable reservation, never a fresh
    // factor or permission to commit its old session-bound signed bytes.
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(r)
}

pub async fn reserve(
    tx: &Transaction<'_>,
    proof: &mut HeldStepUp03<'_, '_>,
    opening: Uuid,
    line: Uuid,
    successor: &[u8],
    origin: &str,
) -> Result<Reservation> {
    ready(tx).await?;
    if opening.is_nil() || line.is_nil() {
        return Err(Error::Conflict);
    }
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    exclusive(tx, &Owner::StepUp(proof)).await?;
    let mut current = state02::Current02::lock(tx, &Owner::StepUp(proof), line, origin).await?;
    let who = proof.selected_identity();
    if opening == current.history.binding_id() {
        return Err(Error::Conflict);
    }
    if let Some(existing) = Reservation::read(tx, who.account, opening).await? {
        if existing.user != who.user || existing.line != line || existing.successor != successor {
            return Err(Error::Conflict);
        }
        // HTTP normally detects this before asking for another factor. Do not
        // allocate/burn another generation or renew the original interval.
        return Ok(existing);
    }
    let now = clock(tx, current.checked_ms.max(proof.checked_primary_ms())).await?;
    let manifest = crypto::verify_from_02(successor, &current.checkpoint, now)
        .map_err(|_| Error::Unsupported)?;
    let identity = manifest.identity_at(now).map_err(|_| Error::Unsupported)?;
    let selected = manifest
        .profile_election_keys(
            current.device.as_bytes(),
            line.as_bytes(),
            &current.device_point,
            &current.owner_point,
            now,
        )
        .map_err(|_| Error::Unsupported)?;
    if selected.reader_id != current.selected.reader_id
        || selected.device_signer_id != current.selected.device_signer_id
        || selected.approval_id != current.selected.approval_id
    {
        return Err(Error::Unsupported);
    }
    let expires = now
        .checked_add(300_000)
        .ok_or(Error::Expired)?
        .min(proof.expires_at_ms())
        .min(current.context.lease_deadline_ms())
        .min(current.selected.expires_ms)
        .min(selected.expires_ms);
    if expires <= now {
        return Err(Error::Expired);
    }
    let generation = current
        .last_issued
        .checked_add(1)
        .filter(|g| *g <= i64::MAX as u64)
        .ok_or(Error::Unsupported)?;
    let challenge = Uuid::new_v4();
    let binding = Uuid::new_v4();
    let nonce: [u8; 32] = rand::random();
    if challenge == binding
        || challenge == opening
        || binding == opening
        || challenge == current.history.binding_id()
        || binding == current.history.binding_id()
        || nonce == [0; 32]
    {
        return Err(Error::Unavailable);
    }
    // Opening IDs are human/client retained recovery handles. They must not
    // alias any retained challenge, binding or opening in this account; all
    // original identities remain permanent after expiry and supersession.
    if tx.query_one("SELECT EXISTS(SELECT 1 FROM public.payload_profile_election_challenges WHERE account_id=$1 AND (opening_id=ANY($2) OR challenge_id=ANY($2) OR new_binding_id=ANY($2)))", &[&who.account, &vec![opening, challenge, binding]]).await?.try_get::<_, bool>(0)? {
        return Err(Error::Conflict);
    }
    let mut core = Vec::with_capacity(500);
    core.extend_from_slice(b"ZTPE\x03\x01\x02\x03");
    for id in [
        who.account,
        current.device,
        line,
        challenge,
        current.history.binding_id(),
    ] {
        core.extend_from_slice(id.as_bytes())
    }
    core.extend_from_slice(&current.generation.to_be_bytes());
    core.extend_from_slice(&generation.to_be_bytes());
    core.extend_from_slice(current.history.old_binding_proof_digest());
    core.extend_from_slice(&current.fingerprint);
    core.extend_from_slice(&1u64.to_be_bytes());
    core.extend_from_slice(&current.manifest_version.to_be_bytes());
    core.extend_from_slice(&current.manifest_digest);
    core.extend_from_slice(&identity.version.to_be_bytes());
    core.extend_from_slice(&identity.digest);
    for digest in [
        selected.reader_id,
        selected.device_signer_id,
        selected.approval_id,
        nonce,
    ] {
        core.extend_from_slice(&digest)
    }
    core.extend_from_slice(&now.to_be_bytes());
    core.extend_from_slice(&expires.to_be_bytes());
    for digest in [
        proof.origin_digest(),
        proof.owner_identity_digest(),
        current.context.identity_digest(),
    ] {
        core.extend_from_slice(digest)
    }
    core.extend_from_slice(&[0; 4]);
    if core.len() != 500 {
        return Err(Error::Unsupported);
    }
    current
        .context
        .revalidate()
        .await
        .map_err(|_| Error::Unavailable)?;
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let deadline = i64::try_from(proof.expires_at_ms()).map_err(|_| Error::Expired)?;
    tx.query_opt(
        "SELECT challenge_id FROM public.payload_profile_election_reserve($1,$2,$3,$4,$5,$6,$7,$8)",
        &[
            &who.account,
            &opening,
            &who.user,
            &who.session,
            &binding,
            &core,
            &successor,
            &deadline,
        ],
    )
    .await?
    .ok_or(Error::Unavailable)?;
    let stored = Reservation::read(tx, who.account, opening)
        .await?
        .ok_or(Error::Unavailable)?;
    if stored.core.as_slice() != core
        || stored.new_binding != binding
        || stored.successor != successor
    {
        return Err(Error::Conflict);
    }
    current.checked_ms = clock(tx, current.checked_ms).await?;
    stored.matches_current(&Owner::StepUp(proof), &current)?;
    current
        .context
        .revalidate()
        .await
        .map_err(|_| Error::Unavailable)?;
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(stored)
}

/// Public historical setup evidence over the ACTUAL enrolled socket. This
/// validates the prior genuine owner's reservation/current records without
/// inventing a new authenticated browser principal or reusing its factor.
pub(crate) async fn device_challenge(
    tx: &Transaction<'_>,
    session: crate::device_socket::DeviceSession,
    site: &str,
    instance: &str,
    deployment: u64,
    origin: &str,
) -> Result<Option<serde_json::Value>> {
    ready(tx).await?;
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
    let rows=tx.query("SELECT opening_id,initiating_user_id,initiating_session_id FROM public.payload_profile_election_challenges WHERE account_id=$1 AND device_id=$2 AND closed_unaccepted_ms IS NULL AND expires_ms>pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint AND NOT EXISTS(SELECT 1 FROM public.payload_profile_elections e WHERE (e.account_id,e.challenge_id)=(payload_profile_election_challenges.account_id,payload_profile_election_challenges.challenge_id)) ORDER BY new_binding_generation LIMIT 2",&[&session.account_id,&session.device_id]).await?;
    if rows.len() > 1 {
        return Err(Error::Unsupported);
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let opening: Uuid = row.try_get(0)?;
    let selector = owner_records::Selector {
        account: session.account_id,
        user: row.try_get(1)?,
        session: row.try_get(2)?,
    };
    let records = owner_records::lock(tx, selector)
        .await
        .map_err(|_| Error::Authentication)?;
    let mut owner = ReservedOwner {
        tx,
        selector,
        records,
        origin: adapter_contract::origin_digest(origin).map_err(|_| Error::Unavailable)?,
    };
    // Locator was not authority. Re-read immutable core, closure and accepted
    // outcome after acquiring the genuine selected-record/account fence.
    let r = Reservation::read(tx, session.account_id, opening)
        .await?
        .ok_or(Error::NotFound)?;
    let mut current =
        state02::Current02::lock(tx, &Owner::Reserved(&owner), r.line, origin).await?;
    let actual = current.context.selected_identity();
    if r.accepted
        || r.closed.is_some()
        || r.device != session.device_id
        || actual.site != site
        || actual.instance != instance
        || actual.connection_epoch != positive(session.connection_epoch)?
        || actual.deployment_epoch != deployment
    {
        return Err(Error::Conflict);
    }
    r.matches_current(&Owner::Reserved(&owner), &current)?;
    owner
        .records
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    current
        .context
        .revalidate()
        .await
        .map_err(|_| Error::Unavailable)?;
    current.checked_ms = clock(
        tx,
        current
            .checked_ms
            .max(owner.records.checked_at_ms())
            .max(current.context.checked_primary_ms()),
    )
    .await?;
    r.matches_current(&Owner::Reserved(&owner), &current)?;
    Ok(Some(
        serde_json::json!({"v":1,"type":"payload_profile_challenge03","challenge_id":r.challenge,"new_binding_id":r.new_binding,"core":B.encode(r.core),"successor_manifest03":B.encode(&r.successor),"original":current.projection(&Owner::Reserved(&owner)),"closed_unaccepted":r.closure_projection()}),
    ))
}

/// Called only after actual enrolled socket authentication. The transport must
/// supply its own configured site/instance/deployment, not received JSON fields.
/// DeviceSession chooses the current lease; genuine device signature plus exact
/// current owner/lease records are independently required here.
pub(crate) async fn device_proof(
    tx: &Transaction<'_>,
    socket: SocketSelection03<'_>,
    challenge: Uuid,
    signature: &[u8],
) -> Result<()> {
    let SocketSelection03 {
        session,
        site,
        instance,
        deployment,
        origin,
    } = socket;
    ready(tx).await?;
    let opening:Uuid=tx.query_opt("SELECT opening_id FROM public.payload_profile_election_challenges WHERE account_id=$1 AND challenge_id=$2",&[&session.account_id,&challenge]).await?.ok_or(Error::NotFound)?.try_get(0)?;
    let r = Reservation::read(tx, session.account_id, opening)
        .await?
        .ok_or(Error::NotFound)?;
    let selector = owner_records::Selector {
        account: r.account,
        user: r.user,
        session: r.session,
    };
    let records = owner_records::lock(tx, selector)
        .await
        .map_err(|_| Error::Authentication)?;
    let mut owner = ReservedOwner {
        tx,
        selector,
        records,
        origin: adapter_contract::origin_digest(origin).map_err(|_| Error::Unavailable)?,
    };
    let r = Reservation::read(tx, session.account_id, opening)
        .await?
        .ok_or(Error::NotFound)?;
    let mut current =
        state02::Current02::lock(tx, &Owner::Reserved(&owner), r.line, origin).await?;
    r.matches_current(&Owner::Reserved(&owner), &current)?;
    let actual = current.context.selected_identity();
    if r.device != session.device_id
        || r.closed.is_some()
        || actual.site != site
        || actual.instance != instance
        || actual.connection_epoch != positive(session.connection_epoch)?
        || actual.deployment_epoch != deployment
    {
        return Err(Error::Conflict);
    }
    crypto::signature(
        &r.device_point,
        signature,
        &crypto::framed(b"ZTSE/line/payload-profile/device/v1\0", &r.core)
            .map_err(|_| Error::Unsupported)?,
    )
    .map_err(|_| Error::Authentication)?;
    let now = clock(
        tx,
        owner
            .records
            .checked_at_ms()
            .max(current.context.checked_primary_ms()),
    )
    .await?;
    if now < r.issued || now >= r.expires {
        return Err(Error::Expired);
    }
    if r.device_signature
        .as_ref()
        .is_some_and(|old| old.as_slice() != signature)
    {
        return Err(Error::Conflict);
    }
    owner
        .records
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    current
        .context
        .revalidate()
        .await
        .map_err(|_| Error::Unavailable)?;
    tx.query_opt(
        "SELECT challenge_id FROM public.payload_profile_election_device_proof($1,$2,$3)",
        &[&r.account, &challenge, &signature],
    )
    .await?
    .ok_or(Error::Unavailable)?;
    owner
        .records
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    current
        .context
        .revalidate()
        .await
        .map_err(|_| Error::Unavailable)?;
    if clock(tx, now).await? >= r.expires {
        return Err(Error::Expired);
    }
    Ok(())
}

/// Exact observed historical retry. Authentication belongs to the current
/// caller; original signed session bytes and acceptance time remain unchanged.
/// Returning this receipt neither re-elects nor restores current permission.
pub async fn historical_accept(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    challenge: Uuid,
    successor: &[u8],
    bundle: &[u8],
) -> Result<Option<serde_json::Value>> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) || opening.is_nil() || challenge.is_nil() {
        return Err(Error::Authentication);
    }
    let who = owner.selected_identity();
    let Some(r) = Reservation::read(tx, who.account, opening).await? else {
        return Ok(None);
    };
    if r.user != who.user
        || r.core[400..432] != *owner.origin_digest()
        || r.challenge != challenge
        || r.successor != successor
        || bundle.len() != 628
        || bundle[..500] != r.core
    {
        return Err(Error::Conflict);
    }
    if !r.accepted {
        return Ok(None);
    }
    let row=tx.query_opt("SELECT * FROM public.payload_profile_elections WHERE account_id=$1 AND challenge_id=$2",&[&who.account,&challenge]).await?.ok_or(Error::Unavailable)?;
    let stored: Vec<u8> = row.try_get("bundle")?;
    if stored != bundle {
        return Err(Error::Conflict);
    }
    let a = accepted_record(&row)?;
    matches_mapping(&r, &a)?;
    election::verify_accepted(&election::AcceptedProofInput03 {
        bundle,
        expected_core: &r.core,
        accepted: &a,
        predecessor02: &r.checkpoint()?,
        accepted_signed_manifest03: &r.successor,
        device_signing_point_at_acceptance: &r.device_point,
        owner_approval_point_at_acceptance: &r.owner_point,
    })
    .map_err(|_| Error::Unsupported)?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let epoch = positive(row.try_get("selection_epoch")?)?;
    Ok(Some(receipt(&r, &a, epoch)))
}

pub async fn accept(
    tx: &Transaction<'_>,
    proof: &mut HeldStepUp03<'_, '_>,
    opening: Uuid,
    challenge: Uuid,
    successor: &[u8],
    bundle: &[u8],
    origin: &str,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    exclusive(tx, &Owner::StepUp(proof)).await?;
    let who = proof.selected_identity();
    let r = Reservation::read(tx, who.account, opening)
        .await?
        .ok_or(Error::NotFound)?;
    if r.user != who.user
        || r.challenge != challenge
        || r.successor != successor
        || bundle.len() != 628
        || bundle[..500] != r.core
    {
        return Err(Error::Conflict);
    }
    let mut current = state02::Current02::lock(tx, &Owner::StepUp(proof), r.line, origin).await?;
    r.matches_current(&Owner::StepUp(proof), &current)?;
    if r.device_signature
        .as_ref()
        .is_none_or(|sig| sig.as_slice() != &bundle[500..564])
    {
        return Err(Error::Conflict);
    }
    let owner_payload = [r.core.as_slice(), &crypto::sha(&bundle[500..564])].concat();
    crypto::signature(
        &r.owner_point,
        &bundle[564..],
        &crypto::framed(b"ZTSE/line/payload-profile/owner/v1\0", &owner_payload)
            .map_err(|_| Error::Unsupported)?,
    )
    .map_err(|_| Error::Authentication)?;
    current
        .context
        .revalidate()
        .await
        .map_err(|_| Error::Unavailable)?;
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let deadline = i64::try_from(proof.expires_at_ms()).map_err(|_| Error::Expired)?;
    let accepted = tx
        .query_opt(
            "SELECT * FROM public.payload_profile_election_accept($1,$2,$3,$4,$5)",
            &[&who.account, &opening, &challenge, &bundle, &deadline],
        )
        .await?
        .ok_or(Error::Unavailable)?;
    let a = accepted_record(&accepted)?;
    matches_mapping(&r, &a)?;
    election::verify_accepted(&election::AcceptedProofInput03 {
        bundle,
        expected_core: &r.core,
        accepted: &a,
        predecessor02: &current.checkpoint,
        accepted_signed_manifest03: successor,
        device_signing_point_at_acceptance: &r.device_point,
        owner_approval_point_at_acceptance: &r.owner_point,
    })
    .map_err(|_| Error::Unsupported)?;
    let epoch = positive(accepted.try_get("selection_epoch")?)?;
    if epoch
        != proof
            .selection_epoch()
            .checked_add(1)
            .ok_or(Error::Unsupported)?
    {
        return Err(Error::Conflict);
    }
    let now = clock(tx, a.accepted_at_ms.max(proof.checked_primary_ms())).await?;
    if now
        >= proof
            .expires_at_ms()
            .min(r.expires)
            .min(current.context.lease_deadline_ms())
            .min(current.selected.expires_ms)
    {
        return Err(Error::Expired);
    }
    // The accepted routine advanced this transaction's epoch itself. Reusing
    // an old-epoch owner witness afterward would correctly refuse. No generic
    // bypass/renewal exists: exact auth/factor rows stay locked, and the closed
    // SQL deferred acceptance deadline refuses a late COMMIT after any wait.
    Ok(receipt(&r, &a, epoch))
}

pub(super) fn accepted_record(r: &Row) -> Result<election::DurableAcceptedElection03> {
    let id = |name: &str| -> Result<[u8; 16]> {
        let v: Uuid = r.try_get(name)?;
        if v.is_nil() {
            return Err(Error::Unsupported);
        }
        Ok(*v.as_bytes())
    };
    let n = |name: &str| -> Result<u64> { positive(r.try_get(name)?) };
    let d = |name: &str| -> Result<[u8; 32]> {
        r.try_get::<_, Vec<u8>>(name)?
            .try_into()
            .map_err(|_| Error::Unsupported)
    };
    Ok(election::DurableAcceptedElection03 {
        account_id: id("account_id")?,
        device_id: id("device_id")?,
        line_id: id("line_id")?,
        root_fingerprint: d("root_fingerprint")?,
        vault_generation: n("vault_generation")?,
        old_binding_id: id("old_binding_id")?,
        old_binding_generation: n("old_binding_generation")?,
        old_binding_proof_digest: d("old_binding_proof_digest")?,
        new_binding_id: id("new_binding_id")?,
        new_binding_generation: n("new_binding_generation")?,
        selected_reader_key_id: d("selected_reader_key_id")?,
        prior_manifest_version: n("prior_manifest_version")?,
        prior_manifest_digest: d("prior_manifest_digest")?,
        prior_signed_manifest_sha256: d("prior_signed_manifest_sha256")?,
        accepted_manifest_version: n("accepted_manifest_version")?,
        accepted_manifest_digest: d("accepted_manifest_digest")?,
        accepted_signed_manifest_sha256: d("accepted_signed_manifest_sha256")?,
        election_core_sha256: d("election_core_sha256")?,
        election_commitment: d("election_commitment")?,
        election_bundle_sha256: d("election_bundle_sha256")?,
        accepted_at_ms: n("accepted_at_ms")?,
    })
}
pub(super) fn matches_mapping(
    r: &Reservation,
    a: &election::DurableAcceptedElection03,
) -> Result<()> {
    if a.account_id != *r.account.as_bytes()
        || a.device_id != *r.device.as_bytes()
        || a.line_id != *r.line.as_bytes()
        || a.old_binding_id != *r.old_binding.as_bytes()
        || a.old_binding_generation != r.old_generation
        || a.new_binding_id != *r.new_binding.as_bytes()
        || a.new_binding_generation != r.new_generation
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub(super) fn receipt(
    r: &Reservation,
    a: &election::DurableAcceptedElection03,
    epoch: u64,
) -> serde_json::Value {
    serde_json::json!({"v":1,"opening_id":r.opening,"challenge_id":r.challenge,"binding_id":r.new_binding,"binding_generation":r.new_generation.to_string(),"election_digest":B.encode(a.election_commitment),"bundle_sha256":B.encode(a.election_bundle_sha256),"accepted_ms":a.accepted_at_ms.to_string(),"selection_epoch":epoch.to_string()})
}
