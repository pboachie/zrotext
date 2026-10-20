// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn exact_actor(
    row: &records::Challenge,
    owner: &HeldOrdinaryOwner03<'_, '_>,
    origin: &str,
) -> Result<()> {
    row.actor(
        owner.selected_identity(),
        false,
        &adapter_contract::origin_digest(origin).map_err(|_| Error::Unsupported)?,
    )
}
pub(crate) async fn status(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    line: Uuid,
    origin: &str,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let row = records::by_opening(tx, owner.selected_identity().account, opening)
        .await?
        .ok_or(Error::NotFound)?;
    exact_actor(&row, owner, origin)?;
    if row.core.ids[2] != line {
        return Err(Error::Conflict);
    }
    let value = row.projection(tx).await?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(value)
}
pub(crate) async fn reserve<'held, 'db>(
    tx: &'held Transaction<'db>,
    proof: &mut HeldStepUp03<'held, 'db>,
    opening: Uuid,
    line: Uuid,
    origin: &str,
) -> Result<(bool, serde_json::Value)> {
    ready(tx).await?;
    if !proof.uses_transaction(tx) || opening.is_nil() || line.is_nil() {
        return Err(Error::Authentication);
    }
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = proof.selected_identity();
    let origin_digest = adapter_contract::origin_digest(origin).map_err(|_| Error::Unsupported)?;
    if let Some(row) = records::by_opening(tx, who.account, opening).await? {
        row.actor(who, false, &origin_digest)?;
        if row.core.ids[2] != line {
            return Err(Error::Conflict);
        }
        return Ok((false, row.projection(tx).await?));
    }
    manifest_history::exclusive(tx, proof).await?;
    let mut scope = Scope::lock(tx, who.account, line, origin).await?;
    let h = scope.selected.history();
    if h.epoch != proof.selection_epoch()
        || &h.accepted.root_fingerprint != proof.root_fingerprint()
        || h.activation.identity().user != who.user
    {
        return Err(Error::Authentication);
    }
    let issued = scope.checked.max(proof.checked_primary_ms());
    let expires = issued
        .checked_add(300_000)
        .ok_or(Error::Unsupported)?
        .min(scope.deadline)
        .min(proof.expires_at_ms());
    if issued >= expires {
        return Err(Error::Expired);
    }
    let refresh = Uuid::new_v4();
    let nonce: [u8; 32] = rand::random();
    if refresh == opening || refresh == h.binding || nonce == [0; 32] {
        return Err(Error::Unavailable);
    }
    let owner_digest = OwnerSessionIdentity03 {
        account_id: *who.account.as_bytes(),
        user_id: *who.user.as_bytes(),
        session_id: *who.session.as_bytes(),
    }
    .digest()
    .map_err(|_| Error::Unsupported)?;
    let mut core = b"ZTSR\x01\x03\x03\0".to_vec();
    for id in [h.account, h.device, h.line, refresh, h.binding] {
        core.extend(id.as_bytes());
    }
    for number in [h.generation, 1, h.tip_version, h.epoch] {
        core.extend(number.to_be_bytes());
    }
    for digest in [
        h.accepted.election_commitment,
        h.accepted.election_bundle_sha256,
        h.accepted.selected_reader_key_id,
        crate::sealed_manifest::key_id(4, &h.device_point),
        crate::sealed_manifest::key_id(4, &h.approval_point),
        h.accepted.root_fingerprint,
        h.tip_digest,
        *scope.context.identity_digest(),
        owner_digest,
        origin_digest,
        nonce,
    ] {
        core.extend(digest);
    }
    core.extend(issued.to_be_bytes());
    core.extend(expires.to_be_bytes());
    core.extend([0; 8]);
    Core03::decode(&core).map_err(|_| Error::Unsupported)?;
    scope.revalidate().await?;
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let rows = tx
        .query(
            "SELECT * FROM public.payload_profile_selection_reserve($1,$2,$3,$4,$5,$6)",
            &[
                &who.account,
                &opening,
                &who.user,
                &who.session,
                &core,
                &dbtime(proof.expires_at_ms())?,
            ],
        )
        .await?;
    let row = only_challenge(rows)?;
    if row.core.bytes.as_slice() != core || row.opening != opening {
        return Err(Error::Conflict);
    }
    row.core
        .matches(&scope.expected(&row).await?)
        .map_err(|_| Error::Conflict)?;
    let value = row.projection(tx).await?;
    scope.revalidate().await?;
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    row.core
        .fresh(scope.checked.max(proof.checked_primary_ms()))
        .map_err(|_| Error::Expired)?;
    Ok((true, value))
}
fn only_challenge(rows: Vec<Row>) -> Result<records::Challenge> {
    if rows.len() != 1 {
        return Err(Error::Unavailable);
    }
    records::Challenge::read(&rows[0])
}
pub(crate) async fn proof(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    refresh: Uuid,
    origin: &str,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let row = records::by_id(tx, owner.selected_identity().account, refresh).await?;
    exact_actor(&row, owner, origin)?;
    if row.opening != opening {
        return Err(Error::Conflict);
    }
    if row.closed.is_some() || clock(tx, owner.checked_at_ms()).await? >= row.core.expires {
        return Err(Error::Expired);
    }
    let observation = row.observation.ok_or(Error::NotFound)?;
    let signature = row.device_signature.ok_or(Error::NotFound)?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(
        serde_json::json!({"v":1,"opening_id":opening,"refresh_id":refresh,"observation":B.encode(observation),"device_signature":B.encode(signature)}),
    )
}
pub(crate) async fn historical_approval(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    refresh: Uuid,
    bundle: &[u8],
    origin: &str,
) -> Result<Option<serde_json::Value>> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let row = records::by_id(tx, owner.selected_identity().account, refresh).await?;
    exact_actor(&row, owner, origin)?;
    if row.opening != opening {
        return Err(Error::Conflict);
    }
    let Some(receipt) = records::Receipt::lookup(tx, row.core.ids[0], refresh).await? else {
        return Ok(None);
    };
    if receipt.bundle.as_slice() != bundle {
        return Err(Error::Conflict);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(Some(receipt.projection(&row)))
}
pub(crate) async fn approve<'held, 'db>(
    tx: &'held Transaction<'db>,
    proof: &mut HeldStepUp03<'held, 'db>,
    opening: Uuid,
    refresh: Uuid,
    bundle: &[u8],
    origin: &str,
) -> Result<(bool, serde_json::Value)> {
    ready(tx).await?;
    if !proof.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = proof.selected_identity();
    manifest_history::exclusive(tx, proof).await?;
    let row = records::by_id(tx, who.account, refresh).await?;
    row.actor(
        who,
        true,
        &adapter_contract::origin_digest(origin).map_err(|_| Error::Unsupported)?,
    )?;
    if row.opening != opening
        || row.closed.is_some()
        || bundle.len() != 745
        || bundle[..496] != row.core.bytes
    {
        return Err(Error::Conflict);
    }
    if let Some(receipt) = records::Receipt::lookup(tx, who.account, refresh).await? {
        if receipt.bundle.as_slice() != bundle {
            return Err(Error::Conflict);
        }
        return Ok((false, receipt.projection(&row)));
    }
    let mut scope = Scope::lock(tx, who.account, row.core.ids[2], origin).await?;
    let expected = scope.expected(&row).await?;
    if row.proof_ms.is_none_or(|at| at > scope.checked) {
        return Err(Error::Unavailable);
    }
    if row.observation.as_ref().map(|v| v.as_slice()) != Some(&bundle[496..617])
        || row.device_signature.as_ref().map(|v| v.as_slice()) != Some(&bundle[617..681])
    {
        return Err(Error::Conflict);
    }
    super::super::core::approved(bundle, scope.checked, &expected)
        .map_err(|_| Error::Unsupported)?;
    scope.revalidate().await?;
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    tx.query(
        "SELECT * FROM public.payload_profile_selection_approve($1,$2,$3,$4,$5)",
        &[
            &who.account,
            &opening,
            &refresh,
            &bundle,
            &dbtime(proof.expires_at_ms())?,
        ],
    )
    .await?;
    let receipt = records::Receipt::lookup(tx, who.account, refresh)
        .await?
        .ok_or(Error::Unavailable)?;
    if receipt.bundle.as_slice() != bundle {
        return Err(Error::Conflict);
    }
    super::super::core::approved(
        &receipt.bundle,
        receipt.accepted,
        &scope.expected(&row).await?,
    )
    .map_err(|_| Error::Unsupported)?;
    scope.revalidate().await?;
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    row.core
        .fresh(scope.checked.max(proof.checked_primary_ms()))
        .map_err(|_| Error::Expired)?;
    Ok((true, receipt.projection(&row)))
}
pub(crate) async fn installed(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    refresh: Uuid,
    origin: &str,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let row = records::by_id(tx, owner.selected_identity().account, refresh).await?;
    exact_actor(&row, owner, origin)?;
    if row.opening != opening {
        return Err(Error::Conflict);
    }
    let receipt = records::Receipt::lookup(tx, row.core.ids[0], refresh)
        .await?
        .ok_or(Error::NotFound)?;
    let (installed, _) = receipt.installed.ok_or(Error::NotFound)?;
    let mut value = receipt.projection(&row);
    value.as_object_mut().ok_or(Error::Unavailable)?.insert(
        "installed_ms".into(),
        serde_json::json!(installed.to_string()),
    );
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(value)
}

pub(crate) async fn device_proof(
    tx: &Transaction<'_>,
    socket: &SocketSelection03<'_>,
    refresh: Uuid,
    observation: &[u8],
    signature: &[u8],
) -> Result<()> {
    device_mutation_mode(tx, socket.session.account_id).await?;
    let row = records::by_id(tx, socket.session.account_id, refresh).await?;
    let mut scope = Scope::lock(
        tx,
        socket.session.account_id,
        row.core.ids[2],
        socket.origin,
    )
    .await?;
    scope.socket(socket)?;
    if row.closed.is_some() {
        return Err(Error::Expired);
    }
    row.core
        .verify_device(observation, signature, &scope.expected(&row).await?)
        .map_err(|_| Error::Unsupported)?;
    if row.observation.as_ref().map(|v| v.as_slice()) == Some(observation)
        && row.device_signature.as_ref().map(|v| v.as_slice()) == Some(signature)
    {
        scope.revalidate().await?;
        return Ok(());
    }
    row.core.fresh(scope.checked).map_err(|_| Error::Expired)?;
    let updated = only_challenge(
        tx.query(
            "SELECT * FROM public.payload_profile_selection_device_proof($1,$2,$3,$4)",
            &[
                &socket.session.account_id,
                &refresh,
                &observation,
                &signature,
            ],
        )
        .await?,
    )?;
    if updated.core.bytes != row.core.bytes
        || updated.observation.as_ref().map(|v| v.as_slice()) != Some(observation)
        || updated.device_signature.as_ref().map(|v| v.as_slice()) != Some(signature)
    {
        return Err(Error::Conflict);
    }
    scope.revalidate().await?;
    scope.socket(socket)?;
    row.core.fresh(scope.checked).map_err(|_| Error::Expired)?;
    Ok(())
}
pub(crate) async fn device_installed(
    tx: &Transaction<'_>,
    socket: &SocketSelection03<'_>,
    refresh: Uuid,
    bundle_sha: &[u8; 32],
    signature: &[u8],
) -> Result<serde_json::Value> {
    device_mutation_mode(tx, socket.session.account_id).await?;
    let row = records::by_id(tx, socket.session.account_id, refresh).await?;
    let receipt = records::Receipt::lookup(tx, socket.session.account_id, refresh)
        .await?
        .ok_or(Error::NotFound)?;
    if crypto::sha(&receipt.bundle) != *bundle_sha || receipt.bundle[..496] != row.core.bytes {
        return Err(Error::Conflict);
    }
    let mut scope = Scope::lock(
        tx,
        socket.session.account_id,
        row.core.ids[2],
        socket.origin,
    )
    .await?;
    scope.socket(socket)?;
    let installed = if let Some((time, original)) = receipt.installed {
        if original.as_slice() != signature {
            return Err(Error::Conflict);
        }
        scope.original_manifest(&row, &receipt)?;
        super::super::verify_installed(
            &receipt.bundle,
            receipt.accepted,
            time,
            signature,
            &scope.historical_expected(&row).await?,
        )
        .map_err(|_| Error::Unsupported)?;
        time
    } else {
        row.core.fresh(scope.checked).map_err(|_| Error::Expired)?;
        super::super::verify_installed(
            &receipt.bundle,
            receipt.accepted,
            scope.checked,
            signature,
            &scope.expected(&row).await?,
        )
        .map_err(|_| Error::Unsupported)?;
        tx.query(
            "SELECT * FROM public.payload_profile_selection_install($1,$2,$3,$4)",
            &[
                &socket.session.account_id,
                &refresh,
                &bundle_sha.as_slice(),
                &signature,
            ],
        )
        .await?;
        let actual = records::Receipt::lookup(tx, socket.session.account_id, refresh)
            .await?
            .ok_or(Error::Unavailable)?;
        if actual.bundle != receipt.bundle || actual.accepted != receipt.accepted {
            return Err(Error::Conflict);
        }
        scope.original_manifest(&row, &actual)?;
        let (time, original) = actual.installed.ok_or(Error::Unavailable)?;
        if original.as_slice() != signature {
            return Err(Error::Conflict);
        }
        super::super::verify_installed(
            &actual.bundle,
            actual.accepted,
            time,
            signature,
            &scope.expected(&row).await?,
        )
        .map_err(|_| Error::Unsupported)?;
        time
    };
    scope.revalidate().await?;
    scope.socket(socket)?;
    if receipt.installed.is_none() {
        row.core.fresh(scope.checked).map_err(|_| Error::Expired)?;
    }
    Ok(
        serde_json::json!({"v":1,"type":"payload_profile_selection_install_ack03","connection_epoch":socket.session.connection_epoch,"refresh_id":refresh,"bundle_sha256":B.encode(bundle_sha),"installed_ms":installed.to_string()}),
    )
}
pub(crate) async fn device_challenge(
    tx: &Transaction<'_>,
    socket: &SocketSelection03<'_>,
) -> Result<Option<serde_json::Value>> {
    ready(tx).await?;
    let row=tx.query_opt("SELECT * FROM public.payload_profile_selection_challenges c WHERE account_id=$1 AND device_id=$2 AND proof_site_id=$3 AND proof_instance_id=$4 AND proof_connection_epoch=$5 AND proof_deployment_epoch=$6 AND closed_unaccepted_ms IS NULL AND expires_ms>pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint AND NOT EXISTS(SELECT 1 FROM public.payload_profile_selection_receipts r WHERE(r.account_id,r.refresh_id)=(c.account_id,c.refresh_id) AND r.installed_ms IS NOT NULL) ORDER BY issued_ms,refresh_id LIMIT 1", &[&socket.session.account_id,&socket.session.device_id,&socket.site,&socket.instance,&socket.session.connection_epoch,&dbtime(socket.deployment)?]).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let row = records::Challenge::read(&row)?;
    let mut scope = Scope::lock(
        tx,
        socket.session.account_id,
        row.core.ids[2],
        socket.origin,
    )
    .await?;
    scope.socket(socket)?;
    row.core.fresh(scope.checked).map_err(|_| Error::Expired)?;
    row.core
        .matches(&scope.expected(&row).await?)
        .map_err(|_| Error::Conflict)?;
    let value = if let Some(receipt) =
        records::Receipt::lookup(tx, socket.session.account_id, row.core.ids[3]).await?
    {
        super::super::core::approved(
            &receipt.bundle,
            receipt.accepted,
            &scope.expected(&row).await?,
        )
        .map_err(|_| Error::Unsupported)?;
        serde_json::json!({"v":1,"type":"payload_profile_selection_approved03","refresh_id":row.core.ids[3],"bundle":B.encode(receipt.bundle),"accepted_ms":receipt.accepted.to_string()})
    } else {
        let public = row.projection(tx).await?;
        serde_json::json!({"v":1,"type":"payload_profile_selection_challenge03","refresh_id":row.core.ids[3],"core":B.encode(row.core.bytes),"evidence":scope.selected.history().evidence,"closed_unaccepted":public["closed_unaccepted"]})
    };
    scope.revalidate().await?;
    scope.socket(socket)?;
    Ok(Some(value))
}
