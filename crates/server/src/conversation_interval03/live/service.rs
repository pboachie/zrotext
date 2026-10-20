// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

pub(crate) struct Reserve03<'a> {
    pub opening: Uuid,
    pub line: Uuid,
    pub peer: &'a [u8],
    pub archive: [u8; 32],
    pub phone: [u8; 32],
    pub browser: [u8; 32],
    pub expires_ms: u64,
    pub integrations: &'a [IntegrationReader03],
}
fn matches_request(value: &StoredInterval03, input: &Reserve03<'_>) -> Result<()> {
    let s = &value.statement;
    if s.opening_id() != input.opening
        || s.line_id() != input.line
        || s.peer() != input.peer
        || s.times().3 != input.expires_ms
        || s.keys() != (&input.archive, &input.phone, &input.browser)
        || s.integrations() != input.integrations
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub(crate) async fn reserve<'held, 'db>(
    tx: &'held Transaction<'db>,
    owner: &mut HeldOrdinaryOwner03<'held, 'db>,
    input: Reserve03<'_>,
    origin: &str,
) -> Result<(bool, serde_json::Value)> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) || input.opening.is_nil() || input.line.is_nil() {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = owner.selected_identity();
    if let Some(row)=tx.query_opt("SELECT * FROM public.conversation_profile03_intervals WHERE account_id=$1 AND opening_id=$2 FOR SHARE NOWAIT",&[&who.account,&input.opening]).await?{
        let prior=StoredInterval03::from_row(&row)?;
        if prior.selected_owner()!=who{return Err(Error::Authentication);}
        matches_request(&prior,&input)?;
        // Passive exact recovery: original public bytes only, no renewal and no
        // current content permission inferred from the retained phase.
        owner.revalidate().await.map_err(|_|Error::Authentication)?;
        return Ok((false,prior.receipt()));
    }
    let mut held = selected::hold_owner_selection(tx, owner, input.line, origin).await?;
    let issued = held.now_ms();
    let setup = issued
        .checked_add(300_000)
        .ok_or(Error::Unsupported)?
        .min(input.expires_ms)
        .min(held.authority().permission_expires_at_ms);
    let nonce: [u8; 32] = rand::random();
    let interval = Uuid::new_v4();
    let receipt = Uuid::new_v4();
    let expected = held.consent_context(
        &input.archive,
        &input.phone,
        &input.browser,
        input.peer,
        input.integrations,
    );
    let statement = compose(
        &expected,
        Reservation03 {
            interval,
            receipt,
            opening: input.opening,
            issued,
            setup,
            expires: input.expires_ms,
            nonce,
        },
    )
    .map_err(|_| Error::Unsupported)?;
    let mapping = mappings::read(&held, &statement).await?;
    if input.expires_ms > mapping.deadline() {
        return Err(Error::Expired);
    }
    held.revalidate().await?;
    mapping.require_current(held.now_ms())?;
    let owner_deadline = dbtime(held.owner_deadline_ms())?;
    let rows = tx
        .query(
            "SELECT * FROM public.conversation_profile03_interval_reserve($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &who.account,
                &input.opening,
                &who.user,
                &who.session,
                &interval,
                &receipt,
                &statement.bytes(),
                &owner_deadline,
            ],
        )
        .await?;
    let stored = only_row(rows)?;
    if stored.statement.bytes() != statement.bytes() {
        return Err(Error::Conflict);
    }
    stored.validate(&mut held, true).await?;
    Ok((true, stored.receipt()))
}

pub(crate) async fn historical_request(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    interval: Uuid,
    statement: &[u8],
    signature: &[u8],
) -> Result<Option<serde_json::Value>> {
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = owner.selected_identity();
    let prior = StoredInterval03::read(tx, who.account, interval).await?;
    if prior.selected_owner().user != who.user
        || prior.statement.opening_id() != opening
        || prior.statement.bytes() != statement
    {
        return Err(Error::Conflict);
    }
    let Some(original) = prior.owner else {
        return Ok(None);
    };
    if original.as_slice() != signature {
        return Err(Error::Conflict);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    // Exact committed evidence only. A fresh cookie may observe it, but no new
    // factor, current permission, timestamp or signature is manufactured.
    Ok(Some(prior.receipt()))
}
pub(crate) async fn request<'held, 'db>(
    tx: &'held Transaction<'db>,
    proof: &mut HeldStepUp03<'held, 'db>,
    opening: Uuid,
    interval: Uuid,
    statement: &[u8],
    signature: &[u8],
    origin: &str,
) -> Result<(bool, serde_json::Value)> {
    let who = proof.selected_identity();
    let prior = StoredInterval03::read(tx, who.account, interval).await?;
    if prior.statement.opening_id() != opening || prior.statement.bytes() != statement {
        return Err(Error::Conflict);
    }
    let signature: [u8; 64] = signature.try_into().map_err(|_| Error::Unsupported)?;
    let mut held =
        selected::hold_step_up_selection(tx, proof, prior.statement.line_id(), origin).await?;
    let current = StoredInterval03::read(tx, who.account, interval).await?;
    if current.statement.bytes() != prior.statement.bytes() {
        return Err(Error::Conflict);
    }
    current.validate(&mut held, true).await?;
    if current.owner.is_some_and(|s| s != signature) {
        return Err(Error::Conflict);
    }
    let new = current.owner.is_none();
    verify_request(
        &current.statement,
        &signature,
        &current.context(&held),
        held.now_ms(),
    )
    .map_err(|_| Error::Unsupported)?;
    let deadline = dbtime(held.factor_deadline_ms().ok_or(Error::Authentication)?)?;
    let rows = tx
        .query(
            "SELECT * FROM public.conversation_profile03_interval_request($1,$2,$3,$4,$5)",
            &[
                &who.account,
                &opening,
                &interval,
                &signature.as_slice(),
                &deadline,
            ],
        )
        .await?;
    let stored = only_row(rows)?;
    if stored.statement.bytes() != current.statement.bytes() || stored.owner != Some(signature) {
        return Err(Error::Conflict);
    }
    stored.validate(&mut held, true).await?;
    Ok((new, stored.receipt()))
}

pub(crate) async fn owner_status(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    interval: Uuid,
) -> Result<serde_json::Value> {
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = owner.selected_identity();
    let prior = StoredInterval03::read(tx, who.account, interval).await?;
    if prior.statement.opening_id() != opening || prior.selected_owner().user != who.user {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(prior.receipt())
}
pub(crate) async fn stop(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    interval: Uuid,
) -> Result<serde_json::Value> {
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let who = owner.selected_identity();
    let prior = StoredInterval03::read(tx, who.account, interval).await?;
    if prior.selected_owner().user != who.user {
        return Err(Error::Authentication);
    }
    let rows = tx
        .query(
            "SELECT * FROM public.conversation_profile03_interval_stop($1,$2,$3,$4)",
            &[&who.account, &interval, &who.user, &who.session],
        )
        .await?;
    let stored = only_row(rows)?;
    if stored.statement.bytes() != prior.statement.bytes()
        || !matches!(stored.phase.as_str(), "stopped" | "expired")
    {
        return Err(Error::Conflict);
    }
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(stored.receipt())
}

#[derive(Clone, Copy)]
pub(crate) struct DeviceInterval03<'a> {
    pub session: crate::device_socket::DeviceSession,
    pub site: &'a str,
    pub instance: &'a str,
    pub deployment: u64,
    pub origin: &'a str,
}
impl DeviceInterval03<'_> {
    async fn hold<'held, 'db>(
        &self,
        tx: &'held Transaction<'db>,
        interval: &StoredInterval03,
    ) -> Result<HeldMessageSelection03<'held, 'held, 'db>> {
        selected::hold_interval_selection(
            tx,
            interval,
            self.session,
            self.site,
            self.instance,
            self.deployment,
            self.origin,
        )
        .await
    }
}
pub(crate) async fn device_challenge(
    tx: &Transaction<'_>,
    device: DeviceInterval03<'_>,
) -> Result<Option<serde_json::Value>> {
    ready(tx).await?;
    // Only a previously owner-signed request on the ACTUAL full connection may
    // reach the phone. A reservation alone is not content disclosure consent.
    // Several peers may have genuine pending requests. Offer the oldest
    // still-actionable one deterministically; an elapsed request for another
    // peer must not monopolize delivery. This read neither expires that row
    // nor renews any consent or acknowledgement.
    let Some(id) = pending::next(tx, device).await? else {
        return Ok(None);
    };
    let prior = StoredInterval03::read(tx, device.session.account_id, id).await?;
    let mut held = device.hold(tx, &prior).await?;
    let current = StoredInterval03::read(tx, device.session.account_id, id).await?;
    if current.statement.bytes() != prior.statement.bytes() {
        return Err(Error::Conflict);
    }
    let permission = current
        .permission(
            &mut held,
            "interval_challenge",
            current.statement.receipt_id(),
        )
        .await?;
    Ok(Some(
        serde_json::json!({"v":1,"type":"conversation_interval_challenge03","interval_id":id,"statement":B.encode(current.statement.bytes()),"owner_signature":current.owner.map(|s|B.encode(s)),"current":held.device_projection()?,"interval_permission":permission}),
    ))
}
pub(crate) async fn device_status(
    tx: &Transaction<'_>,
    device: DeviceInterval03<'_>,
    interval: Uuid,
    challenge: Uuid,
) -> Result<serde_json::Value> {
    if challenge.is_nil() {
        return Err(Error::Unsupported);
    }
    let prior = StoredInterval03::read(tx, device.session.account_id, interval).await?;
    let mut held = device.hold(tx, &prior).await?;
    let current = StoredInterval03::read(tx, device.session.account_id, interval).await?;
    if current.statement.bytes() != prior.statement.bytes() {
        return Err(Error::Conflict);
    }
    let permission = current
        .permission(&mut held, "interval_status", challenge)
        .await?;
    Ok(
        serde_json::json!({"v":1,"type":"conversation_interval_status03","interval_id":interval,"challenge":challenge,"statement_sha256":B.encode(current.statement.digest()),"phase":current.phase,"approved_ms":current.approved_ms.map(|v|v.to_string()),"installed_ms":current.installed_ms.map(|v|v.to_string()),"device_session_digest":B.encode(held.device_session_digest()),"interval_permission":permission}),
    )
}
pub(crate) async fn device_approve(
    tx: &Transaction<'_>,
    device: DeviceInterval03<'_>,
    interval: Uuid,
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<serde_json::Value> {
    device_transition(tx, device, interval, digest, signature, false).await
}
pub(crate) async fn device_install(
    tx: &Transaction<'_>,
    device: DeviceInterval03<'_>,
    interval: Uuid,
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<serde_json::Value> {
    device_transition(tx, device, interval, digest, signature, true).await
}
pub(crate) async fn device_stop(
    tx: &Transaction<'_>,
    device: DeviceInterval03<'_>,
    interval: Uuid,
    digest: &[u8; 32],
) -> Result<serde_json::Value> {
    use crate::sealed_payload_election03::device_context;
    ready(tx).await?;
    let selector = device_context::Selector {
        account: device.session.account_id,
        device: device.session.device_id,
        site: device.site.to_owned(),
        instance: device.instance.to_owned(),
        connection_epoch: scalar(device.session.connection_epoch)?,
        deployment_epoch: device.deployment,
    };
    let mut context = device_context::lock(tx, &selector)
        .await
        .map_err(|_| Error::Authentication)?;
    let prior = StoredInterval03::read(tx, selector.account, interval).await?;
    if prior.statement.device_id() != selector.device || prior.statement.digest() != *digest {
        return Err(Error::Authentication);
    }
    context
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let rows=tx.query("SELECT * FROM public.conversation_profile03_interval_device_stop($1,$2,$3,$4,$5,$6,$7,$8)",&[&selector.account,&interval,&selector.device,&selector.site,&selector.instance,&device.session.connection_epoch,&dbtime(selector.deployment_epoch)?,&digest.as_slice()]).await?;
    let stopped = only_row(rows)?;
    if stopped.statement.bytes() != prior.statement.bytes() || stopped.phase != "stopped" {
        return Err(Error::Conflict);
    }
    context
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(
        serde_json::json!({"v":1,"type":"conversation_interval_stopped03","interval_id":interval,"statement_sha256":B.encode(digest),"stopped_ms":stopped.stopped_ms.ok_or(Error::Conflict)?.to_string(),"device_session_digest":B.encode(context.identity_digest())}),
    )
}
async fn device_transition(
    tx: &Transaction<'_>,
    device: DeviceInterval03<'_>,
    interval: Uuid,
    digest: &[u8; 32],
    signature: &[u8],
    install: bool,
) -> Result<serde_json::Value> {
    let prior = StoredInterval03::read(tx, device.session.account_id, interval).await?;
    let mut held = device.hold(tx, &prior).await?;
    let current = StoredInterval03::read(tx, device.session.account_id, interval).await?;
    if current.statement.bytes() != prior.statement.bytes() || current.statement.digest() != *digest
    {
        return Err(Error::Conflict);
    }
    current.validate(&mut held, true).await?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| Error::Unsupported)?;
    let owner = current.owner.ok_or(Error::Conflict)?;
    if install {
        let phone = current.phone.ok_or(Error::Conflict)?;
        verify_install(
            &current.statement,
            &owner,
            &phone,
            &signature,
            &current.context(&held),
            held.now_ms(),
        )
        .map_err(|_| Error::Unsupported)?;
        if current.installed.is_some_and(|s| s != signature) {
            return Err(Error::Conflict);
        }
    } else {
        verify_approval(
            &current.statement,
            &owner,
            &signature,
            &current.context(&held),
            held.now_ms(),
        )
        .map_err(|_| Error::Unsupported)?;
        if current.phone.is_some_and(|s| s != signature) {
            return Err(Error::Conflict);
        }
    }
    let sql = if install {
        "SELECT * FROM public.conversation_profile03_interval_install($1,$2,$3)"
    } else {
        "SELECT * FROM public.conversation_profile03_interval_approve($1,$2,$3)"
    };
    let stored = only_row(
        tx.query(
            sql,
            &[&device.session.account_id, &interval, &signature.as_slice()],
        )
        .await?,
    )?;
    if stored.statement.bytes() != current.statement.bytes()
        || stored.owner != current.owner
        || if install {
            stored.installed != Some(signature) || stored.phone != current.phone
        } else {
            stored.phone != Some(signature)
        }
    {
        return Err(Error::Conflict);
    }
    stored.validate(&mut held, true).await?;
    if install {
        Ok(
            serde_json::json!({"v":1,"type":"conversation_interval_installed03","interval_id":interval,"statement_sha256":B.encode(digest),"installed_ms":stored.installed_ms.ok_or(Error::Conflict)?.to_string(),"device_session_digest":B.encode(held.device_session_digest())}),
        )
    } else {
        Ok(
            serde_json::json!({"v":1,"type":"conversation_interval_approved03","interval_id":interval,"statement_sha256":B.encode(digest),"approved_ms":stored.approved_ms.ok_or(Error::Conflict)?.to_string()}),
        )
    }
}
