// SPDX-License-Identifier: AGPL-3.0-only
//! Actual transaction-bound manifest installation and historical observation.
//! No function commits, authenticates a fabricated selector or caches newly
//! inserted/uncommitted ancestry. Every refusal requires caller rollback.
use super::*;
use crate::{
    auth::ordinary_owner03::{HeldOrdinaryOwner03, step_up::HeldStepUp03},
    sealed_payload_election03::live::{
        Error,
        manifest_history::{self, History03},
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use tokio_postgres::Transaction;
type Result<T> = std::result::Result<T, Error>;
async fn ready(tx: &Transaction<'_>) -> Result<()> {
    crate::payload_profile_manifests::require(tx)
        .await
        .map_err(|_| Error::Unavailable)
}
async fn clock(tx: &Transaction<'_>, floor: u64) -> Result<u64> {
    let row=tx.query_one("SELECT pg_catalog.pg_is_in_recovery(),pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",&[]).await?;
    let now = u64::try_from(row.try_get::<_, i64>(1)?).map_err(|_| Error::Unavailable)?;
    if row.try_get::<_, bool>(0)? || now == 0 || now < floor {
        return Err(Error::Unavailable);
    }
    Ok(now)
}
fn expected<'a>(
    h: &History03,
    user: Uuid,
    session: Uuid,
    origin: &'a str,
) -> ExpectedInstall03<'a> {
    ExpectedInstall03 {
        account: h.account,
        user,
        owner_session: session,
        device: h.device,
        line: h.line,
        binding: h.binding,
        election_challenge: h.challenge,
        binding_generation: h.generation,
        vault_generation: 1,
        selection_epoch: h.epoch,
        root_fingerprint: h.accepted.root_fingerprint,
        election_commitment: h.accepted.election_commitment,
        election_bundle_sha256: h.accepted.election_bundle_sha256,
        canonical_origin: origin,
    }
}
fn exact(
    row: &records::Receipt,
    opening: Uuid,
    statement: &[u8],
    successor: &[u8],
    signature: &[u8],
) -> Result<()> {
    if row.statement.opening() != opening
        || row.statement.bytes().as_slice() != statement
        || row.signed != successor
        || row.signature.as_slice() != signature
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn historical_crypto(row: &records::Receipt, h: &History03, origin: &str) -> Result<()> {
    row.scope(h, origin)?;
    let prior = shared::verify_checkpoint(
        &h.pin,
        &row.prior_signed,
        &shared::Checkpoint03 {
            account_id: *h.account.as_bytes(),
            root_fingerprint: h.accepted.root_fingerprint,
            version: row.statement.numbers[3],
            digest: row.statement.digests[5],
            accepted_ms: row.prior_accepted,
        },
        row.accepted,
    )
    .map_err(|_| Error::Unsupported)?;
    let successor = shared::verify_successor(
        &prior,
        &row.signed,
        h.line.as_bytes(),
        &row.statement.point,
        row.accepted,
    )
    .map_err(|_| Error::Unsupported)?;
    if successor.operation() != row.operation {
        return Err(Error::Unsupported);
    }
    shared::PossessionStatement03::decode(row.statement.bytes())
        .and_then(|s| s.verify_signature(&row.signature))
        .map_err(|_| Error::Unsupported)
}
/// Same original user may observe exact retained public originals after a new
/// sign-in. This is not permission to sign/install with the historical session.
pub(crate) async fn historical(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    origin: &str,
) -> Result<Option<serde_json::Value>> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) || opening.is_nil() {
        return Err(Error::Authentication);
    }
    let who = owner.selected_identity();
    let Some(row) = records::by_opening(tx, who.account, opening).await? else {
        return Ok(None);
    };
    if row.statement.ids[1] != *who.user.as_bytes()
        || row.statement.digests[3] != *owner.origin_digest()
    {
        return Err(Error::NotFound);
    }
    let h = manifest_history::lock(tx, who.account, row.statement.line(), origin).await?;
    let _verified = verified_history::warm(tx, &h, origin).await?;
    historical_crypto(&row, &h, origin)?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(Some(row.projection()))
}
pub(crate) struct InstallCommand03<'a> {
    pub opening: Uuid,
    pub statement: &'a [u8],
    pub successor: &'a [u8],
    pub signature: &'a [u8],
}
pub(crate) async fn install(
    tx: &Transaction<'_>,
    proof: &mut HeldStepUp03<'_, '_>,
    command: InstallCommand03<'_>,
    origin: &str,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    if !proof.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    let candidate = Statement03::decode(command.statement).map_err(|_| Error::Unsupported)?;
    let who = proof.selected_identity();
    if candidate.account() != who.account || candidate.opening() != command.opening {
        return Err(Error::Conflict);
    }
    // HTTP detects exact history before consuming another factor. A lower
    // caller cannot turn this branch into new authority or a renewed receipt.
    if let Some(row) = records::by_opening(tx, who.account, command.opening).await? {
        exact(
            &row,
            command.opening,
            command.statement,
            command.successor,
            command.signature,
        )?;
        if row.statement.ids[1] != *who.user.as_bytes() {
            return Err(Error::NotFound);
        }
        proof
            .revalidate()
            .await
            .map_err(|_| Error::Authentication)?;
        let h = manifest_history::lock(tx, who.account, candidate.line(), origin).await?;
        let _verified = verified_history::warm(tx, &h, origin).await?;
        historical_crypto(&row, &h, origin)?;
        return Ok(row.projection());
    }
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    manifest_history::exclusive(tx, proof).await?;
    let h = manifest_history::lock(tx, who.account, candidate.line(), origin).await?;
    if h.epoch != proof.selection_epoch()
        || &h.accepted.root_fingerprint != proof.root_fingerprint()
    {
        return Err(Error::Conflict);
    }
    // All source-owned calls warm the COMMITTED predecessor before this
    // operation's first manifest write. Newly inserted progress stays local.
    let prior = verified_history::warm(tx, &h, origin).await?;
    let now = clock(tx, h.checked_ms.max(proof.checked_primary_ms())).await?;
    let checked = verify(
        candidate,
        command.signature,
        command.successor,
        Predecessor03 {
            signed: &prior.signed,
            verified: &prior.verified,
            accepted_ms: prior.accepted,
        },
        &expected(&h, who.user, who.session, origin),
        now,
    )
    .map_err(|_| Error::Unsupported)?;
    if checked.statement.point == h.device_point
        || checked.statement.point == h.approval_point
        || checked.statement.point.as_slice() == &h.pin[29..]
    {
        return Err(Error::Unsupported);
    }
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let deadline = i64::try_from(proof.expires_at_ms()).map_err(|_| Error::Expired)?;
    let row = tx
        .query_opt(
            "SELECT * FROM public.payload_profile_manifest_install($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &who.account,
                &command.opening,
                &who.user,
                &who.session,
                &command.statement,
                &command.successor,
                &command.signature,
                &deadline,
            ],
        )
        .await?
        .ok_or(Error::Unavailable)?;
    let receipt = records::Receipt::decode(&row)?;
    exact(
        &receipt,
        command.opening,
        command.statement,
        command.successor,
        command.signature,
    )?;
    proof
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    let after = manifest_history::lock(tx, who.account, h.line, origin).await?;
    let local = verified_history::advance(&prior, &receipt, &after, origin)?;
    if local.signed != after.tip_signed
        || local.version != after.tip_version
        || local.digest != after.tip_digest
        || local.accepted != after.tip_accepted_ms
    {
        return Err(Error::Conflict);
    }
    let now = clock(tx, after.checked_ms.max(proof.checked_primary_ms())).await?;
    if now >= proof.expires_at_ms().min(checked.statement.expires()) {
        return Err(Error::Expired);
    }
    // Do not publish `local` to the process cache before the caller commits.
    // Deferred SQL guards repeat current owner/root and primary deadlines.
    Ok(receipt.projection())
}

#[derive(Clone, Copy)]
pub(crate) struct Position03 {
    pub version: u64,
    pub digest: [u8; 32],
    pub prefix: [u8; 32],
}
pub(crate) struct HistoryCursor03 {
    pub line: Uuid,
    pub after: Position03,
    pub tip: Option<Position03>,
}
fn position(row: &records::Receipt) -> Position03 {
    Position03 {
        version: row.statement.numbers[4],
        digest: crypto::sha(&row.signed[..row.signed.len() - 64]),
        prefix: row.prefix,
    }
}
fn same(a: Position03, b: Position03) -> bool {
    a.version == b.version && a.digest == b.digest && a.prefix == b.prefix
}
async fn retained_position(
    tx: &Transaction<'_>,
    h: &History03,
    version: u64,
    origin: &str,
) -> Result<Position03> {
    let base = verified_history::base(h)?;
    if version == base.version {
        return Ok(Position03 {
            version,
            digest: base.digest,
            prefix: base.prefix,
        });
    }
    let row = records::by_version(tx, h.account, version)
        .await?
        .ok_or(Error::Conflict)?;
    row.scope(h, origin)?;
    historical_crypto(&row, h, origin)?;
    Ok(position(&row))
}
/// Historical candidates from actual immutable rows, never current effect or
/// physical permission. Receivers still verify their independently selected
/// original root and every complete prefix before publishing a highwater.
pub(crate) async fn history_snapshot(
    tx: &Transaction<'_>,
    h: &History03,
    cursor: &HistoryCursor03,
    origin: &str,
) -> Result<serde_json::Value> {
    if cursor.line != h.line || cursor.after.version > h.tip_version {
        return Err(Error::Conflict);
    }
    let tip = retained_position(tx, h, h.tip_version, origin).await?;
    if tip.digest != h.tip_digest || cursor.tip.is_some_and(|selected| !same(selected, tip)) {
        return Err(Error::Conflict);
    }
    let after = retained_position(tx, h, cursor.after.version, origin).await?;
    if !same(after, cursor.after) {
        return Err(Error::Conflict);
    }
    let rows = records::page(tx, h.account, after.version, tip.version).await?;
    let mut next = after;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        row.scope(h, origin)?;
        historical_crypto(&row, h, origin)?;
        if row.statement.numbers[3] != next.version
            || row.statement.digests[5] != next.digest
            || row.prior_prefix != next.prefix
            || row.accepted > h.checked_ms
        {
            return Err(Error::Conflict);
        }
        next = position(&row);
        entries.push(row.entry());
    }
    if !same(next, tip) && entries.is_empty() {
        return Err(Error::Conflict);
    }
    let now = clock(tx, h.checked_ms).await?;
    let value = serde_json::json!({"v":1,"kind":"manifest_ancestry03","account_id":h.account,"device_id":h.device,"line_id":h.line,"binding_id":h.binding,"binding_generation":h.generation.to_string(),"selection_epoch":h.epoch.to_string(),"election_digest":B.encode(h.accepted.election_commitment),"election_bundle_sha256":B.encode(h.accepted.election_bundle_sha256),"root_fingerprint":B.encode(h.accepted.root_fingerprint),"after_version":after.version.to_string(),"after_digest":B.encode(after.digest),"after_ancestry_sha256":B.encode(after.prefix),"tip_version":tip.version.to_string(),"tip_digest":B.encode(tip.digest),"tip_ancestry_sha256":B.encode(tip.prefix),"tip_accepted_ms":h.tip_accepted_ms.to_string(),"compared_ms":now.to_string(),"entries":entries,"next_version":next.version.to_string(),"next_digest":B.encode(next.digest),"next_ancestry_sha256":B.encode(next.prefix),"complete":same(next,tip),"evidence":h.evidence});
    if serde_json::to_vec(&value)
        .map_err(|_| Error::Unavailable)?
        .len()
        > 192 * 1024
    {
        return Err(Error::Unavailable);
    }
    Ok(value)
}
pub(crate) async fn history(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    cursor: &HistoryCursor03,
    origin: &str,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    let h =
        manifest_history::lock(tx, owner.selected_identity().account, cursor.line, origin).await?;
    let value = history_snapshot(tx, &h, cursor, origin).await?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    Ok(value)
}
pub(crate) async fn observed_status(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    opening: Uuid,
    hashes: [[u8; 32]; 3],
    origin: &str,
) -> Result<serde_json::Value> {
    let value = historical(tx, owner, opening, origin)
        .await?
        .ok_or(Error::NotFound)?;
    let row = records::by_opening(tx, owner.selected_identity().account, opening)
        .await?
        .ok_or(Error::NotFound)?;
    if hashes
        != [
            crypto::sha(row.statement.bytes()),
            crypto::sha(&row.signed),
            crypto::sha(&row.signature),
        ]
    {
        return Err(Error::Conflict);
    }
    Ok(value)
}
pub(crate) async fn exact_historical(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    command: &InstallCommand03<'_>,
    origin: &str,
) -> Result<Option<serde_json::Value>> {
    let value = historical(tx, owner, command.opening, origin).await?;
    if value.is_some() {
        let row = records::by_opening(tx, owner.selected_identity().account, command.opening)
            .await?
            .ok_or(Error::NotFound)?;
        exact(
            &row,
            command.opening,
            command.statement,
            command.successor,
            command.signature,
        )?;
    }
    Ok(value)
}

pub(crate) async fn current_owner(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    line: Uuid,
    origin: &str,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    let who = owner.selected_identity();
    let h = manifest_history::lock(tx, who.account, line, origin).await?;
    let mut context = super::current::context(tx, &h).await?;
    let (mut value, deadline) = super::current::projection(tx, &h, &mut context, origin).await?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    context.revalidate().await.map_err(|_| Error::Unavailable)?;
    let now = clock(
        tx,
        h.checked_ms
            .max(context.checked_primary_ms())
            .max(owner.checked_at_ms()),
    )
    .await?;
    let deadline = deadline.min(owner.session_deadline_ms());
    if now >= deadline
        || h.epoch != owner.selection_epoch()
        || &h.accepted.root_fingerprint != owner.root_fingerprint()
    {
        return Err(Error::Expired);
    }
    let object = value.as_object_mut().ok_or(Error::Unavailable)?;
    object.insert(
        "kind".into(),
        serde_json::json!("owner_manifest_selection03"),
    );
    object.insert("user_id".into(), serde_json::json!(who.user));
    object.insert("owner_session_id".into(), serde_json::json!(who.session));
    object.insert(
        "owner_session_digest".into(),
        serde_json::json!(B.encode(owner.identity_digest())),
    );
    object.insert("compared_ms".into(), serde_json::json!(now.to_string()));
    object.insert(
        "permission_expires_ms".into(),
        serde_json::json!(deadline.to_string()),
    );
    Ok(value)
}
async fn device_scope<'held, 'db>(
    tx: &'held Transaction<'db>,
    h: &History03,
    scope: &crate::sealed_payload_election03::live::SocketSelection03<'_>,
) -> Result<crate::sealed_payload_election03::device_context::HeldDeviceContext03<'held, 'db>> {
    let context = super::current::context(tx, h).await?;
    let selected = context.selected_identity();
    if h.device != scope.session.device_id
        || selected.site != scope.site
        || selected.instance != scope.instance
        || selected.connection_epoch != super::current::positive(scope.session.connection_epoch)?
        || selected.deployment_epoch != scope.deployment
    {
        return Err(Error::Authentication);
    }
    Ok(context)
}
pub(crate) async fn current_device(
    tx: &Transaction<'_>,
    scope: &crate::sealed_payload_election03::live::SocketSelection03<'_>,
    line: Uuid,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    let h = manifest_history::lock(tx, scope.session.account_id, line, scope.origin).await?;
    let mut context = device_scope(tx, &h, scope).await?;
    let (mut value, deadline) =
        super::current::projection(tx, &h, &mut context, scope.origin).await?;
    let object = value.as_object_mut().ok_or(Error::Unavailable)?;
    object.insert(
        "kind".into(),
        serde_json::json!("device_manifest_selection03"),
    );
    object.insert(
        "selection_expires_ms".into(),
        serde_json::json!(deadline.to_string()),
    );
    Ok(value)
}
pub(crate) async fn device_history(
    tx: &Transaction<'_>,
    scope: &crate::sealed_payload_election03::live::SocketSelection03<'_>,
    cursor: &HistoryCursor03,
) -> Result<serde_json::Value> {
    ready(tx).await?;
    let h = manifest_history::lock(tx, scope.session.account_id, cursor.line, scope.origin).await?;
    let mut context = device_scope(tx, &h, scope).await?;
    let value = history_snapshot(tx, &h, cursor, scope.origin).await?;
    context.revalidate().await.map_err(|_| Error::Unavailable)?;
    Ok(value)
}
pub(crate) async fn device_readback(
    tx: &Transaction<'_>,
    scope: &crate::sealed_payload_election03::live::SocketSelection03<'_>,
    line: Uuid,
    tip: Position03,
    election: [u8; 32],
) -> Result<u64> {
    ready(tx).await?;
    let h = manifest_history::lock(tx, scope.session.account_id, line, scope.origin).await?;
    let mut context = device_scope(tx, &h, scope).await?;
    let verified = verified_history::warm(tx, &h, scope.origin).await?;
    if !same(
        tip,
        Position03 {
            version: verified.version,
            digest: verified.digest,
            prefix: verified.prefix,
        },
    ) || election != h.accepted.election_commitment
    {
        return Err(Error::Conflict);
    }
    context.revalidate().await.map_err(|_| Error::Unavailable)?;
    clock(tx, h.checked_ms.max(context.checked_primary_ms())).await
}
