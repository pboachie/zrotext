// SPDX-License-Identifier: AGPL-3.0-only
//! Locked original election/activation and the selected manifest tip. This
//! historical projection deliberately requires neither a live phone lease nor
//! a current content interval: expired public history may authorize renewal
//! only after independent fresh owner/root/possession verification.
use super::*;
use crate::sealed_manifest03 as crypto;
use crate::sealed_payload_election03::{
    self as election, activation_evidence::ActivationEvidence03, activation_records,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use uuid::Uuid;

pub(crate) struct History03 {
    pub(crate) account: Uuid,
    pub(crate) line: Uuid,
    pub(crate) device: Uuid,
    pub(crate) binding: Uuid,
    pub(crate) challenge: Uuid,
    pub(crate) generation: u64,
    pub(crate) epoch: u64,
    pub(crate) pin: [u8; 94],
    pub(crate) accepted: election::DurableAcceptedElection03,
    pub(crate) first: crypto::VerifiedManifest03,
    pub(crate) first_signed: Vec<u8>,
    pub(crate) tip_signed: Vec<u8>,
    pub(crate) tip_version: u64,
    pub(crate) tip_digest: [u8; 32],
    pub(crate) tip_accepted_ms: u64,
    pub(crate) checked_ms: u64,
    pub(crate) device_point: [u8; 65],
    pub(crate) approval_point: [u8; 65],
    pub(crate) evidence: serde_json::Value,
    pub(crate) original_identity: [u8; 32],
    pub(crate) core: [u8; 500],
    pub(crate) activation: activation_records::HistoricalActivation03,
}

pub(crate) async fn exclusive(tx: &Transaction<'_>, proof: &HeldStepUp03<'_, '_>) -> Result<()> {
    super::transition::exclusive(tx, &Owner::StepUp(proof)).await
}

pub(crate) async fn lock(
    tx: &Transaction<'_>,
    account: Uuid,
    line: Uuid,
    origin: &str,
) -> Result<History03> {
    crate::payload_profile_elections::require(tx)
        .await
        .map_err(|_| Error::Unavailable)?;
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
    if tx
        .query_one("SHOW transaction_isolation", &[])
        .await?
        .try_get::<_, String>(0)?
        != "read committed"
    {
        return Err(Error::Unsupported);
    }
    let root=tx.query_opt("SELECT root_pin,root_fingerprint,generation,version,semantic_digest,anchor_digest,manifest,accepted_at_ms,last_verified_ms FROM public.sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE NOWAIT", &[&account]).await?.ok_or(Error::Unsupported)?;
    let pin: [u8; 94] = fixed(&root, 0)?;
    let fingerprint: [u8; 32] = fixed(&root, 1)?;
    if positive(root.try_get(2)?)? != 1
        || fixed::<32>(&root, 5)? != [0; 32]
        || zrotext_root_material::sealed_root_enrollment::root_fingerprint(&pin, account.as_bytes())
            .map_err(|_| Error::Unsupported)?
            != fingerprint
    {
        return Err(Error::Unsupported);
    }
    let fence = election::adapter_contract::account_fence_key(account.as_bytes())
        .map_err(|_| Error::Unsupported)?;
    if !tx
        .query_one(
            "SELECT pg_catalog.pg_try_advisory_xact_lock_shared($1)",
            &[&fence],
        )
        .await?
        .try_get::<_, bool>(0)?
    {
        return Err(Error::Conflict);
    }
    let anchor=tx.query_opt("SELECT selection_epoch FROM public.payload_profile_account_anchors WHERE account_id=$1 AND state='live' FOR SHARE NOWAIT", &[&account]).await?.ok_or(Error::Unsupported)?;
    let epoch = positive(anchor.try_get(0)?)?;
    tx.query_opt(
        "SELECT id FROM public.accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE NOWAIT",
        &[&account],
    )
    .await?
    .ok_or(Error::Authentication)?;
    let selected=tx.query_opt("SELECT b.device_id,b.generation,b.owner_approval_digest,b.device_confirmation_digest,e.opening_id FROM public.phone_lines l JOIN public.device_line_bindings b ON (b.account_id,b.line_id,b.generation)=(l.account_id,l.id,l.current_binding_generation) JOIN public.payload_profile_elections e ON (e.account_id,e.line_id,e.device_id,e.new_binding_generation)=(b.account_id,b.line_id,b.device_id,b.generation) WHERE l.account_id=$1 AND l.id=$2 AND l.state='active' AND l.approved_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' AND b.activated_at IS NOT NULL FOR SHARE OF l,b NOWAIT", &[&account,&line]).await?.ok_or(Error::Unsupported)?;
    let device: Uuid = selected.try_get(0)?;
    let generation = positive(selected.try_get(1)?)?;
    let opening: Uuid = selected.try_get(4)?;
    let r = Reservation::read(tx, account, opening)
        .await?
        .ok_or(Error::Unsupported)?;
    let row = tx
        .query_opt(
            "SELECT * FROM public.payload_profile_elections WHERE account_id=$1 AND opening_id=$2",
            &[&account, &opening],
        )
        .await?
        .ok_or(Error::Unsupported)?;
    let accepted = transition::accepted_record(&row)?;
    transition::matches_mapping(&r, &accepted)?;
    let bundle: Vec<u8> = row.try_get("bundle")?;
    if !r.accepted
        || r.closed.is_some()
        || r.line != line
        || r.device != device
        || r.new_generation != generation
        || positive(row.try_get("selection_epoch")?)? != epoch
        || r.pin != pin
        || accepted.root_fingerprint != fingerprint
        || fixed::<32>(&selected, 2)?.as_slice()
            != row.try_get::<_, Vec<u8>>("owner_approval_digest")?
        || fixed::<32>(&selected, 3)?.as_slice()
            != row.try_get::<_, Vec<u8>>("device_confirmation_digest")?
    {
        return Err(Error::Conflict);
    }
    let checkpoint = r.checkpoint()?;
    election::verify_accepted(&election::AcceptedProofInput03 {
        bundle: &bundle,
        expected_core: &r.core,
        accepted: &accepted,
        predecessor02: &checkpoint,
        accepted_signed_manifest03: &r.successor,
        device_signing_point_at_acceptance: &r.device_point,
        owner_approval_point_at_acceptance: &r.owner_point,
    })
    .map_err(|_| Error::Unsupported)?;
    let first = crypto::verify_from_02(&r.successor, &checkpoint, accepted.accepted_at_ms)
        .map_err(|_| Error::Unsupported)?;
    let history = activation_records::read_locked(
        tx,
        activation_records::Locator {
            account,
            binding: r.old_binding,
            selected_reader_key_id: accepted.selected_reader_key_id,
        },
        origin,
    )
    .await
    .map_err(|_| Error::Unsupported)?;
    let original = ActivationEvidence03::decode(history.canonical_evidence())
        .map_err(|_| Error::Unsupported)?;
    if history.identity().line != line
        || history.identity().device != device
        || history.identity().generation != r.old_generation
        || history.old_binding_proof_digest() != &accepted.old_binding_proof_digest
        || original.device_point != r.device_point
        || original.owner_point != r.owner_point
    {
        return Err(Error::Conflict);
    }
    // Renewal needs current enrollment/root identities, not a current socket.
    // Historical signatures are retained separately from present revocation.
    let enrolled=tx.query_opt("SELECT k.signing_key_sec1,k.fingerprint FROM public.devices d JOIN public.device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL FOR SHARE OF d,k NOWAIT", &[&account,&device]).await?.ok_or(Error::Unsupported)?;
    let approval=tx.query_opt("SELECT signing_key_sec1,fingerprint FROM public.line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE NOWAIT", &[&account]).await?.ok_or(Error::Unsupported)?;
    if fixed::<65>(&enrolled, 0)? != r.device_point
        || fixed::<32>(&enrolled, 1)? != crypto::sha(&r.device_point)
        || fixed::<65>(&approval, 0)? != r.owner_point
        || fixed::<32>(&approval, 1)? != crypto::sha(&r.owner_point)
    {
        return Err(Error::Conflict);
    }
    let tip_signed: Vec<u8> = root.try_get(6)?;
    let tip_version = positive(root.try_get(3)?)?;
    let tip_digest = fixed(&root, 4)?;
    let tip_accepted_ms = positive(root.try_get(7)?)?;
    let checked_ms = clock(
        tx,
        positive(root.try_get(8)?)?
            .max(history.registration().checked_primary_ms())
            .max(tip_accepted_ms),
    )
    .await?;
    let evidence = serde_json::json!({"root_pin":B.encode(pin),"prior_manifest02":B.encode(&r.prior),"prior_accepted_ms":r.prior_accepted.to_string(),"accepted_manifest03":B.encode(&r.successor),"accepted_ms":accepted.accepted_at_ms.to_string(),"bundle":B.encode(&bundle),"device_signing_point":B.encode(r.device_point),"owner_approval_point":B.encode(r.owner_point),"registration_evidence":B.encode(history.registration().canonical_evidence()),"activation_evidence":B.encode(history.canonical_evidence())});
    // Cache scope commits exact original proofs including received signatures;
    // neither semantic manifest hashes nor a caller-supplied version suffices.
    let original_identity = crypto::sha(
        &crypto::framed(
            b"internal/profile03/manifest-history/v1\0",
            &[
                pin.as_slice(),
                &r.core,
                &bundle,
                &r.prior,
                &r.successor,
                history.registration().canonical_evidence(),
                history.canonical_evidence(),
            ]
            .concat(),
        )
        .map_err(|_| Error::Unsupported)?,
    );
    Ok(History03 {
        account,
        line,
        device,
        binding: r.new_binding,
        challenge: r.challenge,
        generation,
        epoch,
        pin,
        accepted,
        first,
        first_signed: r.successor,
        tip_signed,
        tip_version,
        tip_digest,
        tip_accepted_ms,
        checked_ms,
        device_point: r.device_point,
        approval_point: r.owner_point,
        evidence,
        original_identity,
        core: r.core,
        activation: history,
    })
}
