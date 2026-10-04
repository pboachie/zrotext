// SPDX-License-Identifier: AGPL-3.0-only
//! Real owner transactions for the unmounted issuer. No aggregate provisioning.

use super::{
    Error,
    model::*,
    store::{self, Pending, State as IssuerState},
};
use crate::{
    auth::{self, OwnerReductionFence, SessionPrincipal, TokenHasher, abuse_limits, mfa},
    contact_reader_statement::UnsignedStatement,
    sealed_manifest::AccountArchiveStatementRecords,
    sealed_manifest_store::outbound::{CurrentAuthority, PublicCandidate, lock_current},
    sealed_root_ceremony as ceremony,
};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

const PROPOSAL: &str =
    include_str!("../../../../protocol/v1/contact-reader-issuance-storage-proposal.sql");
const SCHEMAS: [(&str, &str); 3] = [
    (
        "contact_reader_state",
        "account_id:uuid root_pin:bytea root_fingerprint:bytea trust_generation:bigint allocation_generation:bigint mutation_revision:bigint last_mutation_ms:bigint receipt_next_slot:smallint phase:text current_authorization:uuid? current_generation:bigint? current_statement_digest:bytea? current_statement:bytea?",
    ),
    (
        "contact_reader_pending",
        "account_id:uuid slot:smallint authorization:uuid generation:bigint create_request:uuid created_by_user:uuid created_session:uuid origin:text create_input_digest:bytea creation_expected_revision:bigint allocated_revision:bigint prior_phase:text prior_authorization:uuid? prior_generation:bigint? prior_digest:bytea? requested_until_ms:bigint unsigned:bytea unsigned_digest:bytea manifest:bytea manifest_version:bigint manifest_digest:bytea reader_id:bytea root_writer_id:bytea reader_point:bytea root_point:bytea reader_from:bigint root_from:bigint reader_until:bigint root_until:bigint manifest_issued:bigint manifest_until:bigint creation_observed_ms:bigint issued:bigint expires:bigint until_ms:bigint",
    ),
    (
        "contact_reader_receipts",
        "account_id:uuid slot:smallint authorization:uuid generation:bigint create_request:uuid create_input_digest:bytea creation_expected_revision:bigint unsigned_digest:bytea terminal_kind:text terminal_ms:bigint signed_statement:bytea? statement_digest:bytea?",
    ),
];

/// Complete named proposal objects are required. Stored values are independently
/// validated on every load; schema presence is never accepted-state admission.
pub(crate) async fn installed(tx: &Transaction<'_>) -> Result<bool, Error> {
    let present=tx.query_one("SELECT to_regclass('contact_reader_state') IS NOT NULL,to_regclass('contact_reader_pending') IS NOT NULL,to_regclass('contact_reader_receipts') IS NOT NULL",&[]).await?;
    let flags = [
        present.try_get::<_, bool>(0)?,
        present.try_get(1)?,
        present.try_get(2)?,
    ];
    if flags == [false; 3] {
        let count:i64=tx.query_one("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema() AND p.proname IN ('contact_reader_state_guard','contact_reader_pending_guard','contact_reader_closure_guard','contact_reader_state_bounds_valid','contact_reader_state_shape_valid','contact_reader_pending_bounds_valid','contact_reader_pending_prior_valid','contact_reader_receipts_bounds_valid','contact_reader_receipts_shape_valid')",&[]).await?.try_get(0)?;
        if count != 0 {
            return Err(Error::Unavailable);
        }
        return Ok(false);
    }
    if flags != [true; 3] {
        return Err(Error::Unavailable);
    }
    for (table, schema) in SCHEMAS {
        let rows=tx.query("SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relname=$1 AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",&[&table]).await?;
        let expected: Vec<_> = schema.split_whitespace().collect();
        if rows.len() != expected.len() {
            return Err(Error::Unavailable);
        }
        for (row, field) in rows.iter().zip(expected) {
            let (name, ty) = field.split_once(':').ok_or(Error::Unavailable)?;
            if row.try_get::<_, String>(0)? != name
                || row.try_get::<_, String>(1)? != ty.trim_end_matches('?')
                || row.try_get::<_, bool>(2)? == ty.ends_with('?')
            {
                return Err(Error::Unavailable);
            }
        }
    }
    // Keys/FKs are compared as complete server-rendered definitions, rather
    // than merely trusting their names. Every CHECK must be validated/present.
    for (table, checks) in [
        (
            "contact_reader_state",
            vec!["contact_reader_state_bounds", "contact_reader_state_shape"],
        ),
        (
            "contact_reader_pending",
            vec![
                "contact_reader_pending_bounds",
                "contact_reader_pending_prior",
            ],
        ),
        (
            "contact_reader_receipts",
            vec![
                "contact_reader_receipts_bounds",
                "contact_reader_receipts_shape",
            ],
        ),
    ] {
        // Deferred constraint triggers have their own pg_constraint entries;
        // their exact trigger metadata is checked separately below.
        let rows=tx.query("SELECT conname,contype::text,convalidated,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=$1::regclass AND contype IN ('c','f','p','u') ORDER BY conname",&[&table]).await?;
        let mut definitions = Vec::new();
        let mut found = Vec::new();
        for row in rows {
            if !row.try_get::<_, bool>(2)? {
                return Err(Error::Unavailable);
            }
            let kind: String = row.try_get(1)?;
            if kind == "c" {
                let name: String = row.try_get(0)?;
                let schema = SCHEMAS
                    .iter()
                    .find(|(name, _)| *name == table)
                    .ok_or(Error::Unavailable)?
                    .1;
                let fields = schema
                    .split_whitespace()
                    .map(|f| f.split_once(':').map(|p| p.0).ok_or(Error::Unavailable))
                    .collect::<Result<Vec<_>, _>>()?;
                if row.try_get::<_, String>(3)?
                    != format!("CHECK ({name}_valid({}))", fields.join(", "))
                {
                    return Err(Error::Unavailable);
                }
                found.push(name);
            } else {
                definitions.push(row.try_get::<_, String>(3)?);
            }
        }
        found.sort();
        let mut expected_checks = checks.into_iter().map(str::to_owned).collect::<Vec<_>>();
        expected_checks.sort();
        let mut expected=if table=="contact_reader_state"{vec!["PRIMARY KEY (account_id)","FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE"]}else{vec!["PRIMARY KEY (account_id, slot)","FOREIGN KEY (account_id) REFERENCES contact_reader_state(account_id) ON DELETE CASCADE","UNIQUE (account_id, authorization)","UNIQUE (account_id, generation)","UNIQUE (account_id, create_request)"]}.into_iter().map(str::to_owned).collect::<Vec<_>>();
        expected.sort();
        definitions.sort();
        if found != expected_checks || definitions != expected {
            return Err(Error::Unavailable);
        }
        for name in found {
            let function = format!("{name}_valid");
            let tag = format!("${name}_body$");
            let body = PROPOSAL.split(&tag).nth(1).ok_or(Error::Unavailable)?;
            let schema = SCHEMAS
                .iter()
                .find(|(name, _)| *name == table)
                .ok_or(Error::Unavailable)?
                .1;
            let argument_types = schema
                .split_whitespace()
                .map(|f| {
                    f.split_once(':')
                        .map(|(_, ty)| ty.trim_end_matches('?'))
                        .ok_or(Error::Unavailable)
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(", ");
            let rows=tx.query("SELECT p.prosrc,p.prorettype='boolean'::regtype,oidvectortypes(p.proargtypes),p.provolatile::text,p.prosecdef,p.proconfig,l.lanname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname=current_schema() AND p.proname=$1",&[&function]).await?;
            let search_path: String = tx
                .query_one("SELECT current_setting('search_path')", &[])
                .await?
                .try_get(0)?;
            if rows.len() != 1 {
                return Err(Error::Unavailable);
            }
            let row = &rows[0];
            if row.try_get::<_, String>(0)? != body
                || !row.try_get::<_, bool>(1)?
                || row.try_get::<_, String>(2)? != argument_types
                || row.try_get::<_, String>(3)? != "i"
                || row.try_get::<_, bool>(4)?
                || row.try_get::<_, Option<Vec<String>>>(5)?
                    != Some(vec![format!("search_path={search_path}")])
                || row.try_get::<_, String>(6)? != "sql"
            {
                return Err(Error::Unavailable);
            }
        }
    }
    for (name, tag) in [
        ("contact_reader_state_guard", "state_guard"),
        ("contact_reader_pending_guard", "pending_guard"),
        ("contact_reader_closure_guard", "closure_guard"),
    ] {
        let delimiter = format!("${tag}$");
        let expected = PROPOSAL
            .split(&delimiter)
            .nth(1)
            .ok_or(Error::Unavailable)?;
        let rows=tx.query("SELECT p.prosrc,p.prorettype='trigger'::regtype,p.pronargs,p.prosecdef,p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema() AND p.proname=$1",&[&name]).await?;
        if rows.len() != 1 {
            return Err(Error::Unavailable);
        }
        let row = &rows[0];
        let config: Option<Vec<String>> = row.try_get(4)?;
        let search_path: String = tx
            .query_one("SELECT current_setting('search_path')", &[])
            .await?
            .try_get(0)?;
        if row.try_get::<_, String>(0)? != expected
            || !row.try_get::<_, bool>(1)?
            || row.try_get::<_, i16>(2)? != 0
            || row.try_get::<_, bool>(3)?
            || config != Some(vec![format!("search_path={search_path}")])
        {
            return Err(Error::Unavailable);
        }
    }
    for (table, name, function, kind, deferred) in [
        (
            "contact_reader_state",
            "contact_reader_state_transition",
            "contact_reader_state_guard",
            19_i16,
            false,
        ),
        (
            "contact_reader_pending",
            "contact_reader_pending_immutable",
            "contact_reader_pending_guard",
            19,
            false,
        ),
        (
            "contact_reader_state",
            "contact_reader_state_closure",
            "contact_reader_closure_guard",
            21,
            true,
        ),
        (
            "contact_reader_pending",
            "contact_reader_pending_closure",
            "contact_reader_closure_guard",
            13,
            true,
        ),
        (
            "contact_reader_receipts",
            "contact_reader_receipts_closure",
            "contact_reader_closure_guard",
            29,
            true,
        ),
    ] {
        let row=tx.query_opt("SELECT p.proname,t.tgtype,t.tgdeferrable,t.tginitdeferred,t.tgenabled::text,t.tgqual IS NULL,t.tgnargs FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid=$1::regclass AND t.tgname=$2 AND NOT t.tgisinternal",&[&table,&name]).await?.ok_or(Error::Unavailable)?;
        if row.try_get::<_, String>(0)? != function
            || row.try_get::<_, i16>(1)? != kind
            || row.try_get::<_, bool>(2)? != deferred
            || row.try_get::<_, bool>(3)? != deferred
            || row.try_get::<_, String>(4)? != "O"
            || !row.try_get::<_, bool>(5)?
            || row.try_get::<_, i16>(6)? != 0
        {
            return Err(Error::Unavailable);
        }
    }
    Ok(true)
}

async fn begin(client: &mut Client) -> Result<Transaction<'_>, Error> {
    Ok(ceremony::begin(client).await?)
}
async fn settle<T>(tx: Transaction<'_>, result: Result<T, Error>) -> Result<T, Error> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}
async fn owner_clock(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    previous: i64,
) -> Result<i64, Error> {
    auth::require_current_owner(tx, owner).await?;
    store::clock(tx, previous).await
}

async fn historical(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Option<(Uuid, [u8; 32])>,
    known: Option<(Uuid, i64)>,
) -> Result<Option<ResultView>, Error> {
    let tx = begin(client).await?;
    let result = async {
        auth::require_current_owner(&tx, owner).await?;
        let aggregate = store::load(&tx, owner.tenant.account_id(), false).await?;
        let mut result = None;
        let mut previous = 0;
        if let Some(a) = aggregate {
            let now = store::clock(&tx, a.state.last_ms).await?;
            previous = now;
            result = if let Some((id, d)) = request {
                a.retained(id, d, now)?
            } else {
                known.map(|(id, g)| a.known(id, g, now))
            };
            if let Some(v) = &result {
                encode(v)?;
            }
        } else if known.is_some() {
            result = Some(ResultView::unavailable());
        }
        owner_clock(&tx, owner, previous).await?;
        Ok(result)
    }
    .await;
    settle(tx, result).await
}
pub(crate) async fn lookup(
    client: &mut Client,
    owner: &SessionPrincipal,
    origin: &str,
    input: Lookup,
) -> Result<ResultView, Error> {
    let digest = input.create.commitment(owner.tenant.account_id(), origin)?;
    if digest != input.expected_input_digest.0 {
        return Err(Error::Conflict);
    }
    Ok(historical(
        client,
        owner,
        Some((input.create.create_request.0, digest)),
        None,
    )
    .await?
    .unwrap_or_else(ResultView::unavailable))
}
pub(crate) async fn status(
    client: &mut Client,
    owner: &SessionPrincipal,
    id: Uuid,
    generation: i64,
) -> Result<ResultView, Error> {
    if id.is_nil() || generation <= 0 {
        return Err(Error::Invalid);
    }
    Ok(historical(client, owner, None, Some((id, generation)))
        .await?
        .unwrap_or_else(ResultView::unavailable))
}

fn source(
    account: Uuid,
    reader: [u8; 32],
    candidate: PublicCandidate,
    r: AccountArchiveStatementRecords,
) -> Result<CreationSource, Error> {
    let s = candidate.snapshot;
    if r.account != *account.as_bytes()
        || r.generation != 1
        || s.generation != 1
        || s.version <= 0
        || s.version as u64 != r.version
        || s.digest != r.digest
        || s.accepted_ms <= 0
        || !(364..=9751).contains(&s.bytes.len())
    {
        return Err(Error::Conflict);
    }
    let until = r.expires.min(r.reader_until).min(r.root_until);
    let now = s.accepted_ms as u64;
    if now >= until || now < r.reader_from || now < r.root_from {
        return Err(Error::Conflict);
    }
    let n = |v: u64| i64::try_from(v).map(Number).map_err(|_| Error::Conflict);
    Ok(CreationSource {
        kind: "historical_creation_source",
        account_id: Id(account),
        root_pin_b64: Fixed(candidate.pin.try_into().map_err(|_| Error::Conflict)?),
        root_fingerprint_b64: Fixed(candidate.fingerprint),
        trust_generation: Number(1),
        manifest_version: Number(s.version),
        manifest_digest_b64: Fixed(s.digest),
        manifest_b64: Packed(s.bytes),
        observed_ms: Number(s.accepted_ms),
        manifest_issued_ms: n(r.issued)?,
        manifest_expires_ms: n(r.expires)?,
        signed_until_ms: n(until)?,
        reader: KeyView {
            key_id_b64: Fixed(reader),
            public_point_b64: Fixed(r.reader_point),
            from_ms: n(r.reader_from)?,
            until_ms: n(r.reader_until)?,
        },
        root_writer: KeyView {
            key_id_b64: Fixed(r.root_id),
            public_point_b64: Fixed(r.root_point),
            from_ms: n(r.root_from)?,
            until_ms: n(r.root_until)?,
        },
    })
}
fn same_source(original: &CreationSource, current: &CreationSource) -> bool {
    let mut c = current.clone();
    c.observed_ms = original.observed_ms;
    c == *original
}
fn bound_source(s: &IssuerState, source: &CreationSource) -> Result<(), Error> {
    if s.pin != source.root_pin_b64.0
        || s.fingerprint != source.root_fingerprint_b64.0
        || source.trust_generation.0 != 1
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
async fn final_source(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    authority: &mut CurrentAuthority<'_, '_>,
    original: &CreationSource,
    previous: i64,
    expires: i64,
) -> Result<i64, Error> {
    ceremony::live(tx, owner).await?;
    let (candidate, records) = authority
        .account_contact_observation(
            &original.reader.key_id_b64.0,
            &original.root_fingerprint_b64.0,
        )
        .await?;
    let current = source(
        owner.tenant.account_id(),
        original.reader.key_id_b64.0,
        candidate,
        records,
    )?;
    if !same_source(original, &current) {
        return Err(Error::Conflict);
    }
    let now = current.observed_ms.0;
    if now < previous || now >= expires || now >= original.signed_until_ms.0 {
        return Err(Error::Conflict);
    }
    Ok(now)
}

pub(crate) async fn create(
    client: &mut Client,
    hasher: &TokenHasher,
    owner: &SessionPrincipal,
    origin: &str,
    input: Create,
) -> Result<ResultView, Error> {
    let account = owner.tenant.account_id();
    let digest = input.commitment(account, origin)?;
    // This probe fully settles before the positive root-first transaction.
    if let Some(value) =
        historical(client, owner, Some((input.create_request.0, digest)), None).await?
    {
        return Ok(value);
    }
    let tx = begin(client).await?;
    let result = async {
        let mut authority = lock_current(&tx, account).await?;
        ceremony::owner_locks(&tx, owner, false).await?;
        let a = store::load(&tx, account, true)
            .await?
            .ok_or(Error::Unavailable)?;
        let (candidate, records) = authority
            .account_contact_observation(
                &input.selected_reader_id.0,
                &input.compared_root_fingerprint.0,
            )
            .await?;
        let observed = source(account, input.selected_reader_id.0, candidate, records)?;
        bound_source(&a.state, &observed)?;
        let now = store::clock(&tx, a.state.last_ms.max(observed.observed_ms.0)).await?;
        if let Some(value) = a.retained(input.create_request.0, digest, now)? {
            encode(&value)?;
            ceremony::live(&tx, owner).await?;
            store::clock(&tx, now).await?;
            return Ok((value, false));
        }
        if input.expected_revision.0 != a.state.revision || input.prior != a.state.prior {
            return Err(Error::Conflict);
        }
        if a.pending.len() >= 4 || a.state.revision > i64::MAX - 2 || a.state.allocator == i64::MAX
        {
            return Err(Error::Unavailable);
        }
        if input.requested_until_ms.0 <= now
            || input.requested_until_ms.0 - now > 86_400_000
            || input.requested_until_ms.0 > observed.signed_until_ms.0
        {
            return Err(Error::Invalid);
        }
        if !abuse_limits::consume_owner_management(&tx, hasher, &owner.user_id.to_string()).await? {
            return Ok((ResultView::unavailable(), true));
        }
        let generation = a.state.allocator + 1;
        let authorization = Uuid::new_v4();
        let allocated_revision = a.state.revision + 1;
        let unsigned = crate::contact_reader_statement::encode_unsigned(&UnsignedStatement {
            authorization_id: *authorization.as_bytes(),
            account_id: *account.as_bytes(),
            origin: origin.to_owned(),
            trust_generation: 1,
            manifest_version: observed.manifest_version.0 as u64,
            reader_generation: generation as u64,
            root_fingerprint: observed.root_fingerprint_b64.0,
            manifest_digest: observed.manifest_digest_b64.0,
            reader_id: input.selected_reader_id.0,
            reader_point: observed.reader.public_point_b64.0,
            issued_ms: now as u64,
            until_ms: input.requested_until_ms.0 as u64,
            capability: 3,
        })
        .map_err(|_| Error::Invalid)?;
        let until = input.requested_until_ms.0;
        let p = Pending {
            slot: (0_i16..4)
                .find(|slot| !a.pending.iter().any(|p| p.slot == *slot))
                .ok_or(Error::Unavailable)?,
            account,
            authorization,
            generation,
            create: input,
            input_digest: digest,
            origin: origin.to_owned(),
            actor: owner.user_id,
            session: owner.session_id,
            allocated_revision,
            unsigned_digest: store::hash(&unsigned),
            unsigned,
            source: observed.clone(),
            issued: now,
            expires: now.checked_add(300_000).ok_or(Error::Unavailable)?,
            until,
        };
        store::stage_pending(&tx, &a.state, &p).await?;
        // Staged postimage, never the obsolete prior image, precedes final time.
        let staged = store::load(&tx, account, true)
            .await?
            .ok_or(Error::Unavailable)?;
        let expected = IssuerState {
            allocator: generation,
            revision: allocated_revision,
            last_ms: now,
            ..a.state.clone()
        };
        if staged.state != expected
            || staged
                .pending
                .iter()
                .find(|q| q.authorization == authorization)
                != Some(&p)
        {
            return Err(Error::Unavailable);
        }
        let final_ms = final_source(
            &tx,
            owner,
            &mut authority,
            &observed,
            now,
            p.expires.min(p.until),
        )
        .await?;
        let value = p.view(&staged.state, final_ms);
        encode(&value)?;
        Ok((value, false))
    }
    .await;
    match result {
        Ok((_, true)) => {
            tx.commit().await?;
            Err(auth::AuthError::RateLimited.into())
        }
        Ok((value, false)) => settle(tx, Ok(value)).await,
        Err(error) => settle(tx, Err(error)).await,
    }
}

pub(crate) async fn complete(
    client: &mut Client,
    hasher: &TokenHasher,
    cipher: &mfa::MfaCipher,
    owner: &SessionPrincipal,
    origin: &str,
    id: Uuid,
    input: Complete,
) -> Result<ResultView, Error> {
    if id.is_nil() || input.generation.0 <= 0 {
        return Err(Error::Invalid);
    }
    // Historical exact whole-signature replay bypasses live root and factor.
    if let Some(value) = historical(client, owner, None, Some((id, input.generation.0))).await? {
        match value {
            ResultView::Receipt(ref receipt) => {
                if receipt.create_request != input.create_request
                    || receipt.creation_expected_revision != input.creation_expected_revision
                    || receipt.unsigned_digest != input.unsigned_digest
                {
                    return Err(Error::Conflict);
                }
                if receipt
                    .signed_statement
                    .as_ref()
                    .is_some_and(|s| s.0 != input.signed_statement.0)
                {
                    return Err(Error::Conflict);
                }
                return Ok(value);
            }
            ResultView::Unavailable { .. } => return Ok(value),
            _ => {}
        }
    }
    let account = owner.tenant.account_id();
    let tx = begin(client).await?;
    let result = async {
        let mut authority = lock_current(&tx, account).await?;
        ceremony::owner_locks(&tx, owner, false).await?;
        let a = store::load(&tx, account, true)
            .await?
            .ok_or(Error::Unavailable)?;
        let p = a
            .pending
            .iter()
            .find(|p| p.authorization == id && p.generation == input.generation.0)
            .cloned()
            .ok_or(Error::Conflict)?;
        let now = store::clock(&tx, a.state.last_ms).await?;
        if p.actor != owner.user_id
            || p.session != owner.session_id
            || p.origin != origin
            || p.create.create_request != input.create_request
            || p.create.expected_revision != input.creation_expected_revision
            || p.unsigned_digest != input.unsigned_digest.0
            || p.create.prior != a.state.prior
            || now >= p.expires
            || now >= p.until
            || a.state.revision == i64::MAX
        {
            return Err(Error::Conflict);
        }
        let (proof, candidate, records) = authority
            .verify_account_contact_statement(
                &input.signed_statement.0,
                origin,
                &p.source.root_fingerprint_b64.0,
            )
            .await?;
        let identity = proof.identity();
        let current = source(account, p.create.selected_reader_id.0, candidate, records)?;
        bound_source(&a.state, &current)?;
        if !same_source(&p.source, &current)
            || identity.parsed.unsigned() != p.unsigned
            || identity.root_writer_id != p.source.root_writer.key_id_b64.0
            || identity.root_point != p.source.root_writer.public_point_b64.0
            || identity.root_from_ms != p.source.root_writer.from_ms.0 as u64
            || identity.root_until_ms != p.source.root_writer.until_ms.0 as u64
            || identity.reader_from_ms != p.source.reader.from_ms.0 as u64
            || identity.reader_until_ms != p.source.reader.until_ms.0 as u64
        {
            return Err(Error::Conflict);
        }
        let factor_ms = store::clock(&tx, now.max(current.observed_ms.0)).await?;
        if factor_ms >= p.expires || factor_ms >= p.until {
            return Err(Error::Conflict);
        }
        let Some(factor) = mfa::consume_ceremony_factor(
            &tx,
            cipher,
            hasher,
            owner,
            &input.code.0,
            factor_ms as u64,
        )
        .await?
        else {
            return Ok((ResultView::unavailable(), true));
        };
        store::terminal(
            &tx,
            &a.state,
            &p,
            "COMPLETED",
            Some(&input.signed_statement.0),
            factor_ms,
        )
        .await?;
        let staged = store::load(&tx, account, true)
            .await?
            .ok_or(Error::Unavailable)?;
        let digest = store::hash(&input.signed_statement.0);
        let expected = IssuerState {
            revision: a.state.revision + 1,
            last_ms: factor_ms,
            next_slot: (a.state.next_slot + 1) % 32,
            prior: Prior::Active {
                authorization: Id(id),
                generation: input.generation,
                digest: Fixed(digest),
            },
            signed: Some(input.signed_statement.0.clone()),
            ..a.state.clone()
        };
        if staged.state != expected || staged.pending.iter().any(|q| q.authorization == id) {
            return Err(Error::Unavailable);
        }
        let receipt = staged
            .receipts
            .iter()
            .find(|r| r.authorization == id && r.generation == p.generation)
            .ok_or(Error::Unavailable)?;
        if receipt.signed.as_ref() != Some(&input.signed_statement.0)
            || receipt.input_digest != p.input_digest
            || receipt.unsigned_digest != p.unsigned_digest
            || receipt.terminal_ms != factor_ms
        {
            return Err(Error::Unavailable);
        }
        let final_ms = final_source(
            &tx,
            owner,
            &mut authority,
            &p.source,
            factor_ms,
            p.expires.min(p.until),
        )
        .await?;
        if !factor.current_at(final_ms as u64) {
            return Err(Error::Conflict);
        }
        let value = receipt.view(&staged.state, final_ms);
        encode(&value)?;
        Ok((value, false))
    }
    .await;
    match result {
        Ok((_, true)) => {
            tx.commit().await?;
            Err(auth::AuthError::InvalidCredentials.into())
        }
        Ok((value, false)) => settle(tx, Ok(value)).await,
        Err(error) => settle(tx, Err(error)).await,
    }
}

pub(crate) async fn cancel(
    client: &mut Client,
    owner: &SessionPrincipal,
    id: Uuid,
    input: Cancel,
) -> Result<ResultView, Error> {
    if id.is_nil() || input.generation.0 <= 0 {
        return Err(Error::Invalid);
    }
    let account = owner.tenant.account_id();
    let tx = begin(client).await?;
    let result = async {
        let fence = OwnerReductionFence::acquire(&tx, owner).await?;
        let a = store::load(&tx, account, true)
            .await?
            .ok_or(Error::Unavailable)?;
        let now = store::clock(&tx, a.state.last_ms).await?;
        let Some(p) = a
            .pending
            .iter()
            .find(|p| p.authorization == id && p.generation == input.generation.0)
        else {
            if let Some(r) = a
                .receipts
                .iter()
                .find(|r| r.authorization == id && r.generation == input.generation.0)
            {
                if r.request != input.create_request.0
                    || r.unsigned_digest != input.unsigned_digest.0
                {
                    return Err(Error::Conflict);
                }
            }
            let value = a.known(id, input.generation.0, now);
            encode(&value)?;
            fence.final_check(now).await?;
            return Ok(value);
        };
        if p.create.create_request != input.create_request
            || p.unsigned_digest != input.unsigned_digest.0
        {
            return Err(Error::Conflict);
        }
        let kind = if now >= p.expires || now >= p.until {
            "EXPIRED"
        } else {
            "CANCELLED"
        };
        store::terminal(&tx, &a.state, p, kind, None, now).await?;
        let staged = store::load(&tx, account, true)
            .await?
            .ok_or(Error::Unavailable)?;
        let expected = IssuerState {
            revision: a.state.revision.saturating_add(1),
            last_ms: now,
            next_slot: (a.state.next_slot + 1) % 32,
            ..a.state.clone()
        };
        if staged.state != expected || staged.pending.iter().any(|q| q.authorization == id) {
            return Err(Error::Unavailable);
        }
        let receipt = staged
            .receipts
            .iter()
            .find(|r| r.authorization == id && r.generation == p.generation)
            .ok_or(Error::Unavailable)?;
        if receipt.kind != kind
            || receipt.input_digest != p.input_digest
            || receipt.terminal_ms != now
        {
            return Err(Error::Unavailable);
        }
        let final_ms = fence.final_check(now).await?;
        let value = receipt.view(&staged.state, final_ms);
        encode(&value)?;
        Ok(value)
    }
    .await;
    settle(tx, result).await
}
pub(crate) async fn withdraw(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: Withdraw,
) -> Result<ResultView, Error> {
    if input.expected_generation.0 <= 0 {
        return Err(Error::Invalid);
    }
    let account = owner.tenant.account_id();
    let tx = begin(client).await?;
    let result=async{
        let fence=OwnerReductionFence::acquire(&tx,owner).await?;let a=store::load(&tx,account,true).await?.ok_or(Error::Unavailable)?;
        let (_,id,g,d)=a.state.prior.tuple();
        if id!=Some(input.expected_authorization.0)||g!=Some(input.expected_generation.0)||d!=Some(input.expected_digest.0){return Err(Error::Conflict);}
        let now=store::clock(&tx,a.state.last_ms).await?;let already=matches!(a.state.prior,Prior::Withdrawn{..});
        if !already&&a.state.revision!=input.expected_revision.0{return Err(Error::Conflict);}
        let revision=if already{a.state.revision}else{a.state.revision.saturating_add(1)};
        if !already{tx.execute("UPDATE contact_reader_state SET phase='WITHDRAWN',current_statement=NULL,mutation_revision=$2,last_mutation_ms=$3 WHERE account_id=$1",&[&account,&revision,&now]).await?;}
        let staged=store::load(&tx,account,true).await?.ok_or(Error::Unavailable)?;
        let expected=IssuerState{revision,last_ms:if already{a.state.last_ms}else{now},prior:Prior::Withdrawn{authorization:input.expected_authorization,generation:input.expected_generation,digest:input.expected_digest},signed:None,..a.state.clone()};
        if staged.state!=expected{return Err(Error::Unavailable);}let final_ms=fence.final_check(now).await?;
        let value=ResultView::Withdraw(WithdrawView{kind:if already{"already_withdrawn"}else{"withdrawn"},authorization:input.expected_authorization,generation:input.expected_generation,statement_digest:input.expected_digest,mutation_revision:Number(revision),observed_ms:Number(final_ms)});encode(&value)?;Ok(value)
    }.await;
    settle(tx, result).await
}
