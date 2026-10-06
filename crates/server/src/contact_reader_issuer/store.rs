// SPDX-License-Identifier: AGPL-3.0-only
//! Exact bounded row copies and staging inside a caller-owned transaction.
//! Nothing here initializes an absent aggregate or establishes restore admission.

use super::{Error, model::*};
use crate::contact_reader_statement::{self as statement, UnsignedStatement};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

pub(super) const STATE_COLUMNS: &str = "account_id,root_pin,root_fingerprint,trust_generation,allocation_generation,mutation_revision,last_mutation_ms,receipt_next_slot,phase,current_authorization,current_generation,current_statement_digest,current_statement";
pub(super) const PENDING_COLUMNS: &str = "account_id,slot,\"authorization\",generation,create_request,created_by_user,created_session,origin,create_input_digest,creation_expected_revision,allocated_revision,prior_phase,prior_authorization,prior_generation,prior_digest,requested_until_ms,unsigned,unsigned_digest,manifest,manifest_version,manifest_digest,reader_id,root_writer_id,reader_point,root_point,reader_from,root_from,reader_until,root_until,manifest_issued,manifest_until,creation_observed_ms,issued,expires,until_ms";
pub(super) const RECEIPT_COLUMNS: &str = "account_id,slot,\"authorization\",generation,create_request,create_input_digest,creation_expected_revision,unsigned_digest,terminal_kind,terminal_ms,signed_statement,statement_digest";
pub(super) const VISIBILITY_MS: i64 = 7 * 86_400_000;

pub(super) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    let value: [u8; N] = bytes.try_into().map_err(|_| Error::Unavailable)?;
    if value == [0; N] {
        return Err(Error::Unavailable);
    }
    Ok(value)
}
fn identity(id: Uuid) -> Result<Uuid, Error> {
    if id.is_nil() {
        Err(Error::Unavailable)
    } else {
        Ok(id)
    }
}
fn number(n: i64, zero: bool) -> Result<i64, Error> {
    if n < 0 || (!zero && n == 0) {
        Err(Error::Unavailable)
    } else {
        Ok(n)
    }
}
fn key(point: [u8; 65], id: [u8; 32], root: bool) -> Result<(), Error> {
    p256::PublicKey::from_sec1_bytes(&point).map_err(|_| Error::Unavailable)?;
    let algorithm = if root { [1, 1] } else { [0, 16] };
    if hash(&[b"ZTSE/key/v1\0".as_slice(), &algorithm, &point].concat()) != id {
        return Err(Error::Unavailable);
    }
    Ok(())
}
/// Public signature mathematics on retained bytes only. This neither creates
/// a VerifiedManifest nor returns an accepted/current statement capability.
fn public_signature(
    pin: &[u8; 94],
    label: &[u8],
    unsigned: &[u8],
    raw: &[u8],
) -> Result<(), Error> {
    let signature = Signature::from_slice(raw).map_err(|_| Error::Unavailable)?;
    if signature.normalize_s().to_bytes().as_slice() != raw {
        return Err(Error::Unavailable);
    }
    let key = VerifyingKey::from_sec1_bytes(&pin[29..94]).map_err(|_| Error::Unavailable)?;
    key.verify(
        &[label, &(unsigned.len() as u32).to_be_bytes(), unsigned].concat(),
        &signature,
    )
    .map_err(|_| Error::Unavailable)
}
pub(super) async fn clock(tx: &Transaction<'_>, previous: i64) -> Result<i64, Error> {
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .try_get(0)?;
    if now <= 0 || now < previous {
        return Err(Error::Unavailable);
    }
    Ok(now)
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct State {
    pub account: Uuid,
    pub pin: [u8; 94],
    pub fingerprint: [u8; 32],
    pub allocator: i64,
    pub revision: i64,
    pub last_ms: i64,
    pub next_slot: i16,
    pub prior: Prior,
    pub signed: Option<Vec<u8>>,
}
impl State {
    fn row(r: &Row) -> Result<Self, Error> {
        let account = identity(r.try_get("account_id")?)?;
        let pin = fixed(r.try_get("root_pin")?)?;
        let fingerprint = fixed(r.try_get("root_fingerprint")?)?;
        if crate::sealed_root_enrollment::root_fingerprint(&pin, account.as_bytes())
            .map_err(|_| Error::Unavailable)?
            != fingerprint
            || r.try_get::<_, i64>("trust_generation")? != 1
        {
            return Err(Error::Unavailable);
        }
        let allocator = number(r.try_get("allocation_generation")?, true)?;
        let revision = number(r.try_get("mutation_revision")?, true)?;
        if allocator > revision {
            return Err(Error::Unavailable);
        }
        let last_ms = number(r.try_get("last_mutation_ms")?, false)?;
        let next_slot: i16 = r.try_get("receipt_next_slot")?;
        if !(0..32).contains(&next_slot) {
            return Err(Error::Unavailable);
        }
        let phase: String = r.try_get("phase")?;
        let id: Option<Uuid> = r.try_get("current_authorization")?;
        let generation: Option<i64> = r.try_get("current_generation")?;
        let digest: Option<Vec<u8>> = r.try_get("current_statement_digest")?;
        let signed: Option<Vec<u8>> = r.try_get("current_statement")?;
        let prior = match (phase.as_str(), id, generation, digest) {
            ("EMPTY", None, None, None) if signed.is_none() => Prior::Empty {},
            ("ACTIVE" | "WITHDRAWN", Some(id), Some(g), Some(d)) if g > 0 && g <= allocator => {
                let authorization = Id(identity(id)?);
                let generation = Number(g);
                let digest = Fixed(fixed(d)?);
                if phase == "ACTIVE" {
                    let bytes = signed.as_ref().ok_or(Error::Unavailable)?;
                    let parsed = statement::parse(bytes).map_err(|_| Error::Unavailable)?;
                    public_signature(
                        &pin,
                        b"ZT/contact-reader/authorization/v1\0",
                        &parsed.unsigned(),
                        &parsed.signature(),
                    )?;
                    let s = parsed.statement();
                    if hash(bytes) != digest.0
                        || s.authorization_id != *id.as_bytes()
                        || s.account_id != *account.as_bytes()
                        || s.reader_generation != g as u64
                        || s.root_fingerprint != fingerprint
                    {
                        return Err(Error::Unavailable);
                    }
                    Prior::Active {
                        authorization,
                        generation,
                        digest,
                    }
                } else {
                    if signed.is_some() {
                        return Err(Error::Unavailable);
                    }
                    Prior::Withdrawn {
                        authorization,
                        generation,
                        digest,
                    }
                }
            }
            _ => return Err(Error::Unavailable),
        };
        Ok(Self {
            account,
            pin,
            fingerprint,
            allocator,
            revision,
            last_ms,
            next_slot,
            prior,
            signed,
        })
    }
    pub(super) fn current(&self, now: i64) -> Current {
        let (phase, id, g, d) = self.prior.tuple();
        Current {
            phase: match phase {
                "EMPTY" => "empty",
                "ACTIVE" => "active",
                _ => "withdrawn",
            },
            mutation_revision: Number(self.revision),
            allocation_generation: Number(self.allocator),
            observed_ms: Number(now),
            authorization: id.map(Id),
            generation: g.map(Number),
            statement_digest: d.map(Fixed),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Pending {
    pub slot: i16,
    pub account: Uuid,
    pub authorization: Uuid,
    pub generation: i64,
    pub create: Create,
    pub input_digest: [u8; 32],
    pub origin: String,
    pub actor: Uuid,
    pub session: Uuid,
    pub allocated_revision: i64,
    pub unsigned: Vec<u8>,
    pub unsigned_digest: [u8; 32],
    pub source: CreationSource,
    pub issued: i64,
    pub expires: i64,
    pub until: i64,
}
impl Pending {
    fn row(r: &Row, state: &State) -> Result<Self, Error> {
        let account = identity(r.try_get("account_id")?)?;
        let slot: i16 = r.try_get("slot")?;
        let authorization = identity(r.try_get("authorization")?)?;
        let generation = number(r.try_get("generation")?, false)?;
        let actor = identity(r.try_get("created_by_user")?)?;
        let session = identity(r.try_get("created_session")?)?;
        let prior_phase: String = r.try_get("prior_phase")?;
        let prior_id: Option<Uuid> = r.try_get("prior_authorization")?;
        let prior_g: Option<i64> = r.try_get("prior_generation")?;
        let prior_d: Option<Vec<u8>> = r.try_get("prior_digest")?;
        let prior = match (prior_phase.as_str(), prior_id, prior_g, prior_d) {
            ("EMPTY", None, None, None) => Prior::Empty {},
            ("ACTIVE" | "WITHDRAWN", Some(id), Some(g), Some(d)) if g > 0 && g < generation => {
                let authorization = Id(identity(id)?);
                let generation = Number(g);
                let digest = Fixed(fixed(d)?);
                if prior_phase == "ACTIVE" {
                    Prior::Active {
                        authorization,
                        generation,
                        digest,
                    }
                } else {
                    Prior::Withdrawn {
                        authorization,
                        generation,
                        digest,
                    }
                }
            }
            _ => return Err(Error::Unavailable),
        };
        let issued = number(r.try_get("issued")?, false)?;
        let expires = number(r.try_get("expires")?, false)?;
        let until = number(r.try_get("until_ms")?, false)?;
        let origin: String = r.try_get("origin")?;
        let reader_id = fixed(r.try_get("reader_id")?)?;
        let reader_point = fixed(r.try_get("reader_point")?)?;
        let root_id = fixed(r.try_get("root_writer_id")?)?;
        let root_point = fixed(r.try_get("root_point")?)?;
        key(reader_point, reader_id, false)?;
        key(root_point, root_id, true)?;
        let manifest: Vec<u8> = r.try_get("manifest")?;
        let manifest_digest = fixed(r.try_get("manifest_digest")?)?;
        let version = number(r.try_get("manifest_version")?, false)?;
        let observed = number(r.try_get("creation_observed_ms")?, false)?;
        let manifest_issued = number(r.try_get("manifest_issued")?, false)?;
        let manifest_until = number(r.try_get("manifest_until")?, false)?;
        let reader_from = number(r.try_get("reader_from")?, true)?;
        let root_from = number(r.try_get("root_from")?, true)?;
        let reader_until = number(r.try_get("reader_until")?, false)?;
        let root_until = number(r.try_get("root_until")?, false)?;
        let expected = number(r.try_get("creation_expected_revision")?, true)?;
        let allocated_revision = number(r.try_get("allocated_revision")?, false)?;
        let requested = number(r.try_get("requested_until_ms")?, false)?;
        let input_digest = fixed(r.try_get("create_input_digest")?)?;
        let unsigned: Vec<u8> = r.try_get("unsigned")?;
        let unsigned_digest = fixed(r.try_get("unsigned_digest")?)?;
        let create = Create {
            create_request: Id(identity(r.try_get("create_request")?)?),
            expected_revision: Number(expected),
            prior,
            selected_reader_id: Fixed(reader_id),
            compared_root_fingerprint: Fixed(state.fingerprint),
            requested_until_ms: Number(requested),
        };
        let wanted = UnsignedStatement {
            authorization_id: *authorization.as_bytes(),
            account_id: *account.as_bytes(),
            origin: origin.clone(),
            trust_generation: 1,
            manifest_version: version as u64,
            reader_generation: generation as u64,
            root_fingerprint: state.fingerprint,
            manifest_digest,
            reader_id,
            reader_point,
            issued_ms: issued as u64,
            until_ms: until as u64,
            capability: 3,
        };
        if account != state.account
            || !(0..4).contains(&slot)
            || generation > state.allocator
            || state.prior.tuple().1 == Some(authorization)
            || state.prior.tuple().2 == Some(generation)
            || expected.checked_add(1) != Some(allocated_revision)
            || allocated_revision > state.revision
            || !(364..=9751).contains(&manifest.len())
            || hash(&manifest[..manifest.len().saturating_sub(64)]) != manifest_digest
            || observed > state.last_ms
            || observed < manifest_issued
            || issued < observed
            || issued < reader_from
            || issued < root_from
            || manifest_until <= manifest_issued
            || expires <= issued
            || expires - issued > 300_000
            || until != requested
            || until <= issued
            || until - issued > 86_400_000
            || until > manifest_until.min(reader_until).min(root_until)
            || create
                .commitment(account, &origin)
                .map_err(|_| Error::Unavailable)?
                != input_digest
            || statement::encode_unsigned(&wanted).map_err(|_| Error::Unavailable)? != unsigned
            || hash(&unsigned) != unsigned_digest
        {
            return Err(Error::Unavailable);
        }
        let source = CreationSource {
            kind: "historical_creation_source",
            account_id: Id(account),
            root_pin_b64: Fixed(state.pin),
            root_fingerprint_b64: Fixed(state.fingerprint),
            trust_generation: Number(1),
            manifest_version: Number(version),
            manifest_digest_b64: Fixed(manifest_digest),
            manifest_b64: Packed(manifest),
            observed_ms: Number(observed),
            manifest_issued_ms: Number(manifest_issued),
            manifest_expires_ms: Number(manifest_until),
            signed_until_ms: Number(manifest_until.min(reader_until).min(root_until)),
            reader: KeyView {
                key_id_b64: Fixed(reader_id),
                public_point_b64: Fixed(reader_point),
                from_ms: Number(reader_from),
                until_ms: Number(reader_until),
            },
            root_writer: KeyView {
                key_id_b64: Fixed(root_id),
                public_point_b64: Fixed(root_point),
                from_ms: Number(root_from),
                until_ms: Number(root_until),
            },
        };
        snapshot_fields(&source)?;
        Ok(Self {
            slot,
            account,
            authorization,
            generation,
            create,
            input_digest,
            origin,
            actor,
            session,
            allocated_revision,
            unsigned,
            unsigned_digest,
            source,
            issued,
            expires,
            until,
        })
    }
    pub(super) fn view(&self, state: &State, now: i64) -> ResultView {
        ResultView::Pending(Box::new(PendingView {
            kind: "pending",
            create_input_digest: Fixed(self.input_digest),
            create_request: self.create.create_request,
            authorization: Id(self.authorization),
            generation: Number(self.generation),
            creation_expected_revision: self.create.expected_revision,
            allocated_revision: Number(self.allocated_revision),
            unsigned_digest: Fixed(self.unsigned_digest),
            unsigned: Packed(self.unsigned.clone()),
            issued_ms: Number(self.issued),
            expires_ms: Number(self.expires),
            until_ms: Number(self.until),
            created_by_user: Id(self.actor),
            created_session: Id(self.session),
            creation_source: self.source.clone(),
            current: state.current(now),
        }))
    }
}

/// Compare the copied public framing/role fields to their frozen byte offsets.
/// This does not deserialize accepted authority or verify a current manifest.
fn snapshot_fields(s: &CreationSource) -> Result<(), Error> {
    let m = &s.manifest_b64.0;
    if !(364..=9751).contains(&m.len())
        || &m[..5] != b"ZTMA\x02"
        || m[5..21] != *s.account_id.0.as_bytes()
        || m[21..29] != 1_u64.to_be_bytes()
        || m[29..37] != (s.manifest_version.0 as u64).to_be_bytes()
        || m[37..45] != (s.manifest_issued_ms.0 as u64).to_be_bytes()
        || m[45..53] != (s.manifest_expires_ms.0 as u64).to_be_bytes()
        || m[85..150] != s.root_pin_b64.0[29..94]
        || m.len() != 215 + 149 * usize::from(m[150])
        || !(1..=64).contains(&m[150])
    {
        return Err(Error::Unavailable);
    }
    for (role, scope, wanted) in [(2_u8, 12_u16, &s.reader), (6, 0, &s.root_writer)] {
        let records = m[151..m.len() - 64]
            .chunks_exact(149)
            .filter(|r| r[0] == role && r[1..33] == wanted.key_id_b64.0)
            .collect::<Vec<_>>();
        if records.len() != 1 {
            return Err(Error::Unavailable);
        }
        let r = records[0];
        if r[33..98] != wanted.public_point_b64.0
            || r[98..130] != [0; 32]
            || r[130..132] != scope.to_be_bytes()
            || r[132..140] != (wanted.from_ms.0 as u64).to_be_bytes()
            || r[140..148] != (wanted.until_ms.0 as u64).to_be_bytes()
            || r[148] != 1
        {
            return Err(Error::Unavailable);
        }
    }
    public_signature(
        &s.root_pin_b64.0,
        b"ZTSE/manifest/v2\0",
        &m[..m.len() - 64],
        &m[m.len() - 64..],
    )?;
    if s.observed_ms.0 >= s.signed_until_ms.0
        || s.observed_ms.0 < s.reader.from_ms.0.max(s.root_writer.from_ms.0)
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Receipt {
    pub slot: i16,
    pub authorization: Uuid,
    pub generation: i64,
    pub request: Uuid,
    pub input_digest: [u8; 32],
    pub expected_revision: i64,
    pub unsigned_digest: [u8; 32],
    pub kind: String,
    pub terminal_ms: i64,
    pub signed: Option<Vec<u8>>,
    pub digest: Option<[u8; 32]>,
}
impl Receipt {
    fn row(r: &Row, state: &State) -> Result<Self, Error> {
        let account: Uuid = r.try_get("account_id")?;
        let slot: i16 = r.try_get("slot")?;
        let authorization = identity(r.try_get("authorization")?)?;
        let generation = number(r.try_get("generation")?, false)?;
        let request = identity(r.try_get("create_request")?)?;
        let input_digest = fixed(r.try_get("create_input_digest")?)?;
        let expected_revision = number(r.try_get("creation_expected_revision")?, true)?;
        let unsigned_digest = fixed(r.try_get("unsigned_digest")?)?;
        let kind: String = r.try_get("terminal_kind")?;
        let terminal_ms = number(r.try_get("terminal_ms")?, false)?;
        let signed: Option<Vec<u8>> = r.try_get("signed_statement")?;
        let digest = r
            .try_get::<_, Option<Vec<u8>>>("statement_digest")?
            .map(fixed)
            .transpose()?;
        if account != state.account
            || !(0..32).contains(&slot)
            || generation > state.allocator
            || expected_revision >= state.revision
            || terminal_ms > state.last_ms
        {
            return Err(Error::Unavailable);
        }
        match (kind.as_str(), &signed, digest) {
            ("COMPLETED", Some(bytes), Some(d)) => {
                let parsed = statement::parse(bytes).map_err(|_| Error::Unavailable)?;
                let s = parsed.statement();
                public_signature(
                    &state.pin,
                    b"ZT/contact-reader/authorization/v1\0",
                    &parsed.unsigned(),
                    &parsed.signature(),
                )?;
                if hash(bytes) != d
                    || hash(&parsed.unsigned()) != unsigned_digest
                    || s.authorization_id != *authorization.as_bytes()
                    || s.account_id != *account.as_bytes()
                    || s.reader_generation != generation as u64
                    || s.root_fingerprint != state.fingerprint
                {
                    return Err(Error::Unavailable);
                }
            }
            ("CANCELLED" | "EXPIRED", None, None) => {}
            _ => return Err(Error::Unavailable),
        }
        Ok(Self {
            slot,
            authorization,
            generation,
            request,
            input_digest,
            expected_revision,
            unsigned_digest,
            kind,
            terminal_ms,
            signed,
            digest,
        })
    }
    pub(super) fn visible(&self, now: i64) -> bool {
        now >= self.terminal_ms && now - self.terminal_ms < VISIBILITY_MS
    }
    pub(super) fn view(&self, state: &State, now: i64) -> ResultView {
        ResultView::Receipt(Box::new(ReceiptView {
            kind: match self.kind.as_str() {
                "COMPLETED" => "historical_completed",
                "CANCELLED" => "cancelled",
                _ => "expired",
            },
            create_input_digest: Fixed(self.input_digest),
            create_request: Id(self.request),
            authorization: Id(self.authorization),
            generation: Number(self.generation),
            creation_expected_revision: Number(self.expected_revision),
            unsigned_digest: Fixed(self.unsigned_digest),
            terminal_ms: Number(self.terminal_ms),
            signed_statement: self.signed.clone().map(Packed),
            statement_digest: self.digest.map(Fixed),
            current: state.current(now),
        }))
    }
}

pub(super) struct Aggregate {
    pub state: State,
    pub pending: Vec<Pending>,
    pub receipts: Vec<Receipt>,
}
impl Aggregate {
    pub(super) fn retained(
        &self,
        request: Uuid,
        digest: [u8; 32],
        now: i64,
    ) -> Result<Option<ResultView>, Error> {
        if let Some(p) = self
            .pending
            .iter()
            .find(|p| p.create.create_request.0 == request)
        {
            if p.input_digest != digest {
                return Err(Error::Conflict);
            }
            return Ok(Some(p.view(&self.state, now)));
        }
        if let Some(r) = self.receipts.iter().find(|r| r.request == request) {
            // Equality still precedes visibility; pruning is never an effect reset.
            if r.input_digest != digest {
                return Err(Error::Conflict);
            }
            return Ok(Some(if r.visible(now) {
                r.view(&self.state, now)
            } else {
                ResultView::unavailable()
            }));
        }
        Ok(None)
    }
    pub(super) fn known(&self, authorization: Uuid, generation: i64, now: i64) -> ResultView {
        if let Some(p) = self
            .pending
            .iter()
            .find(|p| p.authorization == authorization && p.generation == generation)
        {
            return p.view(&self.state, now);
        }
        if let Some(r) = self.receipts.iter().find(|r| {
            r.authorization == authorization && r.generation == generation && r.visible(now)
        }) {
            return r.view(&self.state, now);
        }
        ResultView::unavailable()
    }
}

pub(super) async fn load(
    tx: &Transaction<'_>,
    account: Uuid,
    write: bool,
) -> Result<Option<Aggregate>, Error> {
    if !super::lifecycle::installed(tx).await? {
        return Ok(None);
    }
    let lock = if write {
        "FOR UPDATE NOWAIT"
    } else {
        "FOR SHARE NOWAIT"
    };
    let Some(row) = tx
        .query_opt(
            &format!("SELECT {STATE_COLUMNS} FROM contact_reader_state WHERE account_id=$1 {lock}"),
            &[&account],
        )
        .await?
    else {
        return Ok(None);
    };
    let state = State::row(&row)?;
    let pending=tx.query(&format!("SELECT {PENDING_COLUMNS} FROM contact_reader_pending WHERE account_id=$1 ORDER BY slot {lock}"),&[&account]).await?.iter().map(|r|Pending::row(r,&state)).collect::<Result<Vec<_>,_>>()?;
    let receipts=tx.query(&format!("SELECT {RECEIPT_COLUMNS} FROM contact_reader_receipts WHERE account_id=$1 ORDER BY slot {lock}"),&[&account]).await?.iter().map(|r|Receipt::row(r,&state)).collect::<Result<Vec<_>,_>>()?;
    if pending.len() > 4 || receipts.len() > 32 {
        return Err(Error::Unavailable);
    }
    for (i, p) in pending.iter().enumerate() {
        if pending[..i].iter().any(|q| {
            q.authorization == p.authorization
                || q.generation == p.generation
                || q.create.create_request == p.create.create_request
        }) || receipts.iter().any(|r| {
            r.authorization == p.authorization
                || r.generation == p.generation
                || r.request == p.create.create_request.0
        }) {
            return Err(Error::Unavailable);
        }
    }
    for (i, r) in receipts.iter().enumerate() {
        if receipts[..i].iter().any(|q| {
            q.authorization == r.authorization
                || q.generation == r.generation
                || q.request == r.request
        }) {
            return Err(Error::Unavailable);
        }
    }
    Ok(Some(Aggregate {
        state,
        pending,
        receipts,
    }))
}

pub(super) async fn stage_pending(
    tx: &Transaction<'_>,
    old: &State,
    p: &Pending,
) -> Result<(), Error> {
    tx.execute("UPDATE contact_reader_state SET allocation_generation=$2,mutation_revision=$3,last_mutation_ms=$4 WHERE account_id=$1",&[&old.account,&p.generation,&p.allocated_revision,&p.issued]).await?;
    let (phase, id, g, d) = p.create.prior.tuple();
    let digest = d.map(|d| d.to_vec());
    let s = &p.source;
    tx.execute("INSERT INTO contact_reader_pending(account_id,slot,\"authorization\",generation,create_request,created_by_user,created_session,origin,create_input_digest,creation_expected_revision,allocated_revision,prior_phase,prior_authorization,prior_generation,prior_digest,requested_until_ms,unsigned,unsigned_digest,manifest,manifest_version,manifest_digest,reader_id,root_writer_id,reader_point,root_point,reader_from,root_from,reader_until,root_until,manifest_issued,manifest_until,creation_observed_ms,issued,expires,until_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35)",&[&p.account,&p.slot,&p.authorization,&p.generation,&p.create.create_request.0,&p.actor,&p.session,&p.origin,&&p.input_digest[..],&p.create.expected_revision.0,&p.allocated_revision,&phase,&id,&g,&digest,&p.until,&p.unsigned,&&p.unsigned_digest[..],&s.manifest_b64.0,&s.manifest_version.0,&&s.manifest_digest_b64.0[..],&&s.reader.key_id_b64.0[..],&&s.root_writer.key_id_b64.0[..],&&s.reader.public_point_b64.0[..],&&s.root_writer.public_point_b64.0[..],&s.reader.from_ms.0,&s.root_writer.from_ms.0,&s.reader.until_ms.0,&s.root_writer.until_ms.0,&s.manifest_issued_ms.0,&s.manifest_expires_ms.0,&s.observed_ms.0,&p.issued,&p.expires,&p.until]).await?;
    Ok(())
}

pub(super) async fn terminal(
    tx: &Transaction<'_>,
    old: &State,
    p: &Pending,
    kind: &str,
    signed: Option<&[u8]>,
    now: i64,
) -> Result<(), Error> {
    let revision = if kind == "COMPLETED" {
        old.revision.checked_add(1).ok_or(Error::Conflict)?
    } else {
        old.revision.saturating_add(1)
    };
    let digest = signed.map(hash);
    let digest_bytes = digest.map(|d| d.to_vec());
    let signed_bytes = signed.map(<[u8]>::to_vec);
    if kind == "COMPLETED" {
        tx.execute("UPDATE contact_reader_state SET phase='ACTIVE',current_authorization=$2,current_generation=$3,current_statement_digest=$4,current_statement=$5,mutation_revision=$6,last_mutation_ms=$7,receipt_next_slot=$8 WHERE account_id=$1",&[&old.account,&p.authorization,&p.generation,&digest_bytes,&signed_bytes,&revision,&now,&((old.next_slot+1)%32)]).await?;
    } else {
        tx.execute("UPDATE contact_reader_state SET mutation_revision=$2,last_mutation_ms=$3,receipt_next_slot=$4 WHERE account_id=$1",&[&old.account,&revision,&now,&((old.next_slot+1)%32)]).await?;
    }
    let deleted=tx.execute("DELETE FROM contact_reader_pending WHERE account_id=$1 AND slot=$2 AND \"authorization\"=$3 AND generation=$4",&[&old.account,&p.slot,&p.authorization,&p.generation]).await?;
    if deleted != 1 {
        return Err(Error::Unavailable);
    }
    tx.execute(
        "DELETE FROM contact_reader_receipts WHERE account_id=$1 AND slot=$2",
        &[&old.account, &old.next_slot],
    )
    .await?;
    tx.execute("INSERT INTO contact_reader_receipts(account_id,slot,\"authorization\",generation,create_request,create_input_digest,creation_expected_revision,unsigned_digest,terminal_kind,terminal_ms,signed_statement,statement_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",&[&old.account,&old.next_slot,&p.authorization,&p.generation,&p.create.create_request.0,&&p.input_digest[..],&p.create.expected_revision.0,&&p.unsigned_digest[..],&kind,&now,&signed_bytes,&digest_bytes]).await?;
    Ok(())
}
