// SPDX-License-Identifier: AGPL-3.0-only
//! Copied owner proposal -> real one-shot recovered-root offline statement.
//! No HTTP, factor, issuer, accepted history, current permission or stored unlock.
use super::*;
use serde::Deserialize;
use std::{
    io::{Read, Write},
    time::Instant,
};
use zrotext_root_material::contact_reader_signing::{self as signing, SourceRecord};

const MAX_WRAPPER: usize = 32_768;
const FLAGS: [&str; 8] = [
    "--account",
    "--origin",
    "--bundle",
    "--proposal",
    "--output",
    "--reader",
    "--reader-point",
    "--until",
];
struct Input {
    expected: signing::Expected,
    bundle: [u8; 16],
    proposal: String,
    output: String,
}
fn uuid(value: &str) -> Result<[u8; 16]> {
    let n = uuid::Uuid::parse_str(value).map_err(|_| ())?;
    if n.is_nil() || n.hyphenated().to_string() != value {
        return Err(());
    }
    Ok(*n.as_bytes())
}
fn number(value: &str, zero: bool) -> Result<u64> {
    let n = value.parse::<u64>().map_err(|_| ())?;
    if n > i64::MAX as u64 || (!zero && n == 0) || n.to_string() != value {
        return Err(());
    }
    Ok(n)
}
fn fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    let b = signing::decode_public_base64(value, N, N).map_err(|_| ())?;
    let b = b.try_into().map_err(|_| ())?;
    if b == [0; N] {
        return Err(());
    }
    Ok(b)
}
fn parse(args: &[String]) -> Result<Input> {
    if args.len() != 17
        || args[0] != "contact-reader-sign"
        || args[1..].chunks_exact(2).zip(FLAGS).any(|(p, f)| p[0] != f)
    {
        return Err(());
    }
    let v = |i: usize| args[2 * i + 2].as_str();
    if !(9..=512).contains(&v(1).len())
        || !v(1).bytes().all(|b| (0x21..=0x7e).contains(&b))
        || !canonical_origin(v(1))
    {
        return Err(());
    }
    let bundle = hex(v(2).as_bytes())?;
    let reader = hex(v(5).as_bytes())?;
    let point = hex(v(6).as_bytes())?;
    if bundle == [0; 16] || reader == [0; 32] || point[0] != 4 {
        return Err(());
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| ())?;
    public_path(v(3))?;
    public_path(v(4))?;
    if normalized_path(v(3)) == normalized_path(v(4)) {
        return Err(());
    }
    Ok(Input {
        expected: signing::Expected {
            account: uuid(v(0))?,
            origin: v(1).into(),
            fingerprint: [0; 32],
            reader_id: reader,
            reader_point: point,
            requested_until_ms: number(v(7), false)?,
        },
        bundle,
        proposal: v(3).into(),
        output: v(4).into(),
    })
}
fn normalized_path(value: &str) -> String {
    value.replace('/', "\\").to_ascii_lowercase()
}
fn public_path(value: &str) -> Result<()> {
    let b = value.as_bytes();
    if !(4..=260).contains(&b.len())
        || !value.is_ascii()
        || !b[0].is_ascii_alphabetic()
        || b[1] != b':'
        || !matches!(b[2], b'/' | b'\\')
    {
        return Err(());
    }
    for part in value[3..].split(['/', '\\']) {
        if part.is_empty()
            || matches!(part, "." | "..")
            || part.ends_with([' ', '.'])
            || part.bytes().any(|b| {
                !(0x21..=0x7e).contains(&b)
                    || matches!(b, b':' | b'"' | b'<' | b'>' | b'|' | b'?' | b'*')
            })
        {
            return Err(());
        }
        let stem = part.split('.').next().ok_or(())?.to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(());
        }
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wrapper<'a> {
    #[serde(borrow)]
    create: &'a serde_json::value::RawValue,
    #[serde(borrow)]
    pending: &'a serde_json::value::RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    create_request: String,
    expected_revision: String,
    prior: Prior,
    selected_reader_id: String,
    compared_root_fingerprint: String,
    requested_until_ms: String,
}
type PriorTuple = (u8, [u8; 16], u64, [u8; 32]);
#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Prior {
    Empty,
    Active {
        authorization: String,
        generation: String,
        digest: String,
    },
    Withdrawn {
        authorization: String,
        generation: String,
        digest: String,
    },
}
impl Prior {
    fn tuple(&self) -> Result<PriorTuple> {
        match self {
            Self::Empty => Ok((0, [0; 16], 0, [0; 32])),
            Self::Active {
                authorization,
                generation,
                digest,
            }
            | Self::Withdrawn {
                authorization,
                generation,
                digest,
            } => Ok((
                if matches!(self, Self::Active { .. }) {
                    1
                } else {
                    2
                },
                uuid(authorization)?,
                number(generation, false)?,
                fixed(digest)?,
            )),
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Current {
    Empty {
        mutation_revision: String,
        allocation_generation: String,
        observed_ms: String,
    },
    Active {
        mutation_revision: String,
        allocation_generation: String,
        observed_ms: String,
        authorization: String,
        generation: String,
        statement_digest: String,
    },
    Withdrawn {
        mutation_revision: String,
        allocation_generation: String,
        observed_ms: String,
        authorization: String,
        generation: String,
        statement_digest: String,
    },
}
struct CurrentFacts {
    revision: u64,
    allocation: u64,
    observed: u64,
    prior: PriorTuple,
}
impl Current {
    fn values(&self) -> Result<CurrentFacts> {
        match self {
            Self::Empty {
                mutation_revision,
                allocation_generation,
                observed_ms,
            } => Ok(CurrentFacts {
                revision: number(mutation_revision, true)?,
                allocation: number(allocation_generation, true)?,
                observed: number(observed_ms, false)?,
                prior: (0, [0; 16], 0, [0; 32]),
            }),
            Self::Active {
                mutation_revision,
                allocation_generation,
                observed_ms,
                authorization,
                generation,
                statement_digest,
            }
            | Self::Withdrawn {
                mutation_revision,
                allocation_generation,
                observed_ms,
                authorization,
                generation,
                statement_digest,
            } => Ok(CurrentFacts {
                revision: number(mutation_revision, true)?,
                allocation: number(allocation_generation, false)?,
                observed: number(observed_ms, false)?,
                prior: (
                    if matches!(self, Self::Active { .. }) {
                        1
                    } else {
                        2
                    },
                    uuid(authorization)?,
                    number(generation, false)?,
                    fixed(statement_digest)?,
                ),
            }),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    key_id_b64: String,
    public_point_b64: String,
    from_ms: String,
    until_ms: String,
}
impl Record {
    fn value(&self) -> Result<SourceRecord> {
        Ok(SourceRecord {
            key_id: fixed(&self.key_id_b64)?,
            point: fixed(&self.public_point_b64)?,
            from_ms: number(&self.from_ms, true)?,
            until_ms: number(&self.until_ms, false)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreationSource {
    kind: String,
    account_id: String,
    root_pin_b64: String,
    root_fingerprint_b64: String,
    trust_generation: String,
    manifest_version: String,
    manifest_digest_b64: String,
    manifest_b64: String,
    observed_ms: String,
    manifest_issued_ms: String,
    manifest_expires_ms: String,
    signed_until_ms: String,
    reader: Record,
    root_writer: Record,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    kind: String,
    create_input_digest: String,
    create_request: String,
    authorization: String,
    generation: String,
    creation_expected_revision: String,
    allocated_revision: String,
    unsigned_digest: String,
    unsigned: String,
    issued_ms: String,
    expires_ms: String,
    until_ms: String,
    created_by_user: String,
    created_session: String,
    creation_source: CreationSource,
    current: Current,
}
struct Proposal {
    create: Create,
    pending: Pending,
    unsigned: Vec<u8>,
    pin: Vec<u8>,
    manifest: Vec<u8>,
    input_digest: [u8; 32],
    expires_ms: u64,
}
fn create_digest(create: &Create, expected: &signing::Expected) -> Result<[u8; 32]> {
    let prior = create.prior.tuple()?;
    let mut b = vec![1];
    b.extend_from_slice(&expected.account);
    b.extend_from_slice(&(expected.origin.len() as u16).to_be_bytes());
    b.extend_from_slice(expected.origin.as_bytes());
    b.extend_from_slice(&uuid(&create.create_request)?);
    b.extend_from_slice(&number(&create.expected_revision, true)?.to_be_bytes());
    b.push(prior.0);
    b.extend_from_slice(&prior.1);
    b.extend_from_slice(&prior.2.to_be_bytes());
    b.extend_from_slice(&prior.3);
    b.extend_from_slice(&fixed::<32>(&create.selected_reader_id)?);
    b.extend_from_slice(&fixed::<32>(&create.compared_root_fingerprint)?);
    b.extend_from_slice(&number(&create.requested_until_ms, false)?.to_be_bytes());
    if b.len() != 172 + expected.origin.len() {
        return Err(());
    }
    Ok(Sha256::digest(b).into())
}
fn decode(bytes: &[u8]) -> Result<Proposal> {
    if bytes.len() > MAX_WRAPPER {
        return Err(());
    }
    let wrapper: Wrapper<'_> = serde_json::from_slice(bytes).map_err(|_| ())?;
    if wrapper.create.get().len() > 8192
        || wrapper.pending.get().len() > 20_480
        || !wrapper.create.get().starts_with('{')
        || !wrapper.pending.get().starts_with('{')
    {
        return Err(());
    }
    let create: Create = serde_json::from_str(wrapper.create.get()).map_err(|_| ())?;
    let pending: Pending = serde_json::from_str(wrapper.pending.get()).map_err(|_| ())?;
    if pending.kind != "pending" || pending.creation_source.kind != "historical_creation_source" {
        return Err(());
    }
    let unsigned = signing::decode_public_base64(&pending.unsigned, 250, 753).map_err(|_| ())?;
    let pin = signing::decode_public_base64(&pending.creation_source.root_pin_b64, 94, 94)
        .map_err(|_| ())?;
    let manifest = signing::decode_public_base64(&pending.creation_source.manifest_b64, 364, 9751)
        .map_err(|_| ())?;
    let input_digest = fixed(&pending.create_input_digest)?;
    let expires_ms = number(&pending.expires_ms, false)?;
    Ok(Proposal {
        create,
        pending,
        unsigned,
        pin,
        manifest,
        input_digest,
        expires_ms,
    })
}
impl Proposal {
    fn inspect(
        &self,
        expected: &signing::Expected,
        now: u64,
    ) -> Result<signing::ReviewedContactReader> {
        let p = &self.pending;
        let s = &p.creation_source;
        let revision = number(&self.create.expected_revision, true)?;
        let allocated = number(&p.allocated_revision, false)?;
        let generation = number(&p.generation, false)?;
        let issued = number(&p.issued_ms, false)?;
        let until = number(&p.until_ms, false)?;
        let current = p.current.values()?;
        let prior = self.create.prior.tuple()?;
        if revision > i64::MAX as u64 - 2
            || revision.checked_add(1) != Some(allocated)
            || number(&p.creation_expected_revision, true)? != revision
            || current.revision < allocated
            || current.allocation < generation
            || current.observed < issued
            || current.observed > now
            || current.prior != prior
            || (prior.2 >= generation)
            || uuid(&p.create_request)? != uuid(&self.create.create_request)?
            || create_digest(&self.create, expected)? != self.input_digest
            || fixed::<32>(&self.create.selected_reader_id)? != expected.reader_id
            || fixed::<32>(&self.create.compared_root_fingerprint)? != expected.fingerprint
            || number(&self.create.requested_until_ms, false)? != expected.requested_until_ms
            || self.expires_ms <= issued
            || self.expires_ms - issued > 300_000
            || now < issued
            || now >= self.expires_ms
            || until <= issued
            || until - issued > 86_400_000
            || fixed::<32>(&p.unsigned_digest)? != <[u8; 32]>::from(Sha256::digest(&self.unsigned))
        {
            return Err(());
        }
        uuid(&p.created_by_user)?;
        uuid(&p.created_session)?;
        let source = signing::Source {
            account: uuid(&s.account_id)?,
            pin: &self.pin,
            fingerprint: fixed(&s.root_fingerprint_b64)?,
            generation: number(&s.trust_generation, false)?,
            version: number(&s.manifest_version, false)?,
            digest: fixed(&s.manifest_digest_b64)?,
            manifest: &self.manifest,
            observed_ms: number(&s.observed_ms, false)?,
            issued_ms: number(&s.manifest_issued_ms, false)?,
            expires_ms: number(&s.manifest_expires_ms, false)?,
            signed_until_ms: number(&s.signed_until_ms, false)?,
            reader: s.reader.value()?,
            root_writer: s.root_writer.value()?,
        };
        let reviewed = signing::inspect(&self.unsigned, &source, expected, now).map_err(|_| ())?;
        let f = reviewed.facts();
        if f.authorization != uuid(&p.authorization)?
            || f.reader_generation != generation
            || f.issued_ms != issued
            || f.until_ms != until
        {
            return Err(());
        }
        Ok(reviewed)
    }
}

fn read_proposal(path: &str) -> Result<Vec<u8>> {
    public_path(path)?;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, OPEN_EXISTING,
    };
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    // SAFETY: terminated input buffer; no inherited handle. The final leaf is
    // opened itself; ancestor junctions may still be traversed, as documented.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(());
    }
    // SAFETY: the successful handle is transferred once to an owned File.
    let mut file = unsafe { std::fs::File::from_raw_handle(handle as _) };
    use std::os::windows::fs::MetadataExt;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x0400 != 0
        || metadata.len() > MAX_WRAPPER as u64
    {
        return Err(());
    }
    let mut bytes = vec![0; MAX_WRAPPER + 1];
    let mut filled = 0;
    loop {
        let n = file.read(&mut bytes[filled..]).map_err(|_| ())?;
        if n == 0 {
            break;
        }
        filled += n;
        if filled > MAX_WRAPPER {
            return Err(());
        }
    }
    bytes.truncate(filled);
    std::str::from_utf8(&bytes).map_err(|_| ())?;
    Ok(bytes)
}
fn write_public(path: &str, bytes: &[u8]) -> Result<()> {
    public_path(path)?;
    if !(314..=817).contains(&bytes.len()) {
        return Err(());
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())
}
fn chunks(text: &str) -> Result<Vec<&str>> {
    if !text
        .bytes()
        .all(|b| matches!(b, b'\r' | b'\n' | 0x20..=0x7e))
    {
        return Err(());
    }
    text.as_bytes()
        .chunks(512)
        .map(|b| std::str::from_utf8(b).map_err(|_| ()))
        .collect()
}
fn display(session: &mut Session, text: &str) -> Result<()> {
    for chunk in chunks(text)? {
        session.write_public_prompt(chunk).map_err(|_| ())?;
    }
    Ok(())
}
struct Lifetime {
    expires: u64,
    until: u64,
    last: u64,
    started: Instant,
    budget: Duration,
    signing_start: Option<Instant>,
}
impl Lifetime {
    fn fresh(&mut self) -> Result<u64> {
        self.observe(
            now_millis()?,
            self.started.elapsed(),
            self.signing_start.map(|start| start.elapsed()),
        )
    }
    fn observe(&mut self, now: u64, age: Duration, elapsed: Option<Duration>) -> Result<u64> {
        if now < self.last
            || now >= self.expires
            || now >= self.until
            || age >= self.budget
            || elapsed.is_some_and(|elapsed| elapsed >= Duration::from_secs(10))
        {
            return Err(());
        }
        self.last = now;
        Ok(now)
    }
    fn input_timeout(&mut self) -> Result<Duration> {
        let now = self.fresh()?;
        let wall = Duration::from_millis(
            self.expires
                .min(self.until)
                .checked_sub(now)
                .ok_or(())?
                .min(300_000),
        );
        Ok(wall.min(self.budget.checked_sub(self.started.elapsed()).ok_or(())?))
    }
}
fn review_text(input: &Input, proposal: &Proposal, f: &signing::ReviewFacts) -> Result<String> {
    let prior = proposal.create.prior.tuple()?;
    let s = &proposal.pending.creation_source;
    let text = format!(
        "Offline contact reader signing. This signature is not current access or server completion.\r\nAccount: {}\r\nOrigin: {}\r\nBundle: {}\r\nRoot fingerprint: {}\r\nRoot generation: 1\r\nRoot writer: {}\r\nRoot point: {}\r\nRoot interval: {}..{}\r\nReader: {}\r\nReader point: {}\r\nReader interval: {}..{}\r\nReader generation: {}\r\nManifest version: {}\r\nManifest digest: {}\r\nManifest interval: {}..{}\r\nHistorical source comparison: {}\r\nStatement authorization: {}\r\nStatement issued/until: {}..{}\r\nPending expiry: {}\r\nCapability: 3 (account-contact reader)\r\nCreate request: {}\r\nOriginal user: {}\r\nOriginal session: {}\r\nCreation CAS: {}\r\nAllocated revision: {}\r\nCreate input digest: {}\r\nUnsigned digest: {}\r\nUnsigned bytes: {}\r\nRequested until: {}\r\nPrior phase: {}\r\nPrior authorization/generation/digest: {}/{}/{}\r\nRequest, CAS, actor and historical comparison are contextual; they are not extra fields in the statement signature.\r\nDECLINE ends without token entry, signature or publication.\r\nType APPROVE-READER or DECLINE: ",
        uuid::Uuid::from_bytes(f.account),
        f.origin,
        display_hex(&input.bundle),
        display_hex(&f.fingerprint),
        display_hex(&f.root_writer.key_id),
        display_hex(&f.root_writer.point),
        f.root_writer.from_ms,
        f.root_writer.until_ms,
        display_hex(&f.reader.key_id),
        display_hex(&f.reader.point),
        f.reader.from_ms,
        f.reader.until_ms,
        f.reader_generation,
        f.manifest_version,
        display_hex(&f.manifest_digest),
        s.manifest_issued_ms,
        s.manifest_expires_ms,
        f.observed_ms,
        uuid::Uuid::from_bytes(f.authorization),
        f.issued_ms,
        f.until_ms,
        proposal.expires_ms,
        proposal.create.create_request,
        proposal.pending.created_by_user,
        proposal.pending.created_session,
        proposal.create.expected_revision,
        proposal.pending.allocated_revision,
        display_hex(&proposal.input_digest),
        display_hex(&f.unsigned_digest),
        proposal.unsigned.len(),
        input.expected.requested_until_ms,
        prior.0,
        uuid::Uuid::from_bytes(prior.1),
        prior.2,
        display_hex(&prior.3)
    );
    chunks(&text)?;
    Ok(text)
}
pub(super) fn run(args: &[String], parent: PathBuf) -> Result<()> {
    let mut input = parse(args)?;
    // Refuse malformed public wire before any console/secret interaction.
    let proposal = decode(&read_proposal(&input.proposal)?)?;
    verify_process_eligibility().map_err(|_| ())?;
    let mut preliminary = Session::acquire().map_err(|_| ())?;
    display(
        &mut preliminary,
        "Enter full lowercase fingerprint from your independent kit: ",
    )?;
    let fingerprint = preliminary.read(64, TIMEOUT).map_err(|_| ())?;
    input.expected.fingerprint = hex(fingerprint.expose_ascii())?;
    drop(fingerprint);
    if input.expected.fingerprint == [0; 32] {
        return Err(());
    }
    let started = Instant::now();
    let now = now_millis()?;
    let reviewed = proposal.inspect(&input.expected, now)?;
    let facts = reviewed.facts();
    let expected = ExpectedIdentity {
        account_id: input.expected.account,
        origin: input.expected.origin.clone(),
        root_fingerprint: input.expected.fingerprint,
    };
    let store = Store::open_existing(&parent).map_err(|_| ())?;
    let bundle = store
        .read_bundle(&input.bundle, &expected)
        .map_err(|_| ())?;
    let card = recovery_kit::decode_public_card(
        bundle.public_card(),
        &expected,
        &Sha256::digest(bundle.encrypted_backup()).into(),
    )
    .map_err(|_| ())?;
    if card.root_pin() != proposal.pin.as_slice() {
        return Err(());
    }
    let kit = KitContext::new(expected.clone(), card.root_pin(), input.bundle).map_err(|_| ())?;
    let mut lifetime = Lifetime {
        expires: proposal.expires_ms,
        until: facts.until_ms,
        last: now,
        started,
        budget: Duration::from_millis(
            proposal
                .expires_ms
                .min(facts.until_ms)
                .checked_sub(now)
                .ok_or(())?,
        ),
        signing_start: None,
    };
    let mut review = Session::acquire().map_err(|_| ())?;
    display(&mut review, &review_text(&input, &proposal, &facts)?)?;
    let consent = review.read(14, lifetime.input_timeout()?).map_err(|_| ())?;
    if consent.expose_ascii() != b"APPROVE-READER" {
        return Err(());
    }
    drop(consent);
    lifetime.fresh()?;
    verify_process_eligibility().map_err(|_| ())?;
    let mut token_session = Session::acquire().map_err(|_| ())?;
    display(
        &mut token_session,
        "Enter recovery token from your independent kit: ",
    )?;
    let token = token_session
        .read(79, lifetime.input_timeout()?)
        .map_err(|_| ())?;
    lifetime.fresh()?;
    lifetime.signing_start = Some(Instant::now());
    let recovery = recovery_kit::decode_token(token.expose_ascii(), &kit).map_err(|_| ())?;
    drop(token);
    verify_process_eligibility().map_err(|_| ())?;
    // The SAME new eligible output session stays owned across recovery, signing,
    // publication and receipt. Never reacquire after the secret operation.
    let mut output = Session::acquire().map_err(|_| ())?;
    output.write_public_prompt("").map_err(|_| ())?;
    lifetime.fresh()?;
    let root =
        root_backup::open(bundle.encrypted_backup(), &recovery, &expected).map_err(|_| ())?;
    drop(recovery);
    if pin(&root, &expected.account_id)? != *card.root_pin() {
        return Err(());
    }
    let signed = reviewed.sign(&root, lifetime.fresh()?).map_err(|_| ())?;
    drop(root);
    verify_process_eligibility().map_err(|_| ())?;
    output.write_public_prompt("").map_err(|_| ())?;
    lifetime.fresh()?;
    write_public(&input.output, &signed.bytes)?;
    // Clock/cancellation checks bound success, not synchronous I/O settlement.
    // Failure here may leave a COMPLETE valid file; never automatically retry.
    verify_process_eligibility().map_err(|_| ())?;
    output.write_public_prompt("").map_err(|_| ())?;
    lifetime.fresh()?;
    let receipt = format!(
        "Signed locally; server completion has not been acknowledged.\r\nAuthorization: {}\r\nReader generation: {}\r\nUnsigned digest: {}\r\nWhole signed digest: {}\r\nKeep the original operation and exact whole output. Do not automatically sign or overwrite again.\r\n",
        uuid::Uuid::from_bytes(facts.authorization),
        facts.reader_generation,
        display_hex(&facts.unsigned_digest),
        display_hex(&signed.digest)
    );
    for chunk in chunks(&receipt)? {
        verify_process_eligibility().map_err(|_| ())?;
        lifetime.fresh()?;
        output.write_public_prompt(chunk).map_err(|_| ())?;
    }
    output.finish().map_err(|_| ())?;
    lifetime.fresh()?;
    Ok(())
}

#[cfg(test)]
mod tests;
