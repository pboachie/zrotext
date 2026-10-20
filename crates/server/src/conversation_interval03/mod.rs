// SPDX-License-Identifier: AGPL-3.0-only
//! Distinct ZTCA03 content consent. Historical signatures and syntax are not
//! current owner authentication, a durable install ACK or physical custody.
use crate::sealed_manifest03::{self as crypto, Authorization03, Check, VerifiedManifest03};
use crate::sealed_payload_election03::{self as election, CurrentAuthority03, VerifiedElection03};
use uuid::Uuid;

pub const DISCLOSURE_VERSION: &str = "conversation-content03-v1";
pub const DISCLOSURE: &str = "With your approval, ZROtext sends and receives SMS for this selected phone line and conversation, and transfers encrypted message content to your paired browser and the explicitly listed customer-controlled readers. Stop closes new sending, capture and transfer; retained encrypted content is deleted separately.";
const HEADER: &[u8; 8] = b"ZTCA\x03\x03\x03\0";
const REQUEST: &[u8] = b"zrotext/conversation/request03/v1\0";
const APPROVE: &[u8] = b"zrotext/conversation/approve03/v1\0";
const INSTALL: &[u8] = b"zrotext/conversation/install03/v1\0";

#[derive(Clone, PartialEq, Eq)]
pub struct IntegrationReader03 {
    pub connector_id: Uuid,
    pub read_grant_id: Uuid,
    pub key_id: [u8; 32],
}

pub struct Statement03 {
    bytes: Vec<u8>,
    ids: [[u8; 16]; 9],
    numbers: [u64; 8],
    digests: [[u8; 32]; 13],
    peer: Vec<u8>,
    integrations: Vec<IntegrationReader03>,
}
impl std::fmt::Debug for Statement03 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Statement03").finish_non_exhaustive()
    }
}
fn nonzero(bytes: &[u8]) -> Check<()> {
    if bytes.iter().all(|b| *b == 0) {
        Err("consent zero identity/digest")
    } else {
        Ok(())
    }
}
impl Statement03 {
    pub fn decode(bytes: &[u8]) -> Check<Self> {
        if !(695..=1092).contains(&bytes.len()) || &bytes[..8] != HEADER {
            return Err("consent03 shape/profile");
        }
        let mut ids = [[0; 16]; 9];
        let mut numbers = [0; 8];
        let mut digests = [[0; 32]; 13];
        let mut at = 8;
        for id in &mut ids {
            id.copy_from_slice(&bytes[at..at + 16]);
            nonzero(id)?;
            at += 16;
        }
        for n in &mut numbers {
            *n = crypto::number(&bytes[at..at + 8])?;
            crypto::time(*n)?;
            at += 8;
        }
        for digest in &mut digests {
            digest.copy_from_slice(&bytes[at..at + 32]);
            nonzero(digest)?;
            at += 32;
        }
        let version_len = usize::from(bytes[at]);
        at += 1;
        if bytes.get(at..at + version_len) != Some(DISCLOSURE_VERSION.as_bytes()) {
            return Err("consent disclosure version");
        }
        at += version_len;
        if bytes.get(at..at + 32) != Some(crypto::sha(DISCLOSURE.as_bytes()).as_slice()) {
            return Err("consent disclosure");
        }
        at += 32;
        let peer_len = usize::from(*bytes.get(at).ok_or("consent peer")?);
        at += 1;
        let peer = bytes.get(at..at + peer_len).ok_or("consent peer framing")?;
        if !(3..=16).contains(&peer_len)
            || peer[0] != b'+'
            || !(b'1'..=b'9').contains(&peer[1])
            || !peer[2..].iter().all(u8::is_ascii_digit)
        {
            return Err("consent peer");
        }
        at += peer_len;
        let count = usize::from(*bytes.get(at).ok_or("consent integrations")?);
        at += 1;
        if count > 6 || at + 64 * count != bytes.len() {
            return Err("consent integration framing/trailing");
        }
        let mut integrations: Vec<IntegrationReader03> = Vec::with_capacity(count);
        for _ in 0..count {
            let connector =
                Uuid::from_slice(&bytes[at..at + 16]).map_err(|_| "consent connector")?;
            let grant =
                Uuid::from_slice(&bytes[at + 16..at + 32]).map_err(|_| "consent read grant")?;
            let key: [u8; 32] = bytes[at + 32..at + 64].try_into().unwrap();
            nonzero(&key)?;
            if connector.is_nil()
                || grant.is_nil()
                || integrations.last().is_some_and(|r| r.key_id >= key)
                || integrations
                    .iter()
                    .any(|r| r.connector_id == connector || r.read_grant_id == grant)
            {
                return Err("consent integration identity/order");
            }
            integrations.push(IntegrationReader03 {
                connector_id: connector,
                read_grant_id: grant,
                key_id: key,
            });
            at += 64;
        }
        let [_, _, _, _, issued, setup_expires, starts, expires] = numbers;
        if starts != issued
            || setup_expires <= issued
            || setup_expires - issued > 300_000
            || expires <= starts
            || expires - starts > 86_400_000
        {
            return Err("consent original time bounds");
        }
        // All minted handles occupy distinct retained identity slots; binding
        // is not a challenge/receipt/opening alias.
        let handles = [ids[3], ids[4], ids[5], ids[8]];
        if handles
            .iter()
            .enumerate()
            .any(|(i, id)| handles[..i].contains(id))
        {
            return Err("consent handle alias");
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            ids,
            numbers,
            digests,
            peer: peer.to_vec(),
            integrations,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn account_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[0])
    }
    pub fn interval_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[4])
    }
    pub fn receipt_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[5])
    }
    pub fn opening_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[8])
    }
    pub(crate) fn device_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[1])
    }
    pub(crate) fn line_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[2])
    }
    pub(crate) fn binding_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[3])
    }
    pub(crate) fn owner(&self) -> (Uuid, Uuid) {
        (Uuid::from_bytes(self.ids[6]), Uuid::from_bytes(self.ids[7]))
    }
    pub(crate) fn times(&self) -> (u64, u64, u64, u64) {
        (
            self.numbers[4],
            self.numbers[5],
            self.numbers[6],
            self.numbers[7],
        )
    }
    pub(crate) fn keys(&self) -> (&[u8; 32], &[u8; 32], &[u8; 32]) {
        (&self.digests[1], &self.digests[2], &self.digests[3])
    }
    pub(crate) fn peer(&self) -> &[u8] {
        &self.peer
    }
    pub(crate) fn integrations(&self) -> &[IntegrationReader03] {
        &self.integrations
    }
    pub(crate) fn owner_digest(&self) -> &[u8; 32] {
        &self.digests[8]
    }
    pub(crate) fn device_digest(&self) -> &[u8; 32] {
        &self.digests[10]
    }
    pub(crate) fn physical_digest(&self) -> &[u8; 32] {
        &self.digests[11]
    }
    pub fn digest(&self) -> [u8; 32] {
        crypto::sha(&self.bytes)
    }
    pub fn request_transcript(&self) -> Vec<u8> {
        crypto::framed(REQUEST, &self.bytes).expect("bounded consent")
    }
    fn approval_transcript(&self, owner: &[u8; 64]) -> Vec<u8> {
        crypto::framed(
            APPROVE,
            &[self.bytes.as_slice(), &crypto::sha(owner)].concat(),
        )
        .expect("bounded consent")
    }
    fn installation_transcript(&self, owner: &[u8; 64], phone: &[u8; 64]) -> Vec<u8> {
        crypto::framed(
            INSTALL,
            &[
                self.bytes.as_slice(),
                &crypto::sha(owner),
                &crypto::sha(phone),
            ]
            .concat(),
        )
        .expect("bounded consent")
    }
    pub(crate) fn recipients(&self, outbound: bool) -> Vec<(u8, [u8; 32])> {
        let mut out = Vec::with_capacity(2 + self.integrations.len());
        if outbound {
            out.push((1, self.digests[0]));
        }
        out.push((2, self.digests[1]));
        out.extend(self.integrations.iter().map(|r| (3, r.key_id)));
        out
    }
}

/// Only actual held readers may supply these current inputs. Neither this
/// struct nor matching IDs establish cookie/MFA, grant mapping or local custody.
pub(crate) struct ExpectedConsent03<'a> {
    pub current: &'a CurrentAuthority03,
    pub election: &'a VerifiedElection03,
    pub manifest: &'a VerifiedManifest03,
    pub selection_epoch: u64,
    pub user: Uuid,
    pub session: Uuid,
    pub canonical_origin: &'a str,
    pub device_session_digest: &'a [u8; 32],
    pub physical_digest: &'a [u8; 32],
    pub archive_reader: &'a [u8; 32],
    pub phone_signer: &'a [u8; 32],
    pub browser_signer: &'a [u8; 32],
    pub owner_deadline_ms: u64,
    pub peer: &'a [u8],
    pub integrations: &'a [IntegrationReader03],
}
struct Keys {
    phone: [u8; 65],
    browser: [u8; 65],
}
fn context(s: &Statement03, e: &ExpectedConsent03<'_>, now: u64, pending: bool) -> Check<Keys> {
    let c = election::require_current(e.election, e.manifest, e.current, now)?;
    crypto::time(e.selection_epoch)?;
    crypto::time(e.owner_deadline_ms)?;
    let owner = election::adapter_contract::OwnerSessionIdentity03 {
        account_id: c.account_id,
        user_id: *e.user.as_bytes(),
        session_id: *e.session.as_bytes(),
    }
    .digest()?;
    let origin = election::adapter_contract::origin_digest(e.canonical_origin)?;
    if s.ids[..4] != [c.account_id, c.device_id, c.line_id, c.binding_id]
        || s.ids[6..8] != [*e.user.as_bytes(), *e.session.as_bytes()]
        || s.numbers[..4]
            != [
                c.binding_generation,
                c.vault_generation,
                c.manifest_version,
                e.selection_epoch,
            ]
        || s.digests[..12]
            != [
                c.selected_reader_key_id,
                *e.archive_reader,
                *e.phone_signer,
                *e.browser_signer,
                c.root_fingerprint,
                c.manifest_digest,
                c.election_commitment,
                c.election_bundle_sha256,
                owner,
                origin,
                *e.device_session_digest,
                *e.physical_digest,
            ]
        || s.peer != e.peer
        || s.integrations != e.integrations
    {
        return Err("consent current selection");
    }
    let inbound = s.recipients(false);
    let outbound = s.recipients(true);
    let (phone, phone_from, phone_until) = e.manifest.authorize(
        &Authorization03 {
            kind: 2,
            account: &c.account_id,
            device: &c.device_id,
            line: &c.line_id,
            signer_id: e.phone_signer,
            readers: &inbound,
        },
        now,
    )?;
    let (browser, browser_from, browser_until) = e.manifest.authorize(
        &Authorization03 {
            kind: 1,
            account: &c.account_id,
            device: &c.device_id,
            line: &c.line_id,
            signer_id: e.browser_signer,
            readers: &outbound,
        },
        now,
    )?;
    let issued = s.numbers[4];
    let setup = s.numbers[5];
    let until = s.numbers[7];
    if now < issued
        || now >= until
        || issued < phone_from.max(browser_from)
        || until > phone_until.min(browser_until).min(e.owner_deadline_ms)
        || pending && (now >= setup || setup > c.permission_expires_at_ms)
    {
        return Err("consent current time");
    }
    Ok(Keys { phone, browser })
}
pub(crate) fn verify_request(
    s: &Statement03,
    signature: &[u8; 64],
    e: &ExpectedConsent03<'_>,
    now: u64,
) -> Check<()> {
    let keys = context(s, e, now, true)?;
    crypto::signature(&keys.browser, signature, &s.request_transcript())
}
pub(crate) fn verify_approval(
    s: &Statement03,
    owner: &[u8; 64],
    phone: &[u8; 64],
    e: &ExpectedConsent03<'_>,
    now: u64,
) -> Check<()> {
    let keys = context(s, e, now, true)?;
    crypto::signature(&keys.browser, owner, &s.request_transcript())?;
    crypto::signature(&keys.phone, phone, &s.approval_transcript(owner))
}
pub(crate) fn verify_install(
    s: &Statement03,
    owner: &[u8; 64],
    phone: &[u8; 64],
    installed: &[u8; 64],
    e: &ExpectedConsent03<'_>,
    now: u64,
) -> Check<()> {
    let keys = context(s, e, now, true)?;
    verify_approval(s, owner, phone, e, now)?;
    crypto::signature(
        &keys.phone,
        installed,
        &s.installation_transcript(owner, phone),
    )
}

/// Reverify exact original receipts while checking present authority separately.
/// Original setup timestamps are historical facts, never a renewed deadline.
pub(crate) fn verify_retained(
    s: &Statement03,
    owner: Option<(&[u8; 64], u64)>,
    phone: Option<(&[u8; 64], u64)>,
    installed: Option<(&[u8; 64], u64)>,
    e: &ExpectedConsent03<'_>,
    now: u64,
) -> Check<()> {
    let keys = context(s, e, now, false)?;
    let (_, setup, _, _) = s.times();
    let issued = s.numbers[4];
    let mut prior = issued;
    if let Some((signature, time)) = owner {
        if time < prior || time >= setup || time > now {
            return Err("consent original request time");
        }
        crypto::signature(&keys.browser, signature, &s.request_transcript())?;
        prior = time;
    }
    if let Some((signature, time)) = phone {
        let (owner, _) = owner.ok_or("consent approval without request")?;
        if time < prior || time >= setup || time > now {
            return Err("consent original approval time");
        }
        crypto::signature(&keys.phone, signature, &s.approval_transcript(owner))?;
        prior = time;
    }
    if let Some((signature, time)) = installed {
        let (owner, _) = owner.ok_or("consent install without request")?;
        let (phone, _) = phone.ok_or("consent install without approval")?;
        if time < prior || time >= setup || time > now {
            return Err("consent original install time");
        }
        crypto::signature(
            &keys.phone,
            signature,
            &s.installation_transcript(owner, phone),
        )?;
    }
    Ok(())
}

/// The only production caller supplies actual held owner/current/physical and
/// registry selection. Public routing inputs cannot construct that witness.
pub(crate) struct Reservation03 {
    pub interval: Uuid,
    pub receipt: Uuid,
    pub opening: Uuid,
    pub issued: u64,
    pub setup: u64,
    pub expires: u64,
    pub nonce: [u8; 32],
}
pub(crate) fn compose(e: &ExpectedConsent03<'_>, reservation: Reservation03) -> Check<Statement03> {
    let Reservation03 {
        interval,
        receipt,
        opening,
        issued,
        setup,
        expires,
        nonce,
    } = reservation;
    let c = election::require_current(e.election, e.manifest, e.current, issued)?;
    let owner = election::adapter_contract::OwnerSessionIdentity03 {
        account_id: c.account_id,
        user_id: *e.user.as_bytes(),
        session_id: *e.session.as_bytes(),
    }
    .digest()?;
    let mut bytes = HEADER.to_vec();
    for id in [
        c.account_id,
        c.device_id,
        c.line_id,
        c.binding_id,
        *interval.as_bytes(),
        *receipt.as_bytes(),
        *e.user.as_bytes(),
        *e.session.as_bytes(),
        *opening.as_bytes(),
    ] {
        bytes.extend(id);
    }
    for value in [
        c.binding_generation,
        c.vault_generation,
        c.manifest_version,
        e.selection_epoch,
        issued,
        setup,
        issued,
        expires,
    ] {
        bytes.extend(value.to_be_bytes());
    }
    for digest in [
        c.selected_reader_key_id,
        *e.archive_reader,
        *e.phone_signer,
        *e.browser_signer,
        c.root_fingerprint,
        c.manifest_digest,
        c.election_commitment,
        c.election_bundle_sha256,
        owner,
        election::adapter_contract::origin_digest(e.canonical_origin)?,
        *e.device_session_digest,
        *e.physical_digest,
        nonce,
    ] {
        bytes.extend(digest);
    }
    bytes.push(DISCLOSURE_VERSION.len() as u8);
    bytes.extend(DISCLOSURE_VERSION.as_bytes());
    bytes.extend(crypto::sha(DISCLOSURE.as_bytes()));
    bytes.push(u8::try_from(e.peer.len()).map_err(|_| "consent peer width")?);
    bytes.extend(e.peer);
    bytes.push(u8::try_from(e.integrations.len()).map_err(|_| "consent integrations width")?);
    for r in e.integrations {
        bytes.extend(r.connector_id.as_bytes());
        bytes.extend(r.read_grant_id.as_bytes());
        bytes.extend(r.key_id);
    }
    let statement = Statement03::decode(&bytes)?;
    context(&statement, e, issued, true)?;
    Ok(statement)
}

/// A commitment to independently authenticated physical evidence, not a permit.
pub enum PhysicalSource03<'a> {
    OriginalV2 {
        original_binding: Uuid,
        activation_evidence: &'a [u8],
    },
    OwnerRefresh03 {
        refresh_id: Uuid,
        bundle: &'a [u8],
        accepted_ms: u64,
        installed_ms: u64,
    },
}
pub fn physical_digest(
    account: Uuid,
    device: Uuid,
    line: Uuid,
    binding: Uuid,
    election: &[u8; 32],
    session: &[u8; 32],
    source: PhysicalSource03<'_>,
) -> Check<[u8; 32]> {
    let (tag, source) = match source {
        PhysicalSource03::OriginalV2 {
            original_binding,
            activation_evidence,
        } => {
            if original_binding.is_nil()
                || activation_evidence.is_empty()
                || activation_evidence.len() > 4096
            {
                return Err("physical original source");
            }
            (
                1,
                [
                    original_binding.as_bytes().as_slice(),
                    &crypto::sha(activation_evidence),
                ]
                .concat(),
            )
        }
        PhysicalSource03::OwnerRefresh03 {
            refresh_id,
            bundle,
            accepted_ms,
            installed_ms,
        } => {
            crypto::time(accepted_ms)?;
            crypto::time(installed_ms)?;
            if refresh_id.is_nil() || bundle.len() != 745 || installed_ms < accepted_ms {
                return Err("physical refresh source");
            }
            (
                2,
                [
                    refresh_id.as_bytes().as_slice(),
                    &crypto::sha(bundle),
                    &accepted_ms.to_be_bytes(),
                    &installed_ms.to_be_bytes(),
                ]
                .concat(),
            )
        }
    };
    let mut payload = vec![tag];
    for id in [account, device, line, binding] {
        if id.is_nil() {
            return Err("physical scope");
        }
        payload.extend_from_slice(id.as_bytes());
    }
    nonzero(election)?;
    nonzero(session)?;
    payload.extend(election);
    payload.extend(session);
    payload.extend(source);
    Ok(crypto::sha(&crypto::framed(
        b"ZTSE/line/payload-profile/physical-selection/v1\0",
        &payload,
    )?))
}

pub(crate) mod live;
#[cfg(test)]
mod tests;
