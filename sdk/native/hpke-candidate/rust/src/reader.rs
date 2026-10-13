//! Candidate archive-only inbound reader; no grants or radio authority.
use crate::{
    Error,
    envelope::verify_envelope,
    manifest::{Manifest, window},
    open_software_cek,
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;
/// Routing and present policy must come from independently authenticated sources.
pub struct ArchiveContext<'a> {
    pub account: &'a [u8; 16],
    pub device: &'a [u8; 16],
    pub line: &'a [u8; 16],
    pub reader: &'a [u8; 32],
    pub peer: &'a str,
    pub now: u64,
}
pub(crate) fn key<'a>(m: &'a Manifest, role: u8, id: &[u8]) -> Option<&'a [u8]> {
    let offset = if m.profile == 3 { 2 } else { 0 };
    (0..m.raw[150 + offset] as usize)
        .map(|i| &m.raw[151 + offset + i * 149..151 + offset + (i + 1) * 149])
        .find(|w| w[0] == role && &w[1..33] == id)
}
fn number(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().expect("validated internal width"))
}
pub(crate) fn active(w: &[u8], now: u64, scope: u16) -> bool {
    w[148] == 1
        && number(w, 132) <= now
        && now < number(w, 140)
        && u16::from_be_bytes([w[130], w[131]]) & scope == scope
}
/// Software/exportable private scalar only. Returned owned text is wiped on drop;
/// native providers and caller copies may retain data. Never a protected fallback.
pub fn open_software_archive02(
    input: &[u8],
    historical: &Manifest,
    current: &Manifest,
    scalar: &[u8],
    context: &ArchiveContext<'_>,
) -> Result<Zeroizing<String>, Error> {
    open_archive02(
        input,
        historical,
        current,
        context,
        |public, enc, info, aad, ct| open_software_cek(scalar, public, enc, info, aad, ct),
    )
}
fn open_archive02<F>(
    input: &[u8],
    historical: &Manifest,
    current: &Manifest,
    context: &ArchiveContext<'_>,
    unwrap: F,
) -> Result<Zeroizing<String>, Error>
where
    F: FnOnce(&[u8], &[u8], &[u8], &[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>,
{
    if !(426..=34082).contains(&input.len())
        || historical.profile != 2
        || current.profile != 2
        || input[4] != 2
        || input[5] != 2
    {
        return Err(Error::Shape);
    }
    let b = input;
    let now = context.now;
    if historical.account != current.account
        || historical.root != current.root
        || now < current.comparison
        || !window(current.issued, current.expires, now)
        || !current.lineage.contains(&historical.digest)
    {
        return Err(Error::Authentication);
    }
    let observed = number(b, 146);
    if observed == 0 || observed > now || !window(historical.issued, historical.expires, observed) {
        return Err(Error::Authentication);
    }
    if &b[10..26] != context.account
        || &b[42..58] != context.device
        || &b[58..74] != context.line
        || b[10..26] != historical.account
        || number(b, 74) != historical.version
        || b[82..114] != historical.digest
    {
        return Err(Error::Authentication);
    }
    let signer = key(historical, 4, &b[114..146]).ok_or(Error::Authentication)?;
    if !active(signer, observed, 2)
        || &signer[98..114] != context.device
        || &signer[114..130] != context.line
    {
        return Err(Error::Authentication);
    }
    let envelope = verify_envelope(b, &signer[33..98], 2)?;
    if &b[179..envelope.prefix] != context.peer.as_bytes() || b[envelope.body_end] != 1 {
        return Err(Error::Authentication);
    }
    let w = &b[envelope.body_end + 1..envelope.unsigned_end];
    if w[0] != 2 || &w[1..33] != context.reader {
        return Err(Error::Authentication);
    }
    let old_reader = key(historical, 2, context.reader).ok_or(Error::Authentication)?;
    let reader = key(current, 2, context.reader).ok_or(Error::Authentication)?;
    if !active(old_reader, observed, 8) || !active(reader, now, 8) {
        return Err(Error::Authentication);
    }
    let (info, aad) = envelope.wrap_transcript(0)?;
    let cek = unwrap(&reader[33..98], &w[33..98], &info, &aad, &w[98..])?;
    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|_| Error::Shape)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::try_from(&b[envelope.prefix..envelope.prefix + 12])
                    .map_err(|_| Error::Shape)?,
                Payload {
                    msg: &b[envelope.prefix + 16..envelope.body_end],
                    aad: &envelope.body_aad(),
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    if plain.is_empty()
        || plain.len() > 32768
        || plain.contains(&0)
        || plain.starts_with(&[239, 187, 191])
    {
        return Err(Error::Shape);
    }
    Ok(Zeroizing::new(
        std::str::from_utf8(&plain)
            .map_err(|_| Error::Shape)?
            .to_owned(),
    ))
}
/// No qualified native protected provider is installed by this candidate module.
pub fn open_protected_archive02() -> Result<Zeroizing<String>, Error> {
    Err(Error::ProtectedUnavailable)
}

#[cfg(windows)]
pub fn open_hardware_archive02(
    input: &[u8],
    historical: &Manifest,
    current: &Manifest,
    custody: &crate::cng::HardwareRecipient,
    context: &ArchiveContext<'_>,
) -> Result<Zeroizing<String>, Error> {
    open_archive02(
        input,
        historical,
        current,
        context,
        |public, enc, info, aad, ct| custody.open_cek(public, enc, info, aad, ct),
    )
}
