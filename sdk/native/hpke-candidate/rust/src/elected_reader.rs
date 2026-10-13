//! Current elected profile03 plaintext opening; never live grant or replay authority.
use crate::{
    Error,
    election::{ElectionProof, ElectionRecord, require_current_election03},
    envelope::verify_envelope,
    manifest::Manifest,
    reader::{active, key},
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;
pub struct ElectedContext<'a> {
    pub message: &'a [u8; 16],
    pub peer: &'a str,
    pub now: u64,
}
fn need(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}
fn number(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().expect("validated width"))
}
pub fn open_software_elected03(
    input: &[u8],
    m: &Manifest,
    p: &ElectionProof,
    current: &ElectionRecord,
    scalar: &[u8],
    context: &ElectedContext<'_>,
) -> Result<Zeroizing<String>, Error> {
    open_elected03(
        input,
        m,
        p,
        current,
        context,
        |public, enc, info, aad, ct| crate::open_software_cek(scalar, public, enc, info, aad, ct),
    )
}
fn open_elected03<F>(
    input: &[u8],
    m: &Manifest,
    p: &ElectionProof,
    current: &ElectionRecord,
    context: &ElectedContext<'_>,
    unwrap: F,
) -> Result<Zeroizing<String>, Error>
where
    F: FnOnce(&[u8], &[u8], &[u8], &[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>,
{
    let c = require_current_election03(p, m, current, context.now)?;
    need((426..=36864).contains(&input.len()) && context.message.iter().any(|v| *v != 0))?;
    let b = input;
    let now = context.now;
    need(
        b[4] == 3
            && b[5] == 1
            && &b[10..26] == c.b("accountId")
            && &b[26..42] == context.message
            && &b[42..58] == c.b("deviceId")
            && &b[58..74] == c.b("lineId")
            && number(b, 74) == m.version
            && b[82..114] == m.digest,
    )?;
    let observed = number(b, 146);
    let expires = number(b, 154);
    need(
        observed > 0
            && observed <= now
            && observed < m.expires
            && expires > now
            && expires <= m.expires
            && expires <= c.n("permissionExpiresAtMs"),
    )?;
    let signer = key(m, 5, &b[114..146]).ok_or(Error::Authentication)?;
    need(
        active(signer, now, 1)
            && active(signer, observed, 1)
            && expires <= number(signer, 140)
            && &signer[114..130] == c.b("lineId"),
    )?;
    let e = verify_envelope(b, &signer[33..98], 3)?;
    need(&b[164..e.prefix] == context.peer.as_bytes())?;
    let mut selected = None;
    for i in 0..b[e.body_end] as usize {
        let w = &b[e.body_end + 1 + i * 146..e.body_end + 1 + (i + 1) * 146];
        let k = key(m, w[0], &w[1..33]).ok_or(Error::Authentication)?;
        need(active(k, now, 4) && active(k, observed, 4) && expires <= number(k, 140))?;
        if w[0] == 1 {
            need(&k[98..114] == c.b("deviceId") && &k[114..130] == c.b("lineId"))?;
            if &w[1..33] == c.b("selectedReaderKeyId") {
                selected = Some((i, k, w));
            }
        }
    }
    let (i, reader, wrap) = selected.ok_or(Error::Authentication)?;
    let (info, aad) = e.wrap_transcript(i)?;
    let cek = unwrap(&reader[33..98], &wrap[33..98], &info, &aad, &wrap[98..])?;
    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|_| Error::Shape)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::try_from(&b[e.prefix..e.prefix + 12]).map_err(|_| Error::Shape)?,
                Payload {
                    msg: &b[e.prefix + 16..e.body_end],
                    aad: &e.body_aad(),
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    need(
        !plain.is_empty()
            && plain.len() <= 32768
            && !plain.contains(&0)
            && !plain.starts_with(&[239, 187, 191]),
    )?;
    Ok(Zeroizing::new(
        std::str::from_utf8(&plain)
            .map_err(|_| Error::Shape)?
            .to_owned(),
    ))
}
#[cfg(windows)]
pub fn open_hardware_elected03(
    input: &[u8],
    m: &Manifest,
    p: &ElectionProof,
    current: &ElectionRecord,
    custody: &crate::cng::HardwareRecipient,
    context: &ElectedContext<'_>,
) -> Result<Zeroizing<String>, Error> {
    open_elected03(
        input,
        m,
        p,
        current,
        context,
        |public, enc, info, aad, ct| custody.open_cek(public, enc, info, aad, ct),
    )
}
