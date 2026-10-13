//! Candidate RFC9180 base-mode recipient primitive, never envelope authority.
#[cfg(windows)]
pub mod cng;
#[cfg(windows)]
pub mod compose;
#[cfg(windows)]
pub mod compose02;
pub mod elected_reader;
pub mod election;
pub mod envelope;
pub mod journal;
pub mod manifest;
pub mod original_checkpoint;
pub mod original_current;
pub mod original_http;
pub mod original_reply;
#[cfg(windows)]
pub mod outbound;
pub mod reader;
use aes_gcm::{
    Aes128Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
use sha2::Sha256;
use zeroize::Zeroizing;
const KEM: &[u8] = b"KEM\0\x10";
const SUITE: &[u8] = b"HPKE\0\x10\0\x01\0\x01";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Shape,
    Authentication,
    ProtectedUnavailable,
}
fn extract(salt: &[u8], suite: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new([b"HPKE-v1".as_slice(), suite, label, ikm].concat());
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &input);
    Zeroizing::new(prk.to_vec())
}
fn expand(
    prk: &[u8],
    suite: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let context = [
        &(len as u16).to_be_bytes()[..],
        b"HPKE-v1",
        suite,
        label,
        info,
    ]
    .concat();
    let mut output = Zeroizing::new(vec![0; len]);
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| Error::Shape)?
        .expand(&context, &mut output)
        .map_err(|_| Error::Shape)?;
    Ok(output)
}
/// Open one 32-byte CEK at sequence zero using explicitly software/exportable
/// key material. Caller independently verifies authority and replay state.
pub fn open_software_cek(
    private: &[u8],
    public: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if private.len() != 32
        || public.len() != 65
        || public[0] != 4
        || enc.len() != 65
        || enc[0] != 4
        || info.len() > 36864
        || aad.len() > 36864
        || ciphertext.len() != 48
    {
        return Err(Error::Shape);
    }
    let sk = SecretKey::from_slice(private).map_err(|_| Error::Shape)?;
    if sk.public_key().to_sec1_point(false).as_bytes() != public {
        return Err(Error::Shape);
    }
    let pk = PublicKey::from_sec1_bytes(enc).map_err(|_| Error::Shape)?;
    let dh = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    open_shared_cek(dh.raw_secret_bytes(), public, enc, info, aad, ciphertext)
}
fn open_shared_cek(
    dh: &[u8],
    public: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if dh.len() != 32
        || public.len() != 65
        || enc.len() != 65
        || info.len() > 36864
        || aad.len() > 36864
        || ciphertext.len() != 48
    {
        return Err(Error::Shape);
    }
    let eae = extract(&[], KEM, b"eae_prk", dh);
    let shared = expand(&eae, KEM, b"shared_secret", &[enc, public].concat(), 32)?;
    let psk_hash = extract(&[], SUITE, b"psk_id_hash", &[]);
    let info_hash = extract(&[], SUITE, b"info_hash", info);
    let context = [&[0u8][..], psk_hash.as_slice(), info_hash.as_slice()].concat();
    let secret = extract(&shared, SUITE, b"secret", &[]);
    let key = expand(&secret, SUITE, b"key", &context, 16)?;
    let nonce = expand(&secret, SUITE, b"base_nonce", &context, 12)?;
    let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| Error::Shape)?;
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| Error::Shape)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}
/// No maintained protected recipient provider exists here. Never import a raw
/// scalar or silently fall back when protected custody is required.
pub fn open_protected_cek() -> Result<Zeroizing<Vec<u8>>, Error> {
    Err(Error::ProtectedUnavailable)
}
pub mod original_read;
