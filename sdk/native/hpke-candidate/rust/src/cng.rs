//! Native Windows PCP handles. No scalar import, overwrite or software fallback.
use crate::{Error, open_shared_content};
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
use std::{ptr, sync::Mutex};
use zeroize::Zeroizing;
const SILENT: u32 = 0x40;
const PREFIX: &str = "zrotext-candidate-native-";
#[derive(Debug)]
pub struct NativeError {
    pub operation: &'static str,
    pub status: u32,
}
impl std::fmt::Display for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "native protected custody {}: {:08x}",
            self.operation, self.status
        )
    }
}
impl std::error::Error for NativeError {}
fn refused(operation: &'static str) -> NativeError {
    NativeError {
        operation,
        status: 0,
    }
}
fn check(operation: &'static str, status: u32) -> Result<(), NativeError> {
    if status == 0 {
        Ok(())
    } else {
        Err(NativeError { operation, status })
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
#[link(name = "ncrypt")]
unsafe extern "system" {
    fn NCryptOpenStorageProvider(out: *mut usize, name: *const u16, flags: u32) -> u32;
    fn NCryptIsAlgSupported(h: usize, name: *const u16, flags: u32) -> u32;
    fn NCryptGetProperty(
        h: usize,
        name: *const u16,
        out: *mut u8,
        len: u32,
        size: *mut u32,
        flags: u32,
    ) -> u32;
    fn NCryptSetProperty(h: usize, name: *const u16, input: *const u8, len: u32, flags: u32)
    -> u32;
    fn NCryptCreatePersistedKey(
        h: usize,
        out: *mut usize,
        alg: *const u16,
        name: *const u16,
        legacy: u32,
        flags: u32,
    ) -> u32;
    fn NCryptOpenKey(h: usize, out: *mut usize, name: *const u16, legacy: u32, flags: u32) -> u32;
    fn NCryptFinalizeKey(h: usize, flags: u32) -> u32;
    fn NCryptExportKey(
        h: usize,
        export: usize,
        kind: *const u16,
        params: *const u8,
        out: *mut u8,
        len: u32,
        size: *mut u32,
        flags: u32,
    ) -> u32;
    fn NCryptImportKey(
        h: usize,
        import: usize,
        kind: *const u16,
        params: *const u8,
        out: *mut usize,
        input: *const u8,
        len: u32,
        flags: u32,
    ) -> u32;
    fn NCryptSecretAgreement(key: usize, peer: usize, out: *mut usize, flags: u32) -> u32;
    fn NCryptDeriveKey(
        h: usize,
        kdf: *const u16,
        params: *const u8,
        out: *mut u8,
        len: u32,
        size: *mut u32,
        flags: u32,
    ) -> u32;
    fn NCryptDeleteKey(h: usize, flags: u32) -> u32;
    fn NCryptFreeObject(h: usize) -> u32;
    fn NCryptSignHash(
        h: usize,
        padding: *const u8,
        digest: *const u8,
        digest_len: u32,
        out: *mut u8,
        out_len: u32,
        size: *mut u32,
        flags: u32,
    ) -> u32;
}
struct OwnedHandle(usize);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: this handle was returned by NCrypt and is uniquely owned.
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}
struct State {
    provider: OwnedHandle,
    key: OwnedHandle,
    name: String,
    qualified: bool,
    closed: bool,
}
impl Drop for State {
    fn drop(&mut self) {
        self.close();
    }
}
fn property(handle: usize, name: &str) -> Result<u32, NativeError> {
    let mut value = 0u32;
    let mut size = 0;
    let name = wide(name); // SAFETY: fixed-width output and live terminated UTF16 name.
    check("property", unsafe {
        NCryptGetProperty(
            handle,
            name.as_ptr(),
            (&mut value as *mut u32).cast(),
            4,
            &mut size,
            SILENT,
        )
    })?;
    if size != 4 {
        return Err(refused("property width"));
    }
    Ok(value)
}
impl State {
    fn start() -> Result<Self, NativeError> {
        Self::start_algorithm("ECDH_P256")
    }
    fn start_algorithm(algorithm: &str) -> Result<Self, NativeError> {
        let mut value = Self {
            provider: OwnedHandle(0),
            key: OwnedHandle(0),
            name: String::new(),
            qualified: false,
            closed: false,
        };
        let name = wide("Microsoft Platform Crypto Provider");
        let alg = wide(algorithm); // SAFETY: output handle initialized zero, strings remain alive through calls.
        check("provider", unsafe {
            NCryptOpenStorageProvider(&mut value.provider.0, name.as_ptr(), 0)
        })?;
        if property(value.provider.0, "Impl Type")? & 1 == 0 {
            return Err(refused("hardware provider"));
        }
        check("algorithm", unsafe {
            NCryptIsAlgSupported(value.provider.0, alg.as_ptr(), 0)
        })?;
        Ok(value)
    }
    fn public(&self) -> Result<Vec<u8>, NativeError> {
        self.public_magic(0x314b4345)
    }
    fn public_magic(&self, magic: u32) -> Result<Vec<u8>, NativeError> {
        if self.closed || self.key.0 == 0 {
            return Err(refused("closed key"));
        }
        let mut blob = [0u8; 72];
        let mut size = 0;
        let name = wide("ECCPUBLICBLOB"); // SAFETY: output buffer exactly72 bytes, public export only.
        check("public export", unsafe {
            NCryptExportKey(
                self.key.0,
                0,
                name.as_ptr(),
                ptr::null(),
                blob.as_mut_ptr(),
                72,
                &mut size,
                SILENT,
            )
        })?;
        if size != 72 || blob[..4] != magic.to_le_bytes() || blob[4..8] != 32u32.to_le_bytes() {
            return Err(refused("P256 public blob"));
        }
        let public = [&[4u8][..], &blob[8..]].concat();
        PublicKey::from_sec1_bytes(&public).map_err(|_| refused("public point"))?;
        Ok(public)
    }
    fn exchange(&self, enc: &[u8]) -> Result<Zeroizing<Vec<u8>>, NativeError> {
        if self.closed || self.key.0 == 0 || enc.len() != 65 || enc[0] != 4 {
            return Err(refused("key/point shape"));
        }
        PublicKey::from_sec1_bytes(enc).map_err(|_| refused("point curve"))?;
        let mut peer = OwnedHandle(0);
        let mut agreement = OwnedHandle(0);
        let mut raw = Zeroizing::new([0u8; 32]);
        let mut size = 0;
        let mut blob = [0u8; 72];
        blob[..8].copy_from_slice(&[0x45, 0x43, 0x4b, 0x31, 32, 0, 0, 0]);
        blob[8..].copy_from_slice(&enc[1..]);
        let kind = wide("ECCPUBLICBLOB");
        let kdf = wide("TRUNCATE");
        // SAFETY: all input/output buffers are sized and alive; RAII frees new handles on every path.
        check("public import", unsafe {
            NCryptImportKey(
                self.provider.0,
                0,
                kind.as_ptr(),
                ptr::null(),
                &mut peer.0,
                blob.as_ptr(),
                72,
                SILENT,
            )
        })?;
        check("agreement", unsafe {
            NCryptSecretAgreement(self.key.0, peer.0, &mut agreement.0, SILENT)
        })?;
        check("derive", unsafe {
            NCryptDeriveKey(
                agreement.0,
                kdf.as_ptr(),
                ptr::null(),
                raw.as_mut_ptr(),
                32,
                &mut size,
                0,
            )
        })?;
        if size != 32 {
            return Err(refused("shared width"));
        }
        Ok(Zeroizing::new(raw.iter().rev().copied().collect()))
    }
    fn qualify(&self) -> Result<(), NativeError> {
        if property(self.key.0, "Export Policy")? != 0 {
            return Err(refused("export policy"));
        }
        let kind = wide("ECCPRIVATEBLOB");
        let mut size = 0;
        // SAFETY: size query only, no buffer exists to receive private material.
        let status = unsafe {
            NCryptExportKey(
                self.key.0,
                0,
                kind.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                0,
                &mut size,
                SILENT,
            )
        };
        if status != 0x80090010 && status != 0x8009000a {
            return Err(refused("private export denial"));
        }
        let public = self.public()?;
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut()).map_err(|_| refused("CSPRNG"))?;
        let peer =
            SecretKey::from_slice(entropy.as_ref()).map_err(|_| refused("ephemeral peer"))?;
        let point = PublicKey::from_sec1_bytes(&public).map_err(|_| refused("public curve"))?;
        let expected = diffie_hellman(peer.to_nonzero_scalar(), point.as_affine());
        let actual = self.exchange(peer.public_key().to_sec1_point(false).as_bytes())?;
        if actual.as_slice() != expected.raw_secret_bytes().as_slice() {
            return Err(refused("ECDH qualification"));
        }
        Ok(())
    }
    fn close(&mut self) {
        self.qualified = false;
        self.closed = true;
        self.key = OwnedHandle(0);
        self.provider = OwnedHandle(0);
    }
}
/// Qualified native object; caller-provided booleans or raw handles cannot mint one.
pub struct HardwareRecipient {
    state: Mutex<State>,
}
impl HardwareRecipient {
    pub fn probe() -> Result<(), NativeError> {
        State::start().map(drop)
    }
    pub fn create<F>(record_pending: F) -> Result<Self, NativeError>
    where
        F: FnOnce(&str) -> Result<(), NativeError>,
    {
        let mut state = State::start()?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| refused("CSPRNG"))?;
        state.name = PREFIX.to_owned()
            + &random
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>();
        record_pending(&state.name)?;
        let name = wide(&state.name);
        let alg = wide("ECDH_P256");
        // SAFETY: fresh generated namespace, no overwrite; receipt succeeded before creation.
        check("create", unsafe {
            NCryptCreatePersistedKey(
                state.provider.0,
                &mut state.key.0,
                alg.as_ptr(),
                name.as_ptr(),
                0,
                SILENT,
            )
        })?;
        let result = (|| {
            let policy = 0u32;
            let prop = wide("Export Policy");
            check("deny export", unsafe {
                NCryptSetProperty(
                    state.key.0,
                    prop.as_ptr(),
                    (&policy as *const u32).cast(),
                    4,
                    0,
                )
            })?;
            check("finalize", unsafe {
                NCryptFinalizeKey(state.key.0, SILENT)
            })?;
            state.qualify()
        })();
        if let Err(error) = result {
            check("owned failed-create cleanup", unsafe {
                NCryptDeleteKey(state.key.0, 0)
            })?;
            state.key.0 = 0;
            return Err(error);
        }
        state.qualified = true;
        Ok(Self {
            state: Mutex::new(state),
        })
    }
    pub fn open(name: &str, expected: &[u8]) -> Result<Self, NativeError> {
        if !name.starts_with(PREFIX)
            || name.len() != PREFIX.len() + 32
            || !name[PREFIX.len()..]
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            || expected.len() != 65
            || expected[0] != 4
        {
            return Err(refused("alias/point shape"));
        }
        PublicKey::from_sec1_bytes(expected).map_err(|_| refused("expected point"))?;
        let mut state = State::start()?;
        state.name = name.to_owned();
        let name = wide(name);
        // SAFETY: exact validated alias, no creation or fallback occurs.
        check("open", unsafe {
            NCryptOpenKey(state.provider.0, &mut state.key.0, name.as_ptr(), 0, SILENT)
        })?;
        state.qualify()?;
        if state.public()? != expected {
            return Err(refused("persistent public binding"));
        }
        state.qualified = true;
        Ok(Self {
            state: Mutex::new(state),
        })
    }
    pub fn public_point(&self) -> Result<Vec<u8>, NativeError> {
        let state = self.state.lock().map_err(|_| refused("poisoned lock"))?;
        if !state.qualified {
            return Err(refused("qualification"));
        }
        state.public()
    }
    pub fn alias(&self) -> Result<String, NativeError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| refused("poisoned lock"))?
            .name
            .clone())
    }
    pub fn close(&self) -> Result<(), NativeError> {
        self.state
            .lock()
            .map_err(|_| refused("poisoned lock"))?
            .close();
        Ok(())
    }
    pub fn delete(&self) -> Result<(), NativeError> {
        let mut state = self.state.lock().map_err(|_| refused("poisoned lock"))?;
        if !state.qualified || state.closed {
            return Err(refused("closed/unqualified deletion"));
        }
        // SAFETY: delete exact owned open handle, flags0, never enumerate aliases.
        check("delete", unsafe { NCryptDeleteKey(state.key.0, 0) })?;
        state.key.0 = 0;
        state.close();
        Ok(())
    }
    pub fn open_cek(
        &self,
        public: &[u8],
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if ct.len() != 48 {
            return Err(Error::ProtectedUnavailable);
        };
        self.open_content(public, enc, info, aad, ct)
    }
    pub(crate) fn open_content(
        &self,
        public: &[u8],
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let state = self.state.lock().map_err(|_| Error::ProtectedUnavailable)?;
        if !state.qualified
            || state.closed
            || info.len() > 36864
            || aad.len() > 36864
            || !(17..=32784).contains(&ct.len())
        {
            return Err(Error::ProtectedUnavailable);
        }
        if state.public().map_err(|_| Error::ProtectedUnavailable)? != public {
            return Err(Error::Authentication);
        }
        let dh = state
            .exchange(enc)
            .map_err(|_| Error::ProtectedUnavailable)?;
        open_shared_content(&dh, public, enc, info, aad, ct)
    }
}

const SIGN_PREFIX: &str = "zrotext-candidate-sign-";
/// Qualified Windows signing object. No arbitrary digest or private export API.
pub struct HardwareSigner {
    state: Mutex<(State, bool)>,
}
fn signer_digest(state: &State, digest: &[u8]) -> Result<Vec<u8>, NativeError> {
    if state.closed || state.key.0 == 0 || digest.len() != 32 {
        return Err(refused("signing shape/closed"));
    }
    let mut out = [0u8; 64];
    let mut size = 0;
    // SAFETY: initialized exact-width buffers and live uniquely owned key handle.
    check("sign", unsafe {
        NCryptSignHash(
            state.key.0,
            ptr::null(),
            digest.as_ptr(),
            32,
            out.as_mut_ptr(),
            64,
            &mut size,
            SILENT,
        )
    })?;
    if size != 64 {
        return Err(refused("signature width"));
    }
    let signature =
        p256::ecdsa::Signature::from_slice(&out).map_err(|_| refused("signature scalars"))?;
    Ok(signature.normalize_s().to_bytes().to_vec())
}
fn signer_verify(point: &[u8], digest: &[u8], signature: &[u8]) -> Result<(), NativeError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| refused("signer point"))?
        .verify_prehash(
            digest,
            &p256::ecdsa::Signature::from_slice(signature).map_err(|_| refused("signature"))?,
        )
        .map_err(|_| refused("signature verification"))
}
fn qualify_signer(state: &State) -> Result<(), NativeError> {
    if property(state.key.0, "Export Policy")? != 0 {
        return Err(refused("private export policy"));
    }
    let name = wide("ECCPRIVATEBLOB");
    let mut size = 0;
    // SAFETY: size query only, private bytes are never exported.
    let status = unsafe {
        NCryptExportKey(
            state.key.0,
            0,
            name.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            0,
            &mut size,
            SILENT,
        )
    };
    if status != 0x80090010 && status != 0x8009000a {
        return Err(refused("private export refusal"));
    }
    let point = state.public_magic(0x31534345)?;
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| refused("CSPRNG"))?;
    signer_verify(&point, &challenge, &signer_digest(state, &challenge)?)
}
impl HardwareSigner {
    pub fn probe() -> Result<(), NativeError> {
        State::start_algorithm("ECDSA_P256").map(drop)
    }
    pub fn create<F>(record_pending: F) -> Result<Self, NativeError>
    where
        F: FnOnce(&str) -> Result<(), NativeError>,
    {
        let mut state = State::start_algorithm("ECDSA_P256")?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| refused("CSPRNG"))?;
        state.name = SIGN_PREFIX.to_owned()
            + &random
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>();
        record_pending(&state.name)?;
        let name = wide(&state.name);
        let alg = wide("ECDSA_P256");
        // SAFETY: fresh generated namespace, no overwrite; receipt succeeded before creation.
        check("create", unsafe {
            NCryptCreatePersistedKey(
                state.provider.0,
                &mut state.key.0,
                alg.as_ptr(),
                name.as_ptr(),
                0,
                SILENT,
            )
        })?;
        let result = (|| {
            let policy = 0u32;
            let prop = wide("Export Policy");
            check("deny export", unsafe {
                NCryptSetProperty(
                    state.key.0,
                    prop.as_ptr(),
                    (&policy as *const u32).cast(),
                    4,
                    0,
                )
            })?;
            check("finalize", unsafe {
                NCryptFinalizeKey(state.key.0, SILENT)
            })?;
            qualify_signer(&state)
        })();
        if let Err(error) = result {
            check("owned failed-create cleanup", unsafe {
                NCryptDeleteKey(state.key.0, 0)
            })?;
            state.key.0 = 0;
            return Err(error);
        }
        state.qualified = true;
        Ok(Self {
            state: Mutex::new((state, true)),
        })
    }
    pub fn open(name: &str, expected: &[u8]) -> Result<Self, NativeError> {
        if !name.starts_with(SIGN_PREFIX)
            || name.len() != SIGN_PREFIX.len() + 32
            || !name[SIGN_PREFIX.len()..]
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            || expected.len() != 65
            || expected[0] != 4
        {
            return Err(refused("alias/point shape"));
        }
        PublicKey::from_sec1_bytes(expected).map_err(|_| refused("expected point"))?;
        let mut state = State::start_algorithm("ECDSA_P256")?;
        state.name = name.to_owned();
        let name = wide(name);
        // SAFETY: exact validated alias, no creation or fallback occurs.
        check("open", unsafe {
            NCryptOpenKey(state.provider.0, &mut state.key.0, name.as_ptr(), 0, SILENT)
        })?;
        qualify_signer(&state)?;
        if state.public_magic(0x31534345)? != expected {
            return Err(refused("persistent public binding"));
        }
        state.qualified = true;
        Ok(Self {
            state: Mutex::new((state, false)),
        })
    }

    pub fn public_point(&self) -> Result<Vec<u8>, NativeError> {
        let guard = self.state.lock().map_err(|_| refused("poisoned lock"))?;
        if !guard.0.qualified {
            return Err(refused("qualification"));
        }
        guard.0.public_magic(0x31534345)
    }
    pub fn alias(&self) -> Result<String, NativeError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| refused("poisoned lock"))?
            .0
            .name
            .clone())
    }
    pub fn close(&self) -> Result<(), NativeError> {
        self.state
            .lock()
            .map_err(|_| refused("poisoned lock"))?
            .0
            .close();
        Ok(())
    }
    /// Delete only the exact key created by this instance, never an opened alias.
    pub fn delete_created(&self) -> Result<(), NativeError> {
        let mut guard = self.state.lock().map_err(|_| refused("poisoned lock"))?;
        if !guard.1 || guard.0.closed || guard.0.key.0 == 0 {
            return Err(refused("not owned creation"));
        }
        // SAFETY: exact owned handle, flags zero; success consumes this native handle.
        check("delete", unsafe { NCryptDeleteKey(guard.0.key.0, 0) })?;
        guard.0.key.0 = 0;
        guard.1 = false;
        guard.0.close();
        Ok(())
    }
    pub fn sign_envelope03(&self, unsigned: &[u8]) -> Result<Vec<u8>, NativeError> {
        self.sign_profile(unsigned, 3)
    }
    pub fn sign_envelope02(&self, unsigned: &[u8]) -> Result<Vec<u8>, NativeError> {
        self.sign_profile(unsigned, 2)
    }
    fn sign_profile(&self, unsigned: &[u8], profile: u8) -> Result<Vec<u8>, NativeError> {
        use sha2::{Digest, Sha256};
        let guard = self.state.lock().map_err(|_| refused("poisoned lock"))?;
        let state = &guard.0;
        if !state.qualified
            || state.closed
            || !(493..=34149).contains(&unsigned.len())
            || unsigned[..8] != [90, 84, 83, 69, profile, 1, 0, 0]
        {
            return Err(refused("unsigned envelope shape"));
        }
        let transcript = [
            if profile == 2 {
                b"ZTSE/sign/v2\0".as_slice()
            } else {
                b"ZTSE/sign/v3\0".as_slice()
            },
            &(unsigned.len() as u32).to_be_bytes(),
            unsigned,
        ]
        .concat();
        let digest = Sha256::digest(&transcript);
        let signature = signer_digest(state, &digest)?;
        signer_verify(&state.public_magic(0x31534345)?, &digest, &signature)?;
        Ok(signature)
    }
}
