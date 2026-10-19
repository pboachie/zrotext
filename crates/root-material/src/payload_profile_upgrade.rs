// SPDX-License-Identifier: AGPL-3.0-only
//! First same-root02-to03 manifest only, preserving every prior key and expiry.
//! Scope/high-water are independently expected; no network/election/permission is supplied.
use super::*;

#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub account: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub origin: String,
    pub fingerprint: [u8; 32],
    pub predecessor_version: u64,
    pub predecessor_digest: [u8; 32],
    pub phone_reader: [u8; 32],
    /// Independently paired enrollment signer ID; not manifest conversation role4.
    pub phone_signer: [u8; 32],
    pub issued_ms: u64,
}
pub struct Expected {
    pub identity: ExpectedIdentity,
    pub scope: Scope,
}
pub struct Proposal {
    pub scope: Scope,
    predecessor: Vec<u8>,
    unsigned: Vec<u8>,
}
impl Proposal {
    pub fn predecessor(&self) -> &[u8] {
        &self.predecessor
    }
    pub fn unsigned(&self) -> &[u8] {
        &self.unsigned
    }
}
fn validate(s: &Scope) -> Result<()> {
    if [s.account, s.device, s.line].contains(&[0; 16])
        || [
            s.fingerprint,
            s.predecessor_digest,
            s.phone_reader,
            s.phone_signer,
        ]
        .contains(&[0; 32])
        || !sealed_root_enrollment::canonical_origin(&s.origin)
        || s.origin.len() > 512
        || [s.predecessor_version, s.issued_ms]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
    {
        return Err(Error);
    }
    Ok(())
}
/// ZTPU01: account/device/line16, origin(u16+ASCII), fingerprint32, version8,
/// predecessorDigest/phoneReader/phoneSigner32, issued8, signed02/unsigned03(u16+bytes).
pub fn decode(bytes: &[u8]) -> Result<Proposal> {
    if bytes.len() > MAX_PROPOSAL {
        return Err(Error);
    }
    let mut c = Cursor { bytes, at: 0 };
    if c.take(5)? != b"ZTPU\x01" {
        return Err(Error);
    }
    let account = c.array()?;
    let device = c.array()?;
    let line = c.array()?;
    let origin = String::from_utf8(c.sized()?).map_err(|_| Error)?;
    let fingerprint = c.array()?;
    let predecessor_version = c.num()?;
    let predecessor_digest = c.array()?;
    let phone_reader = c.array()?;
    let phone_signer = c.array()?;
    let issued_ms = c.num()?;
    let predecessor = c.sized()?;
    let unsigned = c.sized()?;
    if c.at != bytes.len() {
        return Err(Error);
    }
    let scope = Scope {
        account,
        device,
        line,
        origin,
        fingerprint,
        predecessor_version,
        predecessor_digest,
        phone_reader,
        phone_signer,
        issued_ms,
    };
    validate(&scope)?;
    Ok(Proposal {
        scope,
        predecessor,
        unsigned,
    })
}
pub fn inspect<'a>(p: &'a Proposal, e: &Expected, now: u64) -> Result<&'a Scope> {
    validate(&e.scope)?;
    if p.scope != e.scope
        || e.scope.account != e.identity.account_id
        || e.scope.origin != e.identity.origin
        || e.scope.fingerprint != e.identity.root_fingerprint
    {
        return Err(Error);
    }
    let s = &p.scope;
    let before = manifest(&p.predecessor, true, &e.identity, now)?;
    if before.version != s.predecessor_version
        || hash(&before.bytes[..before.bytes.len() - 64]) != s.predecessor_digest
        || s.issued_ms < before.issued
        || s.issued_ms > now
    {
        return Err(Error);
    }
    let next = before
        .version
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(Error)?;
    let mut exact = b"ZTMA\x03\x03\x02".to_vec();
    exact.extend_from_slice(&before.bytes[5..before.bytes.len() - 64]);
    exact[31..39].copy_from_slice(&next.to_be_bytes());
    exact[39..47].copy_from_slice(&s.issued_ms.to_be_bytes());
    exact[55..87].copy_from_slice(&s.predecessor_digest);
    if exact != p.unsigned {
        return Err(Error);
    }
    // All old key records, root, account and expiry are exact. Validate the resulting
    // equivalent02 grammar as well; no general03 signer or key mutation is exposed.
    let equivalent02 = [&b"ZTMA\x02"[..], &exact[7..]].concat();
    manifest(&equivalent02, false, &e.identity, now)?;
    let selected: Vec<_> = before
        .records
        .iter()
        .filter(|r| {
            r[0] == 1
                && r[148] == 1
                && u64::from_be_bytes(r[132..140].try_into().unwrap()) <= now
                && now < u64::from_be_bytes(r[140..148].try_into().unwrap())
                && r[98..114] == s.device
                && r[114..130] == s.line
        })
        .collect();
    if selected.len() != 1 || selected[0][1..33] != s.phone_reader {
        return Err(Error);
    }
    Ok(s)
}
#[cfg(feature = "unlock")]
pub fn sign(root: &RootSecret, p: &Proposal, e: &Expected, now: u64) -> Result<Vec<u8>> {
    inspect(p, e, now)?;
    let key = SigningKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
    if key.verifying_key().to_sec1_point(false).as_bytes() != &p.unsigned[87..152] {
        return Err(Error);
    }
    let transcript = [
        b"ZTSE/manifest/v3\0".as_slice(),
        &(p.unsigned.len() as u32).to_be_bytes(),
        &p.unsigned,
    ]
    .concat();
    let signature: Signature = key.sign(&transcript);
    Ok([
        p.unsigned.as_slice(),
        signature.normalize_s().to_bytes().as_slice(),
    ]
    .concat())
}

#[cfg(all(test, feature = "unlock"))]
#[path = "payload_profile_upgrade_tests.rs"]
mod tests;

#[cfg(test)]
mod public_vector {
    use super::*;
    fn bytes(value: &serde_json::Value) -> Vec<u8> {
        value
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn fixed<const N: usize>(value: &serde_json::Value) -> [u8; N] {
        bytes(value).try_into().unwrap()
    }
    #[test]
    fn independent_public_proposal_and_signatures_interoperate_without_root_secret() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/v1/vectors/sealed-profile03-upgrade-proposal-01.json"
        ))
        .unwrap();
        let s = &v["scope"];
        let n = |field: &str| s[field].as_str().unwrap().parse::<u64>().unwrap();
        let scope = Scope {
            account: fixed(&s["account"]),
            device: fixed(&s["device"]),
            line: fixed(&s["line"]),
            origin: s["origin"].as_str().unwrap().into(),
            fingerprint: fixed(&s["rootFingerprint"]),
            predecessor_version: n("predecessorVersion"),
            predecessor_digest: fixed(&s["predecessorDigest"]),
            phone_reader: fixed(&s["phoneReaderKeyId"]),
            phone_signer: fixed(&s["phoneSigningKeyId"]),
            issued_ms: n("issuedMs"),
        };
        let expected = Expected {
            identity: ExpectedIdentity {
                account_id: scope.account,
                origin: scope.origin.clone(),
                root_fingerprint: scope.fingerprint,
            },
            scope,
        };
        let p = decode(&bytes(&v["proposalHex"])).unwrap();
        assert_eq!(
            key_id(4, &bytes(&v["deviceEnrollmentSigningPointHex"])),
            expected.scope.phone_signer
        );
        assert!(inspect(&p, &expected, n("issuedMs")).is_ok());
        assert_eq!(p.predecessor, bytes(&v["predecessorSignedHex"]));
        assert_eq!(p.unsigned, bytes(&v["unsigned03Hex"]));
        let signed = bytes(&v["signed03Hex"]);
        assert_eq!(&signed[..signed.len() - 64], p.unsigned);
        let signature = Signature::from_slice(&signed[signed.len() - 64..]).unwrap();
        assert_eq!(signature.normalize_s().to_bytes(), signature.to_bytes());
        let key = VerifyingKey::from_sec1_bytes(&signed[87..152]).unwrap();
        let transcript = [
            b"ZTSE/manifest/v3\0".as_slice(),
            &(p.unsigned.len() as u32).to_be_bytes(),
            &p.unsigned,
        ]
        .concat();
        assert!(key.verify(&transcript, &signature).is_ok());
    }
}
