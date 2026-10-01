// SPDX-License-Identifier: AGPL-3.0-only
//! One preserved-record activation successor. No interval exists yet. Session/peer
//! are contextual approval, NOT manifest-signed consent; authenticated activation
//! must enforce owner/session/line and require separate phone approval.
use super::*;
pub const MAX_PROPOSAL: usize = super::MAX_PROPOSAL;
#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub account: [u8; 16],
    pub session: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub line_generation: u64,
    pub peer: String,
    pub origin: String,
    pub fingerprint: [u8; 32],
    pub predecessor_version: u64,
    pub predecessor_digest: [u8; 32],
    pub phone_reader: [u8; 32],
    pub archive_reader: [u8; 32],
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
/// ZTCA01: account/session/device/line16, generation8, peer(u8+bytes), origin(u16+bytes),
/// fingerprint32, predecessor version8/digest32, phone-reader/archive-reader/phone-signer32,
/// issued8, signed predecessor(u16+bytes), unsigned successor(u16+bytes). Strict EOF, <=20480.
pub fn decode(bytes: &[u8]) -> Result<Proposal> {
    if bytes.len() > MAX_PROPOSAL {
        return Err(Error);
    }
    let mut c = Cursor { bytes, at: 0 };
    if c.take(5)? != b"ZTCA\x01" {
        return Err(Error);
    }
    let account = c.array()?;
    let session = c.array()?;
    let device = c.array()?;
    let line = c.array()?;
    let line_generation = c.num()?;
    let n = c.take(1)?[0] as usize;
    let peer = String::from_utf8(c.take(n)?.to_vec()).map_err(|_| Error)?;
    let origin = String::from_utf8(c.sized()?).map_err(|_| Error)?;
    let fingerprint = c.array()?;
    let predecessor_version = c.num()?;
    let predecessor_digest = c.array()?;
    let phone_reader = c.array()?;
    let archive_reader = c.array()?;
    let phone_signer = c.array()?;
    let issued_ms = c.num()?;
    let predecessor = c.sized()?;
    let unsigned = c.sized()?;
    if c.at != bytes.len() {
        return Err(Error);
    }
    let scope = Scope {
        account,
        session,
        device,
        line,
        line_generation,
        peer,
        origin,
        fingerprint,
        predecessor_version,
        predecessor_digest,
        phone_reader,
        archive_reader,
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
fn validate(s: &Scope) -> Result<()> {
    if [s.account, s.session, s.device, s.line].contains(&[0; 16])
        || [
            s.fingerprint,
            s.predecessor_digest,
            s.phone_reader,
            s.archive_reader,
            s.phone_signer,
        ]
        .contains(&[0; 32])
        || s.peer.len() < 3
        || s.peer.len() > 16
        || !s.peer.starts_with('+')
        || s.peer.as_bytes()[1] == b'0'
        || !s.peer.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        || !sealed_root_enrollment::canonical_origin(&s.origin)
        || s.origin.len() > 512
        || [s.line_generation, s.predecessor_version, s.issued_ms]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
    {
        return Err(Error);
    }
    Ok(())
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
    let after = manifest(&p.unsigned, false, &e.identity, now)?;
    if before.version != s.predecessor_version
        || hash(&before.bytes[..before.bytes.len() - 64]) != s.predecessor_digest
        || s.issued_ms < before.issued
        || s.issued_ms > now
    {
        return Err(Error);
    }
    let version = before
        .version
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(Error)?;
    let mut exact = before.bytes[..before.bytes.len() - 64].to_vec();
    exact[29..37].copy_from_slice(&version.to_be_bytes());
    exact[37..45].copy_from_slice(&s.issued_ms.to_be_bytes());
    exact[53..85].copy_from_slice(&s.predecessor_digest);
    if exact != after.bytes {
        return Err(Error);
    }
    for (role, id) in [
        (1, s.phone_reader),
        (2, s.archive_reader),
        (4, s.phone_signer),
    ] {
        let found: Vec<_> = before
            .records
            .iter()
            .filter(|r| {
                r[0] == role
                    && r[148] == 1
                    && u64::from_be_bytes(r[132..140].try_into().unwrap()) <= now
                    && now < u64::from_be_bytes(r[140..148].try_into().unwrap())
                    && (role == 2 || (r[98..114] == s.device && r[114..130] == s.line))
            })
            .collect();
        if found.len() != 1 || found[0][1..33] != id {
            return Err(Error);
        }
        let r = found[0];
        if r[148] != 1
            || number(&r[132..140])? > now
            || number(&r[140..148])? <= now
            || role != 2 && (r[98..114] != s.device || r[114..130] != s.line)
        {
            return Err(Error);
        }
    }
    Ok(s)
}
pub fn sign(root: &RootSecret, p: &Proposal, e: &Expected, now: u64) -> Result<Vec<u8>> {
    inspect(p, e, now)?;
    let key = SigningKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
    if key.verifying_key().to_sec1_point(false).as_bytes() != &p.unsigned[85..150] {
        return Err(Error);
    }
    let signature: Signature = key.sign(&transcript(&p.unsigned));
    let mut out = p.unsigned.clone();
    out.extend_from_slice(&signature.normalize_s().to_bytes());
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (RootSecret, Proposal, Expected) {
        let (root, old, e) = super::super::tests::fixture();
        let scope = Scope {
            account: old.scope.account,
            session: old.scope.session,
            device: old.scope.device,
            line: old.scope.line,
            line_generation: 1,
            peer: old.scope.peer,
            origin: old.scope.origin,
            fingerprint: old.scope.fingerprint,
            predecessor_version: old.scope.predecessor_version,
            predecessor_digest: old.scope.predecessor_digest,
            phone_reader: old.scope.phone_reader,
            archive_reader: old.scope.archive_reader,
            phone_signer: old.predecessor[151 + 2 * 149 + 1..151 + 2 * 149 + 33]
                .try_into()
                .unwrap(),
            issued_ms: 2000,
        };
        let mut unsigned = old.predecessor[..old.predecessor.len() - 64].to_vec();
        unsigned[29..37].copy_from_slice(&8u64.to_be_bytes());
        unsigned[37..45].copy_from_slice(&2000u64.to_be_bytes());
        unsigned[53..85].copy_from_slice(&scope.predecessor_digest);
        let expected = Expected {
            identity: e.identity,
            scope: scope.clone(),
        };
        (
            root,
            Proposal {
                scope,
                predecessor: old.predecessor,
                unsigned,
            },
            expected,
        )
    }
    fn encoded(p: &Proposal) -> Vec<u8> {
        let s = &p.scope;
        let sized = |b: &[u8]| [&(b.len() as u16).to_be_bytes(), b].concat();
        [
            b"ZTCA\x01".as_slice(),
            &s.account,
            &s.session,
            &s.device,
            &s.line,
            &s.line_generation.to_be_bytes(),
            &[s.peer.len() as u8],
            s.peer.as_bytes(),
            &sized(s.origin.as_bytes()),
            &s.fingerprint,
            &s.predecessor_version.to_be_bytes(),
            &s.predecessor_digest,
            &s.phone_reader,
            &s.archive_reader,
            &s.phone_signer,
            &s.issued_ms.to_be_bytes(),
            &sized(&p.predecessor),
            &sized(&p.unsigned),
        ]
        .concat()
    }
    #[test]
    fn existing_root_signs_only_preserved_activation_and_public_interop() {
        let (root, p, e) = fixture();
        let bytes = encoded(&p);
        let parsed = decode(&bytes).unwrap();
        assert!(inspect(&parsed, &e, 2000).is_ok());
        let signed = sign(&root, &parsed, &e, 2000).unwrap();
        assert_eq!(
            &signed[151..signed.len() - 64],
            &p.predecessor[151..p.predecessor.len() - 64]
        );
        assert!(manifest(&signed, true, &e.identity, 2000).is_ok());
        if std::env::var_os("ZT_ACTIVATION_INTEROP").is_some() {
            println!(
                "ZT_ACTIVATION_PROPOSAL_HEX={}",
                bytes.iter().map(|v| format!("{v:02x}")).collect::<String>()
            );
            println!(
                "ZT_ACTIVATION_SIGNED_HEX={}",
                signed
                    .iter()
                    .map(|v| format!("{v:02x}"))
                    .collect::<String>()
            );
        }
    }
    #[test]
    fn independent_scope_and_checkpoint_substitution_refused() {
        let (_, p, mut e) = fixture();
        let expected = e.scope.clone();
        for n in 0..13 {
            e.scope = expected.clone();
            match n {
                0 => e.scope.account[0] ^= 1,
                1 => e.scope.session[0] ^= 1,
                2 => e.scope.device[0] ^= 1,
                3 => e.scope.line[0] ^= 1,
                4 => e.scope.line_generation += 1,
                5 => e.scope.peer = "+13".into(),
                6 => e.scope.origin = "https://other.invalid".into(),
                7 => e.scope.fingerprint[0] ^= 1,
                8 => e.scope.predecessor_version += 1,
                9 => e.scope.predecessor_digest[0] ^= 1,
                10 => e.scope.phone_reader[0] ^= 1,
                11 => e.scope.archive_reader[0] ^= 1,
                _ => e.scope.phone_signer[0] ^= 1,
            }
            assert!(inspect(&p, &e, 2000).is_err());
        }
    }
    #[test]
    fn every_unsigned_change_including_archive_or_expiry_is_refused() {
        let (_, mut p, e) = fixture();
        for n in 0..p.unsigned.len() {
            p.unsigned[n] ^= 1;
            assert!(inspect(&p, &e, 2000).is_err(), "{n}");
            p.unsigned[n] ^= 1;
        }
    }
    #[test]
    fn truncation_trailing_oversize_wrong_root_and_expiry_are_refused() {
        let (_, p, e) = fixture();
        let bytes = encoded(&p);
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_err());
        }
        assert!(decode(&[bytes, vec![0]].concat()).is_err());
        assert!(decode(&vec![0; MAX_PROPOSAL + 1]).is_err());
        assert!(inspect(&p, &e, 3_600_000).is_err());
        assert!(inspect(&p, &e, 1999).is_err());
        let mut d = [0; 32];
        d[31] = 2;
        let wrong = RootSecret::new(zeroize::Zeroizing::new(d)).unwrap();
        assert!(sign(&wrong, &p, &e, 2000).is_err());
    }
}
