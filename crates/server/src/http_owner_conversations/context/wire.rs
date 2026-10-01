// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate client-only HPKE context. Public header is authenticated AAD.
use super::ConversationError;
use uuid::Uuid;

pub const AAD_LEN: usize = 222;
pub const HEADER_LEN: usize = AAD_LEN + 65 + 4;
pub const MAX_PLAINTEXT: usize = 32_768;
pub const MAX_ENVELOPE: usize = HEADER_LEN + MAX_PLAINTEXT + 16;
pub const INFO: &[u8] = b"ZT/workflow-context/hpke/v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub account: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub interval: Uuid,
    pub context: Uuid,
    pub binding_generation: i64,
    pub revision: i64,
    pub expires_ms: i64,
    pub trust_generation: i64,
    pub manifest_version: i64,
    pub peer_digest: [u8; 32],
    pub reader: [u8; 32],
    pub manifest_digest: [u8; 32],
}

impl Header {
    pub fn aad(&self) -> Result<Vec<u8>, ConversationError> {
        if !(1..=3).contains(&self.kind)
            || !(1..=128).contains(&self.revision)
            || [
                self.account,
                self.device,
                self.line,
                self.interval,
                self.context,
            ]
            .iter()
            .any(Uuid::is_nil)
            || [
                self.binding_generation,
                self.revision,
                self.expires_ms,
                self.trust_generation,
                self.manifest_version,
            ]
            .iter()
            .any(|v| *v <= 0)
            || [self.peer_digest, self.reader, self.manifest_digest].contains(&[0; 32])
        {
            return Err(ConversationError::Invalid);
        }
        let mut b = b"ZTWC\x01".to_vec();
        b.push(self.kind);
        for id in [
            self.account,
            self.device,
            self.line,
            self.interval,
            self.context,
        ] {
            b.extend(id.as_bytes());
        }
        for n in [
            self.binding_generation,
            self.revision,
            self.expires_ms,
            self.trust_generation,
            self.manifest_version,
        ] {
            b.extend(n.to_be_bytes());
        }
        for digest in [self.peer_digest, self.reader, self.manifest_digest] {
            b.extend(digest);
        }
        Ok(b)
    }
}

pub fn parse(bytes: &[u8]) -> Result<Header, ConversationError> {
    if !(HEADER_LEN + 17..=MAX_ENVELOPE).contains(&bytes.len()) || &bytes[..5] != b"ZTWC\x01" {
        return Err(ConversationError::Invalid);
    }
    let id = |offset| {
        Uuid::from_slice(&bytes[offset..offset + 16]).map_err(|_| ConversationError::Invalid)
    };
    let number = |offset| i64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let h = Header {
        kind: bytes[5],
        account: id(6)?,
        device: id(22)?,
        line: id(38)?,
        interval: id(54)?,
        context: id(70)?,
        binding_generation: number(86),
        revision: number(94),
        expires_ms: number(102),
        trust_generation: number(110),
        manifest_version: number(118),
        peer_digest: bytes[126..158].try_into().unwrap(),
        reader: bytes[158..190].try_into().unwrap(),
        manifest_digest: bytes[190..222].try_into().unwrap(),
    };
    if h.aad()? != bytes[..AAD_LEN] {
        return Err(ConversationError::Invalid);
    }
    p256::PublicKey::from_sec1_bytes(&bytes[AAD_LEN..AAD_LEN + 65])
        .map_err(|_| ConversationError::Invalid)?;
    let len = u32::from_be_bytes(bytes[HEADER_LEN - 4..HEADER_LEN].try_into().unwrap()) as usize;
    if len != bytes.len() - HEADER_LEN {
        return Err(ConversationError::Invalid);
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_is_canonical_and_context_identity_is_authenticated() {
        let h = Header {
            kind: 1,
            account: Uuid::from_u128(1),
            device: Uuid::from_u128(2),
            line: Uuid::from_u128(3),
            interval: Uuid::from_u128(4),
            context: Uuid::from_u128(5),
            binding_generation: 1,
            revision: 1,
            expires_ms: 1_893_500_000_000,
            trust_generation: 1,
            manifest_version: 1,
            peer_digest: {
                use sha2::{Digest, Sha256};
                Sha256::digest(b"+12").into()
            },
            reader: [2; 32],
            manifest_digest: [3; 32],
        };
        assert_eq!(h.aad().unwrap().len(), AAD_LEN);
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../protocol/v1/vectors/workflow-context-01.json"
        ))
        .unwrap();
        let aad = h.aad().unwrap();
        let hex: String = aad.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(vector["aad_hex"].as_str().unwrap(), hex);
        let info: Vec<u8> = [INFO, aad.as_slice()].concat();
        let hex: String = info.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(vector["hpke_info_hex"].as_str().unwrap(), hex);
        let mut changed = h.clone();
        changed.context = Uuid::from_u128(6);
        assert_ne!(h.aad().unwrap(), changed.aad().unwrap());
        changed.revision = 0;
        assert!(changed.aad().is_err());
        assert!(parse(b"synthetic plaintext canary").is_err());
    }
}
