// SPDX-License-Identifier: AGPL-3.0-only
//! Dedicated draft client-only HPKE template. Public header is authenticated AAD.
use crate::http_owner_conversations::ConversationError;
use uuid::Uuid;

pub const AAD_LEN: usize = 222;
pub const HEADER_LEN: usize = AAD_LEN + 65 + 4;
pub const MAX_PLAINTEXT: usize = 32_768;
pub const MAX_ENVELOPE: usize = HEADER_LEN + MAX_PLAINTEXT + 16;
pub const INFO: &[u8] = b"ZT/workflow-template/hpke/v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub account: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub interval: Uuid,
    pub template: Uuid,
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
        if !(1..=128).contains(&self.revision)
            || [
                self.account,
                self.device,
                self.line,
                self.interval,
                self.template,
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
        let mut b = b"ZTWT\x01".to_vec();
        b.push(1);
        for id in [
            self.account,
            self.device,
            self.line,
            self.interval,
            self.template,
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
    if !(HEADER_LEN + 17..=MAX_ENVELOPE).contains(&bytes.len()) || &bytes[..5] != b"ZTWT\x01" {
        return Err(ConversationError::Invalid);
    }
    let id = |offset| {
        Uuid::from_slice(&bytes[offset..offset + 16]).map_err(|_| ConversationError::Invalid)
    };
    let number = |offset| i64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
    if bytes[5] != 1 {
        return Err(ConversationError::Invalid);
    }
    let h = Header {
        account: id(6)?,
        device: id(22)?,
        line: id(38)?,
        interval: id(54)?,
        template: id(70)?,
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

impl Header {
    pub(crate) fn authority_scope(
        &self,
    ) -> crate::http_owner_conversations::context::SelectedReaderScope {
        crate::http_owner_conversations::context::SelectedReaderScope {
            account: self.account,
            device: self.device,
            line: self.line,
            interval: self.interval,
            context: self.template,
            binding_generation: self.binding_generation,
            expires_ms: self.expires_ms,
            trust_generation: self.trust_generation,
            manifest_version: self.manifest_version,
            peer_digest: self.peer_digest,
            reader: self.reader,
            manifest_digest: self.manifest_digest,
        }
    }
}
