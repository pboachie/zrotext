// SPDX-License-Identifier: AGPL-3.0-only
//! Fixed canonical phone approval/install scope; no JSON transcript or optional fields.
use super::ConversationError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DISCLOSURE_TEXT: &str = "With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser. Stop closes new capture and transfer; retained encrypted content is deleted separately.";
pub const APPROVE_DOMAIN: &[u8] = b"zrotext/conversation/approve/v1\0";
pub const INSTALL_DOMAIN: &[u8] = b"zrotext/conversation/install/v1\0";
pub const READER_DISCLOSURE_TEXT: &str = "With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately.";
pub const READER_APPROVE_DOMAIN: &[u8] = b"zrotext/conversation/approve/v2\0";
pub const READER_INSTALL_DOMAIN: &[u8] = b"zrotext/conversation/install/v2\0";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedReader {
    pub connector_id: Uuid,
    pub read_grant_id: Uuid,
    pub key_id: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
pub struct Statement {
    pub account: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub generation: i64,
    pub interval: Uuid,
    pub receipt: Uuid,
    pub originating_session: Uuid,
    pub nonce: [u8; 32],
    pub expires_ms: i64,
    pub peer: String,
    pub reader: [u8; 32],
    pub integration_readers: Vec<SelectedReader>,
    pub signer: [u8; 32],
    pub trust_generation: i64,
    pub predecessor_version: i64,
    pub predecessor_digest: [u8; 32],
    pub activation_version: i64,
    pub activation_digest: [u8; 32],
    pub site: String,
    pub instance: String,
    pub connection_epoch: i64,
    pub deployment_epoch: i64,
}
impl std::fmt::Debug for Statement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Statement(redacted)")
    }
}
impl Statement {
    pub fn disclosure(&self) -> &'static str {
        if self.integration_readers.is_empty() {
            DISCLOSURE_TEXT
        } else {
            READER_DISCLOSURE_TEXT
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, ConversationError> {
        if self.integration_readers.len() > 6
            || self
                .integration_readers
                .iter()
                .any(|r| r.connector_id.is_nil() || r.read_grant_id.is_nil() || r.key_id == [0; 32])
            || self
                .integration_readers
                .windows(2)
                .any(|w| w[0].key_id >= w[1].key_id)
            || self.integration_readers.iter().enumerate().any(|(i, r)| {
                self.integration_readers[..i].iter().any(|p| {
                    p.key_id == r.key_id
                        || p.connector_id == r.connector_id
                        || p.read_grant_id == r.read_grant_id
                })
            })
        {
            return Err(ConversationError::Invalid);
        }
        if [
            self.account,
            self.device,
            self.line,
            self.interval,
            self.receipt,
            self.originating_session,
        ]
        .iter()
        .any(Uuid::is_nil)
            || [
                self.generation,
                self.expires_ms,
                self.trust_generation,
                self.predecessor_version,
                self.activation_version,
                self.connection_epoch,
                self.deployment_epoch,
            ]
            .iter()
            .any(|v| *v <= 0)
            || self.predecessor_version.checked_add(1) != Some(self.activation_version)
            || self.nonce == [0; 32]
            || !(3..=16).contains(&self.peer.len())
            || !self.peer.starts_with('+')
            || !matches!(self.peer.as_bytes()[1], b'1'..=b'9')
            || !self.peer.as_bytes()[2..].iter().all(u8::is_ascii_digit)
            || [&self.site, &self.instance]
                .iter()
                .any(|v| v.is_empty() || v.len() > 64 || !v.bytes().all(|b| b.is_ascii_graphic()))
        {
            return Err(ConversationError::Invalid);
        }
        let mut b = if self.integration_readers.is_empty() {
            b"ZTCA\x01".to_vec()
        } else {
            b"ZTCA\x02".to_vec()
        };
        for id in [self.account, self.device, self.line] {
            b.extend(id.as_bytes());
        }
        b.extend(self.generation.to_be_bytes());
        for id in [self.interval, self.receipt, self.originating_session] {
            b.extend(id.as_bytes());
        }
        b.extend(self.nonce);
        b.extend(self.expires_ms.to_be_bytes());
        for text in [&self.peer, super::super::DISCLOSURE_VERSION] {
            b.push(text.len() as u8);
            b.extend(text.as_bytes());
        }
        b.extend(Sha256::digest(self.disclosure().as_bytes()));
        b.extend(self.reader);
        b.extend(self.signer);
        b.extend(self.trust_generation.to_be_bytes());
        b.extend(self.predecessor_version.to_be_bytes());
        b.extend(self.predecessor_digest);
        b.extend(self.activation_version.to_be_bytes());
        b.extend(self.activation_digest);
        b.extend(self.connection_epoch.to_be_bytes());
        b.extend(self.deployment_epoch.to_be_bytes());
        for text in [&self.site, &self.instance] {
            b.push(text.len() as u8);
            b.extend(text.as_bytes());
        }
        if !self.integration_readers.is_empty() {
            b.push(self.integration_readers.len() as u8);
            for reader in &self.integration_readers {
                b.extend(reader.connector_id.as_bytes());
                b.extend(reader.read_grant_id.as_bytes());
                b.extend(reader.key_id);
            }
        }
        Ok(b)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ConversationError> {
        if !(380..=1536).contains(&bytes.len()) {
            return Err(ConversationError::Invalid);
        }
        let mut r = Reader(bytes);
        let header = r.take(5)?;
        if header != b"ZTCA\x01" && header != b"ZTCA\x02" {
            return Err(ConversationError::Invalid);
        }
        let account = r.id()?;
        let device = r.id()?;
        let line = r.id()?;
        let generation = r.number()?;
        let interval = r.id()?;
        let receipt = r.id()?;
        let originating_session = r.id()?;
        let nonce = r.fixed()?;
        let expires_ms = r.number()?;
        let peer = r.text()?;
        if r.text()? != super::super::DISCLOSURE_VERSION
            || r.fixed::<32>()?
                != Sha256::digest(if header[4] == 1 {
                    DISCLOSURE_TEXT.as_bytes()
                } else {
                    READER_DISCLOSURE_TEXT.as_bytes()
                })
                .as_slice()
        {
            return Err(ConversationError::Invalid);
        }
        let reader = r.fixed()?;
        let signer = r.fixed()?;
        let trust_generation = r.number()?;
        let predecessor_version = r.number()?;
        let predecessor_digest = r.fixed()?;
        let activation_version = r.number()?;
        let activation_digest = r.fixed()?;
        let connection_epoch = r.number()?;
        let deployment_epoch = r.number()?;
        let site = r.text()?;
        let instance = r.text()?;
        let mut integration_readers = Vec::new();
        if header[4] == 2 {
            let count = usize::from(r.take(1)?[0]);
            if !(1..=6).contains(&count) {
                return Err(ConversationError::Invalid);
            }
            for _ in 0..count {
                integration_readers.push(SelectedReader {
                    connector_id: r.id()?,
                    read_grant_id: r.id()?,
                    key_id: r.fixed()?,
                });
            }
        }
        let value = Self {
            account,
            device,
            line,
            generation,
            interval,
            receipt,
            originating_session,
            nonce,
            expires_ms,
            peer,
            reader,
            integration_readers,
            signer,
            trust_generation,
            predecessor_version,
            predecessor_digest,
            activation_version,
            activation_digest,
            site,
            instance,
            connection_epoch,
            deployment_epoch,
        };
        if !r.0.is_empty() || value.encode()?.as_slice() != bytes {
            return Err(ConversationError::Invalid);
        }
        Ok(value)
    }
    pub fn transcript(&self, domain: &[u8]) -> Result<Vec<u8>, ConversationError> {
        let b = self.encode()?;
        let domain = if self.integration_readers.is_empty() {
            domain
        } else if domain == APPROVE_DOMAIN {
            READER_APPROVE_DOMAIN
        } else if domain == INSTALL_DOMAIN {
            READER_INSTALL_DOMAIN
        } else {
            domain
        };
        Ok([domain, &(b.len() as u32).to_be_bytes(), &b].concat())
    }
    pub fn digest(&self) -> Result<[u8; 32], ConversationError> {
        Ok(Sha256::digest(self.transcript(APPROVE_DOMAIN)?).into())
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ConversationError> {
        let b = self.0.get(..n).ok_or(ConversationError::Invalid)?;
        self.0 = &self.0[n..];
        Ok(b)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ConversationError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn id(&mut self) -> Result<Uuid, ConversationError> {
        Ok(Uuid::from_bytes(self.fixed()?))
    }
    fn number(&mut self) -> Result<i64, ConversationError> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }
    fn text(&mut self) -> Result<String, ConversationError> {
        let n = usize::from(self.take(1)?[0]);
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| ConversationError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_reader_vector_pins_statement_length_and_both_signature_domains() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../protocol/v1/vectors/conversation-activation-readers.json"
        ))
        .unwrap();
        let decode = |name: &str| {
            let h = vector[name].as_str().unwrap();
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let statement = Statement::decode(&decode("statement_hex")).unwrap();
        assert_eq!(
            statement.transcript(APPROVE_DOMAIN).unwrap(),
            decode("approval_transcript_hex")
        );
        assert_eq!(
            statement.transcript(INSTALL_DOMAIN).unwrap(),
            decode("installation_transcript_hex")
        );
        assert_eq!(
            statement.digest().unwrap().as_slice(),
            decode("approval_digest_hex")
        );
    }
    #[test]
    fn selected_readers_are_signed_canonical_and_cannot_be_dropped_or_reordered() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../protocol/v1/vectors/conversation-activation.json"
        ))
        .unwrap();
        let bytes: Vec<_> = vector["statement_hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        let mut statement = Statement::decode(&bytes).unwrap();
        let archive_digest = statement.digest().unwrap();
        statement.integration_readers = vec![
            SelectedReader {
                connector_id: Uuid::from_u128(11),
                read_grant_id: Uuid::from_u128(21),
                key_id: [1; 32],
            },
            SelectedReader {
                connector_id: Uuid::from_u128(12),
                read_grant_id: Uuid::from_u128(22),
                key_id: [2; 32],
            },
        ];
        let selected = statement.encode().unwrap();
        assert_eq!(&selected[..5], b"ZTCA\x02");
        assert_eq!(Statement::decode(&selected).unwrap(), statement);
        assert_ne!(statement.digest().unwrap(), archive_digest);
        assert!(
            statement
                .transcript(APPROVE_DOMAIN)
                .unwrap()
                .starts_with(READER_APPROVE_DOMAIN)
        );
        assert!(
            statement
                .transcript(INSTALL_DOMAIN)
                .unwrap()
                .starts_with(READER_INSTALL_DOMAIN)
        );
        let mut reordered = statement.clone();
        reordered.integration_readers.reverse();
        assert!(reordered.encode().is_err());
        let mut duplicate = statement.clone();
        duplicate.integration_readers[1].connector_id =
            duplicate.integration_readers[0].connector_id;
        assert!(duplicate.encode().is_err());
        let mut truncated = selected.clone();
        truncated.truncate(truncated.len() - 64);
        assert!(Statement::decode(&truncated).is_err());
        let mut empty_v2 = bytes.clone();
        empty_v2[4] = 2;
        empty_v2.push(0);
        assert!(Statement::decode(&empty_v2).is_err());
    }
    #[test]
    fn canonical_cross_language_vector_binds_every_byte() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../protocol/v1/vectors/conversation-activation.json"
        ))
        .unwrap();
        let decode = |s: &str| {
            s.as_bytes()
                .chunks_exact(2)
                .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        let bytes = decode(v["statement_hex"].as_str().unwrap());
        let statement = Statement::decode(&bytes).unwrap();
        assert_eq!(statement.encode().unwrap(), bytes);
        assert_eq!(
            statement.digest().unwrap().as_slice(),
            decode(v["approval_digest_hex"].as_str().unwrap())
        );
        assert_eq!(DISCLOSURE_TEXT, v["disclosure_text"].as_str().unwrap());
        assert_eq!(statement.peer, "+12");
        assert_eq!(statement.activation_version, 2);
        for end in 0..bytes.len() {
            assert!(Statement::decode(&bytes[..end]).is_err());
        }
        assert!(Statement::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        // Canonical valid changes must always change the approval digest.
        for field in [5, 21, 37, 61, 77, 93, 109, 150, 260, 310] {
            let mut changed = bytes.clone();
            changed[field] ^= 1;
            if let Ok(changed) = Statement::decode(&changed) {
                assert_ne!(statement.digest().unwrap(), changed.digest().unwrap());
            }
        }
        assert_ne!(
            statement.transcript(APPROVE_DOMAIN).unwrap(),
            statement.transcript(INSTALL_DOMAIN).unwrap()
        );
    }
}
