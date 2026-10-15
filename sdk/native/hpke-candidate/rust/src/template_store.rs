//! Opaque template CAS messages, never review or dispatch authority.
use crate::{Error, original_http::uuid, template_crypto::EncryptedTemplateScope};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub(crate) const CONTENT_TYPE: &str = "application/vnd.zrotext.workflow-template.v1";
pub struct TemplateSaveRequest {
    body: Vec<u8>,
    request: String,
    expected: u8,
    digest: [u8; 32],
}
impl TemplateSaveRequest {
    pub fn new(
        scope: &EncryptedTemplateScope,
        request: &str,
        expected: u8,
        envelope: &[u8],
    ) -> Result<Self, Error> {
        let aad = scope.aad()?;
        if !uuid(request)
            || expected > 127
            || scope.revision != u64::from(expected) + 1
            || !(308..=33075).contains(&envelope.len())
            || envelope[..222] != aad
            || u32::from_be_bytes(envelope[287..291].try_into().map_err(|_| Error::Shape)?) as usize
                != envelope.len() - 291
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            body: envelope.to_vec(),
            request: request.into(),
            expected,
            digest: Sha256::digest(envelope).into(),
        })
    }
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }
    pub fn path(&self) -> &'static str {
        "/v1/owner/workflow/templates"
    }
    pub fn headers(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("content-type".into(), CONTENT_TYPE.into()),
            ("idempotency-key".into(), self.request.clone()),
            (
                "x-zrotext-template-revision".into(),
                self.expected.to_string(),
            ),
        ])
    }
    pub fn revision(&self) -> u8 {
        self.expected + 1
    }
    pub fn encrypted_digest(&self) -> String {
        hex(&self.digest)
    }
    /// Exact canonical owner-client receipt. No BOM, duplicate names or whitespace.
    pub fn receipt(&self, body: &[u8]) -> Result<u8, Error> {
        if body.len() > 256 || body != format!("{{\"revision\":{}}}", self.revision()).as_bytes() {
            return Err(Error::Shape);
        };
        Ok(self.revision())
    }
}
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub(crate) fn parse(w: &[u8]) -> Result<EncryptedTemplateScope, Error> {
    if !(308..=33075).contains(&w.len())
        || w[..6] != *b"ZTWT\x01\x01"
        || w[222] != 4
        || u32::from_be_bytes(w[287..291].try_into().map_err(|_| Error::Shape)?) as usize
            != w.len() - 291
    {
        return Err(Error::Shape);
    }
    let number = |at: usize| u64::from_be_bytes(w[at..at + 8].try_into().unwrap());
    let s = EncryptedTemplateScope {
        account: w[6..22].try_into().unwrap(),
        device: w[22..38].try_into().unwrap(),
        line: w[38..54].try_into().unwrap(),
        interval: w[54..70].try_into().unwrap(),
        template: w[70..86].try_into().unwrap(),
        binding_generation: number(86),
        revision: number(94),
        expires: number(102),
        trust_generation: number(110),
        manifest_version: number(118),
        peer_digest: w[126..158].try_into().unwrap(),
        reader: w[158..190].try_into().unwrap(),
        manifest_digest: w[190..222].try_into().unwrap(),
    };
    s.aad()?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn save_message_owns_exact_cas_and_canonical_receipt() {
        let mut s = EncryptedTemplateScope {
            account: [1; 16],
            device: [1; 16],
            line: [1; 16],
            interval: [1; 16],
            template: [1; 16],
            binding_generation: 1,
            revision: 128,
            expires: 20000,
            trust_generation: 1,
            manifest_version: 1,
            peer_digest: [1; 32],
            reader: [1; 32],
            manifest_digest: [1; 32],
        };
        let mut wire = s.aad().unwrap();
        wire.resize(308, 0);
        wire[222] = 4;
        wire[287..291].copy_from_slice(&17u32.to_be_bytes());
        let r = TemplateSaveRequest::new(&s, "11111111-1111-1111-1111-111111111111", 127, &wire)
            .unwrap();
        wire[0] ^= 1;
        let mut copied = r.body();
        copied[0] ^= 1;
        let mut headers = r.headers();
        headers.insert("idempotency-key".into(), "mutated".into());
        assert_eq!(r.body()[0], b'Z');
        assert_ne!(r.headers()["idempotency-key"], "mutated");
        assert_eq!(r.receipt(b"{\"revision\":128}"), Ok(128));
        for raw in [
            b"{\"revision\":127}".as_slice(),
            b"{\"revision\":128,\"revision\":128}",
            b" {\"revision\":128}",
            b"{\"revision\":128.0}",
            b"{\"revision\":128,\"extra\":0}",
            b"\xef\xbb\xbf{\"revision\":128}",
        ] {
            assert!(r.receipt(raw).is_err())
        }
        assert!(r.receipt(&[b' '; 257]).is_err());
        assert!(
            TemplateSaveRequest::new(&s, "11111111-1111-1111-1111-111111111111", 126, &r.body())
                .is_err()
        );
        for id in [
            "00000000-0000-0000-0000-000000000000",
            "INVALID",
            "11111111-1111-1111-1111-11111111111A",
        ] {
            assert!(TemplateSaveRequest::new(&s, id, 127, &r.body()).is_err())
        }
        s.revision = 129;
        assert!(
            TemplateSaveRequest::new(&s, "11111111-1111-1111-1111-111111111111", 128, &r.body())
                .is_err()
        );
    }
}
