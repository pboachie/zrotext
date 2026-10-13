//! Explicit protected opening; no persistence acknowledgement or message effects.
use super::*;
use crate::template::{SegmentEstimate, TemplateContent};
use zeroize::Zeroizing;

pub struct TemplateOpenedPreview {
    text: String,
    segments: SegmentEstimate,
    revision: u64,
    digest: String,
    matches: bool,
}
impl TemplateOpenedPreview {
    pub fn text(&self) -> &str {
        &self.text
    }
    pub fn segments(&self) -> &SegmentEstimate {
        &self.segments
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn encrypted_digest(&self) -> &str {
        &self.digest
    }
    pub fn matches_pending(&self) -> bool {
        self.matches
    }
    pub fn request_acknowledged(&self) -> bool {
        false
    }
}
#[derive(Clone)]
pub struct OwnerTemplateOpening {
    client: OwnerTemplateClient,
    guard: OwnerTemplateClient,
}
impl OwnerTemplateOpening {
    /// Takes responsibility for the dedicated client's close lifetime. Custody
    /// remains caller-owned; invalidation never deletes a protected key.
    pub fn new(options: OwnerOptions, client: OwnerTemplateClient) -> Result<Self, OwnerError> {
        let bound = &client.inner.reader.inner.options;
        if bound.origin != options.origin
            || bound.binding != options.binding
            || bound.template != options.template
        {
            client.close();
            return Err(OwnerError::InvalidRequest);
        }
        let enabled = options.enabled;
        let guard = match OwnerTemplateClient::new(
            options,
            Arc::new(|_, _| Err(OwnerError::InvalidRequest)),
        ) {
            Ok(g) => g,
            Err(e) => {
                client.close();
                return Err(e);
            }
        };
        let out = Self { client, guard };
        if !enabled {
            out.close()
        };
        Ok(out)
    }
    pub fn close(&self) {
        self.guard.close();
        self.client.close()
    }
    pub fn invalidate(&self) {
        self.close()
    }
    fn open(
        &self,
        point: impl Fn() -> Result<Vec<u8>, OwnerError> + Send + 'static,
        decrypt: impl Fn(
            &Manifest,
            &EncryptedTemplateScope,
            u64,
            &[u8],
        ) -> Result<TemplateContent, OwnerError>
        + Send
        + 'static,
    ) -> Result<TemplateOpenedPreview, TemplateSaveError> {
        let client = self.client.clone();
        let result = self.guard.execute(move |inner, call, _| {
            let operation = (|| {
                call.live()?;
                let public = point()?;
                p256::PublicKey::from_sec1_bytes(&public)
                    .map_err(|_| OwnerError::InvalidRequest)?;
                let session = call.credentials()?;
                inner.authorize(call, None, &session)?;
                {
                    let state = inner
                        .reader
                        .inner
                        .state
                        .lock()
                        .map_err(|_| OwnerError::OwnerChanged)?;
                    let m = state.prior.as_ref().ok_or(OwnerError::OwnerChanged)?;
                    let selected = key(m, 2, &inner.reader.inner.options.binding.archive_reader)
                        .ok_or(OwnerError::OwnerChanged)?;
                    if selected[33..98] != public {
                        return Err(OwnerError::OwnerChanged);
                    }
                }
                // Invoke the concrete implementation; no caller-replaced fetch.
                let snapshot = client.read_latest().map_err(|_| OwnerError::ReadRefused)?;
                call.live()?;
                let scope = snapshot.scope();
                let wire = Zeroizing::new(snapshot.envelope());
                inner.authorize(call, Some(&scope), &session)?;
                let (manifest, now) = {
                    let state = inner
                        .reader
                        .inner
                        .state
                        .lock()
                        .map_err(|_| OwnerError::OwnerChanged)?;
                    (
                        state
                            .prior
                            .as_ref()
                            .ok_or(OwnerError::OwnerChanged)?
                            .clone(),
                        state.now,
                    )
                };
                let content = decrypt(&manifest, &scope, now, &wire)?;
                let live_point = || {
                    if client.inner.reader.inner.closed.load(Ordering::Acquire) {
                        return Err(OwnerError::Closed);
                    }
                    call.live()?;
                    if point()? != public {
                        return Err(OwnerError::OwnerChanged);
                    };
                    call.live()
                };
                live_point()?;
                inner.authorize(call, Some(&scope), &session)?;
                let (text, segments) = content.preview().map_err(|_| OwnerError::InvalidRequest)?;
                inner.authorize(call, Some(&scope), &session)?;
                live_point()?;
                Ok((
                    TemplateOpenedPreview {
                        text,
                        segments,
                        revision: scope.revision,
                        digest: snapshot.encrypted_digest(),
                        matches: snapshot.matches_pending(),
                    },
                    false,
                ))
            })();
            if operation.is_err() {
                inner.reader.close();
                client.close()
            };
            operation
        });
        if result.is_err() {
            self.close()
        };
        if result.is_ok()
            && self
                .client
                .inner
                .reader
                .inner
                .closed
                .load(Ordering::Acquire)
        {
            self.close();
            return Err(self.guard.error(OwnerError::Closed));
        }
        result
    }
    /// Explicit candidate software entrypoint, never protected custody.
    pub fn open_latest_software(
        &self,
        scalar: &[u8],
    ) -> Result<TemplateOpenedPreview, TemplateSaveError> {
        if scalar.len() != 32 {
            return Err(self.guard.error(OwnerError::InvalidRequest));
        }
        let owned = Arc::new(Zeroizing::new(scalar.to_vec()));
        let key = owned.clone();
        self.open(
            move || {
                Ok(p256::SecretKey::from_slice(&key)
                    .map_err(|_| OwnerError::InvalidRequest)?
                    .public_key()
                    .to_sec1_bytes()
                    .to_vec())
            },
            move |m, s, n, w| {
                crate::template_crypto::open_software_encrypted_template(m, s, n, &owned, w)
                    .map_err(|_| OwnerError::InvalidRequest)
            },
        )
    }
    #[cfg(windows)]
    pub fn open_latest_protected(
        &self,
        recipient: Arc<crate::cng::HardwareRecipient>,
    ) -> Result<TemplateOpenedPreview, TemplateSaveError> {
        let point = recipient.clone();
        self.open(
            move || point.public_point().map_err(|_| OwnerError::OwnerChanged),
            move |m, s, n, w| {
                crate::template_crypto::open_protected_encrypted_template(m, s, n, &recipient, w)
                    .map_err(|_| OwnerError::InvalidRequest)
            },
        )
    }
}
