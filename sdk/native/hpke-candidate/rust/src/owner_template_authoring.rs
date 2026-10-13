//! One explicitly reviewed draft; public-key sealing, never automatic persistence.
use super::*;
use crate::template::{SegmentEstimate, TemplateContent};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub struct TemplateDraftState {
    pub epoch: u64,
    pub revision: u64,
    pub custody_live: bool,
}
pub type DraftSource =
    Arc<dyn Fn(&OwnerCall) -> Result<TemplateDraftState, OwnerError> + Send + Sync>;
pub struct TemplateDraftReview {
    pub request_id: String,
    pub expected_revision: u8,
    pub scope: EncryptedTemplateScope,
    pub epoch: u64,
    pub draft_revision: u64,
    pub content: Arc<TemplateContent>,
    pub text: String,
    pub segments: SegmentEstimate,
}
pub type DraftReviewer =
    Arc<dyn Fn(&OwnerCall, TemplateDraftReview) -> Result<bool, OwnerError> + Send + Sync>;
#[derive(Clone)]
pub struct OwnerTemplateAuthoring {
    client: OwnerTemplateClient,
    guard: OwnerTemplateClient,
    draft: DraftSource,
    review: DraftReviewer,
    used: Arc<AtomicBool>,
}
impl OwnerTemplateAuthoring {
    pub fn new(
        options: OwnerOptions,
        ciphertext: CiphertextReviewer,
        draft: DraftSource,
        review: DraftReviewer,
    ) -> Result<Self, OwnerError> {
        let client = OwnerTemplateClient::new(options.clone(), ciphertext)?;
        let guard = match OwnerTemplateClient::new(
            options,
            Arc::new(|_, _| Err(OwnerError::InvalidRequest)),
        ) {
            Ok(v) => v,
            Err(e) => {
                client.close();
                return Err(e);
            }
        };
        Ok(Self {
            client,
            guard,
            draft,
            review,
            used: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn client(&self) -> OwnerTemplateClient {
        self.client.clone()
    }
    pub fn close(&self) {
        self.guard.close();
        self.client.close()
    }
    pub fn invalidate(&self) {
        self.close()
    }
    fn abort(&self, owned: Option<&TemplateTicket>) {
        self.guard.close();
        let Ok(saved) = self.client.inner.saved.try_lock() else {
            return;
        };
        if owned.is_some_and(|ticket| {
            saved
                .as_ref()
                .is_some_and(|r| Arc::ptr_eq(&r.ticket.0, &ticket.0))
        }) {
            self.client.close();
            return;
        }
        let reader = &self.client.inner.reader.inner;
        if saved.is_none()
            && reader
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.client.close();
            reader.busy.store(false, Ordering::Release)
        }
    }

    pub fn prepare(
        &self,
        request_id: &str,
        expected: u8,
        scope: EncryptedTemplateScope,
        content: &TemplateContent,
        epoch: u64,
        revision: u64,
    ) -> Result<TemplateTicket, TemplateSaveError> {
        let raw = Zeroizing::new(content.canonical());
        if raw.len() > 32768 {
            return Err(self.guard.error(OwnerError::InvalidRequest));
        }
        let captured = Arc::new(
            TemplateContent::parse(&raw)
                .map_err(|_| self.guard.error(OwnerError::InvalidRequest))?,
        );
        let this = self.clone();
        let request = request_id.to_string();
        let result = self.guard.execute(move |inner, call, _| {
            // Serialized admission precedes all one-draft state decisions.
            if this.used.load(Ordering::Acquire) || this.client.pending().is_some() {
                return Err(OwnerError::Busy);
            }
            match this.client.inner.saved.try_lock() {
                Ok(saved) if saved.is_none() => (),
                _ => return Err(OwnerError::Busy),
            }
            let mut owned = None;
            let operation = (|| {
                if epoch == 0
                    || revision == 0
                    || expected >= 128
                    || scope.revision != u64::from(expected) + 1
                    || request.len() != 36
                    || request.bytes().enumerate().any(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b != b'-'
                        } else {
                            !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)
                        }
                    })
                {
                    return Err(OwnerError::InvalidRequest);
                }
                let session = call.credentials()?;
                let draft = || {
                    let value = (this.draft)(call)?;
                    if value.epoch != epoch || value.revision != revision || !value.custody_live {
                        return Err(OwnerError::OwnerChanged);
                    };
                    call.live()
                };
                let current = || {
                    draft()?;
                    inner.authorize(call, Some(&scope), &session)?;
                    draft()?;
                    if call.credentials()? != session {
                        return Err(OwnerError::OwnerChanged);
                    };
                    call.live()
                };
                let (text, segments) =
                    captured.preview().map_err(|_| OwnerError::InvalidRequest)?;
                current()?;
                if !(this.review)(
                    call,
                    TemplateDraftReview {
                        request_id: request.clone(),
                        expected_revision: expected,
                        scope: scope.clone(),
                        epoch,
                        draft_revision: revision,
                        content: captured.clone(),
                        text,
                        segments,
                    },
                )? {
                    return Err(OwnerError::ReadRefused);
                }
                current()?;
                let wire = {
                    let state = inner
                        .reader
                        .inner
                        .state
                        .lock()
                        .map_err(|_| OwnerError::OwnerChanged)?;
                    Zeroizing::new(
                        crate::template_crypto::seal_encrypted_template(
                            state.prior.as_ref().ok_or(OwnerError::OwnerChanged)?,
                            &scope,
                            state.now,
                            &captured,
                        )
                        .map_err(|_| OwnerError::ReadRefused)?,
                    )
                };
                current()?;
                let ticket = this
                    .client
                    .prepare_save(scope.clone(), &request, expected, &wire)
                    .map_err(|e| e.code)?;
                owned = Some(ticket.clone());
                current()?;
                if this
                    .client
                    .inner
                    .reader
                    .inner
                    .closed
                    .load(Ordering::Acquire)
                {
                    return Err(OwnerError::Closed);
                }
                {
                    let mut saved = this
                        .client
                        .inner
                        .saved
                        .lock()
                        .map_err(|_| OwnerError::ReadRefused)?;
                    let record = saved.as_mut().ok_or(OwnerError::ReadRefused)?;
                    record.deadline = record.deadline.min(call.deadline());
                }
                let author_deadline = call.deadline();
                for reader in [
                    &this.client.inner.reader.inner,
                    &this.guard.inner.reader.inner,
                ] {
                    let mut lifetime = reader
                        .lifetime
                        .lock()
                        .map_err(|_| OwnerError::ReadRefused)?;
                    *lifetime =
                        Some(lifetime.map_or(author_deadline, |at| at.min(author_deadline)));
                }
                this.used.store(true, Ordering::Release);
                Ok((ticket, false))
            })();
            if operation
                .as_ref()
                .is_err_and(|e| !matches!(e, OwnerError::Busy | OwnerError::Capacity))
            {
                this.abort(owned.as_ref())
            };
            operation
        });
        match result {
            Ok(ticket) => {
                if self
                    .client
                    .inner
                    .reader
                    .inner
                    .closed
                    .load(Ordering::Acquire)
                {
                    self.close();
                    Err(self.guard.error(OwnerError::Closed))
                } else {
                    Ok(ticket)
                }
            }
            Err(e) => {
                if !matches!(e.code, OwnerError::Busy | OwnerError::Capacity) {
                    self.abort(None)
                };
                Err(e)
            }
        }
    }
}
