//! Instance-bound reviewed ciphertext saves and explicit uncertain recovery.
use super::*;
use crate::template_store::TemplateSaveRequest;

#[derive(Clone)]
pub struct TemplateTicket(Arc<()>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplatePending {
    pub request_id: String,
    pub template_id: String,
    pub revision: u8,
    pub encrypted_digest: String,
}
#[derive(Clone, Debug)]
pub struct TemplateAcknowledgement {
    pub pending: TemplatePending,
}
pub struct TemplateCiphertextReview {
    pub request_id: String,
    pub expected_revision: u8,
    pub scope: EncryptedTemplateScope,
    pub encrypted_digest: String,
}
pub type CiphertextReviewer =
    Arc<dyn Fn(&OwnerCall, TemplateCiphertextReview) -> Result<(), OwnerError> + Send + Sync>;
#[derive(Debug)]
pub struct TemplateSaveError {
    pub code: OwnerError,
    pub unknown: bool,
}
impl std::fmt::Display for TemplateSaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owner template operation refused")
    }
}
impl std::error::Error for TemplateSaveError {}
struct Saved {
    ticket: TemplateTicket,
    request: TemplateSaveRequest,
    request_id: String,
    scope: EncryptedTemplateScope,
    session: OwnerSession,
    deadline: Instant,
    attempts: u8,
    verifies: u8,
    unknown: bool,
}
struct SaveInner {
    reader: OwnerTemplateReader,
    review: CiphertextReviewer,
    saved: Mutex<Option<Saved>>,
    pending: Mutex<Option<TemplatePending>>,
}
#[derive(Clone)]
pub struct OwnerTemplateClient {
    inner: Arc<SaveInner>,
}
impl SaveInner {
    fn identity(&self, r: &Saved) -> TemplatePending {
        let id = hex(&r.scope.template);
        TemplatePending {
            request_id: r.request_id.clone(),
            template_id: format!(
                "{}-{}-{}-{}-{}",
                &id[..8],
                &id[8..12],
                &id[12..16],
                &id[16..20],
                &id[20..]
            ),
            revision: r.request.revision(),
            encrypted_digest: r.request.encrypted_digest(),
        }
    }
    fn authorize(
        &self,
        call: &OwnerCall,
        scope: Option<&EncryptedTemplateScope>,
        session: &OwnerSession,
    ) -> Result<(), OwnerError> {
        let mut state = self
            .reader
            .inner
            .state
            .lock()
            .map_err(|_| OwnerError::OwnerChanged)?;
        call.authorize(&mut state, scope, session)
    }
    fn ticket<'a>(
        &self,
        saved: &'a mut Option<Saved>,
        t: &TemplateTicket,
        call: &OwnerCall,
    ) -> Result<&'a mut Saved, OwnerError> {
        let r = saved.as_mut().ok_or(OwnerError::InvalidRequest)?;
        if !Arc::ptr_eq(&r.ticket.0, &t.0) {
            return Err(OwnerError::InvalidRequest);
        };
        call.shorten(r.deadline);
        call.live()?;
        Ok(r)
    }
}
impl OwnerTemplateClient {
    pub fn new(options: OwnerOptions, review: CiphertextReviewer) -> Result<Self, OwnerError> {
        Ok(Self {
            inner: Arc::new(SaveInner {
                reader: OwnerTemplateReader::new(options)?,
                review,
                saved: Mutex::new(None),
                pending: Mutex::new(None),
            }),
        })
    }
    pub fn close(&self) {
        self.inner.reader.close()
    }
    pub fn pending(&self) -> Option<TemplatePending> {
        self.inner.pending.lock().unwrap().clone()
    }
    fn error(&self, code: OwnerError) -> TemplateSaveError {
        TemplateSaveError {
            code,
            unknown: self.pending().is_some()
                && !matches!(
                    code,
                    OwnerError::InvalidRequest | OwnerError::Busy | OwnerError::Capacity
                ),
        }
    }
    // The worker retains busy/admission through the foreground delivery fence.
    // A timed-out callback can settle later but cannot acknowledge or replace state.
    fn execute<T: Send + 'static>(
        &self,
        op: impl FnOnce(&SaveInner, &OwnerCall, &mut Option<Saved>) -> Result<(T, bool), OwnerError>
        + Send
        + 'static,
    ) -> Result<T, TemplateSaveError> {
        let reader = &self.inner.reader.inner;
        if reader
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(self.error(OwnerError::Busy));
        }
        if ADMISSION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 8).then_some(n + 1)
            })
            .is_err()
        {
            reader.busy.store(false, Ordering::Release);
            return Err(self.error(OwnerError::Capacity));
        }
        struct Release(Arc<Inner>);
        impl Drop for Release {
            fn drop(&mut self) {
                ADMISSION.fetch_sub(1, Ordering::AcqRel);
                self.0.busy.store(false, Ordering::Release)
            }
        }
        let release = Release(reader.clone());
        let call = Arc::new(OwnerCall {
            inner: reader.clone(),
            deadline: Mutex::new(Instant::now() + reader.options.timeout),
        });
        let worker = call.clone();
        let inner = self.inner.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        let (done, settled) = mpsc::sync_channel::<()>(1);
        let (released, release_wait) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .spawn(move || {
                let result = match inner.saved.lock() {
                    Ok(mut saved) => op(&inner, &worker, &mut saved),
                    Err(_) => Err(OwnerError::ReadRefused),
                };
                let _ = tx.send(result);
                let _ = settled.recv();
                if inner.reader.inner.closed.load(Ordering::Acquire)
                    && let Ok(mut saved) = inner.saved.lock()
                {
                    *saved = None
                }
                drop(release);
                let _ = released.send(());
            })
            .map_err(|_| self.error(OwnerError::ReadRefused))?;
        loop {
            if let Err(e) = call.live() {
                drop(done);
                return Err(self.error(e));
            }
            match rx.recv_timeout(
                call.deadline()
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5)),
            ) {
                Ok(result) => {
                    let result = (|| {
                        let (value, ack) = result?;
                        call.live()?;
                        if ack {
                            let mut saved = self
                                .inner
                                .saved
                                .lock()
                                .map_err(|_| OwnerError::ReadRefused)?;
                            call.live()?;
                            let r = saved.as_ref().ok_or(OwnerError::InvalidRequest)?;
                            let mut state =
                                reader.state.lock().map_err(|_| OwnerError::ReadRefused)?;
                            if r.scope.revision >= state.head {
                                state.head = r.scope.revision;
                                state.head_digest = Sha256::digest(r.request.body()).into()
                            };
                            *saved = None;
                            *self.inner.pending.lock().unwrap() = None;
                        };
                        Ok(value)
                    })();
                    drop(done);
                    let _ = release_wait.recv();
                    return result.map_err(|e| self.error(e));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    drop(done);
                    return Err(self.error(OwnerError::ReadRefused));
                }
            }
        }
    }
    pub fn prepare_save(
        &self,
        scope: EncryptedTemplateScope,
        request_id: &str,
        expected: u8,
        envelope: &[u8],
    ) -> Result<TemplateTicket, TemplateSaveError> {
        if !(308..=33075).contains(&envelope.len()) {
            return Err(self.error(OwnerError::InvalidRequest));
        }
        let wire = envelope.to_vec();
        let request_id = request_id.to_string();
        self.execute(move |inner, call, saved| {
            // Never capture a saved-record decision before winning admission.
            if saved.is_some() || inner.pending.lock().unwrap().is_some() {
                return Err(OwnerError::Busy);
            }
            call.live()?;
            let request = TemplateSaveRequest::new(&scope, &request_id, expected, &wire)
                .map_err(|_| OwnerError::InvalidRequest)?;
            parse(&wire).map_err(|_| OwnerError::InvalidRequest)?;
            let session = call.credentials()?;
            inner.authorize(call, Some(&scope), &session)?;
            p256::PublicKey::from_sec1_bytes(&wire[222..287])
                .map_err(|_| OwnerError::InvalidRequest)?;
            (inner.review)(
                call,
                TemplateCiphertextReview {
                    request_id: request_id.clone(),
                    expected_revision: expected,
                    scope: scope.clone(),
                    encrypted_digest: request.encrypted_digest(),
                },
            )?;
            inner.authorize(call, Some(&scope), &session)?;
            call.live()?;
            let ticket = TemplateTicket(Arc::new(()));
            *saved = Some(Saved {
                ticket: ticket.clone(),
                request,
                request_id,
                scope,
                session,
                deadline: call.deadline(),
                attempts: 0,
                verifies: 0,
                unknown: false,
            });
            Ok((ticket, false))
        })
    }
    pub fn commit(
        &self,
        ticket: &TemplateTicket,
    ) -> Result<TemplateAcknowledgement, TemplateSaveError> {
        self.post(ticket, false)
    }
    pub fn retry_unknown(
        &self,
        ticket: &TemplateTicket,
    ) -> Result<TemplateAcknowledgement, TemplateSaveError> {
        self.post(ticket, true)
    }
    fn post(
        &self,
        ticket: &TemplateTicket,
        retry: bool,
    ) -> Result<TemplateAcknowledgement, TemplateSaveError> {
        let ticket = ticket.clone();
        self.execute(move |inner, call, saved| {
            let r = inner.ticket(saved, &ticket, call)?;
            if (retry && !r.unknown) || (!retry && r.attempts != 0) {
                return Err(OwnerError::InvalidRequest);
            }
            if r.attempts >= 3 {
                return Err(OwnerError::AttemptsExhausted);
            }
            inner.authorize(call, Some(&r.scope), &r.session)?;
            r.deadline = call.deadline();
            r.attempts += 1;
            r.unknown = true;
            *inner.pending.lock().unwrap() = Some(inner.identity(r));
            if call.credentials()? != r.session {
                inner.reader.close();
                return Err(OwnerError::OwnerChanged);
            };
            call.live()?;
            let mut request = inner
                .reader
                .inner
                .client
                .post(format!(
                    "{}{}",
                    inner.reader.inner.options.origin,
                    r.request.path()
                ))
                .header(header::ACCEPT, "application/json")
                .header(header::COOKIE, &r.session.cookie)
                .header("x-zrotext-csrf", &r.session.csrf)
                .header(header::CACHE_CONTROL, "no-store")
                .body(r.request.body())
                .timeout(call.deadline().saturating_duration_since(Instant::now()));
            for (k, v) in r.request.headers() {
                request = request.header(k, v)
            }
            let mut response = request.send().map_err(|_| OwnerError::ResponseUnknown)?;
            if [401, 403].contains(&response.status().as_u16()) {
                inner.reader.close()
            }
            let typ = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            let parts: Vec<_> = typ.split(';').map(str::trim).collect();
            if response.status().as_u16() != 200
                || response
                    .headers()
                    .get_all(header::CONTENT_TYPE)
                    .iter()
                    .count()
                    != 1
                || !(parts == ["application/json"]
                    || parts == ["application/json", "charset=utf-8"])
            {
                return Err(OwnerError::ResponseUnknown);
            }
            let mut body = vec![];
            response
                .by_ref()
                .take(257)
                .read_to_end(&mut body)
                .map_err(|_| OwnerError::ResponseUnknown)?;
            r.request
                .receipt(&body)
                .map_err(|_| OwnerError::ResponseUnknown)?;
            inner.authorize(call, Some(&r.scope), &r.session)?;
            r.deadline = call.deadline();
            let state = inner
                .reader
                .inner
                .state
                .lock()
                .map_err(|_| OwnerError::ReadRefused)?;
            if r.scope.revision == state.head
                && <[u8; 32]>::from(Sha256::digest(r.request.body())) != state.head_digest
            {
                return Err(OwnerError::ResponseUnknown);
            }
            Ok((
                TemplateAcknowledgement {
                    pending: inner.identity(r),
                },
                true,
            ))
        })
    }
    pub fn read_latest(&self) -> Result<OwnerTemplateSnapshot, TemplateSaveError> {
        self.latest(None)
    }
    pub fn verify_unknown(
        &self,
        ticket: &TemplateTicket,
    ) -> Result<OwnerTemplateSnapshot, TemplateSaveError> {
        self.latest(Some(ticket.clone()))
    }
    fn latest(
        &self,
        ticket: Option<TemplateTicket>,
    ) -> Result<OwnerTemplateSnapshot, TemplateSaveError> {
        self.execute(move |inner, call, saved| {
            if let Some(t) = ticket
                && !inner.ticket(saved, &t, call)?.unknown
            {
                return Err(OwnerError::InvalidRequest);
            }
            if let Some(r) = saved.as_mut() {
                call.shorten(r.deadline);
                call.live()?;
                if r.unknown {
                    if r.verifies >= 3 {
                        return Err(OwnerError::AttemptsExhausted);
                    };
                    r.verifies += 1
                };
                if call.credentials()? != r.session {
                    inner.reader.close();
                    return Err(OwnerError::OwnerChanged);
                }
            }
            let mut snapshot = call
                .read_expected(saved.as_ref().map(|r| &r.session))
                .map_err(|e| {
                    if saved.as_ref().is_some_and(|r| r.unknown) {
                        OwnerError::ResponseUnknown
                    } else {
                        e
                    }
                })?;
            if let Some(r) = saved.as_mut() {
                r.deadline = call.deadline();
                snapshot.matches_pending = snapshot.wire == r.request.body()
            }
            Ok((snapshot, false))
        })
    }
}
