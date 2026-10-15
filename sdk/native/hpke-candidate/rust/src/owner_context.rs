#[path = "context_authoring.rs"]
pub mod authoring;
use super::*;
use crate::workflow_context::WorkflowContextScope;
use zeroize::Zeroizing;

const CONTEXT_TYPE: &str = "application/vnd.zrotext.workflow-context.v1";
#[derive(Clone)]
pub struct ContextOptions {
    pub origin: String,
    pub binding: OwnerBinding,
    pub context: [u8; 16],
    pub kind: u8,
    pub enabled: bool,
    pub timeout: Duration,
    pub additional_roots: Vec<u8>,
    pub current: CurrentSource,
    pub session: SessionSource,
}
impl ContextOptions {
    fn owner(self) -> OwnerOptions {
        OwnerOptions {
            origin: self.origin,
            binding: self.binding,
            template: self.context,
            enabled: self.enabled,
            timeout: self.timeout,
            additional_roots: self.additional_roots,
            current: self.current,
            session: self.session,
        }
    }
}
fn mapped_scope(s: &WorkflowContextScope) -> EncryptedTemplateScope {
    EncryptedTemplateScope {
        account: s.account,
        device: s.device,
        line: s.line,
        interval: s.interval,
        template: s.context,
        binding_generation: s.binding_generation,
        revision: s.revision,
        expires: s.expires,
        trust_generation: s.trust_generation,
        manifest_version: s.manifest_version,
        peer_digest: s.peer_digest,
        reader: s.reader,
        manifest_digest: s.manifest_digest,
    }
}
fn parse_context(wire: &[u8]) -> Result<WorkflowContextScope, OwnerError> {
    let bad = OwnerError::InvalidRequest;
    if !(308..=33075).contains(&wire.len())
        || &wire[..5] != b"ZTWC\x01"
        || wire[222] != 4
        || u32::from_be_bytes(wire[287..291].try_into().map_err(|_| bad)?) as usize
            != wire.len() - 291
    {
        return Err(bad);
    }
    let n = |at| u64::from_be_bytes(wire[at..at + 8].try_into().unwrap());
    let s = WorkflowContextScope {
        kind: wire[5],
        account: wire[6..22].try_into().unwrap(),
        device: wire[22..38].try_into().unwrap(),
        line: wire[38..54].try_into().unwrap(),
        interval: wire[54..70].try_into().unwrap(),
        context: wire[70..86].try_into().unwrap(),
        binding_generation: n(86),
        revision: n(94),
        expires: n(102),
        trust_generation: n(110),
        manifest_version: n(118),
        peer_digest: wire[126..158].try_into().unwrap(),
        reader: wire[158..190].try_into().unwrap(),
        manifest_digest: wire[190..222].try_into().unwrap(),
    };
    s.aad().map_err(|_| bad)?;
    Ok(s)
}
struct Expiry {
    deadline: Mutex<Instant>,
    done: AtomicBool,
}
impl Saved {
    fn shorten(&mut self, call: &OwnerCall) {
        call.shorten(self.deadline);
        self.deadline = call.deadline();
        *self.expiry.deadline.lock().unwrap() = self.deadline
    }
}
impl Drop for Saved {
    fn drop(&mut self) {
        self.expiry.done.store(true, Ordering::Release)
    }
}

#[derive(Clone)]
pub struct ContextTicket(Arc<()>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextPending {
    pub request_id: String,
    pub context_id: String,
    pub revision: u8,
    pub encrypted_digest: String,
}
#[derive(Clone, Debug)]
pub struct ContextReceipt {
    pub pending: ContextPending,
    pub request_acknowledged: bool,
}
#[derive(Clone)]
pub struct ContextWriteReview {
    pub request_id: String,
    pub expected_revision: u8,
    pub scope: WorkflowContextScope,
    pub encrypted_digest: String,
}
pub type ContextReviewer =
    Arc<dyn Fn(&OwnerCall, ContextWriteReview) -> Result<(), OwnerError> + Send + Sync>;
#[derive(Debug)]
pub struct ContextError {
    pub code: String,
    pub state: &'static str,
}
impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owner context operation refused")
    }
}
impl std::error::Error for ContextError {}
struct Saved {
    expiry: Arc<Expiry>,
    ticket: ContextTicket,
    wire: Zeroizing<Vec<u8>>,
    expected: u8,
    digest: [u8; 32],
    request_id: String,
    scope: WorkflowContextScope,
    session: OwnerSession,
    deadline: Instant,
    attempts: u8,
    verifies: u8,
    unknown: bool,
}
struct SaveInner {
    expired: AtomicBool,
    reader: OwnerTemplateReader,
    kind: u8,
    review: ContextReviewer,
    saved: Mutex<Option<Saved>>,
    pending: Mutex<Option<ContextPending>>,
}
#[derive(Clone)]
pub struct OwnerWorkflowContextClient {
    inner: Arc<SaveInner>,
}
impl SaveInner {
    fn identity(&self, r: &Saved) -> ContextPending {
        let id = hex(&r.scope.context);
        ContextPending {
            request_id: r.request_id.clone(),
            context_id: format!(
                "{}-{}-{}-{}-{}",
                &id[..8],
                &id[8..12],
                &id[12..16],
                &id[16..20],
                &id[20..]
            ),
            revision: r.scope.revision as u8,
            encrypted_digest: hex(&r.digest),
        }
    }
    fn authorize(
        &self,
        call: &OwnerCall,
        scope: Option<&WorkflowContextScope>,
        session: &OwnerSession,
    ) -> Result<(), OwnerError> {
        let mut state = self
            .reader
            .inner
            .state
            .lock()
            .map_err(|_| OwnerError::OwnerChanged)?;
        if let Some(scope) = scope
            && scope.kind != self.kind
        {
            self.reader.close();
            return Err(OwnerError::OwnerChanged);
        }
        let mapped = scope.map(mapped_scope);
        call.authorize(&mut state, mapped.as_ref(), session)
    }
    fn ticket<'a>(
        &self,
        saved: &'a mut Option<Saved>,
        t: &ContextTicket,
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
impl OwnerWorkflowContextClient {
    pub fn new(options: ContextOptions, review: ContextReviewer) -> Result<Self, OwnerError> {
        if !(1..=3).contains(&options.kind) {
            return Err(OwnerError::InvalidRequest);
        }
        let kind = options.kind;
        let options = options.owner();
        Ok(Self {
            inner: Arc::new(SaveInner {
                expired: AtomicBool::new(false),
                reader: OwnerTemplateReader::new(options)?,
                kind,
                review,
                saved: Mutex::new(None),
                pending: Mutex::new(None),
            }),
        })
    }
    pub fn close(&self) {
        self.inner.reader.close();
        if let Ok(mut saved) = self.inner.saved.try_lock() {
            *saved = None
        }
    }
    pub fn pending(&self) -> Option<ContextPending> {
        self.inner.pending.lock().unwrap().clone()
    }
    fn error(&self, code: OwnerError) -> ContextError {
        if code == OwnerError::Deadline {
            self.inner.expired.store(true, Ordering::Release);
        }
        let unknown = self.pending().is_some()
            && !matches!(
                code,
                OwnerError::InvalidRequest | OwnerError::Busy | OwnerError::Capacity
            );
        let name = match code {
            OwnerError::InvalidRequest => "invalid_request",
            OwnerError::OwnerChanged => "owner_changed",
            OwnerError::ReadRefused => "read_refused",
            OwnerError::Busy => "busy",
            OwnerError::Capacity => "capacity",
            OwnerError::AttemptsExhausted => "attempts_exhausted",
            OwnerError::Closed => "closed",
            OwnerError::Deadline => "expired",
            _ => "response_unknown",
        };
        ContextError {
            code: name.into(),
            state: if unknown { "unknown" } else { "refused" },
        }
    }
    // The worker retains busy/admission through the foreground delivery fence.
    // A timed-out callback can settle later but cannot acknowledge or replace state.
    fn execute<T: Send + 'static>(
        &self,
        op: impl FnOnce(&SaveInner, &OwnerCall, &mut Option<Saved>) -> Result<(T, bool), OwnerError>
        + Send
        + 'static,
    ) -> Result<T, ContextError> {
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
}

impl SaveInner {
    fn fetch(
        &self,
        call: &OwnerCall,
        r: &Saved,
        post: bool,
    ) -> Result<(u16, String, Vec<u8>), OwnerError> {
        call.live()?;
        if call.credentials()? != r.session {
            self.reader.close();
            return Err(OwnerError::OwnerChanged);
        }
        let path = if post {
            "/v1/owner/workflow/contexts".into()
        } else {
            format!(
                "/v1/owner/workflow/contexts/{}",
                self.identity(r).context_id
            )
        };
        let url = format!("{}{}", self.reader.inner.options.origin, path);
        let mut request = if post {
            self.reader.inner.client.post(url).body(r.wire.to_vec())
        } else {
            self.reader.inner.client.get(url)
        };
        request = request
            .header(
                header::ACCEPT,
                if post {
                    "application/json"
                } else {
                    CONTEXT_TYPE
                },
            )
            .header(header::COOKIE, &r.session.cookie)
            .header("x-zrotext-csrf", &r.session.csrf)
            .header(header::CACHE_CONTROL, "no-store")
            .timeout(call.deadline().saturating_duration_since(Instant::now()));
        if post {
            request = request
                .header(header::CONTENT_TYPE, CONTEXT_TYPE)
                .header("idempotency-key", &r.request_id)
                .header("x-zrotext-context-revision", r.expected.to_string())
        }
        let mut response = request.send().map_err(|_| OwnerError::ResponseUnknown)?;
        call.live()?;
        let status = response.status().as_u16();
        let typ = if response
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            == 1
        {
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        };
        if status != 200 {
            return Ok((status, typ, vec![]));
        }
        let limit = if post { 64 } else { 33075 };
        let mut raw = vec![];
        response
            .by_ref()
            .take(limit + 1)
            .read_to_end(&mut raw)
            .map_err(|_| OwnerError::ResponseUnknown)?;
        call.live()?;
        if raw.len() > limit as usize {
            return Err(OwnerError::ResponseUnknown);
        };
        Ok((status, typ, raw))
    }
    fn latest(
        &self,
        call: &OwnerCall,
        r: &mut Saved,
        ack: bool,
    ) -> Result<Result<ContextReceipt, ContextError>, OwnerError> {
        self.authorize(call, Some(&r.scope), &r.session)?;
        r.shorten(call);
        let (status, typ, raw) = self.fetch(call, r, false)?;
        if status != 200 || typ != CONTEXT_TYPE {
            return Err(OwnerError::ResponseUnknown);
        }
        if raw.as_slice() == r.wire.as_slice() {
            self.authorize(call, Some(&r.scope), &r.session)?;
            r.shorten(call);
            return Ok(Ok(ContextReceipt {
                pending: self.identity(r),
                request_acknowledged: ack,
            }));
        }
        let newer = parse_context(&raw).map_err(|_| OwnerError::ResponseUnknown)?;
        let old = &r.scope;
        if newer.kind != old.kind
            || newer.account != old.account
            || newer.device != old.device
            || newer.line != old.line
            || newer.interval != old.interval
            || newer.context != old.context
            || newer.peer_digest != old.peer_digest
            || newer.reader != old.reader
            || newer.binding_generation != old.binding_generation
            || newer.trust_generation != old.trust_generation
            || newer.revision <= old.revision
        {
            return Err(OwnerError::ResponseUnknown);
        }
        p256::PublicKey::from_sec1_bytes(&raw[222..287])
            .map_err(|_| OwnerError::ResponseUnknown)?;
        self.authorize(call, Some(&newer), &r.session)?;
        r.shorten(call);
        if ack {
            Ok(Err(ContextError {
                code: "head_changed".into(),
                state: "not_current",
            }))
        } else {
            Err(OwnerError::ResponseUnknown)
        }
    }
}
impl OwnerWorkflowContextClient {
    pub fn prepare(
        &self,
        request_id: &str,
        expected: u8,
        scope: WorkflowContextScope,
        envelope: &[u8],
    ) -> Result<ContextTicket, ContextError> {
        if !(308..=33075).contains(&envelope.len())
            || !crate::original_http::uuid(request_id)
            || expected > 127
            || scope.revision != u64::from(expected) + 1
        {
            return Err(self.error(OwnerError::InvalidRequest));
        }
        let wire = Zeroizing::new(envelope.to_vec());
        let request_id = request_id.to_string();
        let owner = self.inner.clone();
        self.execute(move |inner, call, saved| {
            if saved.is_some() || inner.pending.lock().unwrap().is_some() {
                return Err(OwnerError::Busy);
            }
            call.live()?;
            let parsed = parse_context(&wire)?;
            if parsed.aad().map_err(|_| OwnerError::InvalidRequest)?
                != scope.aad().map_err(|_| OwnerError::InvalidRequest)?
            {
                return Err(OwnerError::InvalidRequest);
            }
            let session = call.credentials()?;
            inner.authorize(call, Some(&scope), &session)?;
            p256::PublicKey::from_sec1_bytes(&wire[222..287])
                .map_err(|_| OwnerError::InvalidRequest)?;
            let digest: [u8; 32] = Sha256::digest(&wire).into();
            (inner.review)(
                call,
                ContextWriteReview {
                    request_id: request_id.clone(),
                    expected_revision: expected,
                    scope: scope.clone(),
                    encrypted_digest: hex(&digest),
                },
            )
            .map_err(|_| OwnerError::ReadRefused)?;
            inner.authorize(call, Some(&scope), &session)?;
            call.live()?;
            let ticket = ContextTicket(Arc::new(()));
            let expiry = Arc::new(Expiry {
                deadline: Mutex::new(call.deadline()),
                done: AtomicBool::new(false),
            });
            let clock = expiry.clone();
            let timer_owner = Arc::downgrade(&owner);
            std::thread::Builder::new()
                .name("context-expiry".into())
                .spawn(move || {
                    while !clock.done.load(Ordering::Acquire) {
                        let remaining = clock
                            .deadline
                            .lock()
                            .unwrap()
                            .saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            if let Some(inner) = timer_owner.upgrade() {
                                inner.expired.store(true, Ordering::Release);
                                inner.reader.close();
                                if let Ok(mut saved) = inner.saved.try_lock() {
                                    *saved = None
                                }
                            };
                            break;
                        }
                        std::thread::sleep(remaining.min(Duration::from_millis(5)))
                    }
                })
                .map_err(|_| OwnerError::ReadRefused)?;
            *saved = Some(Saved {
                expiry,
                ticket: ticket.clone(),
                wire,
                expected,
                digest,
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
        .map_err(|mut e| {
            if e.code == "busy" {
                e.code = "pending_write".into()
            };
            e
        })
    }
    pub fn commit(&self, ticket: &ContextTicket) -> Result<ContextReceipt, ContextError> {
        self.post(ticket, false)
    }
    pub fn retry_unknown(&self, ticket: &ContextTicket) -> Result<ContextReceipt, ContextError> {
        self.post(ticket, true)
    }
    fn post(&self, ticket: &ContextTicket, retry: bool) -> Result<ContextReceipt, ContextError> {
        if self.inner.reader.inner.closed.load(Ordering::Acquire) {
            return Err(if self.pending().is_some() {
                ContextError {
                    code: if self.inner.expired.load(Ordering::Acquire) {
                        "expired"
                    } else {
                        "closed"
                    }
                    .into(),
                    state: "unknown",
                }
            } else {
                ContextError {
                    code: "invalid_ticket".into(),
                    state: "refused",
                }
            });
        }
        let ticket = ticket.clone();
        self.execute(move |inner, call, saved| {
            let r = inner.ticket(saved, &ticket, call)?;
            let prior = r.unknown;
            if retry && !prior || !retry && r.attempts != 0 {
                return Err(OwnerError::InvalidRequest);
            }
            if r.attempts >= 3 {
                return Err(OwnerError::AttemptsExhausted);
            }
            inner.authorize(call, Some(&r.scope), &r.session)?;
            r.shorten(call);
            r.attempts += 1;
            r.unknown = true;
            *inner.pending.lock().unwrap() = Some(inner.identity(r));
            let (status, typ, raw) = inner.fetch(call, r, true)?;
            let code = match status {
                400 => Some("invalid_request"),
                401 => Some("unauthorized"),
                403 => Some("forbidden"),
                404 => Some("not_found"),
                409 => Some("conflict"),
                413 => Some("too_large"),
                429 => Some("rate_limited"),
                _ => None,
            };
            if let Some(code) = code {
                if prior {
                    return Err(OwnerError::ResponseUnknown);
                };
                return Ok((
                    Err(ContextError {
                        code: code.into(),
                        state: "refused",
                    }),
                    true,
                ));
            }
            let typ = typ.to_ascii_lowercase();
            let parts: Vec<_> = typ.split(';').map(str::trim).collect();
            let raw = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&raw);
            if status != 200
                || !(parts == ["application/json"]
                    || parts == ["application/json", "charset=utf-8"])
                || raw != format!("{{\"revision\":{}}}", r.scope.revision).as_bytes()
            {
                return Err(OwnerError::ResponseUnknown);
            }
            let result = inner.latest(call, r, true)?;
            Ok((result, true))
        })
        .map_err(|mut e| {
            if e.code == "invalid_request" {
                e.code = "invalid_ticket".into()
            } else if e.state == "unknown" && e.code != "attempts_exhausted" {
                e.code = "response_unknown".into()
            };
            e
        })?
    }
    pub fn verify_unknown(&self, ticket: &ContextTicket) -> Result<ContextReceipt, ContextError> {
        if self.inner.reader.inner.closed.load(Ordering::Acquire) {
            return Err(if self.pending().is_some() {
                ContextError {
                    code: if self.inner.expired.load(Ordering::Acquire) {
                        "expired"
                    } else {
                        "closed"
                    }
                    .into(),
                    state: "unknown",
                }
            } else {
                ContextError {
                    code: "invalid_ticket".into(),
                    state: "refused",
                }
            });
        }
        let ticket = ticket.clone();
        self.execute(move |inner, call, saved| {
            let r = inner.ticket(saved, &ticket, call)?;
            if !r.unknown {
                return Err(OwnerError::InvalidRequest);
            };
            if r.verifies >= 3 {
                return Err(OwnerError::AttemptsExhausted);
            };
            r.verifies += 1;
            Ok((inner.latest(call, r, false)?, false))
        })
        .map_err(|mut e| {
            if e.code == "invalid_request" {
                e.code = "invalid_ticket".into()
            } else if e.state == "unknown" && e.code != "attempts_exhausted" {
                e.code = "response_unknown".into()
            };
            e
        })?
    }
}
