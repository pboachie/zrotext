//! One explicitly reviewed initial owner facts save; public-point sealing only.
//! The host draft lease is not protected private-key custody evidence.
use super::*;
use crate::workflow_context::{WorkflowContextRole, seal_workflow_context};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use zeroize::Zeroizing;

static AUTHORS: AtomicUsize = AtomicUsize::new(0);

/// Independently supplied host authority for one authoring attempt.
pub struct ContextAuthoringCurrent {
    pub binding: OwnerBinding,
    pub manifest: Arc<Manifest>,
    pub now: u64,
    pub owner_session_live: bool,
    pub consent_live: bool,
}
/// Host draft lease state; hosts must invalidate on lifecycle changes.
pub struct ContextDraftState {
    pub epoch: u64,
    pub revision: u64,
    pub custody_live: bool,
}
/// Exact pre-POST review material; the host returns true to accept.
pub struct ContextAuthoringReview {
    pub review: ContextWriteReview,
    pub text: String,
    pub account_id: String,
    pub line_id: String,
    pub peer: String,
    pub expires: u64,
    pub epoch: u64,
    pub draft_revision: u64,
}
pub type AuthoringCurrentSource =
    Arc<dyn Fn() -> Result<ContextAuthoringCurrent, OwnerError> + Send + Sync>;
pub type AuthoringSessionSource = Arc<dyn Fn() -> Result<OwnerSession, OwnerError> + Send + Sync>;
pub type AuthoringDraftSource =
    Arc<dyn Fn() -> Result<ContextDraftState, OwnerError> + Send + Sync>;
pub type AuthoringReviewer =
    Arc<dyn Fn(&ContextAuthoringReview) -> Result<bool, OwnerError> + Send + Sync>;
pub struct ContextAuthoringOptions {
    pub origin: String,
    pub binding: OwnerBinding,
    pub context: [u8; 16],
    pub expires: u64,
    pub enabled: bool,
    pub timeout: Duration,
    pub observation: Duration,
    pub additional_roots: Vec<u8>,
    pub current: AuthoringCurrentSource,
    pub session: AuthoringSessionSource,
    pub draft: AuthoringDraftSource,
    pub review: AuthoringReviewer,
}
#[derive(Clone, Debug)]
pub struct ContextAuthoringState {
    pub phase: &'static str,
    pub pending: Option<ContextPending>,
}
#[derive(Clone, Debug)]
pub struct AcknowledgedContextSource {
    pub account_id: String,
    pub request_id: String,
    pub context_id: String,
    pub revision: u8,
    pub encrypted_digest: String,
    pub request_acknowledged: bool,
}

fn uuid(v: &[u8; 16]) -> String {
    let h = hex(v);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
fn key_end(k: &[u8]) -> u64 {
    u64::from_be_bytes(k[140..148].try_into().unwrap())
}
fn refused(e: ContextError) -> OwnerError {
    if e.state == "unknown" {
        return OwnerError::ResponseUnknown;
    }
    match e.code.as_str() {
        "owner_changed" => OwnerError::OwnerChanged,
        "expired" => OwnerError::Deadline,
        "closed" => OwnerError::Closed,
        _ => OwnerError::ReadRefused,
    }
}

struct Guard {
    closed: bool,
    busy: bool,
    returned: bool,
    finished: bool,
    phase: &'static str,
    end: Option<Instant>,
    timer_done: bool,
    now: u64,
    epoch: u64,
    revision: u64,
    request: String,
    digest: String,
    text: Zeroizing<String>,
    scope: Option<WorkflowContextScope>,
    saved: Option<AcknowledgedContextSource>,
    pending: Option<ContextPending>,
    credentials: Option<OwnerSession>,
    posts: u8,
    checks: u8,
    callbacks: u64,
}
struct Core {
    options: ContextAuthoringOptions,
    guard: Mutex<Guard>,
    settled: Condvar,
    timer: Condvar,
    client: Mutex<Option<OwnerWorkflowContextClient>>,
    ticket: Mutex<Option<ContextTicket>>,
}

/// One initial kind1/revision1 owner facts draft with exact review and
/// explicit bounded reconciliation. No DOM, transport authority, or
/// protected private-key claim.
#[derive(Clone)]
pub struct OwnerContextAuthoring {
    core: Arc<Core>,
}
impl OwnerContextAuthoring {
    pub fn new(mut o: ContextAuthoringOptions) -> Result<Self, OwnerError> {
        if o.timeout.is_zero() {
            o.timeout = Duration::from_secs(10);
        }
        if o.observation.is_zero() {
            o.observation = Duration::from_secs(10);
        }
        if o.context == [0; 16]
            || o.expires == 0
            || o.expires > i64::MAX as u64
            || o.timeout < Duration::from_millis(1)
            || o.timeout > Duration::from_secs(10)
            || o.observation < Duration::from_millis(1)
            || o.observation > Duration::from_secs(10)
        {
            return Err(OwnerError::InvalidRequest);
        }
        // Reuse exact owner origin/binding/transport validation without a transport.
        let validation = OwnerWorkflowContextClient::new(
            ContextOptions {
                origin: o.origin.clone(),
                binding: o.binding.clone(),
                context: o.context,
                kind: 1,
                enabled: false,
                timeout: o.timeout,
                additional_roots: o.additional_roots.clone(),
                current: Arc::new(|_| Err(OwnerError::OwnerChanged)),
                session: Arc::new(|_| Err(OwnerError::OwnerChanged)),
            },
            Arc::new(|_, _| Err(OwnerError::ReadRefused)),
        )?;
        validation.close();
        let authoring = Self {
            core: Arc::new(Core {
                options: o,
                guard: Mutex::new(Guard {
                    closed: false,
                    busy: false,
                    returned: false,
                    finished: false,
                    phase: "editing",
                    end: None,
                    timer_done: true,
                    now: 0,
                    epoch: 0,
                    revision: 0,
                    request: String::new(),
                    digest: String::new(),
                    text: Zeroizing::new(String::new()),
                    scope: None,
                    saved: None,
                    pending: None,
                    credentials: None,
                    posts: 0,
                    checks: 0,
                    callbacks: 0,
                }),
                settled: Condvar::new(),
                timer: Condvar::new(),
                client: Mutex::new(None),
                ticket: Mutex::new(None),
            }),
        };
        if !authoring.core.options.enabled {
            authoring.close();
        }
        Ok(authoring)
    }
    pub fn state(&self) -> ContextAuthoringState {
        let g = self.core.guard.lock().unwrap();
        ContextAuthoringState {
            phase: g.phase,
            pending: g.pending.clone(),
        }
    }
    pub fn saved_source(&self) -> Option<AcknowledgedContextSource> {
        // A closed authoring keeps its terminal phase label; only deadline
        // expiry re-closes here, mirroring the maintained savedSource contract.
        let expired = {
            let g = self.core.guard.lock().unwrap();
            g.end.is_some_and(|end| Instant::now() >= end)
        };
        if self.closed() {
            return None;
        }
        if expired {
            self.close();
            return None;
        }
        let g = self.core.guard.lock().unwrap();
        if g.phase != "saved" {
            return None;
        }
        g.saved.clone()
    }
    pub fn close(&self) {
        let client = self.core.client.lock().unwrap().take();
        let mut g = self.core.guard.lock().unwrap();
        g.closed = true;
        g.phase = "closed";
        g.saved = None;
        g.text = Zeroizing::new(String::new());
        g.credentials = None;
        g.timer_done = true;
        self.core.timer.notify_all();
        self.core.settled.notify_all();
        drop(g);
        if let Some(client) = client {
            let pending = client.pending();
            client.close();
            if let Some(pending) = pending {
                self.core.guard.lock().unwrap().pending = Some(pending);
            }
        }
        self.core.ticket.lock().unwrap().take();
    }
    pub fn invalidate(&self) {
        self.close()
    }
    fn live(&self) -> Result<(), OwnerError> {
        if self.closed() {
            // A terminal label (refused/unknown/closed) is already settled;
            // a liveness probe reports it without re-closing.
            return Err(OwnerError::Closed);
        }
        let expired = {
            let g = self.core.guard.lock().unwrap();
            g.end.is_some_and(|end| Instant::now() >= end)
        };
        if expired {
            self.close();
            return Err(OwnerError::Closed);
        }
        Ok(())
    }
    fn closed(&self) -> bool {
        self.core.guard.lock().unwrap().closed
    }
    fn cap(&self, end: Instant) -> Result<(), OwnerError> {
        {
            let mut g = self.core.guard.lock().unwrap();
            if g.closed || g.end.is_some_and(|current| end > current) {
                return Err(OwnerError::OwnerChanged);
            }
            g.end = Some(end);
            g.timer_done = false;
            self.core.timer.notify_all();
        }
        let core = self.core.clone();
        std::thread::Builder::new()
            .name("authoring-deadline".into())
            .spawn(move || {
                let mut guard = core.guard.lock().unwrap();
                loop {
                    if guard.timer_done || guard.closed {
                        return;
                    }
                    let Some(end) = guard.end else {
                        return;
                    };
                    let now = Instant::now();
                    if now >= end {
                        break;
                    }
                    let (next, _) = core.timer.wait_timeout(guard, end - now).unwrap();
                    guard = next;
                }
                drop(guard);
                let client = core.client.lock().unwrap().take();
                core.ticket.lock().unwrap().take();
                let mut g = core.guard.lock().unwrap();
                g.closed = true;
                g.phase = "closed";
                g.saved = None;
                g.text = Zeroizing::new(String::new());
                g.credentials = None;
                if let Some(client) = client {
                    let pending = client.pending();
                    client.close();
                    if let Some(pending) = pending {
                        g.pending = Some(pending);
                    }
                }
            })
            .map_err(|_| OwnerError::ReadRefused)?;
        self.live()
    }
    fn host<T>(&self, call: impl FnOnce() -> Result<T, OwnerError>) -> Result<T, OwnerError> {
        {
            let mut g = self.core.guard.lock().unwrap();
            if g.closed || g.end.is_some_and(|end| Instant::now() >= end) {
                return Err(OwnerError::Closed);
            }
            g.callbacks += 1;
        }
        let result = call();
        {
            let mut g = self.core.guard.lock().unwrap();
            g.callbacks -= 1;
            self.core.settled.notify_all();
        }
        result
    }
    fn draft(&self) -> Result<(), OwnerError> {
        let value = self.host(|| (self.core.options.draft)())?;
        let valid = {
            let g = self.core.guard.lock().unwrap();
            value.epoch == g.epoch && value.revision == g.revision && value.custody_live
        };
        if !valid {
            self.close();
            return Err(OwnerError::OwnerChanged);
        }
        self.live()
    }
    fn current(&self) -> Result<OwnerAuthority, OwnerError> {
        let result = self.current_authority();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn current_authority(&self) -> Result<OwnerAuthority, OwnerError> {
        self.draft()?;
        let started = Instant::now();
        let c = self.host(|| (self.core.options.current)())?;
        self.live()?;
        let m = &c.manifest;
        let b = &self.core.options.binding;
        let now_floor = self.core.guard.lock().unwrap().now;
        if c.binding != *b
            || !c.owner_session_live
            || !c.consent_live
            || c.now == 0
            || c.now < now_floor
            || m.profile != 2
            || m.account != b.account
            || !window(m.issued, m.expires, c.now)
            || c.now < m.comparison
            || self.core.options.expires <= c.now
            || self.core.options.expires - c.now > 30 * 86400000
        {
            return Err(OwnerError::OwnerChanged);
        }
        let phone = key(m, 1, &b.phone_reader).ok_or(OwnerError::OwnerChanged)?;
        let reader = key(m, 2, &b.archive_reader).ok_or(OwnerError::OwnerChanged)?;
        let signer = m.raw[151..m.raw.len() - 64]
            .chunks_exact(149)
            .find(|w| {
                w[0] == 4
                    && active(w, c.now, 2)
                    && w[130..132] == [0, 2]
                    && w[98..114] == b.device
                    && w[114..130] == b.line
            })
            .ok_or(OwnerError::OwnerChanged)?;
        if !active(phone, c.now, 0)
            || phone[98..114] != b.device
            || phone[114..130] != b.line
            || !active(reader, c.now, 8)
        {
            return Err(OwnerError::OwnerChanged);
        }
        let signed = m
            .expires
            .min(key_end(phone))
            .min(key_end(reader))
            .min(key_end(signer))
            .min(self.core.options.expires);
        let observation = self.core.options.observation.as_millis();
        let horizon = u64::try_from(observation).unwrap_or(u64::MAX);
        let mut next = started + Duration::from_millis((signed - c.now).min(horizon));
        if let Some(end) = self.core.guard.lock().unwrap().end
            && end < next
        {
            next = end;
        }
        self.cap(next)?;
        self.core.guard.lock().unwrap().now = c.now;
        self.draft()?;
        let valid_for = next.saturating_duration_since(Instant::now());
        if valid_for < Duration::from_millis(1) {
            return Err(OwnerError::OwnerChanged);
        }
        Ok(OwnerAuthority {
            binding: b.clone(),
            manifest: c.manifest.clone(),
            now: c.now,
            valid_for,
            owner_session_live: true,
            consent_live: true,
            active: true,
        })
    }
    fn session(&self) -> Result<OwnerSession, OwnerError> {
        let result = (|| {
            let value = self.host(|| (self.core.options.session)())?;
            self.live()?;
            let mut g = self.core.guard.lock().unwrap();
            if !value.valid(&self.core.options.origin)
                || g.credentials.as_ref().is_some_and(|prior| *prior != value)
            {
                return Err(OwnerError::OwnerChanged);
            }
            g.credentials = Some(value.clone());
            Ok(value)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn review(&self, v: &ContextWriteReview) -> Result<(), OwnerError> {
        self.draft()?;
        let (text, scope, request, digest, epoch, revision) = {
            let g = self.core.guard.lock().unwrap();
            (
                g.text.to_string(),
                g.scope.clone(),
                g.request.clone(),
                g.digest.clone(),
                g.epoch,
                g.revision,
            )
        };
        {
            let mut g = self.core.guard.lock().unwrap();
            g.phase = "review";
        }
        let same = scope
            .as_ref()
            .zip(v.scope.aad().ok())
            .is_some_and(|(mine, theirs)| mine.aad().ok() == Some(theirs));
        if v.request_id != request
            || v.expected_revision != 0
            || v.scope.revision != 1
            || v.encrypted_digest != digest
            || !same
            || v.scope.context != self.core.options.context
        {
            return Err(OwnerError::OwnerChanged);
        }
        let accepted = self.host(|| {
            (self.core.options.review)(&ContextAuthoringReview {
                review: v.clone(),
                text,
                account_id: uuid(&self.core.options.binding.account),
                line_id: uuid(&self.core.options.binding.line),
                peer: self.core.options.binding.peer.clone(),
                expires: self.core.options.expires,
                epoch,
                draft_revision: revision,
            })
        })?;
        if !accepted {
            return Err(OwnerError::ReadRefused);
        }
        self.draft()?;
        let mut g = self.core.guard.lock().unwrap();
        if g.closed {
            return Err(OwnerError::Closed);
        }
        g.phase = "saving";
        Ok(())
    }
    fn retain(&self, r: &ContextReceipt) -> Result<(), OwnerError> {
        self.live()?;
        let mut g = self.core.guard.lock().unwrap();
        if g.closed
            || !r.request_acknowledged
            || r.pending.request_id != g.request
            || r.pending.context_id != uuid(&self.core.options.context)
            || r.pending.revision != 1
            || r.pending.encrypted_digest != g.digest
        {
            return Err(OwnerError::OwnerChanged);
        }
        g.saved = Some(AcknowledgedContextSource {
            account_id: uuid(&self.core.options.binding.account),
            request_id: r.pending.request_id.clone(),
            context_id: r.pending.context_id.clone(),
            revision: 1,
            encrypted_digest: r.pending.encrypted_digest.clone(),
            request_acknowledged: true,
        });
        g.pending = None;
        g.request.clear();
        g.digest.clear();
        g.text = Zeroizing::new(String::new());
        g.phase = "saved";
        g.timer_done = true;
        self.core.timer.notify_all();
        Ok(())
    }
    fn outcome(&self, error: OwnerError) {
        let client_pending = self
            .core
            .client
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|client| client.pending());
        let mut g = self.core.guard.lock().unwrap();
        g.saved = None;
        g.text = Zeroizing::new(String::new());
        g.pending = client_pending.or_else(|| g.pending.take());
        let expired = matches!(
            error,
            OwnerError::Closed | OwnerError::Deadline | OwnerError::OwnerChanged
        ) || g.end.is_some_and(|end| Instant::now() >= end);
        if expired {
            drop(g);
            self.close();
            g = self.core.guard.lock().unwrap();
        }
        if g.closed {
            g.phase = "closed";
        } else if g.pending.is_some() {
            g.phase = "unknown";
        } else {
            // Flip the terminal label with the closed flag in one critical
            // section so a concurrent foreground read never observes a
            // half-settled refusal.
            let client = self.core.client.lock().unwrap().take();
            self.core.ticket.lock().unwrap().take();
            g.closed = true;
            g.phase = "refused";
            g.credentials = None;
            g.timer_done = true;
            self.core.timer.notify_all();
            self.core.settled.notify_all();
            drop(g);
            if let Some(client) = client {
                client.close();
            }
            return;
        }
        drop(g);
    }
    fn operation(
        &self,
        required: &'static str,
        enter: impl FnOnce(&mut Guard),
        run: impl FnOnce() -> Result<(), OwnerError> + Send + 'static,
    ) -> ContextAuthoringState {
        {
            let g = self.core.guard.lock().unwrap();
            if g.closed || g.busy || g.phase != required {
                return ContextAuthoringState {
                    phase: g.phase,
                    pending: g.pending.clone(),
                };
            }
        }
        if AUTHORS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 4).then_some(n + 1)
            })
            .is_err()
        {
            self.outcome(OwnerError::Capacity);
            return self.state();
        }
        {
            let mut g = self.core.guard.lock().unwrap();
            if g.closed || g.busy || g.phase != required {
                drop(g);
                AUTHORS.fetch_sub(1, Ordering::AcqRel);
                return self.state();
            }
            g.busy = true;
            enter(&mut g);
        }
        let core = self.core.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("authoring-operation".into())
            .spawn(move || {
                if let Err(error) = run() {
                    let authoring = OwnerContextAuthoring { core: core.clone() };
                    authoring.outcome(error);
                }
                let _ = tx.send(());
                {
                    let mut g = core.guard.lock().unwrap();
                    while g.callbacks > 0 {
                        g = core.settled.wait(g).unwrap();
                    }
                }
                AUTHORS.fetch_sub(1, Ordering::AcqRel);
                {
                    let mut g = core.guard.lock().unwrap();
                    if g.returned {
                        g.busy = false;
                    }
                    g.finished = true;
                }
                let _ = release_tx.send(());
            });
        if worker.is_err() {
            AUTHORS.fetch_sub(1, Ordering::AcqRel);
            self.core.guard.lock().unwrap().busy = false;
            self.close();
            return self.state();
        }
        // The foreground returns as soon as the outcome is observable; backend
        // callbacks may still hold this author's admission until they settle.
        let mut settled = false;
        let outcome = loop {
            if self.closed() {
                break self.state();
            }
            match rx.recv_timeout(Duration::from_millis(5)) {
                Ok(()) => {
                    settled = true;
                    break self.state();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.live().is_err() {
                        break self.state();
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break self.state(),
            }
        };
        {
            let mut g = self.core.guard.lock().unwrap();
            g.returned = true;
            if g.finished {
                g.busy = false;
            }
        }
        if settled {
            // The result path waits for the deterministic busy release so an
            // immediately following reconciliation observes admission reset.
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
        }
        outcome
    }
    pub fn author(&self, text: &str, epoch: u64, revision: u64) -> ContextAuthoringState {
        let core = self.core.clone();
        let timeout = core.options.timeout;
        let text = text.to_string();
        self.operation(
            "editing",
            |g| {
                g.phase = "preparing";
                g.end = Some(Instant::now() + timeout);
            },
            move || author_run(&core, &text, epoch, revision),
        )
    }
    pub fn retry_unknown(&self) -> ContextAuthoringState {
        let core = self.core.clone();
        self.operation(
            "unknown",
            |g| g.phase = "saving",
            move || reconcile_run(&core, true),
        )
    }
    pub fn verify_unknown(&self) -> ContextAuthoringState {
        let core = self.core.clone();
        self.operation(
            "unknown",
            |g| g.phase = "saving",
            move || reconcile_run(&core, false),
        )
    }
    fn review_adapter(&self) -> ContextReviewer {
        let core = self.core.clone();
        Arc::new(move |_, review: ContextWriteReview| {
            let authoring = OwnerContextAuthoring { core: core.clone() };
            authoring.review(&review)
        })
    }
    fn current_adapter(&self) -> CurrentSource {
        let core = self.core.clone();
        Arc::new(move |_| {
            let authoring = OwnerContextAuthoring { core: core.clone() };
            authoring.current()
        })
    }
    fn session_adapter(&self) -> SessionSource {
        let core = self.core.clone();
        Arc::new(move |_| {
            let authoring = OwnerContextAuthoring { core: core.clone() };
            authoring.session()
        })
    }
}
fn author_run(core: &Arc<Core>, text: &str, epoch: u64, revision: u64) -> Result<(), OwnerError> {
    let authoring = OwnerContextAuthoring { core: core.clone() };
    let end = core.guard.lock().unwrap().end;
    authoring.cap(end.ok_or(OwnerError::OwnerChanged)?)?;
    if epoch == 0 || revision == 0 || text.is_empty() || text.len() > 32768 {
        return Err(OwnerError::InvalidRequest);
    }
    {
        let mut g = core.guard.lock().unwrap();
        *g.text = text.to_string();
        g.epoch = epoch;
        g.revision = revision;
    }
    let authority = authoring.current()?;
    let m = authority.manifest.clone();
    let b = &core.options.binding;
    let scope = WorkflowContextScope {
        kind: 1,
        account: b.account,
        device: b.device,
        line: b.line,
        interval: b.interval,
        context: core.options.context,
        binding_generation: b.generation,
        revision: 1,
        expires: core.options.expires,
        trust_generation: m.generation,
        manifest_version: m.version,
        peer_digest: <[u8; 32]>::from(Sha256::digest(b.peer.as_bytes())),
        reader: b.archive_reader,
        manifest_digest: m.digest,
    };
    let wire = Zeroizing::new(
        seal_workflow_context(
            &m,
            &scope,
            WorkflowContextRole::Owner,
            authority.now,
            text.as_bytes(),
        )
        .map_err(|_| OwnerError::ReadRefused)?,
    );
    authoring.draft()?;
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| OwnerError::ReadRefused)?;
    id[6] = (id[6] & 15) | 64;
    id[8] = (id[8] & 63) | 128;
    let request = uuid(&id);
    let digest = hex(&Sha256::digest(wire.as_slice()));
    {
        let mut g = core.guard.lock().unwrap();
        g.scope = Some(scope.clone());
        g.request = request.clone();
        g.digest = digest.clone();
    }
    let remaining = end
        .map(|at| at.saturating_duration_since(Instant::now()))
        .unwrap_or_default();
    if remaining < Duration::from_millis(1) {
        return Err(OwnerError::OwnerChanged);
    }
    let client = OwnerWorkflowContextClient::new(
        ContextOptions {
            origin: core.options.origin.clone(),
            binding: b.clone(),
            context: core.options.context,
            kind: 1,
            enabled: true,
            timeout: remaining,
            additional_roots: core.options.additional_roots.clone(),
            current: authoring.current_adapter(),
            session: authoring.session_adapter(),
        },
        authoring.review_adapter(),
    )?;
    if core.guard.lock().unwrap().closed {
        client.close();
        return Err(OwnerError::Closed);
    }
    *core.client.lock().unwrap() = Some(client);
    let client = core
        .client
        .lock()
        .unwrap()
        .clone()
        .ok_or(OwnerError::OwnerChanged)?;
    let ticket = client
        .prepare(&request, 0, scope, wire.as_slice())
        .map_err(refused)?;
    drop(client);
    authoring.draft()?;
    *core.ticket.lock().unwrap() = Some(ticket.clone());
    core.guard.lock().unwrap().posts += 1;
    let client = core
        .client
        .lock()
        .unwrap()
        .clone()
        .ok_or(OwnerError::OwnerChanged)?;
    let receipt = client.commit(&ticket).map_err(refused)?;
    drop(client);
    authoring.draft()?;
    authoring.retain(&receipt)
}
fn reconcile_run(core: &Arc<Core>, retry: bool) -> Result<(), OwnerError> {
    let authoring = OwnerContextAuthoring { core: core.clone() };
    authoring.draft()?;
    let client = core
        .client
        .lock()
        .unwrap()
        .clone()
        .ok_or(OwnerError::OwnerChanged)?;
    let ticket = core
        .ticket
        .lock()
        .unwrap()
        .clone()
        .ok_or(OwnerError::OwnerChanged)?;
    {
        let mut g = core.guard.lock().unwrap();
        let limit = if retry { g.posts } else { g.checks };
        if limit >= 3 {
            g.phase = "unknown";
            return Ok(());
        }
        if retry {
            g.posts += 1;
        } else {
            g.checks += 1;
        }
    }
    let receipt = if retry {
        client.retry_unknown(&ticket).map_err(refused)?
    } else {
        client.verify_unknown(&ticket).map_err(refused)?
    };
    drop(client);
    authoring.draft()?;
    if !receipt.request_acknowledged {
        let mut g = core.guard.lock().unwrap();
        if !g.closed {
            g.phase = "unknown";
        }
        return Ok(());
    }
    authoring.retain(&receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(current: AuthoringCurrentSource) -> OwnerContextAuthoring {
        OwnerContextAuthoring::new(ContextAuthoringOptions {
            origin: "https://owner.example.invalid".into(),
            binding: OwnerBinding {
                account: [1; 16],
                device: [1; 16],
                line: [1; 16],
                interval: [1; 16],
                session: [1; 16],
                generation: 1,
                peer: "+12".into(),
                phone_reader: [1; 32],
                archive_reader: [1; 32],
            },
            context: [2; 16],
            expires: 1 << 40,
            enabled: true,
            timeout: Duration::from_secs(2),
            observation: Duration::from_secs(2),
            additional_roots: vec![],
            current,
            session: Arc::new(|| Err(OwnerError::OwnerChanged)),
            draft: Arc::new(|| {
                Ok(ContextDraftState {
                    epoch: 1,
                    revision: 1,
                    custody_live: true,
                })
            }),
            review: Arc::new(|_| Ok(true)),
        })
        .unwrap()
    }

    // An unresolved host callback keeps this author's admission; a fifth
    // concurrent author is refused before any callback, and admission frees
    // once the blocked workers settle.
    #[test]
    fn unresolved_callbacks_retain_admission() {
        let (entered, entered_wait) = std::sync::mpsc::sync_channel(4);
        let entered = Arc::new(entered);
        let (release, release_wait) = std::sync::mpsc::sync_channel::<()>(1);
        let release_wait = Arc::new(Mutex::new(release_wait));
        let block: AuthoringCurrentSource = Arc::new(move || {
            let _ = entered.send(());
            let _ = release_wait.lock().unwrap().recv();
            Err(OwnerError::OwnerChanged)
        });
        let mut states = vec![];
        for _ in 0..4 {
            let authoring = fixture(block.clone());
            states.push(std::thread::spawn(move || authoring.author("Facts", 1, 1)));
        }
        for _ in 0..4 {
            entered_wait
                .recv_timeout(Duration::from_secs(1))
                .expect("host callback not entered");
        }
        let extra = fixture(Arc::new(|| Err(OwnerError::OwnerChanged)));
        assert_eq!(extra.author("Facts", 1, 1).phase, "refused");
        drop(release);
        for state in states {
            let _ = state.join().unwrap();
        }
        let currents = Arc::new(AtomicUsize::new(0));
        let count = currents.clone();
        let after = fixture(Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            Err(OwnerError::OwnerChanged)
        }));
        let state = after.author("Facts", 1, 1);
        assert_eq!(state.phase, "closed");
        assert_eq!(currents.load(Ordering::SeqCst), 1);
    }
}
