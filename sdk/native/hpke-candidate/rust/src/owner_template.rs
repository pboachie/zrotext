//! Cold opaque owner-template HTTPS loading; no plaintext or save acknowledgement.
#[path = "owner_context.rs"]
pub mod context;
#[path = "owner_template_save.rs"]
pub mod save;
use crate::{
    manifest::{Manifest, window},
    reader::{active, key},
    template_crypto::EncryptedTemplateScope,
    template_store::{CONTENT_TYPE, hex, parse},
};
use reqwest::{Certificate, Url, blocking::Client, header};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerError {
    InvalidRequest,
    OwnerChanged,
    ReadRefused,
    ResponseUnknown,
    HeadRegressed,
    HeadChanged,
    Busy,
    Capacity,
    AttemptsExhausted,
    Closed,
    Deadline,
}
impl std::fmt::Display for OwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owner template refused")
    }
}
impl std::error::Error for OwnerError {}
static ADMISSION: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, PartialEq, Eq)]
pub struct OwnerBinding {
    pub account: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub interval: [u8; 16],
    pub session: [u8; 16],
    pub generation: u64,
    pub peer: String,
    pub phone_reader: [u8; 32],
    pub archive_reader: [u8; 32],
}
impl OwnerBinding {
    fn valid(&self) -> bool {
        [
            self.account,
            self.device,
            self.line,
            self.interval,
            self.session,
        ]
        .iter()
        .all(|v| *v != [0; 16])
            && (1..=i64::MAX as u64).contains(&self.generation)
            && self.phone_reader != [0; 32]
            && self.archive_reader != [0; 32]
            && (3..=16).contains(&self.peer.len())
            && self.peer.as_bytes()[0] == b'+'
            && (b'1'..=b'9').contains(&self.peer.as_bytes()[1])
            && self.peer.as_bytes()[2..].iter().all(u8::is_ascii_digit)
    }
}
pub struct OwnerAuthority {
    pub binding: OwnerBinding,
    pub manifest: Arc<Manifest>,
    pub now: u64,
    pub valid_for: Duration,
    pub owner_session_live: bool,
    pub consent_live: bool,
    pub active: bool,
}
/// Independently authenticated host session; never extracted from a browser.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerSession {
    pub origin: String,
    pub cookie: String,
    pub csrf: String,
}
impl OwnerSession {
    fn valid(&self, origin: &str) -> bool {
        self.origin == origin
            && (1..=4096).contains(&self.cookie.len())
            && self.cookie.contains('=')
            && self.cookie.bytes().all(|b| (32..=126).contains(&b))
            && (1..=256).contains(&self.csrf.len())
            && self.csrf.bytes().all(|b| (33..=126).contains(&b))
    }
}
pub type CurrentSource =
    Arc<dyn Fn(&OwnerCall) -> Result<OwnerAuthority, OwnerError> + Send + Sync>;
pub type SessionSource = Arc<dyn Fn(&OwnerCall) -> Result<OwnerSession, OwnerError> + Send + Sync>;
#[derive(Clone)]
pub struct OwnerOptions {
    pub origin: String,
    pub binding: OwnerBinding,
    pub template: [u8; 16],
    pub enabled: bool,
    pub timeout: Duration,
    pub additional_roots: Vec<u8>,
    pub current: CurrentSource,
    pub session: SessionSource,
}
pub struct OwnerTemplateSnapshot {
    scope: EncryptedTemplateScope,
    wire: Vec<u8>,
    digest: [u8; 32],
    matches_pending: bool,
}
impl OwnerTemplateSnapshot {
    pub fn scope(&self) -> EncryptedTemplateScope {
        self.scope.clone()
    }
    pub fn envelope(&self) -> Vec<u8> {
        self.wire.clone()
    }
    pub fn encrypted_digest(&self) -> String {
        hex(&self.digest)
    }
    pub fn request_acknowledged(&self) -> bool {
        false
    }
    pub fn matches_pending(&self) -> bool {
        self.matches_pending
    }
}
struct State {
    prior: Option<Arc<Manifest>>,
    now: u64,
    head: u64,
    head_digest: [u8; 32],
}
struct Inner {
    options: OwnerOptions,
    client: Client,
    closed: AtomicBool,
    busy: AtomicBool,
    lifetime: Mutex<Option<Instant>>,
    state: Mutex<State>,
}
/// Shared cancellation/deadline for trusted callbacks. Callbacks must not reenter.
pub struct OwnerCall {
    inner: Arc<Inner>,
    deadline: Mutex<Instant>,
}
impl OwnerCall {
    pub fn deadline(&self) -> Instant {
        let deadline = *self.deadline.lock().unwrap();
        self.inner
            .lifetime
            .lock()
            .unwrap()
            .map_or(deadline, |at| deadline.min(at))
    }
    pub fn cancelled(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire) || Instant::now() >= self.deadline()
    }
    fn live(&self) -> Result<(), OwnerError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(OwnerError::Closed);
        };
        if Instant::now() >= self.deadline() {
            self.inner.closed.store(true, Ordering::Release);
            return Err(OwnerError::Deadline);
        };
        Ok(())
    }
    fn shorten(&self, at: Instant) {
        let mut end = self.deadline.lock().unwrap();
        *end = (*end).min(at)
    }
    fn credentials(&self) -> Result<OwnerSession, OwnerError> {
        self.live()?;
        let s = (self.inner.options.session)(self).map_err(|_| OwnerError::OwnerChanged)?;
        if !s.valid(&self.inner.options.origin) {
            return Err(OwnerError::OwnerChanged);
        };
        self.live()?;
        Ok(s)
    }
    fn authorize(
        &self,
        state: &mut State,
        scope: Option<&EncryptedTemplateScope>,
        session: &OwnerSession,
    ) -> Result<(), OwnerError> {
        let result = (|| {
            self.live()?;
            let started = Instant::now();
            let a = (self.inner.options.current)(self)?;
            self.live()?;
            let m = &a.manifest;
            let b = &self.inner.options.binding;
            if &a.binding != b
                || !a.owner_session_live
                || !a.consent_live
                || !a.active
                || a.now == 0
                || a.now < state.now
                || a.valid_for.is_zero()
                || a.valid_for > Duration::from_secs(60)
                || m.profile != 2
                || m.account != b.account
                || !window(m.issued, m.expires, a.now)
                || a.now < m.comparison
            {
                return Err(OwnerError::OwnerChanged);
            }
            if state.prior.as_ref().is_some_and(|p| {
                m.root != p.root
                    || m.enrolled != p.enrolled
                    || m.generation != p.generation
                    || m.version < p.version
                    || (m.version == p.version && m.digest != p.digest)
            }) {
                return Err(OwnerError::OwnerChanged);
            }
            let reader = key(m, 2, &b.archive_reader).ok_or(OwnerError::OwnerChanged)?;
            if !active(reader, a.now, 8) {
                return Err(OwnerError::OwnerChanged);
            }
            let phone = m.raw[151..m.raw.len() - 64]
                .chunks_exact(149)
                .find(|k| {
                    k[0] == 4
                        && active(k, a.now, 2)
                        && k[98..114] == b.device
                        && k[114..130] == b.line
                })
                .ok_or(OwnerError::OwnerChanged)?;
            if phone[130..132] != [0, 2] {
                return Err(OwnerError::OwnerChanged);
            }
            let end = |k: &[u8]| u64::from_be_bytes(k[140..148].try_into().unwrap());
            let mut expiry = m.expires.min(end(reader)).min(end(phone));
            if let Some(s) = scope {
                if s.account != b.account
                    || s.device != b.device
                    || s.line != b.line
                    || s.interval != b.interval
                    || s.template != self.inner.options.template
                    || s.binding_generation != b.generation
                    || s.reader != b.archive_reader
                    || s.trust_generation != m.generation
                    || s.manifest_version != m.version
                    || s.manifest_digest != m.digest
                    || s.expires <= a.now
                    || s.expires - a.now > 30 * 86400000
                    || s.peer_digest != <[u8; 32]>::from(Sha256::digest(b.peer.as_bytes()))
                {
                    return Err(OwnerError::OwnerChanged);
                }
                expiry = expiry.min(s.expires)
            }
            self.shorten(started + a.valid_for.min(Duration::from_millis(expiry - a.now)));
            if &self.credentials()? != session {
                return Err(OwnerError::OwnerChanged);
            };
            self.live()?;
            state.prior = Some(a.manifest);
            state.now = a.now;
            Ok(())
        })();
        if result.is_err() {
            self.inner.closed.store(true, Ordering::Release);
            return Err(OwnerError::OwnerChanged);
        };
        result
    }
    fn read(&self) -> Result<OwnerTemplateSnapshot, OwnerError> {
        self.read_expected(None)
    }
    fn read_expected(
        &self,
        expected: Option<&OwnerSession>,
    ) -> Result<OwnerTemplateSnapshot, OwnerError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| OwnerError::ReadRefused)?;
        let session = self.credentials()?;
        if expected.is_some_and(|v| v != &session) {
            self.inner.closed.store(true, Ordering::Release);
            return Err(OwnerError::OwnerChanged);
        }
        self.authorize(&mut state, None, &session)?;
        if self.credentials()? != session {
            self.inner.closed.store(true, Ordering::Release);
            return Err(OwnerError::OwnerChanged);
        }
        let id = hex(&self.inner.options.template);
        let id = format!(
            "{}-{}-{}-{}-{}",
            &id[..8],
            &id[8..12],
            &id[12..16],
            &id[16..20],
            &id[20..]
        );
        self.live()?;
        let mut response = self
            .inner
            .client
            .get(format!(
                "{}/v1/owner/workflow/templates/{id}",
                self.inner.options.origin
            ))
            .header(header::ACCEPT, CONTENT_TYPE)
            .header("x-zrotext-csrf", &session.csrf)
            .header(header::COOKIE, &session.cookie)
            .header(header::CACHE_CONTROL, "no-store")
            .timeout(self.deadline().saturating_duration_since(Instant::now()))
            .send()
            .map_err(|_| OwnerError::ReadRefused)?;
        if response.status().is_redirection() {
            return Err(OwnerError::ResponseUnknown);
        }
        if response.status().as_u16() != 200
            || response
                .headers()
                .get_all(header::CONTENT_TYPE)
                .iter()
                .count()
                != 1
            || response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                != Some(CONTENT_TYPE)
        {
            if [401, 403].contains(&response.status().as_u16()) {
                self.inner.closed.store(true, Ordering::Release)
            };
            return Err(OwnerError::ReadRefused);
        }
        let mut wire = vec![];
        response
            .by_ref()
            .take(33076)
            .read_to_end(&mut wire)
            .map_err(|_| OwnerError::ResponseUnknown)?;
        self.live()?;
        let scope = parse(&wire).map_err(|_| OwnerError::InvalidRequest)?;
        if scope.revision < state.head {
            return Err(OwnerError::HeadRegressed);
        }
        self.authorize(&mut state, Some(&scope), &session)?;
        p256::PublicKey::from_sec1_bytes(&wire[222..287])
            .map_err(|_| OwnerError::InvalidRequest)?;
        let digest: [u8; 32] = Sha256::digest(&wire).into();
        self.authorize(&mut state, Some(&scope), &session)?;
        if scope.revision == state.head && digest != state.head_digest {
            return Err(OwnerError::HeadChanged);
        };
        self.live()?;
        state.head = scope.revision;
        state.head_digest = digest;
        Ok(OwnerTemplateSnapshot {
            scope,
            wire,
            digest,
            matches_pending: false,
        })
    }
}
#[derive(Clone)]
pub struct OwnerTemplateReader {
    inner: Arc<Inner>,
}
impl OwnerTemplateReader {
    pub fn new(mut o: OwnerOptions) -> Result<Self, OwnerError> {
        let bad = OwnerError::InvalidRequest;
        if !o.binding.valid()
            || o.template == [0; 16]
            || o.timeout < Duration::from_millis(1)
            || o.timeout > Duration::from_secs(10)
            || !o.origin.is_ascii()
            || o.origin
                .bytes()
                .any(|b| b <= 32 || b >= 127 || b == b'\\' || b == b'@')
        {
            return Err(bad);
        }
        let url = Url::parse(&o.origin).map_err(|_| bad)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.origin().ascii_serialization() != o.origin
        {
            return Err(bad);
        }
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only()
            .pool_max_idle_per_host(0)
            .timeout(o.timeout)
            .tls_version_min(reqwest::tls::Version::TLS_1_2);
        if !o.additional_roots.is_empty() {
            let certs = Certificate::from_pem_bundle(&o.additional_roots).map_err(|_| bad)?;
            if certs.is_empty() {
                return Err(bad);
            };
            builder = builder.tls_certs_merge(certs)
        };
        o.additional_roots.clear();
        let client = builder.build().map_err(|_| bad)?;
        let closed = AtomicBool::new(!o.enabled);
        Ok(Self {
            inner: Arc::new(Inner {
                options: o,
                client,
                closed,
                busy: AtomicBool::new(false),
                lifetime: Mutex::new(None),
                state: Mutex::new(State {
                    prior: None,
                    now: 0,
                    head: 0,
                    head_digest: [0; 32],
                }),
            }),
        })
    }
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release)
    }
    pub fn read_latest(&self) -> Result<OwnerTemplateSnapshot, OwnerError> {
        if self
            .inner
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(OwnerError::Busy);
        }
        if ADMISSION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 8).then_some(n + 1)
            })
            .is_err()
        {
            self.inner.busy.store(false, Ordering::Release);
            return Err(OwnerError::Capacity);
        }
        struct Release(Arc<Inner>);
        impl Drop for Release {
            fn drop(&mut self) {
                ADMISSION.fetch_sub(1, Ordering::AcqRel);
                self.0.busy.store(false, Ordering::Release)
            }
        }
        let release = Release(self.inner.clone());
        let call = Arc::new(OwnerCall {
            inner: self.inner.clone(),
            deadline: Mutex::new(Instant::now() + self.inner.options.timeout),
        });
        let worker = call.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .spawn(move || {
                let _release = release;
                let result = worker.read();
                let _ = tx.send(result);
            })
            .map_err(|_| OwnerError::ReadRefused)?;
        loop {
            call.live()?;
            let wait = call
                .deadline()
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(5));
            match rx.recv_timeout(wait) {
                Ok(result) => {
                    let snapshot = result?;
                    call.live()?;
                    return Ok(snapshot);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(OwnerError::ReadRefused),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callback_retains_admission_until_actual_settlement() {
        let stop = Arc::new(AtomicBool::new(false));
        struct Stop(Arc<AtomicBool>);
        impl Drop for Stop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release)
            }
        }
        let _stop = Stop(stop.clone());
        let make = || {
            let stop = stop.clone();
            OwnerTemplateReader::new(OwnerOptions {
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
                template: [1; 16],
                enabled: true,
                timeout: Duration::from_millis(100),
                additional_roots: vec![],
                current: Arc::new(move |_| {
                    while !stop.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(OwnerError::OwnerChanged)
                }),
                session: Arc::new(|_| {
                    Ok(OwnerSession {
                        origin: "https://owner.example.invalid".into(),
                        cookie: "synthetic=owner".into(),
                        csrf: "synthetic".into(),
                    })
                }),
            })
            .unwrap()
        };
        let mut readers = vec![];
        for _ in 0..8 {
            let r = make();
            assert!(r.read_latest().is_err());
            readers.push(r)
        }
        assert_eq!(ADMISSION.load(Ordering::Acquire), 8);
        assert!(matches!(readers[0].read_latest(), Err(OwnerError::Busy)));
        assert!(matches!(make().read_latest(), Err(OwnerError::Capacity)));
        stop.store(true, Ordering::Release);
        let end = Instant::now() + Duration::from_secs(1);
        while ADMISSION.load(Ordering::Acquire) > 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(1))
        }
        assert_eq!(ADMISSION.load(Ordering::Acquire), 0);
    }
}
