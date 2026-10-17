// SPDX-License-Identifier: AGPL-3.0-only
//! Closed version-one review cookie frames. These are not root proof wire bytes.
use super::{AccessError, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac, digest::KeyInit};
use rand::{Rng, rng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;

pub const DAY: u64 = 86_400_000;
pub const WINDOW: u64 = 300_000;
pub const DELIVERY: u64 = 7 * DAY;
pub const MAX_FRAME: usize = 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub realm: Uuid,
    pub database: [u8; 32],
    pub origin: String,
    pub config: [u8; 32],
    pub config_revision: u64,
    pub key: [u8; 32],
}

impl Scope {
    pub fn validate(&self) -> Result<()> {
        if self.realm.is_nil()
            || !nonzero(&self.database)
            || !nonzero(&self.config)
            || !nonzero(&self.key)
            || self.config_revision == 0
            || self.config_revision > i64::MAX as u64
            || self.origin.len() > 255
            || !self.origin.is_ascii()
            || !crate::sealed_root_enrollment::canonical_origin(&self.origin)
        {
            return Err(AccessError::Rejected);
        }
        Ok(())
    }
}

// No Debug/Serialize or raw-key getter. A Scope/key pair alone is not an
// ActivatedReviewRealm and this module performs no supplied-observation upgrade.
pub struct CookieKey(Zeroizing<[u8; 32]>);
impl CookieKey {
    pub fn new(secret: [u8; 32], scope: &Scope) -> Result<Self> {
        scope.validate()?;
        if !nonzero(&secret) || Sha256::digest(secret).as_slice() != scope.key {
            return Err(AccessError::Rejected);
        }
        Ok(Self(Zeroizing::new(secret)))
    }
    fn mac(&self, purpose: Purpose, bytes: &[u8]) -> [u8; 32] {
        let mut h = <Hmac<Sha256> as KeyInit>::new_from_slice(self.0.as_ref()).expect("fixed key");
        h.update(purpose.domain());
        h.update(&[0]);
        h.update(bytes);
        h.finalize().into_bytes().into()
    }
    fn digest(&self, scope: &Scope, purpose: DigestPurpose, fields: &[u8]) -> [u8; 32] {
        let mut input = vec![1];
        input.extend_from_slice(scope.realm.as_bytes());
        input.extend_from_slice(&scope.database);
        string(&mut input, &scope.origin);
        input.extend_from_slice(&scope.key);
        input.extend_from_slice(fields);
        self.mac(purpose.into(), &input)
    }
    fn session_digest(
        &self,
        scope: &Scope,
        purpose: DigestPurpose,
        session: Uuid,
        candidate: &[u8; 32],
    ) -> Result<[u8; 32]> {
        if session.is_nil() || !nonzero(candidate) {
            return Err(AccessError::Rejected);
        }
        let mut fields = Zeroizing::new(Vec::with_capacity(48));
        fields.extend_from_slice(session.as_bytes());
        fields.extend_from_slice(candidate);
        Ok(self.digest(scope, purpose, &fields))
    }
    pub fn broker_token(
        &self,
        scope: &Scope,
        session: Uuid,
        candidate: &[u8; 32],
    ) -> Result<[u8; 32]> {
        self.session_digest(scope, DigestPurpose::BrokerToken, session, candidate)
    }
    pub fn broker_csrf(
        &self,
        scope: &Scope,
        session: Uuid,
        candidate: &[u8; 32],
    ) -> Result<[u8; 32]> {
        self.session_digest(scope, DigestPurpose::BrokerCsrf, session, candidate)
    }
    pub fn owner_token(
        &self,
        scope: &Scope,
        session: Uuid,
        candidate: &[u8; 32],
    ) -> Result<[u8; 32]> {
        self.session_digest(scope, DigestPurpose::OwnerToken, session, candidate)
    }
    pub fn owner_csrf(
        &self,
        scope: &Scope,
        session: Uuid,
        candidate: &[u8; 32],
    ) -> Result<[u8; 32]> {
        self.session_digest(scope, DigestPurpose::OwnerCsrf, session, candidate)
    }
    pub fn locator(&self, scope: &Scope, candidate: &[u8; 32]) -> Result<[u8; 32]> {
        if !nonzero(candidate) {
            return Err(AccessError::Rejected);
        }
        Ok(self.digest(scope, DigestPurpose::Locator, candidate))
    }
    fn seal(&self, purpose: Purpose, mut input: Vec<u8>) -> String {
        input.extend_from_slice(&self.mac(purpose, &input));
        URL_SAFE_NO_PAD.encode(input)
    }
    fn open(&self, purpose: Purpose, input: &str, bound: usize) -> Result<Zeroizing<Vec<u8>>> {
        if input.len() > bound.div_ceil(3) * 4 {
            return Err(AccessError::Rejected);
        }
        let mut bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(input)
                .map_err(|_| AccessError::Rejected)?,
        );
        if bytes.len() > bound
            || bytes.len() < 33
            || URL_SAFE_NO_PAD.encode(bytes.as_slice()) != input
        {
            return Err(AccessError::Rejected);
        }
        let split = bytes.len() - 32;
        let expected_mac = self.mac(purpose, &bytes[..split]);
        if expected_mac.len() != bytes[split..].len()
            || !bool::from(expected_mac.ct_eq(&bytes[split..]))
        {
            return Err(AccessError::Rejected);
        }
        bytes.truncate(split);
        Ok(bytes)
    }
}

#[derive(Clone, Copy)]
enum Purpose {
    Browser,
    Preparation,
    BrowserId,
    Request,
    BrokerToken,
    BrokerCsrf,
    OwnerToken,
    OwnerCsrf,
    Locator,
    LocatorSelector,
}
impl Purpose {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Browser => b"zrotext/review/browser/v1",
            Self::Preparation => b"zrotext/review/preparation/v1",
            Self::BrowserId => b"zrotext/review/browser-id/v1",
            Self::Request => b"zrotext/review/request/v1",
            Self::BrokerToken => b"zrotext/review/broker-token/v1",
            Self::BrokerCsrf => b"zrotext/review/broker-csrf/v1",
            Self::OwnerToken => b"zrotext/review/owner-token/v1",
            Self::OwnerCsrf => b"zrotext/review/owner-csrf/v1",
            Self::Locator => b"zrotext/review/locator/v1",
            Self::LocatorSelector => b"zrotext/review/locator-selector/v1",
        }
    }
}
#[derive(Clone, Copy)]
enum DigestPurpose {
    BrowserId,
    BrokerToken,
    BrokerCsrf,
    OwnerToken,
    OwnerCsrf,
    Locator,
}
impl From<DigestPurpose> for Purpose {
    fn from(value: DigestPurpose) -> Self {
        match value {
            DigestPurpose::BrowserId => Self::BrowserId,
            DigestPurpose::BrokerToken => Self::BrokerToken,
            DigestPurpose::BrokerCsrf => Self::BrokerCsrf,
            DigestPurpose::OwnerToken => Self::OwnerToken,
            DigestPurpose::OwnerCsrf => Self::OwnerCsrf,
            DigestPurpose::Locator => Self::Locator,
        }
    }
}

pub fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|b| *b != 0)
}
pub fn random_secret() -> [u8; 32] {
    loop {
        let mut out = [0; 32];
        rng().fill_bytes(&mut out);
        if nonzero(&out) {
            return out;
        }
    }
}
pub fn valid_alias(alias: &str) -> bool {
    let b = alias.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}
fn time(value: u64) -> Result<()> {
    if value == 0 || value > i64::MAX as u64 {
        Err(AccessError::Rejected)
    } else {
        Ok(())
    }
}
fn string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}
fn number(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_be_bytes());
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let chunk = self.0.get(..N).ok_or(AccessError::Rejected)?;
        let out = chunk.try_into().map_err(|_| AccessError::Rejected)?;
        self.0 = &self.0[N..];
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }
    fn uuid(&mut self) -> Result<Uuid> {
        Ok(Uuid::from_bytes(self.fixed()?))
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn string(&mut self, max: usize) -> Result<String> {
        let n = u16::from_be_bytes(self.fixed()?) as usize;
        if n > max {
            return Err(AccessError::Rejected);
        }
        let bytes = self.0.get(..n).ok_or(AccessError::Rejected)?;
        let out = std::str::from_utf8(bytes)
            .map_err(|_| AccessError::Rejected)?
            .to_owned();
        self.0 = &self.0[n..];
        Ok(out)
    }
    fn end(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(AccessError::Rejected)
        }
    }
}

pub struct Browser {
    pub nonce: [u8; 32],
    pub issued: u64,
    pub expires: u64,
}
impl Browser {
    pub fn fresh(now: u64) -> Result<Self> {
        time(now)?;
        let expires = now.checked_add(14 * DAY).ok_or(AccessError::Rejected)?;
        time(expires)?;
        Ok(Self {
            nonce: random_secret(),
            issued: now,
            expires,
        })
    }
    pub fn seal(&self, key: &CookieKey, scope: &Scope) -> String {
        let mut b = vec![1];
        b.extend_from_slice(scope.realm.as_bytes());
        b.extend_from_slice(&scope.database);
        string(&mut b, &scope.origin);
        b.extend_from_slice(&self.nonce);
        number(&mut b, self.issued);
        number(&mut b, self.expires);
        b.extend_from_slice(&scope.key);
        key.seal(Purpose::Browser, b)
    }
    pub fn open(input: &str, key: &CookieKey, scope: &Scope, now: u64) -> Result<Self> {
        let bytes = key.open(Purpose::Browser, input, 512)?;
        let mut r = Reader(&bytes);
        if r.byte()? != 1
            || r.uuid()? != scope.realm
            || r.fixed::<32>()? != scope.database
            || r.string(255)? != scope.origin
        {
            return Err(AccessError::Rejected);
        }
        let out = Self {
            nonce: r.fixed()?,
            issued: r.number()?,
            expires: r.number()?,
        };
        if r.fixed::<32>()? != scope.key {
            return Err(AccessError::Rejected);
        }
        r.end()?;
        time(now)?;
        time(out.issued)?;
        time(out.expires)?;
        if !nonzero(&out.nonce)
            || out.issued > now
            || now >= out.expires
            || out.expires - out.issued > 14 * DAY
        {
            return Err(AccessError::Rejected);
        }
        Ok(out)
    }
    pub fn digest(&self, key: &CookieKey, scope: &Scope) -> [u8; 32] {
        key.digest(scope, DigestPurpose::BrowserId, &self.nonce)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Operation {
    InitialBootstrap = 1,
    BrokerForResume = 2,
    RetainedRootResume = 3,
    RootIssue = 4,
    RootComplete = 5,
}
impl TryFrom<u8> for Operation {
    type Error = AccessError;
    fn try_from(n: u8) -> Result<Self> {
        match n {
            1 => Ok(Self::InitialBootstrap),
            2 => Ok(Self::BrokerForResume),
            3 => Ok(Self::RetainedRootResume),
            4 => Ok(Self::RootIssue),
            5 => Ok(Self::RootComplete),
            _ => Err(AccessError::Rejected),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Identities {
    pub principal: Uuid,
    pub credential: Uuid,
    pub revision: u64,
    pub broker_session: Uuid,
    pub event: Uuid,
    pub owner_session: Uuid,
    pub account: Uuid,
    pub user: Uuid,
}
impl Identities {
    fn validate(&self, op: Operation) -> Result<()> {
        let pre = matches!(op, Operation::InitialBootstrap | Operation::BrokerForResume);
        if pre {
            if !self.principal.is_nil() || !self.credential.is_nil() || self.revision != 0 {
                return Err(AccessError::Rejected);
            }
        } else if self.principal.is_nil()
            || self.credential.is_nil()
            || self.revision == 0
            || self.revision > i64::MAX as u64
        {
            return Err(AccessError::Rejected);
        }
        let mut required = vec![self.broker_session, self.event];
        if op == Operation::BrokerForResume {
            if !self.owner_session.is_nil() || !self.account.is_nil() || !self.user.is_nil() {
                return Err(AccessError::Rejected);
            }
        } else {
            required.extend([self.owner_session, self.account, self.user]);
        }
        if !pre {
            required.extend([self.principal, self.credential]);
        }
        for (i, id) in required.iter().enumerate() {
            if id.is_nil() || required[..i].contains(id) {
                return Err(AccessError::Rejected);
            }
        }
        Ok(())
    }
}

// Secret candidates are owned/zeroized, never Debug/Serialize. Copies are
// explicit snapshots before awaits; no accessor-backed caller objects exist.
pub struct Candidates {
    pub csrf: Zeroizing<[u8; 32]>,
    pub broker: Zeroizing<[u8; 32]>,
    pub broker_csrf: Zeroizing<[u8; 32]>,
    pub owner: Zeroizing<[u8; 32]>,
    pub owner_csrf: Zeroizing<[u8; 32]>,
    pub locator: Zeroizing<[u8; 32]>,
}
impl Candidates {
    pub fn fresh(op: Operation) -> Self {
        let mut out = Self {
            csrf: Zeroizing::new(random_secret()),
            broker: Zeroizing::new([0; 32]),
            broker_csrf: Zeroizing::new([0; 32]),
            owner: Zeroizing::new([0; 32]),
            owner_csrf: Zeroizing::new([0; 32]),
            locator: Zeroizing::new([0; 32]),
        };
        if matches!(op, Operation::InitialBootstrap | Operation::BrokerForResume) {
            *out.broker = random_secret();
            *out.broker_csrf = random_secret();
        }
        if matches!(
            op,
            Operation::InitialBootstrap | Operation::RetainedRootResume
        ) {
            *out.owner = random_secret();
            *out.owner_csrf = random_secret();
        }
        if op == Operation::InitialBootstrap {
            *out.locator = random_secret();
        }
        out
    }
    fn validate(&self, op: Operation) -> Result<()> {
        let values = [
            &*self.csrf,
            &*self.broker,
            &*self.broker_csrf,
            &*self.owner,
            &*self.owner_csrf,
            &*self.locator,
        ];
        let broker = matches!(op, Operation::InitialBootstrap | Operation::BrokerForResume);
        let owner = matches!(
            op,
            Operation::InitialBootstrap | Operation::RetainedRootResume
        );
        let required = [
            true,
            broker,
            broker,
            owner,
            owner,
            op == Operation::InitialBootstrap,
        ];
        for (i, (value, wanted)) in values.iter().zip(required).enumerate() {
            if nonzero(*value) != wanted || (wanted && values[..i].contains(value)) {
                return Err(AccessError::Rejected);
            }
        }
        Ok(())
    }
}

pub struct Preparation {
    pub operation: Operation,
    pub browser: [u8; 32],
    pub id: Uuid,
    pub request: Uuid,
    pub generation: u64,
    pub prepared: u64,
    pub create_deadline: u64,
    pub delivery_deadline: u64,
    pub alias: String,
    pub identities: Identities,
    pub target: [u8; 32],
    pub candidates: Candidates,
}

/// Private selection-only transport. Unlike the preparation frame, this
/// contains no broker/owner bearer, CSRF, session, or authentication event.
/// It supplies no root or session authority and has no Debug/Serialize.
pub struct LocatorSelector {
    pub account: Uuid,
    pub user: Uuid,
    pub preparation: Uuid,
    pub request: Uuid,
    pub generation: u64,
    pub created: u64,
    locator: Zeroizing<[u8; 32]>,
}
impl LocatorSelector {
    pub fn from_initial(
        preparation: &Preparation,
        browser: &Browser,
        key: &CookieKey,
        scope: &Scope,
        now: u64,
    ) -> Result<Self> {
        preparation.validate(browser, key, scope, now, false)?;
        if preparation.operation != Operation::InitialBootstrap {
            return Err(AccessError::Rejected);
        }
        Ok(Self {
            account: preparation.identities.account,
            user: preparation.identities.user,
            preparation: preparation.id,
            request: preparation.request,
            generation: preparation.generation,
            created: preparation.prepared,
            locator: Zeroizing::new(*preparation.candidates.locator),
        })
    }
    pub fn digest(&self, key: &CookieKey, scope: &Scope) -> Result<[u8; 32]> {
        key.locator(scope, &self.locator)
    }
    fn validate(&self, now: u64) -> Result<()> {
        time(now)?;
        time(self.created)?;
        time(self.generation)?;
        let ids = [self.account, self.user, self.preparation, self.request];
        for (i, id) in ids.iter().enumerate() {
            if id.is_nil() || ids[..i].contains(id) {
                return Err(AccessError::Rejected);
            }
        }
        if self.created > now || !nonzero(&*self.locator) {
            return Err(AccessError::Rejected);
        }
        Ok(())
    }
    fn bytes(&self, scope: &Scope) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(vec![1]);
        b.extend_from_slice(scope.realm.as_bytes());
        b.extend_from_slice(&scope.database);
        string(&mut b, &scope.origin);
        b.extend_from_slice(&scope.config);
        number(&mut b, scope.config_revision);
        b.extend_from_slice(&scope.key);
        for id in [self.account, self.user, self.preparation, self.request] {
            b.extend_from_slice(id.as_bytes());
        }
        number(&mut b, self.generation);
        number(&mut b, self.created);
        b.extend_from_slice(self.locator.as_ref());
        b
    }
    pub fn seal(&self, key: &CookieKey, scope: &Scope, now: u64) -> Result<String> {
        scope.validate()?;
        self.validate(now)?;
        Ok(key.seal(Purpose::LocatorSelector, self.bytes(scope).to_vec()))
    }
    pub fn open(input: &str, key: &CookieKey, scope: &Scope, now: u64) -> Result<Self> {
        scope.validate()?;
        // Fixed fields + maximum 255-byte origin + MAC fit within MAX_FRAME.
        let bytes = key.open(Purpose::LocatorSelector, input, MAX_FRAME)?;
        let mut r = Reader(&bytes);
        if r.byte()? != 1
            || r.uuid()? != scope.realm
            || r.fixed::<32>()? != scope.database
            || r.string(255)? != scope.origin
            || r.fixed::<32>()? != scope.config
            || r.number()? != scope.config_revision
            || r.fixed::<32>()? != scope.key
        {
            return Err(AccessError::Rejected);
        }
        let out = Self {
            account: r.uuid()?,
            user: r.uuid()?,
            preparation: r.uuid()?,
            request: r.uuid()?,
            generation: r.number()?,
            created: r.number()?,
            locator: Zeroizing::new(r.fixed()?),
        };
        r.end()?;
        out.validate(now)?;
        Ok(out)
    }
}
impl Preparation {
    pub fn validate(
        &self,
        browser: &Browser,
        key: &CookieKey,
        scope: &Scope,
        now: u64,
        creation: bool,
    ) -> Result<()> {
        scope.validate()?;
        self.identities.validate(self.operation)?;
        self.candidates.validate(self.operation)?;
        for n in [
            now,
            self.generation,
            self.prepared,
            self.create_deadline,
            self.delivery_deadline,
        ] {
            time(n)?;
        }
        let login = matches!(
            self.operation,
            Operation::InitialBootstrap | Operation::BrokerForResume
        );
        if self.id.is_nil()
            || self.request.is_nil()
            || self.id == self.request
            || self.browser != browser.digest(key, scope)
            || self.prepared < browser.issued
            || self.prepared > now
            || self.create_deadline < self.prepared
            || self.create_deadline - self.prepared > WINDOW
            || self.delivery_deadline < self.create_deadline
            || self.delivery_deadline - self.prepared > DELIVERY
            || self.delivery_deadline > browser.expires
            || now >= self.delivery_deadline
            || (creation && now >= self.create_deadline)
            || (login && (!valid_alias(&self.alias) || nonzero(&self.target)))
            || (!login && (!self.alias.is_empty() || !nonzero(&self.target)))
        {
            return Err(AccessError::Rejected);
        }
        Ok(())
    }
    pub fn bytes(&self, scope: &Scope) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(vec![1, self.operation as u8]);
        b.extend_from_slice(scope.realm.as_bytes());
        b.extend_from_slice(&scope.database);
        string(&mut b, &scope.origin);
        b.extend_from_slice(&scope.config);
        b.extend_from_slice(&scope.key);
        b.extend_from_slice(&self.browser);
        b.extend_from_slice(self.id.as_bytes());
        b.extend_from_slice(self.request.as_bytes());
        for n in [
            self.generation,
            self.prepared,
            self.create_deadline,
            self.delivery_deadline,
        ] {
            number(&mut b, n)
        }
        string(&mut b, &self.alias);
        b.extend_from_slice(self.identities.principal.as_bytes());
        b.extend_from_slice(self.identities.credential.as_bytes());
        number(&mut b, self.identities.revision);
        for id in [
            self.identities.broker_session,
            self.identities.event,
            self.identities.owner_session,
            self.identities.account,
            self.identities.user,
        ] {
            b.extend_from_slice(id.as_bytes());
        }
        b.extend_from_slice(&self.target);
        for secret in [
            &self.candidates.csrf,
            &self.candidates.broker,
            &self.candidates.broker_csrf,
            &self.candidates.owner,
            &self.candidates.owner_csrf,
            &self.candidates.locator,
        ] {
            b.extend_from_slice(secret.as_ref());
        }
        b
    }
    pub fn commitment(&self, key: &CookieKey, scope: &Scope) -> [u8; 32] {
        key.mac(Purpose::Request, &self.bytes(scope))
    }
    pub fn seal(&self, key: &CookieKey, scope: &Scope) -> String {
        key.seal(Purpose::Preparation, self.bytes(scope).to_vec())
    }
    pub fn open(
        input: &str,
        key: &CookieKey,
        scope: &Scope,
        browser: &Browser,
        now: u64,
        creation: bool,
    ) -> Result<Self> {
        let b = key.open(Purpose::Preparation, input, MAX_FRAME)?;
        let mut r = Reader(&b);
        if r.byte()? != 1 {
            return Err(AccessError::Rejected);
        }
        let operation = r.byte()?.try_into()?;
        if r.uuid()? != scope.realm
            || r.fixed::<32>()? != scope.database
            || r.string(255)? != scope.origin
            || r.fixed::<32>()? != scope.config
            || r.fixed::<32>()? != scope.key
        {
            return Err(AccessError::Rejected);
        }
        let browser_digest = r.fixed()?;
        let id = r.uuid()?;
        let request = r.uuid()?;
        let generation = r.number()?;
        let prepared = r.number()?;
        let create_deadline = r.number()?;
        let delivery_deadline = r.number()?;
        let alias = r.string(32)?;
        let identities = Identities {
            principal: r.uuid()?,
            credential: r.uuid()?,
            revision: r.number()?,
            broker_session: r.uuid()?,
            event: r.uuid()?,
            owner_session: r.uuid()?,
            account: r.uuid()?,
            user: r.uuid()?,
        };
        let target = r.fixed()?;
        let candidates = Candidates {
            csrf: Zeroizing::new(r.fixed()?),
            broker: Zeroizing::new(r.fixed()?),
            broker_csrf: Zeroizing::new(r.fixed()?),
            owner: Zeroizing::new(r.fixed()?),
            owner_csrf: Zeroizing::new(r.fixed()?),
            locator: Zeroizing::new(r.fixed()?),
        };
        r.end()?;
        let out = Self {
            operation,
            browser: browser_digest,
            id,
            request,
            generation,
            prepared,
            create_deadline,
            delivery_deadline,
            alias,
            identities,
            target,
            candidates,
        };
        out.validate(browser, key, scope, now, creation)?;
        Ok(out)
    }
}
