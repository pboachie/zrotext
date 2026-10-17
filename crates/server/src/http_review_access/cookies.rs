// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded owned review cookies; no ordinary session-cookie/parser reuse.
use crate::auth::review_access::{
    AccessError, Result,
    frames::{self, Browser, CookieKey, LocatorSelector, Operation, Preparation, Scope},
};
use axum::http::{HeaderMap, HeaderValue, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) const BROWSER: &str = "__Host-ztrw-browser";
pub(super) const BROKER: &str = "__Host-ztrw-broker";
pub(super) const OWNER: &str = "__Host-ztrw-owner";
pub(super) const BROKER_CSRF: &str = "__Host-ztrw-broker-csrf";
pub(super) const OWNER_CSRF: &str = "__Host-ztrw-owner-csrf";
pub(super) const PREPARED_HEADER: &str = "x-ztrw-prepared-csrf";

pub(super) struct Cookies(BTreeMap<String, Zeroizing<String>>);
impl Cookies {
    pub(super) fn parse(headers: &HeaderMap) -> Result<Self> {
        let mut out = BTreeMap::new();
        let mut length = 0usize;
        for header in headers.get_all(header::COOKIE) {
            length = length
                .checked_add(header.as_bytes().len())
                .ok_or(AccessError::Rejected)?;
            if length > 8192 {
                return Err(AccessError::Rejected);
            }
            let value = header.to_str().map_err(|_| AccessError::Rejected)?;
            for entry in value.split(';') {
                let entry = entry.trim_matches(' ');
                if entry.is_empty() {
                    continue;
                }
                let (name, value) = entry.split_once('=').ok_or(AccessError::Rejected)?;
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                    || !value.bytes().all(|b| {
                        b == 0x21
                            || (0x23..=0x2b).contains(&b)
                            || (0x2d..=0x3a).contains(&b)
                            || (0x3c..=0x5b).contains(&b)
                            || (0x5d..=0x7e).contains(&b)
                    })
                    || out.contains_key(name)
                {
                    return Err(AccessError::Rejected);
                }
                if name.starts_with("__Host-ztrw-") && !known(name) {
                    return Err(AccessError::Rejected);
                }
                out.insert(name.to_owned(), Zeroizing::new(value.to_owned()));
            }
        }
        for prefix in ["__Host-ztrw-p-", "__Host-ztrw-c-", "__Host-ztrw-l-"] {
            if out.keys().filter(|name| name.starts_with(prefix)).count() > 1 {
                return Err(AccessError::Rejected);
            }
        }
        Ok(Self(out))
    }
    pub(super) fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|s| s.as_str())
    }
    pub(super) fn staged(&self, prefix: &str) -> Option<(&str, &str)> {
        self.0
            .iter()
            .find(|(name, _)| name.starts_with(prefix))
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
    pub(super) fn no_staging(&self) -> Result<()> {
        if ["__Host-ztrw-p-", "__Host-ztrw-c-", "__Host-ztrw-l-"]
            .iter()
            .any(|prefix| self.staged(prefix).is_some())
        {
            return Err(AccessError::Unavailable);
        }
        Ok(())
    }
    pub(super) fn browser(&self, key: &CookieKey, scope: &Scope, now: u64) -> Result<Browser> {
        Browser::open(
            self.get(BROWSER).ok_or(AccessError::Unavailable)?,
            key,
            scope,
            now,
        )
    }
    pub(super) fn prepared(
        &self,
        headers: &HeaderMap,
        key: &CookieKey,
        scope: &Scope,
        browser: &Browser,
        now: u64,
        creation: bool,
    ) -> Result<Preparation> {
        let (name, value) = self
            .staged("__Host-ztrw-p-")
            .ok_or(AccessError::Unavailable)?;
        let id = Uuid::parse_str(&name[14..]).map_err(|_| AccessError::Rejected)?;
        let csrf_name = format!("__Host-ztrw-c-{}", id.simple());
        let csrf = self.csrf(headers, &csrf_name, PREPARED_HEADER)?;
        let prep = Preparation::open(value, key, scope, browser, now, creation)?;
        if prep.id != id
            || csrf.as_ref().len() != prep.candidates.csrf.as_ref().len()
            || !bool::from(csrf.as_ref().ct_eq(prep.candidates.csrf.as_ref()))
        {
            return Err(AccessError::Rejected);
        }
        if creation && prep.operation == Operation::InitialBootstrap {
            let supplied = self
                .get(&format!("__Host-ztrw-l-{}", id.simple()))
                .ok_or(AccessError::Unavailable)?;
            let expected = Zeroizing::new(
                LocatorSelector::from_initial(&prep, browser, key, scope, now)?
                    .seal(key, scope, now)?,
            );
            if supplied.len() != expected.len()
                || !bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()))
            {
                return Err(AccessError::Rejected);
            }
        }
        Ok(prep)
    }
    pub(super) fn csrf(
        &self,
        headers: &HeaderMap,
        name: &str,
        header_name: &str,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let cookie = self.get(name).ok_or(AccessError::Unavailable)?;
        let supplied = one_header(headers, header_name)?;
        if cookie.len() != supplied.len()
            || !bool::from(cookie.as_bytes().ct_eq(supplied.as_bytes()))
        {
            return Err(AccessError::Rejected);
        }
        decode_secret(cookie)
    }
}
fn known(name: &str) -> bool {
    if [BROWSER, BROKER, OWNER, BROKER_CSRF, OWNER_CSRF].contains(&name) {
        return true;
    }
    ["__Host-ztrw-p-", "__Host-ztrw-c-", "__Host-ztrw-l-"]
        .iter()
        .any(|prefix| {
            name.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && Uuid::parse_str(suffix).is_ok_and(|id| !id.is_nil())
            })
        })
}
pub(super) fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(AccessError::Rejected)?;
    if values.next().is_some() {
        return Err(AccessError::Rejected);
    }
    value.to_str().map_err(|_| AccessError::Rejected)
}
pub(super) fn require_origin(headers: &HeaderMap, scope: &Scope) -> Result<()> {
    if one_header(headers, "origin")? != scope.origin {
        return Err(AccessError::Rejected);
    }
    Ok(())
}
pub(super) fn decode_secret(value: &str) -> Result<Zeroizing<[u8; 32]>> {
    if value.len() != 43 {
        return Err(AccessError::Rejected);
    }
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| AccessError::Rejected)?,
    );
    if bytes.len() != 32
        || URL_SAFE_NO_PAD.encode(bytes.as_slice()) != value
        || !frames::nonzero(&bytes)
    {
        return Err(AccessError::Rejected);
    }
    Ok(Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| AccessError::Rejected)?,
    ))
}
pub(crate) struct ActiveCredential {
    pub(crate) session: Uuid,
    pub(crate) candidate: Zeroizing<[u8; 32]>,
}
impl ActiveCredential {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        if value.len() != 64 {
            return Err(AccessError::Rejected);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| AccessError::Rejected)?,
        );
        if bytes.len() != 48 || URL_SAFE_NO_PAD.encode(bytes.as_slice()) != value {
            return Err(AccessError::Rejected);
        }
        let session = Uuid::from_slice(&bytes[..16]).map_err(|_| AccessError::Rejected)?;
        let candidate: [u8; 32] = bytes[16..].try_into().map_err(|_| AccessError::Rejected)?;
        if session.is_nil() || !frames::nonzero(&candidate) {
            return Err(AccessError::Rejected);
        }
        Ok(Self {
            session,
            candidate: Zeroizing::new(candidate),
        })
    }
}
pub(super) fn active_value(session: Uuid, candidate: &[u8; 32]) -> Result<Zeroizing<String>> {
    if session.is_nil() || !frames::nonzero(candidate) {
        return Err(AccessError::Rejected);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(48));
    bytes.extend_from_slice(session.as_bytes());
    bytes.extend_from_slice(candidate);
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice())))
}
pub(super) fn set(
    name: &str,
    value: &str,
    now: u64,
    deadline: u64,
    http_only: bool,
) -> Result<HeaderValue> {
    if !known(name)
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(AccessError::Rejected);
    }
    let seconds = deadline.checked_sub(now).ok_or(AccessError::Unavailable)? / 1000;
    if seconds == 0 {
        return Err(AccessError::Unavailable);
    }
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Secure; SameSite=Strict; Max-Age={seconds}{}",
        if http_only { "; HttpOnly" } else { "" }
    ))
    .map_err(|_| AccessError::Rejected)
}
pub(super) fn clear(name: &str, http_only: bool) -> Result<HeaderValue> {
    if !known(name) {
        return Err(AccessError::Rejected);
    }
    HeaderValue::from_str(&format!(
        "{name}=; Path=/; Secure; SameSite=Strict; Max-Age=0{}",
        if http_only { "; HttpOnly" } else { "" }
    ))
    .map_err(|_| AccessError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_unknown_and_oversized_cookie_headers_are_refused_before_work() {
        for value in [
            "__Host-ztrw-browser=one; __Host-ztrw-browser=two",
            "__Host-ztrw-unknown=x",
            "__Host-ztrw-p-00000000000000000000000000000000=x",
            "__Host-ztrw-p-10000000000040008000000000000001=x; __Host-ztrw-p-10000000000040008000000000000002=y",
        ] {
            let mut h = HeaderMap::new();
            h.insert(header::COOKIE, HeaderValue::from_str(value).unwrap());
            assert!(Cookies::parse(&h).is_err());
        }
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("a={}", "x".repeat(4095))).unwrap(),
        );
        h.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("b={}", "x".repeat(4095))).unwrap(),
        );
        assert!(Cookies::parse(&h).is_err());
    }
    #[test]
    fn active_values_require_fixed_nonzero_identity_and_canonical_encoding() {
        let id = Uuid::new_v4();
        let value = active_value(id, &[7; 32]).unwrap();
        let parsed = ActiveCredential::parse(&value).unwrap();
        assert_eq!(parsed.session, id);
        assert_eq!(*parsed.candidate, [7; 32]);
        assert!(ActiveCredential::parse(&(value.to_string() + "=")).is_err());
        assert!(active_value(Uuid::nil(), &[7; 32]).is_err());
        assert!(decode_secret(&URL_SAFE_NO_PAD.encode([0; 32])).is_err());
    }
    #[test]
    fn double_submit_rejects_duplicate_header_and_cookie_disagreement() {
        let secret = URL_SAFE_NO_PAD.encode([7; 32]);
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{OWNER_CSRF}={secret}")).unwrap(),
        );
        h.insert("x-ztrw-owner-csrf", HeaderValue::from_str(&secret).unwrap());
        let c = Cookies::parse(&h).unwrap();
        assert!(c.csrf(&h, OWNER_CSRF, "x-ztrw-owner-csrf").is_ok());
        h.append("x-ztrw-owner-csrf", HeaderValue::from_str(&secret).unwrap());
        assert!(c.csrf(&h, OWNER_CSRF, "x-ztrw-owner-csrf").is_err());
    }
}
