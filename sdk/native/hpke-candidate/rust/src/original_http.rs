//! Single-attempt original-grant HTTPS transport. Returned JSON is untrusted:
//! no authority verification, accepted-history persistence or plaintext release.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Certificate, Url, blocking::Client, header};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::{
    io::Read,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    Unavailable,
    Unknown,
}
impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "original reply unavailable",
            Self::Unknown => "original reply outcome unknown",
        })
    }
}
impl std::error::Error for HttpError {}

// Generic requests never carry output credentials. Typed proposal APIs use a
// private validated exchange while retaining the same transport policy.
pub enum Request {
    Current,
    Page {
        limit: u8,
        cursor: Option<(u64, String)>,
    },
    Read {
        event_id: String,
    },
    OwnerReview {
        event_id: String,
        request_id: String,
        active_request_id: Option<String>,
    },
    Status {
        consumption_id: String,
    },
}
impl Request {
    fn method(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Page { .. } => "page",
            Self::Read { .. } => "read",
            Self::OwnerReview { .. } => "consume",
            Self::Status { .. } => "status",
        }
    }
    fn body(&self, version: u64) -> Result<Vec<u8>, HttpError> {
        let bad = HttpError::Unavailable;
        if !(1..=9007199254740991).contains(&version) {
            return Err(bad);
        }
        let mut b = json!({"v":1,"method":self.method(),"accepted_manifest_version":version});
        match self {
            Self::Current => {}
            Self::Read { event_id } => {
                if !uuid(event_id) {
                    return Err(bad);
                };
                b["event_id"] = json!(event_id)
            }
            Self::Status { consumption_id } => {
                if !uuid(consumption_id) {
                    return Err(bad);
                };
                b["consumption_id"] = json!(consumption_id)
            }
            Self::Page { limit, cursor } => {
                if !(1..=32).contains(limit) {
                    return Err(bad);
                };
                b["limit"] = json!(limit);
                b["cursor"] = Value::Null;
                if let Some((time, event)) = cursor {
                    if !(1..=9007199254740991).contains(time) || !uuid(event) {
                        return Err(bad);
                    };
                    b["cursor"] = json!({"accepted_at_ms":time,"event_id":event})
                }
            }
            Self::OwnerReview {
                event_id,
                request_id,
                active_request_id,
            } => {
                if !uuid(event_id)
                    || !uuid(request_id)
                    || active_request_id.as_ref().is_some_and(|id| !uuid(id))
                {
                    return Err(bad);
                };
                b["params"] = json!({"event_id":event_id,"request_id":request_id,
                    "active_request_id":active_request_id,"descriptor":null})
            }
        }
        let encoded = serde_json::to_vec(&b).map_err(|_| bad)?;
        if encoded.len() > 4096 {
            return Err(bad);
        };
        Ok(encoded)
    }
}
pub(crate) fn uuid(s: &str) -> bool {
    s.len() == 36
        && s != "00000000-0000-0000-0000-000000000000"
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn credential(s: &str) -> bool {
    s.len() == 47
        && s.starts_with("ztr_")
        && URL_SAFE_NO_PAD
            .decode(&s[4..])
            .is_ok_and(|b| b.len() == 32 && URL_SAFE_NO_PAD.encode(b) == s[4..])
}

/// Untrusted JSON, never a verified grant proof or consumption result.
pub struct UntrustedWire {
    pub json: Box<RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    kind: String,
    result: Box<RawValue>,
}

pub struct OriginalHttp {
    client: Client,
    endpoint: Url,
    timeout: Duration,
}
impl OriginalHttp {
    /// Optional roots must be independently trusted CA PEM, never data from a
    /// response. Platform/public roots remain enabled. No insecure TLS switch.
    pub fn new(
        origin: &str,
        timeout: Duration,
        additional_roots: &[u8],
    ) -> Result<Self, HttpError> {
        let bad = HttpError::Unavailable;
        if timeout < Duration::from_millis(1)
            || timeout > Duration::from_secs(10)
            || !origin.is_ascii()
            || origin.bytes().any(|b| b <= 32 || b == 127 || b == b'\\')
        {
            return Err(bad);
        }
        let mut u = Url::parse(origin).map_err(|_| bad)?;
        if u.scheme() != "https"
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.path() != "/"
            || u.query().is_some()
            || u.fragment().is_some()
            || origin.contains('@')
        {
            return Err(bad);
        }
        // Reject path normalization (e.g. /a/../) rather than silently targeting a
        // different authority path. The only accepted suffix is a single slash.
        let authority = origin.strip_prefix("https://").ok_or(bad)?;
        if authority.find('/').is_some_and(|i| &authority[i..] != "/") {
            return Err(bad);
        }
        u.set_path("/v1/reply-events");
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only()
            .pool_max_idle_per_host(0)
            .timeout(timeout)
            .tls_version_min(reqwest::tls::Version::TLS_1_2);
        if !additional_roots.is_empty() {
            let certificates = Certificate::from_pem_bundle(additional_roots).map_err(|_| bad)?;
            if certificates.is_empty() {
                return Err(bad);
            };
            builder = builder.tls_certs_merge(certificates)
        }
        Ok(Self {
            client: builder.build().map_err(|_| bad)?,
            endpoint: u,
            timeout,
        })
    }
    pub fn exchange(
        &self,
        grant: &str,
        version: u64,
        request: Request,
    ) -> Result<UntrustedWire, HttpError> {
        self.exchange_proposal(grant, version, request, None, None)
    }
    pub(crate) fn exchange_proposal(
        &self,
        grant: &str,
        version: u64,
        request: Request,
        action: Option<&crate::workflow_action::WorkflowAction>,
        output: Option<&str>,
    ) -> Result<UntrustedWire, HttpError> {
        if !credential(grant) {
            return Err(HttpError::Unavailable);
        }
        let mut body = request.body(version)?;
        if let Some(action) = action {
            if !matches!(
                &request,
                Request::OwnerReview {
                    active_request_id: Some(_),
                    ..
                }
            ) || !action.production()
                || !output.is_some_and(output_credential)
            {
                return Err(HttpError::Unavailable);
            }
            let mut value: Value =
                serde_json::from_slice(&body).map_err(|_| HttpError::Unavailable)?;
            value["params"]["descriptor"] =
                serde_json::from_slice(&action.canonical()).map_err(|_| HttpError::Unavailable)?;
            body = serde_json::to_vec(&value).map_err(|_| HttpError::Unavailable)?;
            if body.len() > 4096 {
                return Err(HttpError::Unavailable);
            }
        } else if output.is_some() {
            return Err(HttpError::Unavailable);
        }
        let bad = if matches!(request, Request::OwnerReview { .. }) {
            HttpError::Unknown
        } else {
            HttpError::Unavailable
        };
        let start = Instant::now();
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {grant}"))
            .map_err(|_| HttpError::Unavailable)?;
        authorization.set_sensitive(true);
        // Set the request timeout too: this reaches the async response body's total
        // deadline; the blocking client's timeout alone bounds individual reads.
        let mut builder = self
            .client
            .post(self.endpoint.clone())
            .timeout(self.timeout)
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(body);
        if let Some(output) = output {
            let mut header = header::HeaderValue::from_str(&format!("Bearer {output}"))
                .map_err(|_| HttpError::Unavailable)?;
            header.set_sensitive(true);
            builder = builder.header("x-zrotext-output-authorization", header);
        }
        let mut response = builder.send().map_err(|_| bad)?;
        if !response.status().is_success()
            || response.content_length().is_some_and(|n| n > 524288)
            || response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .is_none_or(|h| h.split(';').next().unwrap_or("").trim() != "application/json")
        {
            return Err(bad);
        }
        let mut raw = Vec::new();
        response
            .by_ref()
            .take(524289)
            .read_to_end(&mut raw)
            .map_err(|_| bad)?;
        if raw.len() > 524288 || start.elapsed() >= self.timeout {
            return Err(bad);
        }
        let envelope: Envelope = serde_json::from_slice(&raw).map_err(|_| bad)?;
        if envelope.kind != request.method() {
            return Err(bad);
        }
        Ok(UntrustedWire {
            json: envelope.result,
        })
    }
}

pub(crate) fn output_credential(s: &str) -> bool {
    s.len() == 47 && s.starts_with("ztw_") && credential(&format!("ztr_{}", &s[4..]))
}
