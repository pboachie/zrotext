// SPDX-License-Identifier: AGPL-3.0-only
//! Customer-controlled, independently signed HTTPS fencing and epoch authority.
//! The remote authority, not the writer database, owns durable linearizable state.
//! A signed assertion is trusted only under the explicitly pinned authority key.
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
use zrotext_failover_quorum::fence::{
    AnchorReading, AnchorRecord, ExternalEpochAnchor, ExternalFencing, FenceAuthority, FenceStatus,
    FenceToken, HostFenceOutcome,
};

const MAX_WIRE: usize = 4096;
const DOMAIN: &[u8] = b"ZT/external-authority/v1\0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    namespace: String,
    url: String,
    public_key_base64: String,
    bearer_file: PathBuf,
    ca_certificate_file: Option<PathBuf>,
    timeout_ms: u64,
    minimum_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Request {
    namespace: String,
    nonce: Uuid,
    operation: Operation,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Fence { site: String, epoch: u64 },
    Status { site: String },
    ReadEpoch,
    RecordEpoch { epoch: u64 },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Fenced { epoch: u64 },
    AlreadyFenced { epoch: u64 },
    CompetingFence { epoch: u64 },
    Unfenced,
    Epoch { epoch: u64 },
    Recorded { epoch: u64 },
    RefusedEpoch { epoch: u64 },
    Unconfirmed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    request: Request,
    reply: Reply,
    signature: String,
}
fn transcript(request: &Request, reply: &Reply) -> Result<Vec<u8>, ()> {
    let mut bytes = DOMAIN.to_vec();
    for part in [
        serde_json::to_vec(request).map_err(|_| ())?,
        serde_json::to_vec(reply).map_err(|_| ())?,
    ] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend(part);
    }
    Ok(bytes)
}
fn bounded_file(path: &Path, max: usize) -> Result<Vec<u8>, &'static str> {
    let resolved = path
        .canonicalize()
        .map_err(|_| "external authority file unavailable")?;
    let path = resolved
        .to_str()
        .ok_or("external authority file unavailable")?;
    if path.contains("../") || path.contains("..\\") {
        return Err("external authority file unavailable");
    }
    // Operator-controlled paths must remain regular files while loading.
    // Check before opening so an ordinary FIFO cannot wait for a writer.
    // This is not protection against a privileged concurrent path replacement.
    if !fs::metadata(path)
        .map_err(|_| "external authority file unavailable")?
        .is_file()
    {
        return Err("external authority file unavailable");
    }
    let file = fs::File::open(path).map_err(|_| "external authority file unavailable")?;
    if !file
        .metadata()
        .map_err(|_| "external authority file unavailable")?
        .is_file()
    {
        return Err("external authority file unavailable");
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "external authority file unavailable")?;
    if bytes.len() > max {
        return Err("external authority file too large");
    }
    Ok(bytes)
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

struct Authority {
    namespace: String,
    url: reqwest::Url,
    key: VerifyingKey,
    bearer: zeroize::Zeroizing<String>,
    client: reqwest::Client,
    runtime: tokio::runtime::Runtime,
    timeout: Duration,
    high_water: u64,
    failed: bool,
}
impl Authority {
    fn load(path: &Path) -> Result<Self, &'static str> {
        let config: Config = serde_json::from_slice(&bounded_file(path, 16384)?)
            .map_err(|_| "external authority configuration")?;
        let url = reqwest::Url::parse(&config.url).map_err(|_| "external authority URL")?;
        if !label(&config.namespace)
            || config.url.len() > 1024
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !(1..=5000).contains(&config.timeout_ms)
            || config.minimum_epoch == 0
            || config.minimum_epoch > i64::MAX as u64
        {
            return Err("external authority bounds");
        }
        let key = VerifyingKey::from_sec1_bytes(
            &STANDARD
                .decode(config.public_key_base64)
                .map_err(|_| "external authority key")?,
        )
        .map_err(|_| "external authority key")?;
        let bearer = zeroize::Zeroizing::new(
            String::from_utf8(bounded_file(&config.bearer_file, 258)?)
                .map_err(|_| "external authority credential")?,
        );
        let bearer = bearer.trim_end_matches(['\r', '\n']);
        if !(32..=256).contains(&bearer.len()) || !bearer.bytes().all(|c| c.is_ascii_graphic()) {
            return Err("external authority credential");
        }
        let timeout = Duration::from_millis(config.timeout_ms);
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .connect_timeout(timeout)
            .pool_max_idle_per_host(0);
        if let Some(path) = config.ca_certificate_file {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&bounded_file(&path, 16384)?)
                    .map_err(|_| "external authority CA")?,
            );
        }
        Ok(Self {
            namespace: config.namespace,
            url,
            key,
            bearer: zeroize::Zeroizing::new(bearer.into()),
            client: builder.build().map_err(|_| "external authority client")?,
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "external authority runtime")?,
            timeout,
            high_water: config.minimum_epoch,
            failed: false,
        })
    }
    fn verify(&mut self, request: &Request, receipt: Receipt) -> Option<Reply> {
        if receipt.request != *request {
            return None;
        }
        let signature = Signature::from_slice(&STANDARD.decode(&receipt.signature).ok()?).ok()?;
        self.key
            .verify(&transcript(request, &receipt.reply).ok()?, &signature)
            .ok()?;
        if matches!(receipt.reply, Reply::Fenced { epoch } | Reply::AlreadyFenced { epoch }
            | Reply::CompetingFence { epoch } | Reply::Epoch { epoch } | Reply::Recorded { epoch }
            | Reply::RefusedEpoch { epoch } if epoch == 0 || epoch > i64::MAX as u64)
        {
            return None;
        }
        let valid = match (&request.operation, &receipt.reply) {
            (_, Reply::Unconfirmed) => true,
            (
                Operation::Fence {
                    epoch: requested, ..
                },
                Reply::Fenced { epoch } | Reply::AlreadyFenced { epoch },
            ) => epoch == requested,
            (
                Operation::Fence {
                    epoch: requested, ..
                },
                Reply::CompetingFence { epoch },
            ) => epoch != requested && *epoch > 0,
            (Operation::Status { .. }, Reply::Fenced { epoch }) => *epoch > 0,
            (Operation::Status { .. }, Reply::Unfenced) => true,
            (Operation::ReadEpoch, Reply::Epoch { .. }) => true,
            (Operation::RecordEpoch { epoch: requested }, Reply::Recorded { epoch }) => {
                epoch == requested
            }
            (Operation::RecordEpoch { epoch: requested }, Reply::RefusedEpoch { epoch }) => {
                epoch >= requested
            }
            _ => false,
        };
        if !valid {
            return None;
        }
        if let Reply::Epoch { epoch } | Reply::Recorded { epoch } | Reply::RefusedEpoch { epoch } =
            receipt.reply
        {
            if epoch < self.high_water {
                self.failed = true;
                return None;
            }
            self.high_water = epoch;
        }
        Some(receipt.reply)
    }
    fn call(&mut self, operation: Operation) -> Option<Reply> {
        if self.failed {
            return None;
        }
        let request = Request {
            namespace: self.namespace.clone(),
            nonce: Uuid::new_v4(),
            operation,
        };
        let body = serde_json::to_vec(&request).ok()?;
        let result = self
            .runtime
            .block_on(async {
                tokio::time::timeout(self.timeout, async {
                    let mut response = self
                        .client
                        .post(self.url.clone())
                        .bearer_auth(self.bearer.as_str())
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .header(reqwest::header::ACCEPT, "application/json")
                        .body(body)
                        .send()
                        .await
                        .ok()?;
                    if response.status() != reqwest::StatusCode::OK
                        || response.url() != &self.url
                        || response
                            .content_length()
                            .is_some_and(|n| n > MAX_WIRE as u64)
                        || response
                            .headers()
                            .get(reqwest::header::CONTENT_TYPE)?
                            .to_str()
                            .ok()?
                            .split(';')
                            .next()?
                            .trim()
                            != "application/json"
                    {
                        return None;
                    }
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response.chunk().await.ok()? {
                        if bytes.len() + chunk.len() > MAX_WIRE {
                            return None;
                        }
                        bytes.extend(chunk);
                    }
                    serde_json::from_slice::<Receipt>(&bytes).ok()
                })
                .await
            })
            .ok()??;
        self.verify(&request, result)
    }
}

#[derive(Clone)]
struct SharedAuthority(Arc<Mutex<Authority>>);
impl SharedAuthority {
    fn call(&self, operation: Operation) -> Option<Reply> {
        self.0.lock().ok()?.call(operation)
    }
}
impl FenceAuthority for SharedAuthority {
    fn fence_host(&mut self, site: &str, token: FenceToken) -> HostFenceOutcome {
        if !label(site) || token.epoch() == 0 || token.epoch() > i64::MAX as u64 {
            return HostFenceOutcome::RefusedUnconfirmed;
        }
        match self.call(Operation::Fence {
            site: site.into(),
            epoch: token.epoch(),
        }) {
            Some(Reply::Fenced { epoch }) => HostFenceOutcome::Fenced {
                token: FenceToken::for_promotion(epoch),
            },
            Some(Reply::AlreadyFenced { epoch }) => HostFenceOutcome::AlreadyFenced {
                token: FenceToken::for_promotion(epoch),
            },
            Some(Reply::CompetingFence { epoch }) => HostFenceOutcome::RefusedCompetingFence {
                holder: FenceToken::for_promotion(epoch),
            },
            _ => HostFenceOutcome::RefusedUnconfirmed,
        }
    }
    fn fence_status(&mut self, site: &str) -> FenceStatus {
        if !label(site) {
            return FenceStatus::Unconfirmed;
        }
        match self.call(Operation::Status { site: site.into() }) {
            Some(Reply::Fenced { epoch }) => FenceStatus::Fenced {
                token: FenceToken::for_promotion(epoch),
            },
            Some(Reply::Unfenced) => FenceStatus::Unfenced,
            _ => FenceStatus::Unconfirmed,
        }
    }
}
impl ExternalEpochAnchor for SharedAuthority {
    fn confirmed_epoch(&mut self) -> AnchorReading {
        match self.call(Operation::ReadEpoch) {
            Some(Reply::Epoch { epoch }) => AnchorReading::Confirmed { epoch },
            _ => AnchorReading::Unconfirmed,
        }
    }
    fn record_promotion(&mut self, epoch: u64) -> AnchorRecord {
        if epoch == 0 || epoch > i64::MAX as u64 {
            return AnchorRecord::RefusedUnconfirmed;
        }
        match self.call(Operation::RecordEpoch { epoch }) {
            Some(Reply::Recorded { .. }) => AnchorRecord::Recorded,
            Some(Reply::RefusedEpoch { epoch }) => AnchorRecord::Refused {
                anchored_epoch: epoch,
            },
            _ => AnchorRecord::RefusedUnconfirmed,
        }
    }
}
/// Called on the dedicated synchronous executor thread, never inside the API runtime.
pub(crate) fn load(path: &Path) -> Result<ExternalFencing, &'static str> {
    let shared = SharedAuthority(Arc::new(Mutex::new(Authority::load(path)?)));
    Ok(ExternalFencing::new(shared.clone(), shared))
}

#[cfg(test)]
mod tests;
