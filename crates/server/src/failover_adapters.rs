// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded HTTPS observation input and signed member-report exchange.
//! This adapter never manufactures fencing evidence from a transport failure.
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use zrotext_failover_quorum::{
    decision::{MemberReport, WriterObservation},
    observe::{ProbeFault, RoundProbes, StopConfirmation, WriterProbe},
    report::{ObservationSink, ProbeSource},
    store::{ConsensusStore, JournalRecord},
};

const MAX_WIRE: usize = 4096;
const MAX_CONFIG: usize = 16384;
const LABEL: &[u8] = b"ZT/quorum-report/v1\0";
/// Maximum lifetime of authenticated evidence, matching the decision model.
pub const FRESHNESS_MS: u64 = zrotext_failover_quorum::decision::DEFAULT_OBSERVATION_FRESHNESS_MS;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    namespace: String,
    purpose: String,
    journal: String,
    signature: String,
}

fn transcript(namespace: &str, purpose: &str, journal: &str) -> Vec<u8> {
    let mut out = LABEL.to_vec();
    for part in [namespace, purpose, journal] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part.as_bytes());
    }
    out
}

fn sign(
    namespace: &str,
    purpose: &str,
    record: &JournalRecord,
    key: &SigningKey,
) -> Result<Wire, &'static str> {
    let journal = record.encode().map_err(|_| "invalid report")?;
    let signature: Signature = key.sign(&transcript(namespace, purpose, &journal));
    Ok(Wire {
        namespace: namespace.into(),
        purpose: purpose.into(),
        journal,
        signature: STANDARD.encode(signature.to_bytes()),
    })
}

fn verify(
    wire: &Wire,
    namespace: &str,
    purpose: &str,
    member: &str,
    key: &VerifyingKey,
) -> Result<JournalRecord, &'static str> {
    if wire.namespace != namespace || wire.purpose != purpose || wire.journal.len() > MAX_WIRE {
        return Err("report domain");
    }
    let bytes = STANDARD
        .decode(&wire.signature)
        .map_err(|_| "report signature")?;
    let signature = Signature::from_slice(&bytes).map_err(|_| "report signature")?;
    key.verify(&transcript(namespace, purpose, &wire.journal), &signature)
        .map_err(|_| "report signature")?;
    let record = JournalRecord::decode(&wire.journal).map_err(|_| "invalid report")?;
    if record.report.member_id != member
        || (record.sequence == 0 || record.sequence == u64::MAX)
        || record.encode().map_err(|_| "invalid report")? != wire.journal
    {
        return Err("report identity");
    }
    Ok(record)
}

fn bounded_file(path: &Path, max: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "adapter file unavailable")?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "adapter file unavailable")?;
    if bytes.len() > max {
        return Err("adapter file too large");
    }
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointConfig {
    member_id: String,
    url: String,
    public_key_base64: String,
    bearer_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterConfig {
    namespace: String,
    signing_key_file: PathBuf,
    serving_bearer_file: PathBuf,
    probe: EndpointConfig,
    peers: Vec<EndpointConfig>,
    ca_certificate_file: Option<PathBuf>,
}

struct Endpoint {
    member: String,
    url: reqwest::Url,
    key: VerifyingKey,
    bearer: String,
}
impl Endpoint {
    fn load(config: EndpointConfig) -> Result<Self, &'static str> {
        let url = reqwest::Url::parse(&config.url).map_err(|_| "adapter URL")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || config.url.len() > 1024
        {
            return Err("HTTPS adapter URL required");
        }
        if config.member_id.is_empty()
            || config.member_id.len() > 64
            || !config
                .member_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err("adapter member identity");
        }
        let key = VerifyingKey::from_sec1_bytes(
            &STANDARD
                .decode(config.public_key_base64)
                .map_err(|_| "adapter public key")?,
        )
        .map_err(|_| "adapter public key")?;
        let bearer = read_bearer(&config.bearer_file)?;
        Ok(Self {
            member: config.member_id,
            url,
            key,
            bearer,
        })
    }
}
fn read_bearer(path: &Path) -> Result<String, &'static str> {
    let token = String::from_utf8(bounded_file(path, 258)?).map_err(|_| "adapter credential")?;
    let token = token.trim_end_matches(['\r', '\n']);
    if !(32..=256).contains(&token.len()) || !token.bytes().all(|c| c.is_ascii_graphic()) {
        return Err("adapter credential");
    }
    Ok(token.into())
}

/// One authenticated replay checkpoint per peer/purpose; committed before
/// consensus append, so an interrupted append can lose a vote but never replay it.
struct ReplayFence {
    directory: PathBuf,
    last: HashMap<String, (u64, u64)>,
    failed: bool,
}
impl ReplayFence {
    fn open(
        directory: PathBuf,
        namespace: &str,
        purpose: &str,
        endpoints: &[&Endpoint],
    ) -> Result<Self, &'static str> {
        fs::create_dir_all(&directory).map_err(|_| "replay store unavailable")?;
        let mut last = HashMap::new();
        for endpoint in endpoints {
            let file = directory.join(format!("{}.json", endpoint.member));
            match fs::metadata(&file) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err("replay store unavailable"),
                Ok(_) => {}
            }
            let bytes = bounded_file(&file, MAX_WIRE)?;
            let wire: Wire = serde_json::from_slice(&bytes).map_err(|_| "replay store corrupt")?;
            let record = verify(&wire, namespace, purpose, &endpoint.member, &endpoint.key)?;
            last.insert(
                endpoint.member.clone(),
                (record.sequence, record.report.observed_at_ms),
            );
        }
        Ok(Self {
            directory,
            last,
            failed: false,
        })
    }
    fn accept(
        &mut self,
        member: &str,
        record: &JournalRecord,
        wire: &Wire,
        now: u64,
    ) -> Result<(), &'static str> {
        if self.failed
            || now == 0
            || record.report.observed_at_ms == 0
            || record.report.observed_at_ms > now
            || now - record.report.observed_at_ms > FRESHNESS_MS
            || (record.sequence <= self.last.get(member).map_or(0, |v| v.0)
                || record.report.observed_at_ms < self.last.get(member).map_or(0, |v| v.1))
        {
            return Err("stale report");
        }
        let bytes = serde_json::to_vec(wire).map_err(|_| "report encoding")?;
        let path = self.directory.join(format!("{member}.json"));
        let temporary = self.directory.join(format!("{member}.pending"));
        let durable = (|| -> std::io::Result<()> {
            let mut file = fs::File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            #[cfg(unix)]
            fs::File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if durable.is_err() {
            self.failed = true;
            return Err("replay store unavailable");
        }
        self.last.insert(
            member.into(),
            (record.sequence, record.report.observed_at_ms),
        );
        Ok(())
    }
}

#[derive(Clone)]
struct Serving {
    token_hash: [u8; 32],
    report: Arc<Mutex<Option<Wire>>>,
}
async fn latest(
    State(state): State<Serving>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<Wire>), StatusCode> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !bool::from(
        state
            .token_hash
            .ct_eq(&<[u8; 32]>::from(Sha256::digest(value.as_bytes()))),
    ) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let report = state
        .report
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .clone()
        .ok_or(StatusCode::NOT_FOUND)?;
    let record =
        JournalRecord::decode(&report.journal).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let now = now_ms();
    if now == 0
        || record.report.observed_at_ms > now
        || now - record.report.observed_at_ms > FRESHNESS_MS
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok((headers, Json(report)))
}

/// Parsed explicit adapter runtime. Construction is skipped entirely when
/// quorum is disabled. Secrets/configuration are never formatted or logged.
pub struct Adapters {
    namespace: String,
    signer: SigningKey,
    serving: Serving,
    probe: Endpoint,
    peers: Vec<Endpoint>,
    replay_probe: ReplayFence,
    replay_peers: ReplayFence,
    client: reqwest::Client,
    observed_at: Arc<AtomicU64>,
}
impl Adapters {
    pub fn load(
        path: &Path,
        env: &crate::failover_executor::ExecutorEnv,
    ) -> Result<Self, &'static str> {
        let member = env.report_member_id();
        let members = env.config().members();
        let store_dir = env.store_dir();
        let timeout_ms = env.probe_timeout_ms();
        if timeout_ms == 0 || timeout_ms > 5000 {
            return Err("adapter timeout bound");
        }
        let config: AdapterConfig = serde_json::from_slice(&bounded_file(path, MAX_CONFIG)?)
            .map_err(|_| "adapter configuration")?;
        if config.namespace.is_empty()
            || config.namespace.len() > 128
            || !config
                .namespace
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err("adapter namespace");
        }
        let namespace = topology_namespace(env, &config.namespace)?;
        let secret = zeroize::Zeroizing::new(bounded_file(&config.signing_key_file, 32)?);
        let signer = SigningKey::from_slice(&secret).map_err(|_| "adapter signing key")?;
        let token_hash =
            Sha256::digest(read_bearer(&config.serving_bearer_file)?.as_bytes()).into();
        let probe = Endpoint::load(config.probe)?;
        let peers: Vec<Endpoint> = config
            .peers
            .into_iter()
            .map(Endpoint::load)
            .collect::<Result<_, _>>()?;
        if probe.member != member
            || probe.key == *signer.verifying_key()
            || peers.len() != 2
            || peers
                .iter()
                .any(|p| p.member == member || !members.contains(&p.member))
            || peers[0].member == peers[1].member
            || peers[0].key == peers[1].key
            || peers
                .iter()
                .any(|peer| peer.key == *signer.verifying_key() || peer.key == probe.key)
        {
            return Err("adapter membership");
        }
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(timeout_ms))
            .connect_timeout(Duration::from_millis(timeout_ms))
            .pool_max_idle_per_host(1);
        if let Some(path) = config.ca_certificate_file {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&bounded_file(&path, 16384)?)
                    .map_err(|_| "adapter CA certificate")?,
            );
        }
        let client = builder.build().map_err(|_| "adapter TLS client")?;
        let replay_probe = ReplayFence::open(
            store_dir.join("probe-replay"),
            &namespace,
            "probe",
            &[&probe],
        )?;
        let replay_peers = ReplayFence::open(
            store_dir.join("peer-replay"),
            &namespace,
            "report",
            &peers.iter().collect::<Vec<_>>(),
        )?;
        Ok(Self {
            namespace,
            signer,
            serving: Serving {
                token_hash,
                report: Arc::new(Mutex::new(None)),
            },
            probe,
            peers,
            replay_probe,
            replay_peers,
            client,
            observed_at: Arc::new(AtomicU64::new(0)),
        })
    }
    pub fn router(&self) -> Router {
        Router::new()
            .route("/internal/failover/report", get(latest))
            .layer(axum::middleware::from_fn(
                |request: axum::extract::Request, next: axum::middleware::Next| async move {
                    let mut response = next.run(request).await;
                    response
                        .headers_mut()
                        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
                    response
                },
            ))
            .with_state(self.serving.clone())
    }
    pub(crate) fn into_ports(
        self,
        store: Arc<Mutex<ConsensusStore>>,
    ) -> (AdapterProbes, AdapterSink) {
        let sink = AdapterSink {
            store: store.clone(),
            namespace: self.namespace.clone(),
            signer: self.signer,
            report: self.serving.report,
            observed_at: self.observed_at.clone(),
        };
        (
            AdapterProbes {
                namespace: self.namespace,
                probe: self.probe,
                peers: self.peers,
                replay_probe: self.replay_probe,
                replay_peers: self.replay_peers,
                runtime: tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("adapter reporter runtime"),
                client: self.client,
                store,
                observed_at: self.observed_at,
            },
            sink,
        )
    }
}

async fn fetch(client: &reqwest::Client, endpoint: &Endpoint) -> Result<Wire, &'static str> {
    let mut response = client
        .get(endpoint.url.clone())
        .bearer_auth(&endpoint.bearer)
        .send()
        .await
        .map_err(|_| "adapter transport")?;
    if response.status() != reqwest::StatusCode::OK
        || response
            .content_length()
            .is_some_and(|n| n > MAX_WIRE as u64)
    {
        return Err("adapter response");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "adapter body")? {
        if bytes.len() + chunk.len() > MAX_WIRE {
            return Err("adapter body bound");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "adapter body")
}

pub(crate) struct AdapterProbes {
    runtime: tokio::runtime::Runtime,
    namespace: String,
    probe: Endpoint,
    peers: Vec<Endpoint>,
    replay_probe: ReplayFence,
    replay_peers: ReplayFence,
    client: reqwest::Client,
    store: Arc<Mutex<ConsensusStore>>,
    observed_at: Arc<AtomicU64>,
}
impl ProbeSource for AdapterProbes {
    fn probe(&mut self) -> RoundProbes {
        for endpoint in &self.peers {
            let accepted = self
                .runtime
                .block_on(fetch(&self.client, endpoint))
                .and_then(|wire| {
                    let record = verify(
                        &wire,
                        &self.namespace,
                        "report",
                        &endpoint.member,
                        &endpoint.key,
                    )?;
                    self.replay_peers
                        .accept(&endpoint.member, &record, &wire, now_ms())?;
                    Ok(record.report)
                });
            if let Ok(report) = accepted
                && let Ok(mut store) = self.store.lock()
            {
                let _ = store.record(&report);
            }
        }
        let result = self
            .runtime
            .block_on(fetch(&self.client, &self.probe))
            .and_then(|wire| {
                let record = verify(
                    &wire,
                    &self.namespace,
                    "probe",
                    &self.probe.member,
                    &self.probe.key,
                )?;
                self.replay_probe
                    .accept(&self.probe.member, &record, &wire, now_ms())?;
                Ok(record.report)
            });
        match result {
            Ok(report) => {
                self.observed_at
                    .store(report.observed_at_ms, Ordering::Release);
                probes(report)
            }
            Err(_) => abstain(),
        }
    }
}
fn probes(report: MemberReport) -> RoundProbes {
    RoundProbes {
        writer: match report.writer {
            WriterObservation::Reachable { epoch } => WriterProbe::Reachable { epoch },
            WriterObservation::Unreachable => WriterProbe::Unreachable,
        },
        writer_site_fence: report.writer_site_fence.ok_or(ProbeFault::Indeterminate),
        writer_stop: report
            .writer_stop_confirmed
            .map(|confirmed| StopConfirmation { confirmed })
            .ok_or(ProbeFault::Indeterminate),
        standby: report.standby_ready.ok_or(ProbeFault::Indeterminate),
        former_writer: report
            .former_writer_healthy
            .ok_or(ProbeFault::Indeterminate),
    }
}
fn abstain() -> RoundProbes {
    RoundProbes {
        writer: WriterProbe::Indeterminate,
        writer_site_fence: Err(ProbeFault::Indeterminate),
        writer_stop: Err(ProbeFault::Indeterminate),
        standby: Err(ProbeFault::Indeterminate),
        former_writer: Err(ProbeFault::Indeterminate),
    }
}
pub(crate) struct AdapterSink {
    store: Arc<Mutex<ConsensusStore>>,
    namespace: String,
    signer: SigningKey,
    report: Arc<Mutex<Option<Wire>>>,
    observed_at: Arc<AtomicU64>,
}
impl ObservationSink for AdapterSink {
    type Error = &'static str;
    fn submit(&mut self, report: &MemberReport) -> Result<(), Self::Error> {
        let mut report = report.clone();
        report.observed_at_ms = self.observed_at.load(Ordering::Acquire);
        let now = now_ms();
        if now == 0
            || report.observed_at_ms == 0
            || report.observed_at_ms > now
            || now - report.observed_at_ms > FRESHNESS_MS
        {
            return Err("stale probe input");
        }
        let mut store = self.store.lock().map_err(|_| "consensus unavailable")?;
        store.record(&report).map_err(|_| "consensus unavailable")?;
        let sequence = store
            .next_sequence(&report.member_id)
            .ok_or("member unavailable")?
            - 1;
        let wire = sign(
            &self.namespace,
            "report",
            &JournalRecord { sequence, report },
            &self.signer,
        )?;
        *self.report.lock().map_err(|_| "publisher unavailable")? = Some(wire);
        Ok(())
    }
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn topology_namespace(
    env: &crate::failover_executor::ExecutorEnv,
    namespace: &str,
) -> Result<String, &'static str> {
    let mut members = env.config().members().to_vec();
    members.sort();
    let mut bytes = b"ZT/quorum-topology/v1\0".to_vec();
    for value in std::iter::once(namespace)
        .chain([
            env.config().writer_site_id(),
            env.config().standby_site_id(),
        ])
        .chain(members.iter().map(String::as_str))
    {
        if value.is_empty() || value.len() > 128 {
            return Err("adapter topology bound");
        }
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests;
