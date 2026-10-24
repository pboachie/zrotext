// SPDX-License-Identifier: AGPL-3.0-only
//! Closed frontend transcript for the current ordinary-runtime Store fixture.
//! SQL hashes commit to exact query bytes; auth and Bind values are never retained.
use crate::test_database::Driver;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_postgres::{Client, Config, NoTls, config::Host};

// Reviewed metadata batches plus the unchanged per-transaction entry. This is
// a fixed source contract, never a dynamically learned baseline.
const NATIVE: [(&str, usize); 15] = [
    (
        "36a86777b1416371c6c75bfd18873a7969a6aac004b01159f99ef492c73e336c",
        0,
    ),
    (
        "32994d944a9b00698c412346272026cdcb33bf6966cee58bf397ec12d7ed4f36",
        0,
    ),
    (
        "0e77680a5c1e5912098160103add96ce78daae5a3bda4704d25c30a9b6eaa8aa",
        0,
    ),
    (
        "2357f2a77e4e51dbd0f4895484f55b3d499b59c74f6d273a6141aabbe611d8bf",
        2,
    ),
    (
        "9454482f9881a8897fcb9473a92d17bfeff8fd23f59401eed7e5d03bc9539a23",
        1,
    ),
    (
        "d3eb6045d648de3b171ebd255ea01c49c3c49872ed02c8dd4ad48191b88d478d",
        1,
    ),
    (
        "36a86777b1416371c6c75bfd18873a7969a6aac004b01159f99ef492c73e336c",
        0,
    ),
    (
        "32994d944a9b00698c412346272026cdcb33bf6966cee58bf397ec12d7ed4f36",
        0,
    ),
    (
        "0e77680a5c1e5912098160103add96ce78daae5a3bda4704d25c30a9b6eaa8aa",
        0,
    ),
    (
        "2357f2a77e4e51dbd0f4895484f55b3d499b59c74f6d273a6141aabbe611d8bf",
        2,
    ),
    (
        "9454482f9881a8897fcb9473a92d17bfeff8fd23f59401eed7e5d03bc9539a23",
        1,
    ),
    (
        "d3eb6045d648de3b171ebd255ea01c49c3c49872ed02c8dd4ad48191b88d478d",
        1,
    ),
    (
        "d87b446d9a7d9ca9efc8b3fc8360dc072b6355cbc222c957254ed7716413306e",
        0,
    ),
    (
        "7d5cac9441270c7ea922633f44bf20ddecb639af5f7323efa799a192d22e58f5",
        0,
    ),
    (
        "66e05d3cd0a7cb2679fc8352d8126fc0f71b12dfd38918fdff15ff03e90d20b8",
        0,
    ),
];
pub const UNMETERED: [&str; 6] = [
    "dff461f6b68ffd04beda0eb52d01ee47745ec5c2ee79274ccc4b9d10e38d7e64",
    "e3baee171d5082e29d8812d707d0ec8c75b9ed48af3418d46ab4d6ecbf7308ec",
    "6ac7705618c5a4f926ae4e7500861d0734ca09680cbd585cedd296badade748d",
    "95de6681d5cf0bce352c0ad757a7545a03938b6b8e1538d12e433aec133ae7e5",
    "426997f92745f5d59195d8fa18c6bae187018162b53028469c74faa77b509c37",
    "9364a79bbbbe26694307b41e38d871321e9a7e8e55db14d56f403e6832ba597f",
];
pub const BILLED: [&str; 9] = [
    "d242071240f44f7049479dc7bcb64507cdeba6cec941a7b6dbf345cdb3edee7d",
    "dff461f6b68ffd04beda0eb52d01ee47745ec5c2ee79274ccc4b9d10e38d7e64",
    "e3baee171d5082e29d8812d707d0ec8c75b9ed48af3418d46ab4d6ecbf7308ec",
    "6ac7705618c5a4f926ae4e7500861d0734ca09680cbd585cedd296badade748d",
    "95de6681d5cf0bce352c0ad757a7545a03938b6b8e1538d12e433aec133ae7e5",
    "426997f92745f5d59195d8fa18c6bae187018162b53028469c74faa77b509c37",
    "e4b104f14c7733f929bf2eab37ca5b4ddba0e326c19e6d58f145b5f8e6796b1e",
    "4976b6ae93318ede606cd633f1c5395b689ef79608dc6bad143ff95b69de037c",
    "9364a79bbbbe26694307b41e38d871321e9a7e8e55db14d56f403e6832ba597f",
];
pub const EXPIRY: [&str; 1] = ["e59bfde5ba1bc46a17e0fbb3474e87c7b16a8868712c032342e42c32da1b22eb"];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Frame {
    Startup,
    Auth,
    Parse(String, String, usize),
    Bind(String, String, usize),
    Describe(u8, String),
    Execute(String),
    Close(u8, String),
    Sync,
    Query(String),
    Terminate,
}
fn cstring(data: &[u8], at: &mut usize) -> Result<String, &'static str> {
    let end = data
        .get(*at..)
        .ok_or("offset")?
        .iter()
        .position(|b| *b == 0)
        .ok_or("cstring")?
        + *at;
    let value = std::str::from_utf8(&data[*at..end])
        .map_err(|_| "utf8")?
        .to_owned();
    *at = end + 1;
    Ok(value)
}
fn number(data: &[u8], at: &mut usize, size: usize) -> Result<usize, &'static str> {
    let bytes = data.get(*at..*at + size).ok_or("integer")?;
    *at += size;
    Ok(bytes.iter().fold(0, |n, b| (n << 8) | usize::from(*b)))
}
fn frame(tag: u8, data: &[u8]) -> Result<Frame, &'static str> {
    let mut at = 0;
    let value = match tag {
        b'p' => return Ok(Frame::Auth), // Never retain an authentication payload.
        b'P' => {
            let name = cstring(data, &mut at)?;
            let sql = cstring(data, &mut at)?;
            let params = number(data, &mut at, 2)?;
            for _ in 0..params {
                number(data, &mut at, 4)?;
            }
            Frame::Parse(
                name,
                format!("{:x}", Sha256::digest(sql.as_bytes())),
                params,
            )
        }
        b'B' => {
            let portal = cstring(data, &mut at)?;
            let statement = cstring(data, &mut at)?;
            let formats = number(data, &mut at, 2)?;
            for _ in 0..formats {
                number(data, &mut at, 2)?;
            }
            let params = number(data, &mut at, 2)?;
            for _ in 0..params {
                let len = number(data, &mut at, 4)?;
                if len != u32::MAX as usize {
                    let end = at.checked_add(len).ok_or("parameter length")?;
                    data.get(at..end).ok_or("parameter bytes")?;
                    at = end;
                }
            }
            let results = number(data, &mut at, 2)?;
            for _ in 0..results {
                number(data, &mut at, 2)?;
            }
            Frame::Bind(portal, statement, params)
        }
        b'D' | b'C' => {
            let kind = *data.first().ok_or("target")?;
            at = 1;
            let name = cstring(data, &mut at)?;
            if tag == b'D' {
                Frame::Describe(kind, name)
            } else {
                Frame::Close(kind, name)
            }
        }
        b'E' => {
            let portal = cstring(data, &mut at)?;
            if number(data, &mut at, 4)? != 0 {
                return Err("bounded portal");
            }
            Frame::Execute(portal)
        }
        b'S' => Frame::Sync,
        b'Q' => Frame::Query(cstring(data, &mut at)?),
        b'X' => Frame::Terminate,
        _ => return Err("unknown frontend tag"),
    };
    if at != data.len() {
        return Err("trailing payload");
    }
    Ok(value)
}
#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    startup: bool,
    frames: Vec<Frame>,
    error: Option<&'static str>,
}
impl Capture {
    fn feed(&mut self, data: &[u8]) {
        if self.error.is_some() {
            return;
        }
        self.bytes.extend_from_slice(data);
        if self.bytes.len() > 1_048_576 {
            self.error = Some("frame cap");
            return;
        }
        loop {
            let header = if self.startup { 5 } else { 4 };
            if self.bytes.len() < header {
                return;
            }
            let at = usize::from(self.startup);
            let len = u32::from_be_bytes(self.bytes[at..at + 4].try_into().unwrap()) as usize;
            if len < if self.startup { 4 } else { 8 } {
                self.error = Some("frame length");
                return;
            }
            let end = at + len;
            if end > 1_048_576 {
                self.error = Some("frame cap");
                return;
            }
            if self.bytes.len() < end {
                return;
            }
            let parsed = if self.startup {
                frame(self.bytes[0], &self.bytes[5..end])
            } else if self.bytes[4..8] == [0, 3, 0, 0] {
                Ok(Frame::Startup)
            } else {
                Err("unsupported startup protocol")
            };
            match parsed {
                Ok(value) => self.frames.push(value),
                Err(error) => {
                    self.error = Some(error);
                    return;
                }
            }
            self.startup = true;
            self.bytes.drain(..end);
            if self.frames.len() > 4096 {
                self.error = Some("transcript cap");
                return;
            }
        }
    }
    fn snapshot(&self) -> Vec<Frame> {
        assert_eq!(self.error, None);
        assert!(self.bytes.is_empty(), "partial frontend frame");
        self.frames.clone()
    }
}
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub struct Proxy {
    pub client: Client,
    driver: Driver,
    task: tokio::task::JoinHandle<()>,
    capture: Arc<Mutex<Capture>>,
}
impl Proxy {
    pub async fn start(config: &Config) -> Self {
        assert_eq!(config.get_hosts().len(), 1, "one explicit fixture endpoint");
        assert!(config.get_ports().len() <= 1);
        let port = config.get_ports().first().copied().unwrap_or(5432);
        let upstream: Box<dyn Io> = match &config.get_hosts()[0] {
            Host::Tcp(host) => {
                assert!(config.get_hostaddrs().len() <= 1);
                let host = config
                    .get_hostaddrs()
                    .first()
                    .map_or_else(|| host.clone(), ToString::to_string);
                Box::new(TcpStream::connect((host.as_str(), port)).await.unwrap())
            }
            #[cfg(unix)]
            Host::Unix(path) => Box::new(
                tokio::net::UnixStream::connect(path.join(format!(".s.PGSQL.{port}")))
                    .await
                    .unwrap(),
            ),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let capture = Arc::new(Mutex::new(Capture::default()));
        let recorded = capture.clone();
        let task = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut server = upstream;
            let mut from_client = [0; 8192];
            let mut from_server = [0; 8192];
            loop {
                tokio::select! {
                    read = client.read(&mut from_client) => {
                        let n = read.unwrap();
                        if n == 0 { break; }
                        recorded.lock().unwrap().feed(&from_client[..n]);
                        if server.write_all(&from_client[..n]).await.is_err() { break; }
                    }
                    read = server.read(&mut from_server) => {
                        let n = read.unwrap();
                        if n == 0 { break; }
                        if client.write_all(&from_server[..n]).await.is_err() { break; }
                    }
                }
            }
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let (client, connection) = config.connect_raw(stream, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        let value = Self {
            client,
            driver,
            task,
            capture,
        };
        let initial = value.capture.lock().unwrap().snapshot();
        assert_eq!(initial.first(), Some(&Frame::Startup));
        assert!(initial[1..].iter().all(|f| *f == Frame::Auth));
        value
    }
    pub fn mark(&self) -> usize {
        self.capture.lock().unwrap().snapshot().len()
    }
    pub fn transaction(&self, before: usize, business: &[&str]) -> (usize, usize) {
        let frames = self.capture.lock().unwrap().snapshot();
        let count = check_transaction(&frames[before..], business).unwrap();
        (frames.len(), count)
    }
    pub fn syncs(&self, before: usize, after: usize) -> usize {
        self.capture.lock().unwrap().snapshot()[before..after]
            .iter()
            .filter(|f| **f == Frame::Sync)
            .count()
    }
    pub async fn finish(self, after: usize, raw_control: bool) {
        drop(self.client);
        tokio::time::timeout(Duration::from_secs(5), self.driver)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap();
        let frames = self.capture.lock().unwrap().snapshot();
        if raw_control {
            check_raw_control(&frames[after..]).unwrap();
        } else {
            assert_eq!(frames[after..], [Frame::Terminate]);
        }
    }
}
fn check_transaction(frames: &[Frame], business: &[&str]) -> Result<usize, &'static str> {
    let mut native = BTreeMap::<String, (usize, usize, usize)>::new();
    let mut parses = 0;
    let mut typed = 0;
    let mut syncs = 0;
    let mut simple = Vec::new();
    let mut batch = Vec::new();
    for f in frames {
        if let Frame::Query(sql) = f {
            if !batch.is_empty() {
                return Err("simple query inside batch");
            }
            match simple.len() {
                0 if parses == 0 && syncs == 0 => {}
                1 if parses == 15 && typed == 0 && syncs == 45 => {}
                2 if typed == business.len() && syncs == 45 + business.len() => {}
                _ => return Err("simple query position"),
            }
            simple.push(sql.as_str());
            continue;
        }
        if *f != Frame::Sync {
            batch.push(f);
            continue;
        }
        syncs += 1;
        match batch.as_slice() {
            [Frame::Parse(name, sql, 0), Frame::Describe(b'S', described)]
                if !name.is_empty() && name == described =>
            {
                if native.values().any(|(_, executed, _)| *executed != 1)
                    || typed != 0
                    || parses >= NATIVE.len()
                    || sql != NATIVE[parses].0
                    || native.contains_key(name)
                {
                    return Err("native Parse order");
                }
                native.insert(name.clone(), (NATIVE[parses].1, 0, 0));
                parses += 1;
            }
            [Frame::Bind(portal, name, params), Frame::Execute(executed)]
                if portal.is_empty() && executed == portal =>
            {
                let state = native.get_mut(name).ok_or("unmapped native execution")?;
                if state.0 != *params || state.1 != 0 || state.2 != 0 {
                    return Err("native execution count");
                }
                state.1 += 1;
            }
            [Frame::Close(b'S', name)] => {
                let state = native.get_mut(name).ok_or("unmapped Close")?;
                if state.1 != 1 || state.2 != 0 {
                    return Err("native Close count");
                }
                state.2 += 1;
            }
            [
                Frame::Parse(name, sql, params),
                Frame::Bind(portal, bound, values),
                Frame::Describe(b'S', described),
                Frame::Execute(executed),
            ] if name.is_empty()
                && portal.is_empty()
                && bound.is_empty()
                && described.is_empty()
                && executed.is_empty()
                && params == values =>
            {
                if parses != NATIVE.len() || typed >= business.len() || sql != business[typed] {
                    return Err("business Parse order");
                }
                typed += 1;
            }
            _ => return Err("unknown Sync batch"),
        }
        batch.clear();
    }
    if !batch.is_empty()
        || simple
            != [
                "START TRANSACTION",
                "SET LOCAL search_path TO pg_catalog,public,pg_temp",
                "COMMIT",
            ]
    {
        return Err("transaction simple queries");
    }
    if parses != 15
        || native
            .values()
            .any(|(_, executed, closed)| *executed != 1 || *closed != 1)
        || typed != business.len()
        || syncs != 45 + business.len()
    {
        return Err("closed transaction count");
    }
    Ok(typed)
}
fn check_raw_control(frames: &[Frame]) -> Result<(), &'static str> {
    let digest = format!("{:x}", Sha256::digest(b"SELECT $1::text"));
    match frames {
        [
            Frame::Parse(name, sql, 0),
            Frame::Describe(b'S', described),
            Frame::Sync,
            Frame::Bind(portal, bound, 1),
            Frame::Execute(executed),
            Frame::Sync,
            Frame::Close(b'S', closed),
            Frame::Sync,
            Frame::Terminate,
        ] if !name.is_empty()
            && name == described
            && name == bound
            && name == closed
            && sql == &digest
            && portal.is_empty()
            && executed == portal =>
        {
            Ok(())
        }
        _ => Err("raw control transcript"),
    }
}

fn successful(business: &[&str], defer_closes: bool) -> Vec<Frame> {
    let mut frames = vec![Frame::Query(String::from("START TRANSACTION"))];
    for (i, (sql, params)) in NATIVE.iter().enumerate() {
        let name = format!("s{i}");
        frames.extend([
            Frame::Parse(name.clone(), (*sql).to_owned(), 0),
            Frame::Describe(b'S', name.clone()),
            Frame::Sync,
            Frame::Bind(String::new(), name.clone(), *params),
            Frame::Execute(String::new()),
            Frame::Sync,
        ]);
        if !defer_closes {
            frames.extend([Frame::Close(b'S', name), Frame::Sync]);
        }
    }
    if defer_closes {
        for i in (0..NATIVE.len()).rev() {
            frames.extend([Frame::Close(b'S', format!("s{i}")), Frame::Sync]);
        }
    }
    frames.push(Frame::Query(String::from(
        "SET LOCAL search_path TO pg_catalog,public,pg_temp",
    )));
    for sql in business {
        frames.extend([
            Frame::Parse(String::new(), (*sql).to_owned(), 1),
            Frame::Bind(String::new(), String::new(), 1),
            Frame::Describe(b'S', String::new()),
            Frame::Execute(String::new()),
            Frame::Sync,
        ]);
    }
    frames.push(Frame::Query(String::from("COMMIT")));
    frames
}
#[test]
fn closed_transcript_rejects_unknown_extra_and_missing_statements() {
    let exact = successful(&UNMETERED, false);
    assert_eq!(check_transaction(&exact, &UNMETERED), Ok(6));
    let mut wrong = exact.clone();
    if let Frame::Parse(_, sql, _) = &mut wrong[1] {
        *sql = String::from("unknown query");
    }
    assert!(check_transaction(&wrong, &UNMETERED).is_err());
    let mut missing = exact.clone();
    let close = missing
        .iter()
        .position(|f| matches!(f, Frame::Close(..)))
        .unwrap();
    missing.drain(close..close + 2);
    assert!(check_transaction(&missing, &UNMETERED).is_err());
    let mut extra = exact;
    extra.insert(extra.len() - 1, Frame::Sync);
    assert!(check_transaction(&extra, &UNMETERED).is_err());
}
#[test]
fn named_close_interleaving_still_requires_exact_statement_identity() {
    for business in [&UNMETERED[..], &BILLED[..], &EXPIRY[..]] {
        assert_eq!(
            check_transaction(&successful(business, true), business),
            Ok(business.len())
        );
    }
    let mut wrong = successful(&BILLED, true);
    let close = wrong
        .iter()
        .position(|f| matches!(f, Frame::Close(..)))
        .unwrap();
    wrong[close] = Frame::Close(b'S', String::from("unknown statement"));
    assert!(check_transaction(&wrong, &BILLED).is_err());
}
#[test]
fn simple_transaction_brackets_cannot_move_across_native_entry() {
    let mut wrong = successful(&EXPIRY, false);
    let local = wrong
        .iter()
        .position(|f| matches!(f, Frame::Query(sql) if sql.starts_with("SET LOCAL")))
        .unwrap();
    let frame = wrong.remove(local);
    wrong.insert(1, frame);
    assert!(check_transaction(&wrong, &EXPIRY).is_err());
    let mut wrong = successful(&EXPIRY, false);
    wrong.swap(0, 1);
    assert!(check_transaction(&wrong, &EXPIRY).is_err());
}
fn encoded(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u32::try_from(payload.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
#[test]
fn fragmented_frames_keep_correlations_without_auth_or_bind_values() {
    let mut bytes = vec![0, 0, 0, 8, 0, 3, 0, 0];
    bytes.extend(encoded(b'p', b"synthetic authentication response"));
    bytes.extend(encoded(b'P', b"s8\0SELECT $1::text\0\0\0"));
    let mut bind = b"\0s8\0\0\0\0\x01".to_vec();
    bind.extend_from_slice(&6u32.to_be_bytes());
    bind.extend_from_slice(b"secret");
    bind.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend(encoded(b'B', &bind));
    bytes.extend(encoded(b'E', &[0, 0, 0, 0, 0]));
    bytes.extend(encoded(b'S', &[]));
    let mut whole = Capture::default();
    whole.feed(&bytes);
    let mut fragmented = Capture::default();
    for byte in bytes {
        fragmented.feed(&[byte]);
    }
    assert_eq!(fragmented.snapshot(), whole.snapshot());
    assert!(
        matches!(&whole.frames[3], Frame::Bind(portal, name, 1) if portal.is_empty() && name == "s8")
    );
    let shown = format!("{:?}", whole.snapshot());
    assert!(!shown.contains("secret") && !shown.contains("authentication response"));
    let mut unknown = Capture::default();
    unknown.feed(&[0, 0, 0, 8, 0, 3, 0, 0]);
    unknown.feed(&encoded(b'?', &[]));
    assert_eq!(unknown.error, Some("unknown frontend tag"));
    assert!(frame(b'S', &[0]).is_err());
}
#[test]
fn raw_query_control_exposes_prepare_execute_and_named_close() {
    let name = String::from("s99");
    let mut exact = vec![
        Frame::Parse(
            name.clone(),
            format!("{:x}", Sha256::digest(b"SELECT $1::text")),
            0,
        ),
        Frame::Describe(b'S', name.clone()),
        Frame::Sync,
        Frame::Bind(String::new(), name.clone(), 1),
        Frame::Execute(String::new()),
        Frame::Sync,
        Frame::Close(b'S', name),
        Frame::Sync,
        Frame::Terminate,
    ];
    assert_eq!(check_raw_control(&exact), Ok(()));
    exact[6] = Frame::Close(b'S', String::from("other"));
    assert!(check_raw_control(&exact).is_err());
}
