//! Metadata-only local acceptance. Independent signed root history is always rechecked.
use super::*;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
static LIVE: AtomicUsize = AtomicUsize::new(0);
const APP: i64 = 0x5a544348;
#[derive(Debug)]
pub enum HistoryError {
    Refused,
    RootMismatch,
}
use HistoryError::Refused;
type Result<T> = std::result::Result<T, HistoryError>;
impl From<rusqlite::Error> for HistoryError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Refused
    }
}
impl From<std::io::Error> for HistoryError {
    fn from(_: std::io::Error) -> Self {
        Self::Refused
    }
}
impl From<Error> for HistoryError {
    fn from(_: Error) -> Self {
        Self::Refused
    }
}
fn require(v: bool) -> Result<()> {
    if v { Ok(()) } else { Err(Refused) }
}
#[derive(Clone)]
pub struct Metadata {
    pub contact: [u8; 16],
    pub revision: u64,
    pub digest: [u8; 32],
    pub request: [u8; 16],
    pub routing: [u8; 32],
    pub name: Slot,
    pub notes: Slot,
    pub statement_digest: [u8; 32],
    pub manifest_version: u64,
    pub manifest_digest: [u8; 32],
    pub reader_id: [u8; 32],
    pub reader_generation: u64,
    pub root_writer_id: [u8; 32],
    pub comparison: u64,
    pub root_version: u64,
    pub root_digest: [u8; 32],
    pub root_time: u64,
}
/// A private session-bound exact-row CAS token. Never integrity or permission.
pub struct LocalToken {
    owner: Arc<()>,
    raw: Vec<u8>,
}
pub struct Outcome {
    pub kind: &'static str,
    pub reason: &'static str,
    pub token: Option<Arc<LocalToken>>,
    pub metadata: Option<Metadata>,
}
impl Outcome {
    fn plain(kind: &'static str) -> Self {
        Self {
            kind,
            reason: "",
            token: None,
            metadata: None,
        }
    }
}
struct State {
    db: Connection,
    tokens: BTreeMap<[u8; 16], Arc<LocalToken>>,
}
pub enum OpenMode {
    Create,
    Existing,
    LocalReduction,
}
pub struct History {
    state: Mutex<Option<State>>,
    path: PathBuf,
    root_path: PathBuf,
    identity: same_file::Handle,
    pin: Vec<u8>,
    fingerprint: Vec<u8>,
    origin: String,
    header: Vec<u8>,
    maximum: usize,
    reduction: bool,
    born: Instant,
    closed: AtomicBool,
    released: AtomicBool,
    owner: Arc<()>,
}
fn connection(path: &Path) -> Result<Connection> {
    require(fs::symlink_metadata(path)?.file_type().is_file())?;
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    c.busy_timeout(Duration::from_secs(5))?;
    c.pragma_update(None, "trusted_schema", "OFF")?;
    c.pragma_update(None, "synchronous", "FULL")?;
    Ok(c)
}
impl Drop for History {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.release();
    }
}
impl History {
    fn release(&self) {
        if self.closed.load(Ordering::SeqCst) && !self.released.swap(true, Ordering::SeqCst) {
            LIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(mut s) = self.state.try_lock() {
            s.take();
            self.release();
        }
    }
    fn live(&self, until: Instant) -> Result<()> {
        if self.born.elapsed() >= Duration::from_secs(1800) {
            self.closed.store(true, Ordering::SeqCst);
        }
        require(
            !self.closed.load(Ordering::SeqCst)
                && self.born.elapsed() < Duration::from_secs(1800)
                && Instant::now() < until,
        )
    }
    fn operation<T>(&self, run: impl FnOnce(&mut State, Instant) -> Result<T>) -> Result<T> {
        let mut s = self.state.try_lock().map_err(|_| Refused)?;
        let until = Instant::now() + Duration::from_secs(10);
        let out = self.live(until).and_then(|()| {
            let state = s.as_mut().ok_or(Refused)?;
            // A short-lived external writer may checkpoint and unlink the WAL
            // while this handle is idle, which would leave an already-open
            // connection pinned to the unlinked pre-checkpoint snapshot.
            state.db = connection(&self.path)?;
            run(state, until)
        });
        if self.closed.load(Ordering::SeqCst) {
            s.take();
            self.release();
        }
        out
    }
    /// Explicit creation; the root journal must already exist. Keep both parent directories private.
    pub fn open(
        path: impl AsRef<Path>,
        root_path: impl AsRef<Path>,
        pin: &[u8],
        fingerprint: &[u8],
        origin: &str,
        maximum: usize,
        mode: OpenMode,
    ) -> Result<Self> {
        let create = matches!(mode, OpenMode::Create);
        let reduction = matches!(mode, OpenMode::LocalReduction);
        enroll_root(pin, fingerprint)?;
        validate_origin01(origin)?;
        require((1..=256).contains(&maximum) && !(create && reduction))?;
        let path = std::path::absolute(path)?;
        let root_path = std::path::absolute(root_path)?;
        require(path != root_path)?;
        LIVE.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            if n < 4 { Some(n + 1) } else { None }
        })
        .map_err(|_| Refused)?;
        let opened = (|| -> Result<Self> {
            if create {
                let mut o = OpenOptions::new();
                o.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    o.mode(0o600);
                }
                o.open(&path)?.sync_all()?;
            }
            let db = connection(&path)?;
            let identity = same_file::Handle::from_path(&path)?;
            let header = [
                b"ZTCH\x01".as_slice(),
                pin,
                fingerprint,
                &(origin.len() as u16).to_be_bytes(),
                origin.as_bytes(),
                &(maximum as u16).to_be_bytes(),
            ]
            .concat();
            Ok(Self {
                state: Mutex::new(Some(State {
                    db,
                    tokens: BTreeMap::new(),
                })),
                path,
                root_path,
                identity,
                pin: pin.to_vec(),
                fingerprint: fingerprint.to_vec(),
                origin: origin.to_string(),
                header,
                maximum,
                reduction,
                born: Instant::now(),
                closed: AtomicBool::new(false),
                released: AtomicBool::new(false),
                owner: Arc::new(()),
            })
        })();
        let h = match opened {
            Ok(h) => h,
            Err(e) => {
                LIVE.fetch_sub(1, Ordering::SeqCst);
                return Err(e);
            }
        };
        h.operation(|s,until|{
   if !reduction{h.root_snapshot(until)?;}
   let tx=s.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
   if create{tx.execute_batch("PRAGMA application_id=1515471688; CREATE TABLE header (id INTEGER PRIMARY KEY CHECK(id=1),payload BLOB NOT NULL,count INTEGER NOT NULL) STRICT; CREATE TABLE contacts (id BLOB PRIMARY KEY,payload BLOB NOT NULL) STRICT;")?;tx.execute("INSERT INTO header VALUES(1,?1,0)",[&h.header])?;}
   h.read(&tx,until)?;tx.commit()?;let mode:String=s.db.query_row("PRAGMA journal_mode=WAL",[],|r|r.get(0))?;require(mode=="wal")?;s.db.pragma_update(None,"synchronous","FULL")?;Ok(())
  })?;
        Ok(h)
    }
    fn read(&self, c: &Connection, until: Instant) -> Result<BTreeMap<[u8; 16], Vec<u8>>> {
        self.live(until)?;
        require(
            fs::symlink_metadata(&self.path)?.file_type().is_file()
                && same_file::Handle::from_path(&self.path)? == self.identity,
        )?;
        let app: i64 = c.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        require(app == APP)?;
        let names:String=c.query_row("SELECT group_concat(type||':'||name,',') FROM (SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name)",[],|r|r.get(0))?;
        require(names == "table:contacts,table:header")?;
        let n: i64 = c.query_row("SELECT count(*) FROM header", [], |r| r.get(0))?;
        require(n == 1)?;
        let (header, count): (Vec<u8>, i64) = c.query_row(
            "SELECT CASE WHEN length(payload)<=647 THEN payload END,count FROM header WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        require(header == self.header && count >= 0 && count <= self.maximum as i64)?;
        let mut q=c.prepare("SELECT CASE WHEN length(id)=16 THEN id END,CASE WHEN length(payload)<=387 THEN payload END FROM contacts LIMIT 257")?;
        let mut rows = q.query([])?;
        let mut out = BTreeMap::new();
        while let Some(r) = rows.next()? {
            let id: Vec<u8> = r.get(0)?;
            let raw: Vec<u8> = r.get(1)?;
            parse(&raw)?;
            require(id.len() == 16 && id == raw[1..17])?;
            let id = id.try_into().map_err(|_| Refused)?;
            require(out.insert(id, raw).is_none())?;
        }
        require(out.len() as i64 == count)?;
        Ok(out)
    }
    fn root_snapshot(&self, until: Instant) -> Result<RootSnapshot> {
        self.live(until)?;
        let mut db = connection(&self.root_path)?;
        let tx = db.transaction()?;
        let app: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        require(app == 0x5a544e4a && version == 2)?;
        let names:String=tx.query_row("SELECT group_concat(type||':'||name,',') FROM (SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name)",[],|r|r.get(0))?;
        require(names == "table:elections,table:identity,table:manifests,table:transitions")?;
        let n: i64 = tx.query_row(
            "SELECT (SELECT count(*) FROM transitions)+(SELECT count(*) FROM elections)",
            [],
            |r| r.get(0),
        )?;
        require(n == 0)?;
        let n: i64 = tx.query_row("SELECT count(*) FROM identity", [], |r| r.get(0))?;
        require(n == 1)?;
        let (pin,fp):(Vec<u8>,Vec<u8>)=tx.query_row("SELECT CASE WHEN length(root)=94 THEN root END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM identity WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if pin != self.pin || fp != self.fingerprint {
            return Err(HistoryError::RootMismatch);
        }
        let mut q=tx.prepare("SELECT revision,comparison,CASE WHEN length(signed)<=9751 THEN signed END FROM manifests ORDER BY revision LIMIT 65")?;
        let mut rows = q.query([])?;
        let root = enroll_root(&self.pin, &self.fingerprint)?;
        let mut out = RootSnapshot {
            manifests: Vec::new(),
            version: 0,
            clock: 0,
            digest: [0; 32],
            exact: [0; 32],
        };
        let mut hash = Sha256::new();
        while let Some(r) = rows.next()? {
            self.live(until)?;
            let rev = u64::try_from(r.get::<_, i64>(0)?).map_err(|_| Refused)?;
            let clock = u64::try_from(r.get::<_, i64>(1)?).map_err(|_| Refused)?;
            let raw: Vec<u8> = r.get(2)?;
            require(rev == out.version + 1 && rev <= 64 && clock >= out.clock)?;
            let m = verify_manifest(&raw, &root, out.manifests.last(), 2, clock)?;
            require(m.generation == 1 && m.version == rev)?;
            out.version = rev;
            out.clock = clock;
            out.digest = m.digest;
            hash.update(clock.to_be_bytes());
            hash.update(&raw);
            out.manifests.push(m);
        }
        require(out.version > 0)?;
        out.exact = hash.finalize().into();
        Ok(out)
    }
    fn evidence(
        &self,
        m: &Metadata,
        st: Option<&Statement>,
        until: Instant,
    ) -> Result<RootSnapshot> {
        let before = self.root_snapshot(until)?;
        if m.root_version > 0 {
            require(
                before
                    .manifests
                    .iter()
                    .any(|v| v.version == m.root_version && v.digest == m.root_digest),
            )?;
        }
        require(
            before.version >= m.root_version
                && before.clock >= m.root_time
                && (before.version != m.root_version || before.digest == m.root_digest),
        )?;
        let selected = before
            .manifests
            .iter()
            .find(|v| v.version == m.manifest_version && v.digest == m.manifest_digest)
            .ok_or(Refused)?;
        let previous = Manifest {
            raw: selected.raw.clone(),
            profile: selected.profile,
            predecessor: selected.predecessor,
            generation: selected.generation,
            version: selected.version,
            issued: selected.issued,
            expires: selected.expires,
            comparison: 0,
            digest: selected.digest,
            account: selected.account,
            root: selected.root,
            enrolled: selected.enrolled,
            lineage: selected.lineage.clone(),
        };
        let root = enroll_root(&self.pin, &self.fingerprint)?;
        let v = verify_manifest(&selected.raw, &root, Some(&previous), 2, m.comparison)?;
        let reader = key(&v, 2, &m.reader_id).ok_or(Refused)?;
        let writer = key(&v, 6, &m.root_writer_id).ok_or(Refused)?;
        require(
            active(reader, m.comparison, 12)
                && active(writer, m.comparison, 0)
                && reader[130..132] == 12u16.to_be_bytes()
                && writer[130..132] == [0, 0]
                && writer[33..98] == self.pin[29..],
        )?;
        if let Some(st) = st {
            let verified = verify_statement02(
                &st.raw,
                selected,
                &self.pin[5..21],
                &self.origin,
                &self.fingerprint,
            )?;
            require(verified.raw == st.raw)?;
        }
        require(self.root_snapshot(until)?.exact == before.exact)?;
        Ok(before)
    }
    fn token(&self, s: &mut State, raw: &[u8]) -> Arc<LocalToken> {
        let id: [u8; 16] = raw[1..17].try_into().expect("validated row");
        if let Some(t) = s.tokens.get(&id)
            && t.raw == raw
        {
            return t.clone();
        }
        let t = Arc::new(LocalToken {
            owner: self.owner.clone(),
            raw: raw.to_vec(),
        });
        s.tokens.insert(id, t.clone());
        t
    }
    fn expected(&self, s: &State, t: Option<&Arc<LocalToken>>, raw: Option<&Vec<u8>>) -> bool {
        match t {
            None => raw.is_none(),
            Some(t) => {
                if !Arc::ptr_eq(&self.owner, &t.owner) || t.raw.len() < 17 {
                    return false;
                };
                let id: [u8; 16] = t.raw[1..17].try_into().expect("token row");
                s.tokens.get(&id).is_some_and(|v| Arc::ptr_eq(v, t))
                    && raw.is_some_and(|r| *r == t.raw)
            }
        }
    }
    pub fn lookup(&self, id: [u8; 16]) -> Result<Outcome> {
        self.operation(|s, until| {
            require(id != [0; 16])?;
            let tx = s.db.transaction()?;
            let rows = self.read(&tx, until)?;
            tx.commit()?;
            let Some(raw) = rows.get(&id) else {
                s.tokens.remove(&id);
                return Ok(Outcome {
                    reason: "unobserved",
                    ..Outcome::plain("unavailable")
                });
            };
            let m = parse(raw)?;
            let token = Some(self.token(s, raw));
            let reason = if m.is_none() {
                "local_stop"
            } else if self.reduction {
                "reduction_only"
            } else {
                match self.evidence(m.as_ref().ok_or(Refused)?, None, until) {
                    Ok(_) => "",
                    Err(HistoryError::RootMismatch) => "root_mismatch",
                    Err(_) => "history_missing",
                }
            };
            self.live(until)?;
            Ok(Outcome {
                kind: if reason.is_empty() {
                    "accepted_local_history"
                } else {
                    "unavailable"
                },
                reason,
                token,
                metadata: if reason.is_empty() { m } else { None },
            })
        })
    }
    pub fn accept(
        &self,
        expected: Option<&Arc<LocalToken>>,
        transition: &Transition,
        st: &Statement,
    ) -> Result<Outcome> {
        self.operation(|s, until| {
            require(
                !self.reduction
                    && transition.mutation.statement.raw == st.raw
                    && st.account == self.pin[5..21]
                    && st.origin == self.origin
                    && st.root_point == self.pin[29..]
                    && st.fingerprint == self.fingerprint.as_slice(),
            )?;
            let mutation = &transition.mutation;
            let n = &mutation.input;
            let raw = &mutation.raw;
            let at = 40
                + usize::from(u16::from_be_bytes(
                    st.raw[38..40].try_into().map_err(|_| Refused)?,
                ));
            let initial = self.root_snapshot(until)?;
            let mut m = Metadata {
                contact: raw[22..38].try_into().map_err(|_| Refused)?,
                revision: n.revision,
                digest: mutation.digest,
                request: n.request_id,
                routing: raw[182..214].try_into().map_err(|_| Refused)?,
                name: n.name,
                notes: n.notes,
                statement_digest: st.digest,
                manifest_version: st.version,
                manifest_digest: st.manifest_digest,
                reader_id: st.reader_id,
                reader_generation: st.reader_generation,
                root_writer_id: st.root_writer_id,
                comparison: number(&st.raw, at + 185),
                root_version: initial.version,
                root_digest: initial.digest,
                root_time: initial.clock,
            };
            let before = self.evidence(&m, Some(st), until)?;
            // Token ownership is checked before borrowing the database transaction.
            if let Some(t) = expected {
                require(
                    Arc::ptr_eq(&self.owner, &t.owner)
                        && s.tokens.values().any(|v| Arc::ptr_eq(v, t)),
                )?;
            }
            let tx =
                s.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let rows = self.read(&tx, until)?;
            let old = rows.get(&m.contact);
            require(match expected {
                None => old.is_none(),
                Some(t) => old.is_some_and(|r| *r == t.raw),
            })?;
            if let Some(old) = old {
                let p = parse(old)?.ok_or(Refused)?;
                self.evidence(&p, None, until)?;
                if p.revision == m.revision {
                    m.root_version = p.root_version;
                    m.root_digest = p.root_digest;
                    m.root_time = p.root_time;
                    require(encode(&m) == *old)?;
                } else {
                    require(
                        n.operation == 2
                            && p.revision < i64::MAX as u64
                            && m.revision == p.revision + 1
                            && n.previous_digest == p.digest
                            && m.routing == p.routing
                            && (m.manifest_version > p.manifest_version
                                || m.manifest_version == p.manifest_version
                                    && m.manifest_digest == p.manifest_digest)
                            && (m.reader_generation > p.reader_generation
                                || m.reader_generation == p.reader_generation
                                    && m.reader_id == p.reader_id),
                    )?;
                }
            } else {
                require(
                    [1, 3].contains(&n.operation) && m.revision == 1 && rows.len() < self.maximum,
                )?;
            }
            let raw = encode(&m);
            parse(&raw)?;
            self.live(until)?;
            let count = rows.len() + usize::from(old.is_none());
            if tx
                .execute(
                    "INSERT OR REPLACE INTO contacts VALUES(?1,?2)",
                    params![m.contact.as_slice(), &raw],
                )
                .is_err()
                || tx
                    .execute("UPDATE header SET count=?1 WHERE id=1", [count as i64])
                    .is_err()
            {
                return Ok(Outcome::plain("write_unknown"));
            }
            if tx.commit().is_err() || self.live(until).is_err() {
                return Ok(Outcome::plain("write_unknown"));
            }
            let after = self.root_snapshot(until);
            if self.live(until).is_err() {
                return Ok(Outcome::plain("write_unknown"));
            }
            if after.is_err() || after?.exact != before.exact {
                return Ok(Outcome::plain("recorded_needs_recheck"));
            }
            Ok(Outcome {
                kind: "accepted_local_history",
                reason: "",
                token: Some(self.token(s, &raw)),
                metadata: Some(m),
            })
        })
    }
    pub fn mark_unavailable(&self, expected: &Arc<LocalToken>) -> Result<Outcome> {
        self.operation(|s, until| {
            require(expected.raw.len() >= 17)?;
            let id: [u8; 16] = expected.raw[1..17].try_into().map_err(|_| Refused)?;
            require(self.expected(s, Some(expected), Some(&expected.raw)))?;
            let tx =
                s.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let rows = self.read(&tx, until)?;
            require(rows.get(&id).is_some_and(|r| *r == expected.raw))?;
            let raw = [&[0], id.as_slice()].concat();
            self.live(until)?;
            if tx
                .execute(
                    "UPDATE contacts SET payload=?1 WHERE id=?2",
                    params![&raw, id.as_slice()],
                )
                .is_err()
                || tx.commit().is_err()
                || self.live(until).is_err()
            {
                return Ok(Outcome::plain("write_unknown"));
            }
            Ok(Outcome {
                kind: "unavailable",
                reason: "local_stop",
                token: Some(self.token(s, &raw)),
                metadata: None,
            })
        })
    }
}
struct RootSnapshot {
    manifests: Vec<Manifest>,
    version: u64,
    clock: u64,
    digest: [u8; 32],
    exact: [u8; 32],
}
fn encode(m: &Metadata) -> Vec<u8> {
    let mut b = [
        &[1],
        m.contact.as_slice(),
        &m.revision.to_be_bytes(),
        &m.digest,
        &m.request,
        &m.routing,
    ]
    .concat();
    for s in [m.name, m.notes] {
        b.push(s.tag);
        b.extend_from_slice(&s.seal_revision.to_be_bytes());
        b.extend_from_slice(&s.digest)
    }
    b.extend_from_slice(
        &[
            m.statement_digest.as_slice(),
            &m.manifest_version.to_be_bytes(),
            &m.manifest_digest,
            &m.reader_id,
            &m.reader_generation.to_be_bytes(),
            &m.root_writer_id,
            &m.comparison.to_be_bytes(),
            &m.root_version.to_be_bytes(),
            &m.root_digest,
            &m.root_time.to_be_bytes(),
        ]
        .concat(),
    );
    b
}
fn parse(b: &[u8]) -> Result<Option<Metadata>> {
    if b.len() == 17 && b[0] == 0 && b[1..] != [0; 16] {
        return Ok(None);
    }
    require(b.len() == 387 && b[0] == 1)?;
    let array = |at: usize| -> Result<[u8; 32]> { b[at..at + 32].try_into().map_err(|_| Refused) };
    let slot = |at: usize| -> Result<Slot> {
        Ok(Slot {
            tag: b[at],
            seal_revision: number(b, at + 1),
            digest: array(at + 9)?,
        })
    };
    let m = Metadata {
        contact: b[1..17].try_into().map_err(|_| Refused)?,
        revision: number(b, 17),
        digest: array(25)?,
        request: b[57..73].try_into().map_err(|_| Refused)?,
        routing: array(73)?,
        name: slot(105)?,
        notes: slot(146)?,
        statement_digest: array(187)?,
        manifest_version: number(b, 219),
        manifest_digest: array(227)?,
        reader_id: array(259)?,
        reader_generation: number(b, 291),
        root_writer_id: array(299)?,
        comparison: number(b, 331),
        root_version: number(b, 339),
        root_digest: array(347)?,
        root_time: number(b, 379),
    };
    require(
        m.contact != [0; 16]
            && m.request != [0; 16]
            && slot_valid(m.name, m.revision)
            && slot_valid(m.notes, m.revision)
            && m.root_time <= i64::MAX as u64,
    )?;
    require(
        [
            m.revision,
            m.manifest_version,
            m.reader_generation,
            m.comparison,
            m.root_version,
        ]
        .into_iter()
        .all(positive),
    )?;
    require(
        [
            m.digest,
            m.routing,
            m.statement_digest,
            m.manifest_digest,
            m.reader_id,
            m.root_writer_id,
            m.root_digest,
        ]
        .into_iter()
        .all(|v| v != [0; 32]),
    )?;
    Ok(Some(m))
}
