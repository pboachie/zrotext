//! Scope-bound accepted reply history and local clock CAS, never live grant authority.
use crate::{
    journal::JournalError,
    manifest::{Manifest, RootTrust, enroll_root, verify_manifest},
    original_reply::{OriginalScope, valid_scope},
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::Mutex,
};
const APP: i64 = 0x5a545248;
const CAPACITY: usize = 64;
type Result<T> = std::result::Result<T, JournalError>;
struct Saved {
    version: u64,
    comparison: u64,
    raw: Vec<u8>,
}
pub struct OriginalReplySnapshot {
    pub revision: u64,
    pub comparison: u64,
    pub history: Vec<Manifest>,
}
/// Keep the directory private/trusted. Whole-database hostile rollback is not detected.
pub struct OriginalReplyCheckpoint {
    connection: Mutex<Connection>,
    path: PathBuf,
    identity: same_file::Handle,
    pin: Vec<u8>,
    fingerprint: Vec<u8>,
    scope: [u8; 32],
}
fn need(v: bool) -> Result<()> {
    if v {
        Ok(())
    } else {
        Err(JournalError::Refused)
    }
}
pub(crate) fn scope_hash(s: &OriginalScope) -> Result<[u8; 32]> {
    need(valid_scope(s))?;
    let mut b = b"ZTSE/native/original-checkpoint-scope/v1\0".to_vec();
    for p in [
        &s.account[..],
        &s.device[..],
        &s.line[..],
        &s.interval[..],
        &s.connector[..],
        &s.read_grant[..],
        &s.reader[..],
    ] {
        b.extend_from_slice(p)
    }
    b.push(s.peer.len() as u8);
    b.extend_from_slice(s.peer.as_bytes());
    Ok(Sha256::digest(b).into())
}
fn capture(history: &[&Manifest]) -> Result<Vec<Saved>> {
    need((1..=CAPACITY).contains(&history.len()))?;
    history
        .iter()
        .map(|m| {
            need(m.profile == 2 && m.generation == 1)?;
            Ok(Saved {
                version: m.version,
                comparison: m.comparison,
                raw: m.raw.clone(),
            })
        })
        .collect()
}
// Server acceptance times are independent from the local durable clock floor.
// Keep all signed/root/lineage checks; only the private profile02/gen1 history
// replay adapter does not import a preceding server time as a local clock.
pub(crate) fn accepted_manifest_at(
    raw: &[u8],
    root: &RootTrust,
    previous: Option<&Manifest>,
    at: u64,
) -> Result<Manifest> {
    let copied = previous.map(|p| Manifest {
        raw: p.raw.clone(),
        profile: p.profile,
        predecessor: p.predecessor,
        generation: p.generation,
        version: p.version,
        issued: p.issued,
        expires: p.expires,
        comparison: 0,
        digest: p.digest,
        account: p.account,
        root: p.root,
        enrolled: p.enrolled,
        lineage: p.lineage.clone(),
    });
    if let Some(p) = previous {
        need(p.profile == 2 && p.generation == 1)?;
    }
    let result = verify_manifest(raw, root, copied.as_ref(), 2, at)?;
    need(result.generation == 1)?;
    Ok(result)
}
fn verify(rows: &[Saved], pin: &[u8], fingerprint: &[u8], now: u64) -> Result<Vec<Manifest>> {
    need(now > 0 && now <= i64::MAX as u64 && (1..=CAPACITY).contains(&rows.len()))?;
    let root = enroll_root(pin, fingerprint)?;
    let mut history = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        // Server acceptance time is distinct from the durable local clock.
        need(r.version == i as u64 + 1 && r.comparison > 0 && r.comparison <= now + 30000)?;
        let m = accepted_manifest_at(&r.raw, &root, history.last(), r.comparison)?;
        need(m.version == r.version && m.generation == 1)?;
        history.push(m);
    }
    let previous = history.last().ok_or(JournalError::Refused)?;
    let current = accepted_manifest_at(&previous.raw, &root, Some(previous), now)?;
    *history.last_mut().ok_or(JournalError::Refused)? = current;
    Ok(history)
}
impl OriginalReplyCheckpoint {
    /// Explicitly initialize a new file from complete independently accepted genesis history.
    pub fn create(
        path: impl AsRef<Path>,
        pin: &[u8],
        fingerprint: &[u8],
        scope: &OriginalScope,
        history: &[&Manifest],
        now: u64,
    ) -> Result<Self> {
        let rows = capture(history)?;
        let tokens = verify(&rows, pin, fingerprint, now)?;
        need(tokens[0].account == scope.account)?;
        Self::connect(path, pin, fingerprint, scope, Some((&rows, now)))
    }
    /// Reopen existing state; missing/corrupt state never implicitly initializes trust.
    pub fn open(
        path: impl AsRef<Path>,
        pin: &[u8],
        fingerprint: &[u8],
        scope: &OriginalScope,
    ) -> Result<Self> {
        Self::connect(path, pin, fingerprint, scope, None)
    }
    fn connect(
        path: impl AsRef<Path>,
        pin: &[u8],
        fingerprint: &[u8],
        scope: &OriginalScope,
        initial: Option<(&[Saved], u64)>,
    ) -> Result<Self> {
        enroll_root(pin, fingerprint)?;
        need(pin[5..21] == scope.account)?;
        let digest = scope_hash(scope)?;
        let path = std::path::absolute(path)?;
        if initial.is_some() {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&path)?.sync_all()?;
        }
        need(fs::symlink_metadata(&path)?.file_type().is_file())?;
        let identity = same_file::Handle::from_path(&path)?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        let result = Self {
            connection: Mutex::new(connection),
            path,
            identity,
            pin: pin.to_vec(),
            fingerprint: fingerprint.to_vec(),
            scope: digest,
        };
        {
            let mut c = result
                .connection
                .lock()
                .map_err(|_| JournalError::Refused)?;
            if initial.is_none() {
                result.check(&c)?;
            }
            let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
            need(mode == "wal")?;
            c.pragma_update(None, "synchronous", "FULL")?;
            if let Some((rows, now)) = initial {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute_batch("PRAGMA application_id=1515475528; PRAGMA user_version=1; CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB NOT NULL, fingerprint BLOB NOT NULL, scope BLOB NOT NULL) STRICT; CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, comparison INTEGER NOT NULL) STRICT; CREATE TABLE manifests (version INTEGER PRIMARY KEY, comparison INTEGER NOT NULL, signed BLOB NOT NULL) STRICT;")?;
                tx.execute(
                    "INSERT INTO identity VALUES (1,?1,?2,?3)",
                    params![pin, fingerprint, digest],
                )?;
                tx.execute("INSERT INTO state VALUES (1,1,?1)", params![now as i64])?;
                for r in rows {
                    tx.execute(
                        "INSERT INTO manifests VALUES (?1,?2,?3)",
                        params![r.version as i64, r.comparison as i64, r.raw],
                    )?;
                }
                tx.commit()?;
            }
            result.check(&c)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            result.load(&tx)?;
            tx.commit()?;
        }
        Ok(result)
    }
    fn check(&self, c: &Connection) -> Result<()> {
        need(
            fs::symlink_metadata(&self.path)?.file_type().is_file()
                && same_file::Handle::from_path(&self.path)? == self.identity,
        )?;
        let app: i64 = c.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        need(app == APP && version == 1)?;
        let mut q=c.prepare("SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 4")?;
        let values = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        need(
            values
                == [
                    ("table".into(), "identity".into()),
                    ("table".into(), "manifests".into()),
                    ("table".into(), "state".into()),
                ],
        )
    }
    fn load(&self, c: &Connection) -> Result<(OriginalReplySnapshot, Vec<Saved>)> {
        for table in ["identity", "state"] {
            let count: i64 =
                c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
            need(count == 1)?;
        }
        let (pin,fingerprint,scope):(Vec<u8>,Vec<u8>,Vec<u8>)=c.query_row("SELECT CASE WHEN length(root)=94 THEN root END,CASE WHEN length(fingerprint)=32 THEN fingerprint END,CASE WHEN length(scope)=32 THEN scope END FROM identity WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        need(pin == self.pin && fingerprint == self.fingerprint && scope == self.scope)?;
        let (revision, comparison): (u64, u64) = c.query_row(
            "SELECT revision,comparison FROM state WHERE id=1",
            [],
            |r| Ok((positive(r, 0)?, positive(r, 1)?)),
        )?;
        need(
            revision > 0
                && revision <= i64::MAX as u64
                && comparison > 0
                && comparison <= i64::MAX as u64,
        )?;
        let mut q=c.prepare("SELECT version,comparison,CASE WHEN length(signed) BETWEEN 364 AND 9751 THEN signed END FROM manifests ORDER BY version LIMIT 65")?;
        let rows = q
            .query_map([], |r| {
                Ok(Saved {
                    version: positive(r, 0)?,
                    comparison: positive(r, 1)?,
                    raw: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let history = verify(&rows, &self.pin, &self.fingerprint, comparison)?;
        Ok((
            OriginalReplySnapshot {
                revision,
                comparison,
                history,
            },
            rows,
        ))
    }
    /// Read/reverify at now. Call accept to durably fence fresh time before exposing output.
    pub fn snapshot(&self, scope: &OriginalScope, now: u64) -> Result<OriginalReplySnapshot> {
        need(scope_hash(scope)? == self.scope)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Refused)?;
        self.check(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut s, rows) = self.load(&tx)?;
        need(now >= s.comparison)?;
        s.history = verify(&rows, &self.pin, &self.fingerprint, now)?;
        tx.commit()?;
        Ok(s)
    }
    /// Atomically retain original signed prefix, append successors and advance comparison/CAS.
    /// The fence is a trusted adapter recheck under the write lock, not HTTP provenance.
    pub fn accept<F>(
        &self,
        scope: &OriginalScope,
        history: &[&Manifest],
        expected: u64,
        mut now: u64,
        fence: F,
    ) -> Result<OriginalReplySnapshot>
    where
        F: FnOnce(&Manifest, u64) -> Result<u64>,
    {
        need(scope_hash(scope)? == self.scope)?;
        let mut proposed = capture(history)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Refused)?;
        self.check(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (saved, old) = self.load(&tx)?;
        if expected != saved.revision {
            return Err(JournalError::Conflict);
        }
        need(
            saved.revision < i64::MAX as u64
                && now >= saved.comparison
                && proposed.len() >= old.len(),
        )?;
        verify(&proposed, &self.pin, &self.fingerprint, now)?;
        let old_len = old.len();
        for (i, r) in old.into_iter().enumerate() {
            need(r.raw[..r.raw.len() - 64] == proposed[i].raw[..proposed[i].raw.len() - 64])?;
            proposed[i] = r;
        }
        let tokens = verify(&proposed, &self.pin, &self.fingerprint, now)?;
        let checked = fence(tokens.last().ok_or(JournalError::Refused)?, now)?;
        need(checked >= now)?;
        now = checked;
        let history = verify(&proposed, &self.pin, &self.fingerprint, now)?;
        for r in &proposed[old_len..] {
            tx.execute(
                "INSERT INTO manifests VALUES (?1,?2,?3)",
                params![r.version as i64, r.comparison as i64, r.raw],
            )?;
        }
        tx.execute(
            "UPDATE state SET revision=?1,comparison=?2 WHERE id=1",
            params![(saved.revision + 1) as i64, now as i64],
        )?;
        tx.commit()?;
        Ok(OriginalReplySnapshot {
            revision: saved.revision + 1,
            comparison: now,
            history,
        })
    }
}

fn positive(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    if value > 0 {
        Ok(value as u64)
    } else {
        Err(rusqlite::Error::IntegralValueOutOfRange(index, value))
    }
}
