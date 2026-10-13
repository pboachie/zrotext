//! Atomic host-local signed checkpoints. Never antirollback, live authority or root enrollment.
use crate::{
    Error,
    election::{ElectionEvidence, ElectionProof, ElectionRecord, verify_accepted_election03},
    manifest::{Manifest, enroll_root, verify_manifest, window},
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::Mutex,
};
const APP: i64 = 0x5a544e4a;
const CAPACITY: u64 = 1024;
#[derive(Debug)]
pub enum JournalError {
    Refused,
    Conflict,
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    Crypto(Error),
}
impl From<rusqlite::Error> for JournalError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}
impl From<std::io::Error> for JournalError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<Error> for JournalError {
    fn from(e: Error) -> Self {
        Self::Crypto(e)
    }
}
fn need(v: bool) -> Result<(), JournalError> {
    if v {
        Ok(())
    } else {
        Err(JournalError::Refused)
    }
}
/// These expectations must come from independently authenticated application records each time.
pub struct ElectionExpectations {
    pub core: Vec<u8>,
    pub accepted: ElectionRecord,
    pub device_point: Vec<u8>,
    pub owner_point: Vec<u8>,
}
impl ElectionExpectations {
    fn capture(&self) -> Result<Self, JournalError> {
        need(
            self.core.len() == 500 && self.device_point.len() == 65 && self.owner_point.len() == 65,
        )?;
        Ok(Self {
            core: self.core.clone(),
            accepted: self.accepted.capture(false)?,
            device_point: self.device_point.clone(),
            owner_point: self.owner_point.clone(),
        })
    }
    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for name in [
            "accountId",
            "deviceId",
            "lineId",
            "oldBindingId",
            "newBindingId",
            "rootFingerprint",
            "oldBindingProofDigest",
            "selectedReaderKeyId",
            "priorManifestDigest",
            "priorSignedManifestSha256",
            "acceptedManifestDigest",
            "acceptedSignedManifestSha256",
            "electionCoreSha256",
            "electionCommitment",
            "electionBundleSha256",
        ] {
            out.extend_from_slice(self.accepted.b(name));
        }
        for name in [
            "vaultGeneration",
            "oldBindingGeneration",
            "newBindingGeneration",
            "priorManifestVersion",
            "acceptedManifestVersion",
            "acceptedAtMs",
        ] {
            out.extend_from_slice(&self.accepted.n(name).to_be_bytes());
        }
        out
    }
}
pub struct JournalSnapshot {
    pub revision: u64,
    pub manifest: Option<Manifest>,
    pub proof: Option<ElectionProof>,
}
/// Keep the parent directory private/trusted. Opening requires independent root enrollment.
pub struct Journal {
    connection: Mutex<Connection>,
    path: PathBuf,
    identity: same_file::Handle,
    pin: Vec<u8>,
    fingerprint: Vec<u8>,
}
impl Journal {
    pub fn open(
        path: impl AsRef<Path>,
        pin: &[u8],
        fingerprint: &[u8],
    ) -> Result<Self, JournalError> {
        enroll_root(pin, fingerprint)?;
        let path = std::path::absolute(path)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let created = match options.open(&path) {
            Ok(file) => {
                file.sync_all()?;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(e.into()),
        };
        need(fs::symlink_metadata(&path)?.file_type().is_file())?;
        let identity = same_file::Handle::from_path(&path)?;
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        if created {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch("PRAGMA application_id=1515474506; PRAGMA user_version=1; CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB NOT NULL, fingerprint BLOB NOT NULL) STRICT; CREATE TABLE manifests (revision INTEGER PRIMARY KEY, comparison INTEGER NOT NULL, signed BLOB NOT NULL) STRICT; CREATE TABLE elections (revision INTEGER PRIMARY KEY, bundle BLOB NOT NULL, accepted BLOB NOT NULL, core BLOB NOT NULL, device BLOB NOT NULL, owner BLOB NOT NULL) STRICT;")?;
            tx.execute(
                "INSERT INTO identity VALUES (1,?1,?2)",
                params![pin, fingerprint],
            )?;
            tx.commit()?;
        }
        let result = Self {
            connection: Mutex::new(connection),
            path,
            identity,
            pin: pin.to_vec(),
            fingerprint: fingerprint.to_vec(),
        };
        {
            let c = result
                .connection
                .lock()
                .map_err(|_| JournalError::Refused)?;
            result.check_schema(&c)?;
            result.check_identity(&c)?;
            let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
            need(mode == "wal")?;
            c.pragma_update(None, "synchronous", "FULL")?;
        }
        Ok(result)
    }
    fn check_schema(&self, c: &Connection) -> Result<(), JournalError> {
        need(
            fs::symlink_metadata(&self.path)?.file_type().is_file()
                && same_file::Handle::from_path(&self.path)? == self.identity,
        )?;
        let app: i64 = c.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        need(app == APP && version == 1)?;
        let mut statement=c.prepare("SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 4")?;
        let values = statement
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        need(
            values
                == [
                    ("table".into(), "elections".into()),
                    ("table".into(), "identity".into()),
                    ("table".into(), "manifests".into()),
                ],
        )
    }
    fn check_identity(&self, c: &Connection) -> Result<(), JournalError> {
        let count: i64 = c.query_row("SELECT count(*) FROM identity", [], |r| r.get(0))?;
        need(count == 1)?;
        let (pin,fingerprint):(Vec<u8>,Vec<u8>)=c.query_row("SELECT CASE WHEN length(root)=94 THEN root END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM identity WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        need(pin == self.pin && fingerprint == self.fingerprint)
    }
    fn load(
        &self,
        c: &Connection,
        expected: Option<&ElectionExpectations>,
    ) -> Result<(JournalSnapshot, u64), JournalError> {
        self.check_identity(c)?;
        let root = enroll_root(&self.pin, &self.fingerprint)?;
        let count: i64 = c.query_row("SELECT count(*) FROM elections", [], |r| r.get(0))?;
        need((0..=1).contains(&count))?;
        let captured = if count == 1 {
            Some(expected.ok_or(JournalError::Refused)?.capture()?)
        } else {
            None
        };
        let mut election_revision = 0;
        let mut bundle = Vec::new();
        if let Some(e) = &captured {
            let mut statement=c.prepare("SELECT revision,CASE WHEN length(bundle)=628 THEN bundle END,CASE WHEN length(accepted)=448 THEN accepted END,CASE WHEN length(core)=500 THEN core END,CASE WHEN length(device)=65 THEN device END,CASE WHEN length(owner)=65 THEN owner END FROM elections")?;
            let mut rows = statement.query([])?;
            let r = rows.next()?.ok_or(JournalError::Refused)?;
            election_revision =
                u64::try_from(r.get::<_, i64>(0)?).map_err(|_| JournalError::Refused)?;
            bundle = r.get::<_, Vec<u8>>(1)?;
            need(
                r.get::<_, Vec<u8>>(2)? == e.canonical()
                    && r.get::<_, Vec<u8>>(3)? == e.core
                    && r.get::<_, Vec<u8>>(4)? == e.device_point
                    && r.get::<_, Vec<u8>>(5)? == e.owner_point,
            )?;
        }
        let mut statement=c.prepare("SELECT revision,comparison,CASE WHEN length(signed) BETWEEN 364 AND 9753 THEN signed END FROM manifests ORDER BY revision LIMIT 1025")?;
        let mut rows = statement.query([])?;
        let mut result = JournalSnapshot {
            revision: 0,
            manifest: None,
            proof: None,
        };
        let mut last = 0;
        while let Some(r) = rows.next()? {
            let revision = u64::try_from(r.get::<_, i64>(0)?).map_err(|_| JournalError::Refused)?;
            let now = u64::try_from(r.get::<_, i64>(1)?).map_err(|_| JournalError::Refused)?;
            let raw: Vec<u8> = r.get(2)?;
            need(
                revision == result.revision + 1
                    && revision <= CAPACITY
                    && now >= last
                    && raw.len() >= 364,
            )?;
            let next = verify_manifest(&raw, &root, result.manifest.as_ref(), raw[4], now)?;
            if let Some(prior) = &result.manifest {
                need(next.version == prior.version + 1)?;
            }
            if revision == election_revision {
                let e = captured.as_ref().ok_or(JournalError::Refused)?;
                let prior = result.manifest.as_ref().ok_or(JournalError::Refused)?;
                need(prior.profile == 2 && raw[4] == 3 && now == e.accepted.n("acceptedAtMs"))?;
                result.proof = Some(verify_accepted_election03(ElectionEvidence {
                    bundle: &bundle,
                    expected_core: &e.core,
                    accepted: &e.accepted,
                    predecessor: prior,
                    signed02: &prior.raw,
                    signed03: &raw,
                    device_point: &e.device_point,
                    owner_point: &e.owner_point,
                })?);
            } else if raw[4] == 3 {
                need(result.proof.is_some())?;
            }
            result.revision = revision;
            result.manifest = Some(next);
            last = now;
        }
        need(count == 0 || result.proof.is_some())?;
        Ok((result, last))
    }
    pub fn snapshot(
        &self,
        now: u64,
        expected: Option<&ElectionExpectations>,
    ) -> Result<JournalSnapshot, JournalError> {
        let mut c = self.connection.lock().map_err(|_| JournalError::Refused)?;
        self.check_schema(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (result, last) = self.load(&tx, expected)?;
        need(now > 0 && now <= i64::MAX as u64 && now >= last)?;
        if let Some(m) = &result.manifest {
            need(window(m.issued, m.expires, now))?;
        }
        tx.commit()?;
        Ok(result)
    }
    pub fn append_manifest(
        &self,
        raw: &[u8],
        expected_revision: u64,
        now: u64,
        expected: Option<&ElectionExpectations>,
    ) -> Result<u64, JournalError> {
        need((364..=9753).contains(&raw.len()))?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Refused)?;
        self.check_schema(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (snapshot, last) = self.load(&tx, expected)?;
        if snapshot.revision != expected_revision {
            return Err(JournalError::Conflict);
        };
        need(expected_revision < CAPACITY && now >= last)?;
        if raw[4] == 3 {
            need(snapshot.manifest.as_ref().is_some_and(|m| m.profile == 3))?;
        }
        let root = enroll_root(&self.pin, &self.fingerprint)?;
        let next = verify_manifest(raw, &root, snapshot.manifest.as_ref(), raw[4], now)?;
        if let Some(m) = &snapshot.manifest {
            need(next.version == m.version + 1)?;
        }
        tx.execute(
            "INSERT INTO manifests VALUES (?1,?2,?3)",
            params![(expected_revision + 1) as i64, now as i64, raw],
        )?;
        tx.commit()?;
        Ok(expected_revision + 1)
    }
    pub fn append_election(
        &self,
        signed: &[u8],
        bundle: &[u8],
        expected_revision: u64,
        expected: &ElectionExpectations,
    ) -> Result<u64, JournalError> {
        let e = expected.capture()?;
        need((366..=9753).contains(&signed.len()) && bundle.len() == 628)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Refused)?;
        self.check_schema(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (snapshot, last) = self.load(&tx, Some(&e))?;
        if snapshot.revision != expected_revision {
            return Err(JournalError::Conflict);
        };
        let now = e.accepted.n("acceptedAtMs");
        let prior = snapshot.manifest.as_ref().ok_or(JournalError::Refused)?;
        need(
            expected_revision < CAPACITY
                && now >= last
                && prior.profile == 2
                && snapshot.proof.is_none(),
        )?;
        verify_accepted_election03(ElectionEvidence {
            bundle,
            expected_core: &e.core,
            accepted: &e.accepted,
            predecessor: prior,
            signed02: &prior.raw,
            signed03: signed,
            device_point: &e.device_point,
            owner_point: &e.owner_point,
        })?;
        tx.execute(
            "INSERT INTO manifests VALUES (?1,?2,?3)",
            params![(expected_revision + 1) as i64, now as i64, signed],
        )?;
        tx.execute(
            "INSERT INTO elections VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                (expected_revision + 1) as i64,
                bundle,
                e.canonical(),
                e.core,
                e.device_point,
                e.owner_point
            ],
        )?;
        tx.commit()?;
        Ok(expected_revision + 1)
    }
}
