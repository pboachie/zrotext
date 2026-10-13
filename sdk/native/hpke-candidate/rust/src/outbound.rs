//! Durable exact profile03 outbound retry state, never transport permission.
use crate::{
    compose::{ComposeRequest, authorize, compose, recheck},
    envelope::verify_envelope,
    journal::JournalError,
    manifest::enroll_root,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::Mutex,
};
fn need(v: bool) -> Result<(), JournalError> {
    if v {
        Ok(())
    } else {
        Err(JournalError::Refused)
    }
}
/// Private trusted local directory required. Initialize before concurrent callers.
pub struct OutboundJournal {
    connection: Mutex<Connection>,
    path: PathBuf,
    identity: same_file::Handle,
    pin: Vec<u8>,
    fingerprint: Vec<u8>,
}
impl OutboundJournal {
    pub fn open(
        path: impl AsRef<Path>,
        pin: &[u8],
        fingerprint: &[u8],
    ) -> Result<Self, JournalError> {
        enroll_root(pin, fingerprint)?;
        let path = std::path::absolute(path)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
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
        let mut c = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        c.busy_timeout(std::time::Duration::from_secs(5))?;
        c.pragma_update(None, "trusted_schema", "OFF")?;
        if created {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch("PRAGMA application_id=1515474483; PRAGMA user_version=1; CREATE TABLE identity(id INTEGER PRIMARY KEY CHECK(id=1),root BLOB NOT NULL,fingerprint BLOB NOT NULL,comparison INTEGER NOT NULL) STRICT; CREATE TABLE outbound(identity BLOB PRIMARY KEY,intent BLOB NOT NULL,envelope BLOB NOT NULL) STRICT;")?;
            tx.execute(
                "INSERT INTO identity VALUES(1,?1,?2,0)",
                params![pin, fingerprint],
            )?;
            tx.commit()?;
        }
        let result = Self {
            connection: Mutex::new(c),
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
            result.check(&c)?;
            let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
            need(mode == "wal")?;
            c.pragma_update(None, "synchronous", "FULL")?;
        }
        Ok(result)
    }
    fn check(&self, c: &Connection) -> Result<(), JournalError> {
        need(
            fs::symlink_metadata(&self.path)?.file_type().is_file()
                && same_file::Handle::from_path(&self.path)? == self.identity,
        )?;
        let app: i64 = c.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        need(app == 1515474483 && version == 1)?;
        let mut statement=c.prepare("SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 3")?;
        let names = statement
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        need(
            names
                == [
                    ("table".into(), "identity".into()),
                    ("table".into(), "outbound".into()),
                ],
        )?;
        let count: i64 = c.query_row("SELECT count(*) FROM identity", [], |r| r.get(0))?;
        need(count == 1)?;
        let (pin,fp):(Vec<u8>,Vec<u8>)=c.query_row("SELECT CASE WHEN length(root)=94 THEN root END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM identity WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        need(pin == self.pin && fp == self.fingerprint)
    }
    /// Reauthorize every replay and after commit. An error after commit is ambiguous;
    /// retry only the exact original intent to retrieve already committed ciphertext.
    pub fn compose_or_replay(&self, r: &ComposeRequest<'_>) -> Result<Vec<u8>, JournalError> {
        let mut p = authorize(r)?;
        need(self.pin[5..21] == r.manifest.account && self.pin[29..94] == r.manifest.root)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Refused)?;
        self.check(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM outbound", [], |r| r.get(0))?;
        need((0..=256).contains(&count))?;
        floor(&tx, p.now)?;
        let existing:Option<(Vec<u8>,Vec<u8>)>=tx.query_row("SELECT CASE WHEN length(intent)=32 THEN intent END,CASE WHEN length(envelope) BETWEEN 557 AND 34213 THEN envelope END FROM outbound WHERE identity=?1",[&p.prefix[10..74]],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((intent, envelope)) = existing {
            if intent != p.intent {
                return Err(JournalError::Conflict);
            };
            let verified = verify_envelope(&envelope, &p.public, 3)?;
            need(
                envelope[..verified.prefix] == p.prefix
                    && envelope[verified.body_end] as usize == p.recipients.len(),
            )?;
            for (i, k) in p.recipients.iter().enumerate() {
                need(
                    envelope[verified.body_end + 1 + i * 146..verified.body_end + 34 + i * 146]
                        == k[..33],
                )?;
            }
            recheck(r, &mut p)?;
            tx.execute(
                "UPDATE identity SET comparison=?1 WHERE id=1",
                [p.now as i64],
            )?;
            tx.commit()?;
            finalize(&mut c, r, &mut p)?;
            return Ok(envelope);
        }
        need(count < 256)?;
        let envelope = compose(r, &mut p)?;
        tx.execute(
            "INSERT INTO outbound VALUES(?1,?2,?3)",
            params![&p.prefix[10..74], p.intent, envelope],
        )?;
        tx.execute(
            "UPDATE identity SET comparison=?1 WHERE id=1",
            [p.now as i64],
        )?;
        tx.commit()?;
        finalize(&mut c, r, &mut p)?;
        Ok(envelope)
    }
}

fn floor(c: &Connection, now: u64) -> Result<(), JournalError> {
    let value: i64 = c.query_row("SELECT comparison FROM identity WHERE id=1", [], |r| {
        r.get(0)
    })?;
    need(value >= 0 && now >= value as u64)
}
fn finalize(
    c: &mut Connection,
    r: &ComposeRequest<'_>,
    p: &mut crate::compose::Plan,
) -> Result<(), JournalError> {
    recheck(r, p)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    floor(&tx, p.now)?;
    tx.execute(
        "UPDATE identity SET comparison=?1 WHERE id=1",
        [p.now as i64],
    )?;
    tx.commit()?;
    Ok(())
}
