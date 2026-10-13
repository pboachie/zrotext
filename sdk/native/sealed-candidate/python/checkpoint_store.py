"""Atomic signed manifest checkpoints; host-local durability, not antirollback.

The database contains public signed evidence only. A separately authenticated
root pin is required on every open; database contents never enroll a root.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3

import sealed_candidate as sealed

APP_ID = 0x5a544350
MAX_RECORDS = 1024


class CheckpointStore:
    def __init__(self, path, root_pin, independently_compared_fingerprint):
        self._pin = sealed.capture(root_pin, 94)
        self._fingerprint = sealed.capture(independently_compared_fingerprint, 32)
        sealed.enroll_root02(self._pin, self._fingerprint)
        self.path = Path(path).absolute()
        sealed.require(not self.path.is_symlink(), 'checkpoint symlink refused')
        created = False
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            sealed.require(self.path.is_file() and self.path.stat().st_nlink == 1, 'checkpoint file kind')
        else:
            os.close(fd)
            created = True
        with self._connection(initializing=created) as db:
            if created:
                db.execute('BEGIN IMMEDIATE')
                try:
                    db.execute(f'PRAGMA application_id={APP_ID}')
                    db.execute('CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB NOT NULL, fingerprint BLOB NOT NULL)')
                    db.execute('CREATE TABLE manifests (revision INTEGER PRIMARY KEY, comparison INTEGER NOT NULL, signed BLOB NOT NULL)')
                    db.execute('INSERT INTO identity VALUES (1, ?, ?)', (self._pin, self._fingerprint))
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
            self._load(db)

    @contextmanager
    def _connection(self, initializing=False):
        sealed.require(not self.path.is_symlink() and self.path.is_file() and self.path.stat().st_nlink == 1,
                       'checkpoint path changed')
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 10000)
            db.execute('PRAGMA trusted_schema=OFF')
            if not initializing:
                sealed.require(db.execute('PRAGMA application_id').fetchone()[0] == APP_ID, 'foreign checkpoint database')
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=FULL')
            yield db
        finally:
            db.close()

    def _load(self, db):
        identity = db.execute('SELECT root, fingerprint FROM identity WHERE id=1').fetchone()
        sealed.require(identity == (self._pin, self._fingerprint), 'checkpoint root binding')
        trust = sealed.enroll_root02(self._pin, self._fingerprint)
        current, revision, last_time = None, 0, 0
        rows = db.execute('SELECT revision, comparison, signed FROM manifests ORDER BY revision LIMIT ?', (MAX_RECORDS + 1,)).fetchall()
        sealed.require(len(rows) <= MAX_RECORDS, 'checkpoint history capacity')
        for rev, comparison, raw in rows:
            sealed.require(type(rev) is int and rev == revision + 1 and
                           type(comparison) is int and comparison >= last_time, 'checkpoint sequence/clock')
            raw = sealed.capture(raw, 364, 9753)
            if raw[4] == 2:
                sealed.require(current is None or sealed.manifest_identity(current)['profile'] == 2, 'checkpoint downgrade')
                next_token = sealed.verify_manifest02(raw, trust, comparison)
                if current is not None:
                    sealed.require(sealed.manifest_identity(next_token)['version'] == sealed.manifest_identity(current)['version'] + 1,
                                   'checkpoint successor required')
                trust = sealed.advance_trust02(trust, next_token)
            else:
                sealed.require(current is not None, 'original02 predecessor required')
                next_token = sealed.verify_manifest03(raw, current, comparison)
            current, revision, last_time = next_token, rev, comparison
        return current, trust, revision, last_time

    def snapshot(self, comparison_ms):
        """Reverify signed history from independent pin; no database-minted tokens."""
        now = sealed.integer(comparison_ms)
        with self._connection() as db:
            db.execute('BEGIN')
            current, _, revision, last_time = self._load(db)
            sealed.require(now >= last_time, 'checkpoint clock rollback')
            if current is not None:
                m = sealed._bound(sealed._manifests, current)
                sealed.window(m.issued, m.expires, now)
            db.commit()
            return revision, current

    def accept_manifest(self, raw, expected_revision, comparison_ms):
        """One exact successor, verified and committed under a SQLite write lock."""
        raw = sealed.capture(raw, 364, 9753)
        expected, now = sealed.integer(expected_revision), sealed.integer(comparison_ms)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                current, trust, revision, last_time = self._load(db)
                sealed.require(revision == expected and revision < MAX_RECORDS, 'checkpoint CAS/capacity')
                sealed.require(now >= last_time, 'checkpoint clock rollback')
                if raw[4] == 2:
                    sealed.require(current is None or sealed.manifest_identity(current)['profile'] == 2, 'checkpoint downgrade')
                    accepted = sealed.verify_manifest02(raw, trust, now)
                    if current is not None:
                        sealed.require(sealed.manifest_identity(accepted)['version'] == sealed.manifest_identity(current)['version'] + 1,
                                       'checkpoint successor required')
                else:
                    sealed.require(current is not None, 'original02 predecessor required')
                    accepted = sealed.verify_manifest03(raw, current, now)
                db.execute('INSERT INTO manifests VALUES (?, ?, ?)', (revision + 1, now, raw))
                db.commit()
                return revision + 1, accepted
            except BaseException:
                db.rollback()
                raise
