"""Atomic local election evidence; independent authority is required on restore.

This is neither server election acceptance nor hardware antirollback. The
separately enrolled root and authenticated acceptance expectations are external.
"""
import json

from . import election03 as e
from . import sealed_candidate as s
from .checkpoint_store import CheckpointStore


def accepted_bytes(record):
    captured = e._record(record, e._ACCEPTED_UUIDS, e._ACCEPTED_TIMES, e._ACCEPTED_DIGESTS)
    encoded = {key: value.hex() if type(value) is bytes else value for key, value in captured.items()}
    return json.dumps(encoded, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


class ElectionJournal(CheckpointStore):
    """A separate database format; importing an existing checkpoint is refused.

    Bootstrap profile02 history, then atomically append its exact profile03
    election and binding tuple. Subsequent profile03 manifests can be appended
    only with independently authenticated election expectations supplied again.
    Root transitions and a second election are deliberately unsupported.
    """
    def __init__(self, path, root_pin, independently_compared_fingerprint):
        from pathlib import Path
        existed = Path(path).exists()
        super().__init__(path, root_pin, independently_compared_fingerprint)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                if not existed:
                    s.require(self._load(db)[2] == 0, 'journal initialization race')
                    db.execute('CREATE TABLE election (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, accepted BLOB NOT NULL, bundle BLOB NOT NULL)')
                self._entry(db)
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _entry(self, db):
        # Missing/changed schema is corruption, never an implicit trust reset.
        rows = db.execute('SELECT id, revision, accepted, bundle FROM election LIMIT 2').fetchall()
        s.require(len(rows) <= 1 and (not rows or rows[0][0] == 1), 'election singleton')
        return rows[0] if rows else None

    def _verified(self, db, *, expected_core, accepted_record, device_signing_point, owner_approval_point):
        current, _, revision, last_time = self._load(db)
        entry = self._entry(db)
        s.require(entry is not None, 'accepted election missing')
        _, at, stored_record, bundle = entry
        s.require(type(at) is int and 2 <= at <= revision and
                  stored_record == accepted_bytes(accepted_record), 'independent accepted record mismatch')
        # Rebuild the exact predecessor from the independently enrolled root.
        trust, prior = s.enroll_root02(self._pin, self._fingerprint), None
        rows = db.execute('SELECT revision, comparison, signed FROM manifests WHERE revision<=? ORDER BY revision', (at,)).fetchall()
        s.require(len(rows) == at, 'election journal sequence')
        for _, comparison, raw in rows[:-1]:
            s.require(raw[4] == 2, 'election original02 history')
            prior = s.verify_manifest02(raw, trust, comparison)
            trust = s.advance_trust02(trust, prior)
        s.require(prior is not None and rows[-1][1] == accepted_record['acceptedAtMs'], 'election acceptance comparison')
        proof = e.verify_accepted_election03(
            bundle=bundle, expected_core=expected_core, accepted_record=accepted_record,
            predecessor02=prior, prior_signed02=rows[-2][2], accepted_signed03=rows[-1][2],
            device_signing_point=device_signing_point, owner_approval_point=owner_approval_point)
        return revision, current, proof, last_time

    def snapshot(self, comparison_ms):
        raise s.SealedError('use snapshot_election with independent acceptance expectations')

    def accept_manifest(self, raw, expected_revision, comparison_ms, *, election_expectations=None):
        raw = s.capture(raw, 364, 9753)
        expected, now = s.integer(expected_revision), s.integer(comparison_ms)
        if election_expectations is not None:
            s.require(type(election_expectations) is dict and set(election_expectations) ==
                      {'expected_core', 'accepted_record', 'device_signing_point', 'owner_approval_point'}, 'closed election expectations')
            election_expectations = dict(election_expectations)
            election_expectations['expected_core'] = s.capture(election_expectations['expected_core'], 500)
            election_expectations['accepted_record'] = e._record(election_expectations['accepted_record'], e._ACCEPTED_UUIDS, e._ACCEPTED_TIMES, e._ACCEPTED_DIGESTS)
            for name in ('device_signing_point', 'owner_approval_point'):
                election_expectations[name] = s.capture(election_expectations[name], 65)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                current, trust, revision, last_time = self._load(db)
                entry = self._entry(db)
                s.require(revision == expected and revision < 1024 and now >= last_time, 'journal CAS/capacity/clock')
                if entry is None:
                    s.require(raw[4] == 2 and (current is None or s.manifest_identity(current)['profile'] == 2), 'atomic election required')
                    token = s.verify_manifest02(raw, trust, now)
                    if current is not None:
                        s.require(s.manifest_identity(token)['version'] == s.manifest_identity(current)['version'] + 1, 'journal successor')
                else:
                    s.require(type(election_expectations) is dict and raw[4] == 3, 'independent election expectations required')
                    self._verified(db, **election_expectations)
                    token = s.verify_manifest03(raw, current, now)
                db.execute('INSERT INTO manifests VALUES (?, ?, ?)', (revision + 1, now, raw))
                db.commit()
                return revision + 1, token
            except BaseException:
                db.rollback()
                raise

    def accept_election(self, *, expected_revision, signed03, bundle, expected_core,
                        accepted_record, device_signing_point, owner_approval_point):
        expected = s.integer(expected_revision)
        signed03, bundle = s.capture(signed03, 366, 9753), s.capture(bundle, 628)
        expected_core = s.capture(expected_core, 500)
        accepted_record = e._record(accepted_record, e._ACCEPTED_UUIDS, e._ACCEPTED_TIMES, e._ACCEPTED_DIGESTS)
        device_signing_point, owner_approval_point = s.capture(device_signing_point, 65), s.capture(owner_approval_point, 65)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                current, _, revision, last_time = self._load(db)
                s.require(revision == expected and revision < 1024 and self._entry(db) is None, 'election CAS/already accepted')
                s.require(current is not None and s.manifest_identity(current)['profile'] == 2 and
                          accepted_record['acceptedAtMs'] >= last_time, 'election predecessor/clock')
                prior_raw = s._bound(s._manifests, current).raw
                proof = e.verify_accepted_election03(bundle=bundle, expected_core=expected_core, accepted_record=accepted_record,
                    predecessor02=current, prior_signed02=prior_raw, accepted_signed03=signed03,
                    device_signing_point=device_signing_point, owner_approval_point=owner_approval_point)
                token = s.verify_manifest03(signed03, current, accepted_record['acceptedAtMs'])
                db.execute('INSERT INTO manifests VALUES (?, ?, ?)', (revision + 1, accepted_record['acceptedAtMs'], signed03))
                db.execute('INSERT INTO election VALUES (1, ?, ?, ?)', (revision + 1, accepted_bytes(accepted_record), bundle))
                db.commit()
                return revision + 1, token, proof
            except BaseException:
                db.rollback()
                raise

    def snapshot_election(self, comparison_ms, *, expected_core, accepted_record, device_signing_point, owner_approval_point):
        now = s.integer(comparison_ms)
        # Capture all externally authenticated inputs before reading storage.
        expected_core = s.capture(expected_core, 500)
        accepted_record = e._record(accepted_record, e._ACCEPTED_UUIDS, e._ACCEPTED_TIMES, e._ACCEPTED_DIGESTS)
        device_signing_point, owner_approval_point = s.capture(device_signing_point, 65), s.capture(owner_approval_point, 65)
        with self._connection() as db:
            db.execute('BEGIN')
            revision, current, proof, last_time = self._verified(db, expected_core=expected_core, accepted_record=accepted_record,
                device_signing_point=device_signing_point, owner_approval_point=owner_approval_point)
            s.require(now >= last_time, 'journal clock rollback')
            manifest = s._bound(s._manifests, current)
            s.window(manifest.issued, manifest.expires, now)
            db.commit()
            return revision, current, proof
