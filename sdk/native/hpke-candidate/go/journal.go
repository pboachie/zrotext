package hpke

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	_ "modernc.org/sqlite"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var ErrJournal = errors.New("native journal refused")
var ErrJournalConflict = errors.New("native journal revision conflict")

const journalApp = 0x5a544e4a
const journalCapacity = 1024

// ElectionExpectations must be authenticated independently on every restore or append.
type ElectionExpectations struct {
	Core                    []byte
	Accepted                ElectionRecord
	DevicePoint, OwnerPoint []byte
}
type JournalSnapshot struct {
	Revision uint64
	Manifest *Manifest
	Proof    *ElectionProof
}

// Journal is host-local durability, not antirollback or a source of live authority.
// Keep its parent directory private/trusted. Close releases the database connection.
type Journal struct {
	db               *sql.DB
	path             string
	identity         os.FileInfo
	pin, fingerprint []byte
	transitionRoots  map[uint64][65]byte
}

func canonicalAccepted(a ElectionRecord) []byte {
	var out []byte
	for _, names := range [][]string{acceptedUUIDs, acceptedDigests} {
		for _, name := range names {
			out = append(out, a.Bytes[name]...)
		}
	}
	for _, name := range acceptedTimes {
		out = binary.BigEndian.AppendUint64(out, a.Numbers[name])
	}
	return out
}
func captureExpectations(e *ElectionExpectations) (*ElectionExpectations, error) {
	if e == nil {
		return nil, ErrJournal
	}
	a, err := electionRecord(e.Accepted, false)
	if err != nil || len(e.Core) != 500 || len(e.DevicePoint) != 65 || len(e.OwnerPoint) != 65 {
		return nil, ErrJournal
	}
	return &ElectionExpectations{Core: append([]byte(nil), e.Core...), Accepted: a, DevicePoint: append([]byte(nil), e.DevicePoint...), OwnerPoint: append([]byte(nil), e.OwnerPoint...)}, nil
}
func OpenJournal(path string, pin, fingerprint []byte) (*Journal, error) {
	return OpenJournalWithTransitions(path, pin, fingerprint, nil)
}

// OpenJournalWithTransitions requires independently compared new public roots,
// keyed by the journal revision containing the transitioned genesis. All stored
// transitions must match an expectation on every reopen; wire roots are not trust.
func OpenJournalWithTransitions(path string, pin, fingerprint []byte, roots map[uint64][65]byte) (*Journal, error) {
	capturedRoots := map[uint64][65]byte{}
	for rev, point := range roots {
		if rev < 2 || rev > journalCapacity {
			return nil, ErrJournal
		}
		capturedRoots[rev] = point
	}

	if _, err := EnrollRoot(pin, fingerprint); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	created := false
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		created = true
		if err = file.Close(); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	identity, err := os.Lstat(absolute)
	if err != nil || !identity.Mode().IsRegular() {
		return nil, ErrJournal
	}
	uriPath := filepath.ToSlash(absolute)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	query := url.Values{}
	query.Set("mode", "rw")
	query.Set("_txlock", "immediate")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "trusted_schema(OFF)")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	j := &Journal{transitionRoots: capturedRoots, db: db, path: absolute, identity: identity, pin: append([]byte(nil), pin...), fingerprint: append([]byte(nil), fingerprint...)}
	success := false
	defer func() {
		if !success {
			db.Close()
		}
	}()
	if created {
		tx, e := db.Begin()
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		statements := []string{"CREATE TABLE transitions (revision INTEGER PRIMARY KEY, signed BLOB NOT NULL) STRICT", "PRAGMA application_id=1515474506", "PRAGMA user_version=2", "CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB NOT NULL, fingerprint BLOB NOT NULL) STRICT", "CREATE TABLE manifests (revision INTEGER PRIMARY KEY, comparison INTEGER NOT NULL, signed BLOB NOT NULL) STRICT", "CREATE TABLE elections (revision INTEGER PRIMARY KEY, bundle BLOB NOT NULL, accepted BLOB NOT NULL, core BLOB NOT NULL, device BLOB NOT NULL, owner BLOB NOT NULL) STRICT"}
		for _, statement := range statements {
			if _, e = tx.Exec(statement); e != nil {
				return nil, e
			}
		}
		if _, e = tx.Exec("INSERT INTO identity VALUES (1,?,?)", j.pin, j.fingerprint); e != nil {
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
	}
	if err = j.checkSchema(); err != nil {
		return nil, err
	}
	var rootBytes, fingerprintBytes []byte
	var identityCount int
	if err = db.QueryRow("SELECT count(*) FROM identity").Scan(&identityCount); err != nil || identityCount != 1 {
		return nil, ErrJournal
	}
	if err = db.QueryRow("SELECT CASE WHEN length(root)=94 THEN root END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM identity WHERE id=1").Scan(&rootBytes, &fingerprintBytes); err != nil || !bytes.Equal(rootBytes, j.pin) || !bytes.Equal(fingerprintBytes, j.fingerprint) {
		return nil, ErrJournal
	}
	var mode string
	if err = db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		return nil, ErrJournal
	}
	if _, err = db.Exec("PRAGMA synchronous=FULL"); err != nil {
		return nil, err
	}
	success = true
	return j, nil
}
func (j *Journal) Close() error { return j.db.Close() }
func (j *Journal) checkPath() error {
	info, e := os.Lstat(j.path)
	if e != nil || !info.Mode().IsRegular() || !os.SameFile(info, j.identity) {
		return ErrJournal
	}
	return nil
}
func (j *Journal) checkSchema() error {
	if e := j.checkPath(); e != nil {
		return e
	}
	var app, version int
	if e := j.db.QueryRow("PRAGMA application_id").Scan(&app); e != nil || app != journalApp {
		return ErrJournal
	}
	if e := j.db.QueryRow("PRAGMA user_version").Scan(&version); e != nil || version != 2 {
		return ErrJournal
	}
	rows, e := j.db.Query("SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 5")
	if e != nil {
		return e
	}
	defer rows.Close()
	expected := []string{"elections", "identity", "manifests", "transitions"}
	i := 0
	for rows.Next() {
		var kind, name string
		if e = rows.Scan(&kind, &name); e != nil || i >= len(expected) || kind != "table" || name != expected[i] {
			return ErrJournal
		}
		i++
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if i != len(expected) {
		return ErrJournal
	}
	return nil
}
func (j *Journal) load(tx *sql.Tx, expect *ElectionExpectations) (*JournalSnapshot, uint64, error) {
	var pin, fingerprint []byte
	var identities int
	if e := tx.QueryRow("SELECT count(*) FROM identity").Scan(&identities); e != nil || identities != 1 {
		return nil, 0, ErrJournal
	}
	if e := tx.QueryRow("SELECT CASE WHEN length(root)=94 THEN root END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM identity WHERE id=1").Scan(&pin, &fingerprint); e != nil || !bytes.Equal(pin, j.pin) || !bytes.Equal(fingerprint, j.fingerprint) {
		return nil, 0, ErrJournal
	}
	root, e := EnrollRoot(j.pin, j.fingerprint)
	if e != nil {
		return nil, 0, e
	}
	transitionRows, e := tx.Query("SELECT revision,CASE WHEN length(signed)=343 THEN signed END FROM transitions ORDER BY revision LIMIT 1025")
	if e != nil {
		return nil, 0, e
	}
	transitions := map[uint64][]byte{}
	for transitionRows.Next() {
		var rev uint64
		var raw []byte
		if e = transitionRows.Scan(&rev, &raw); e != nil {
			transitionRows.Close()
			return nil, 0, e
		}
		if rev < 2 || rev > journalCapacity || len(raw) != 343 {
			transitionRows.Close()
			return nil, 0, ErrJournal
		}
		if _, ok := j.transitionRoots[rev]; !ok {
			transitionRows.Close()
			return nil, 0, ErrJournal
		}
		transitions[rev] = raw
	}
	e = transitionRows.Err()
	transitionRows.Close()
	if e != nil {
		return nil, 0, e
	}
	var electionCount int
	if e = tx.QueryRow("SELECT count(*) FROM elections").Scan(&electionCount); e != nil || electionCount > 1 {
		return nil, 0, ErrJournal
	}
	var electionRevision uint64
	var bundle, accepted, core, device, owner []byte
	var captured *ElectionExpectations
	if electionCount == 1 {
		captured, e = captureExpectations(expect)
		if e != nil {
			return nil, 0, e
		}
		e = tx.QueryRow("SELECT revision,CASE WHEN length(bundle)=628 THEN bundle END,CASE WHEN length(accepted)=448 THEN accepted END,CASE WHEN length(core)=500 THEN core END,CASE WHEN length(device)=65 THEN device END,CASE WHEN length(owner)=65 THEN owner END FROM elections").Scan(&electionRevision, &bundle, &accepted, &core, &device, &owner)
		if e != nil || !bytes.Equal(accepted, canonicalAccepted(captured.Accepted)) || !bytes.Equal(core, captured.Core) || !bytes.Equal(device, captured.DevicePoint) || !bytes.Equal(owner, captured.OwnerPoint) {
			return nil, 0, ErrJournal
		}
	}
	rows, e := tx.Query("SELECT revision,comparison,CASE WHEN length(signed) BETWEEN 364 AND 9753 THEN signed END FROM manifests ORDER BY revision LIMIT 1025")
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	snapshot := &JournalSnapshot{}
	var last uint64
	for rows.Next() {
		var rev, now uint64
		var raw []byte
		if e = rows.Scan(&rev, &now, &raw); e != nil {
			return nil, 0, e
		}
		if rev != snapshot.Revision+1 || rev > journalCapacity || now < last || len(raw) < 364 {
			return nil, 0, ErrJournal
		}
		previous := snapshot.Manifest
		transition, rotated := transitions[rev]
		if rotated {
			compared := j.transitionRoots[rev]
			if electionCount != 0 || raw[4] != 2 {
				return nil, 0, ErrJournal
			}
			root, e = VerifyRootTransition02(transition, previous, compared[:], now)
			if e != nil {
				return nil, 0, e
			}
			previous = nil
			delete(transitions, rev)
		}
		next, e := VerifyManifest(raw, root, previous, raw[4], now)
		if e != nil {
			return nil, 0, e
		}
		if previous != nil && next.version != previous.version+1 {
			return nil, 0, ErrJournal
		}
		if rev == electionRevision {
			if previous == nil || captured == nil || previous.profile != 2 || raw[4] != 3 || now != captured.Accepted.Numbers["acceptedAtMs"] {
				return nil, 0, ErrJournal
			}
			snapshot.Proof, e = VerifyAcceptedElection03(bundle, core, captured.Accepted, previous, previous.raw, raw, device, owner)
			if e != nil {
				return nil, 0, e
			}
		} else if raw[4] == 3 && snapshot.Proof == nil {
			return nil, 0, ErrJournal
		}
		snapshot.Revision = rev
		snapshot.Manifest = next
		last = now
	}
	if e = rows.Err(); e != nil {
		return nil, 0, e
	}
	if len(transitions) != 0 {
		return nil, 0, ErrJournal
	}
	if electionCount == 1 && snapshot.Proof == nil {
		return nil, 0, ErrJournal
	}
	return snapshot, last, nil
}
func (j *Journal) Snapshot(now uint64, expect *ElectionExpectations) (*JournalSnapshot, error) {
	if e := j.checkSchema(); e != nil {
		return nil, e
	}
	tx, e := j.db.BeginTx(context.Background(), nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	snapshot, last, e := j.load(tx, expect)
	if e != nil {
		return nil, e
	}
	if now == 0 || now > 0x7fffffffffffffff || now < last || snapshot.Manifest != nil && !manifestWindow(snapshot.Manifest.issued, snapshot.Manifest.expires, now) {
		return nil, ErrJournal
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return snapshot, nil
}
func (j *Journal) AppendManifest(raw []byte, expected, now uint64, expect *ElectionExpectations) (uint64, error) {
	if len(raw) < 364 || len(raw) > 9753 {
		return 0, ErrShape
	}
	raw = append([]byte(nil), raw...)
	if e := j.checkSchema(); e != nil {
		return 0, e
	}
	tx, e := j.db.BeginTx(context.Background(), nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	snapshot, last, e := j.load(tx, expect)
	if e != nil {
		return 0, e
	}
	if snapshot.Revision != expected {
		return 0, ErrJournalConflict
	}
	if expected >= journalCapacity || now < last {
		return 0, ErrJournal
	}
	if raw[4] == 3 && (snapshot.Manifest == nil || snapshot.Manifest.profile == 2) {
		return 0, ErrJournal
	}
	root, e := EnrollRoot(j.pin, j.fingerprint)
	if e != nil {
		return 0, e
	}
	if snapshot.Manifest != nil {
		root = snapshot.Manifest.rootTrust()
	}
	next, e := VerifyManifest(raw, root, snapshot.Manifest, raw[4], now)
	if e != nil {
		return 0, e
	}
	if snapshot.Manifest != nil && next.version != snapshot.Manifest.version+1 {
		return 0, ErrJournal
	}
	if _, e = tx.Exec("INSERT INTO manifests VALUES (?,?,?)", expected+1, now, raw); e != nil {
		return 0, e
	}
	if e = tx.Commit(); e != nil {
		return 0, e
	}
	return expected + 1, nil
}
func (j *Journal) AppendElection(signed, bundle []byte, expected uint64, expect *ElectionExpectations) (uint64, error) {
	captured, e := captureExpectations(expect)
	if e != nil {
		return 0, e
	}
	if len(signed) < 366 || len(signed) > 9753 || len(bundle) != 628 {
		return 0, ErrShape
	}
	signed = append([]byte(nil), signed...)
	bundle = append([]byte(nil), bundle...)
	if e = j.checkSchema(); e != nil {
		return 0, e
	}
	tx, e := j.db.BeginTx(context.Background(), nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	snapshot, last, e := j.load(tx, captured)
	if e != nil {
		return 0, e
	}
	if snapshot.Revision != expected {
		return 0, ErrJournalConflict
	}
	now := captured.Accepted.Numbers["acceptedAtMs"]
	if expected >= journalCapacity || now < last || snapshot.Manifest == nil || snapshot.Manifest.profile != 2 || snapshot.Proof != nil {
		return 0, ErrJournal
	}
	if _, e = VerifyAcceptedElection03(bundle, captured.Core, captured.Accepted, snapshot.Manifest, snapshot.Manifest.raw, signed, captured.DevicePoint, captured.OwnerPoint); e != nil {
		return 0, e
	}
	if _, e = tx.Exec("INSERT INTO manifests VALUES (?,?,?)", expected+1, now, signed); e != nil {
		return 0, e
	}
	if _, e = tx.Exec("INSERT INTO elections VALUES (?,?,?,?,?,?)", expected+1, bundle, canonicalAccepted(captured.Accepted), captured.Core, captured.DevicePoint, captured.OwnerPoint); e != nil {
		return 0, e
	}
	if e = tx.Commit(); e != nil {
		return 0, e
	}
	return expected + 1, nil
}

// AppendTransition02 commits the dual-signed transition and its exact new genesis
// in one immediate CAS transaction. Old signed history remains in the journal.
func (j *Journal) AppendTransition02(transition, genesis []byte, expected, now uint64) (uint64, error) {
	if len(transition) != 343 || len(genesis) < 364 || len(genesis) > 9751 || genesis[4] != 2 {
		return 0, ErrShape
	}
	transition = append([]byte(nil), transition...)
	genesis = append([]byte(nil), genesis...)
	compared, ok := j.transitionRoots[expected+1]
	if !ok {
		return 0, ErrJournal
	}
	if e := j.checkSchema(); e != nil {
		return 0, e
	}
	tx, e := j.db.BeginTx(context.Background(), nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	snapshot, last, e := j.load(tx, nil)
	if e != nil {
		return 0, e
	}
	if snapshot.Revision != expected {
		return 0, ErrJournalConflict
	}
	if expected >= journalCapacity || now < last || snapshot.Manifest == nil || snapshot.Proof != nil {
		return 0, ErrJournal
	}
	root, e := VerifyRootTransition02(transition, snapshot.Manifest, compared[:], now)
	if e != nil {
		return 0, e
	}
	if _, e = VerifyManifest(genesis, root, nil, 2, now); e != nil {
		return 0, e
	}
	if _, e = tx.Exec("INSERT INTO manifests VALUES (?,?,?)", expected+1, now, genesis); e != nil {
		return 0, e
	}
	if _, e = tx.Exec("INSERT INTO transitions VALUES (?,?)", expected+1, transition); e != nil {
		return 0, e
	}
	if e = tx.Commit(); e != nil {
		return 0, e
	}
	return expected + 1, nil
}
