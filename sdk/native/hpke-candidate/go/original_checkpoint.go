package hpke

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const replyCheckpointApp = 0x5a545248
const replyHistoryCapacity = 64

// OriginalReplyCheckpoint persists accepted cryptographic history, never grant authority.
// Its directory must be private/trusted. A restored old whole database is not detected.
// Create is explicit; Open never enrolls, creates missing state, or resets corrupt state.
type OriginalReplyCheckpoint struct {
	db               *sql.DB
	path             string
	identity         os.FileInfo
	pin, fingerprint []byte
	scope            [32]byte
}
type OriginalReplySnapshot struct {
	Revision, Comparison uint64
	History              []*Manifest
}
type replySaved struct {
	version, comparison uint64
	raw                 []byte
}

func replyScopeHash(s OriginalScope) ([32]byte, error) {
	if !s.valid() {
		return [32]byte{}, ErrJournal
	}
	framed := []byte("ZTSE/native/original-checkpoint-scope/v1\x00")
	for _, p := range [][]byte{s.Account[:], s.Device[:], s.Line[:], s.Interval[:], s.Connector[:], s.ReadGrant[:], s.Reader[:]} {
		framed = append(framed, p...)
	}
	framed = append(framed, byte(len(s.Peer)))
	framed = append(framed, []byte(s.Peer)...)
	return sha256.Sum256(framed), nil
}
func replyCapture(history []*Manifest) ([]replySaved, error) {
	if len(history) < 1 || len(history) > replyHistoryCapacity {
		return nil, ErrJournal
	}
	rows := make([]replySaved, 0, len(history))
	for _, m := range history {
		if m == nil || m.profile != 2 || m.generation != 1 {
			return nil, ErrJournal
		}
		rows = append(rows, replySaved{m.version, m.comparison, append([]byte(nil), m.raw...)})
	}
	return rows, nil
}
func replyVerify(rows []replySaved, pin, fingerprint []byte, now uint64) ([]*Manifest, error) {
	if now == 0 || now > 0x7fffffffffffffff || len(rows) < 1 || len(rows) > replyHistoryCapacity {
		return nil, ErrJournal
	}
	root, e := EnrollRoot(pin, fingerprint)
	if e != nil {
		return nil, e
	}
	history := make([]*Manifest, 0, len(rows))
	var previous *Manifest
	for i, r := range rows {
		if r.version != uint64(i+1) || r.comparison == 0 || r.comparison > now {
			return nil, ErrJournal
		}
		m, e := VerifyManifest(r.raw, root, previous, 2, r.comparison)
		if e != nil {
			return nil, e
		}
		if m.version != r.version || m.generation != 1 {
			return nil, ErrJournal
		}
		history = append(history, m)
		previous = m
	}
	current, e := VerifyManifest(previous.raw, root, previous, 2, now)
	if e != nil {
		return nil, e
	}
	history[len(history)-1] = current
	return history, nil
}

// CreateOriginalReplyCheckpoint captures complete independently accepted genesis history.
func CreateOriginalReplyCheckpoint(path string, pin, fingerprint []byte, scope OriginalScope, history []*Manifest, now uint64) (*OriginalReplyCheckpoint, error) {
	rows, e := replyCapture(history)
	if e != nil {
		return nil, e
	}
	verified, e := replyVerify(rows, pin, fingerprint, now)
	if e != nil {
		return nil, e
	}
	if verified[0].account != scope.Account {
		return nil, ErrJournal
	}
	return openOriginalCheckpoint(path, pin, fingerprint, scope, rows, now, true)
}
func OpenOriginalReplyCheckpoint(path string, pin, fingerprint []byte, scope OriginalScope) (*OriginalReplyCheckpoint, error) {
	return openOriginalCheckpoint(path, pin, fingerprint, scope, nil, 0, false)
}
func openOriginalCheckpoint(path string, pin, fingerprint []byte, scope OriginalScope, rows []replySaved, now uint64, create bool) (*OriginalReplyCheckpoint, error) {
	root, e := EnrollRoot(pin, fingerprint)
	if e != nil {
		return nil, e
	}
	if root.account != scope.Account {
		return nil, ErrJournal
	}
	digest, e := replyScopeHash(scope)
	if e != nil {
		return nil, e
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	if create {
		f, e := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		e = f.Sync()
		e = errors.Join(e, f.Close())
		if e != nil {
			return nil, e
		}
	}
	identity, e := os.Lstat(absolute)
	if e != nil || !identity.Mode().IsRegular() {
		return nil, ErrJournal
	}
	p := filepath.ToSlash(absolute)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	uri := url.URL{Scheme: "file", Path: p}
	q := url.Values{}
	q.Set("mode", "rw")
	q.Set("_txlock", "immediate")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "trusted_schema(OFF)")
	q.Add("_pragma", "synchronous(FULL)")
	uri.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", uri.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	j := &OriginalReplyCheckpoint{db: db, path: absolute, identity: identity, pin: append([]byte(nil), pin...), fingerprint: append([]byte(nil), fingerprint...), scope: digest}
	success := false
	defer func() {
		if !success {
			db.Close()
		}
	}()
	if !create {
		if e = j.check(); e != nil {
			return nil, e
		}
	}
	var mode string
	if e = db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); e != nil || mode != "wal" {
		return nil, ErrJournal
	}
	if _, e = db.Exec("PRAGMA synchronous=FULL"); e != nil {
		return nil, e
	}
	if create {
		tx, e := db.Begin()
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		for _, s := range []string{"PRAGMA application_id=1515475528", "PRAGMA user_version=1", "CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB NOT NULL, fingerprint BLOB NOT NULL, scope BLOB NOT NULL) STRICT", "CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, comparison INTEGER NOT NULL) STRICT", "CREATE TABLE manifests (version INTEGER PRIMARY KEY, comparison INTEGER NOT NULL, signed BLOB NOT NULL) STRICT"} {
			if _, e = tx.Exec(s); e != nil {
				return nil, e
			}
		}
		if _, e = tx.Exec("INSERT INTO identity VALUES (1,?,?,?)", j.pin, j.fingerprint, j.scope[:]); e != nil {
			return nil, e
		}
		if _, e = tx.Exec("INSERT INTO state VALUES (1,1,?)", now); e != nil {
			return nil, e
		}
		for _, r := range rows {
			if _, e = tx.Exec("INSERT INTO manifests VALUES (?,?,?)", r.version, r.comparison, r.raw); e != nil {
				return nil, e
			}
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
	}
	if e = j.check(); e != nil {
		return nil, e
	}
	tx, e := db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, _, e = j.load(tx); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	success = true
	return j, nil
}
func (j *OriginalReplyCheckpoint) Close() error { return j.db.Close() }
func (j *OriginalReplyCheckpoint) check() error {
	info, e := os.Lstat(j.path)
	if e != nil || !info.Mode().IsRegular() || !os.SameFile(info, j.identity) {
		return ErrJournal
	}
	var app, version int
	if e = j.db.QueryRow("PRAGMA application_id").Scan(&app); e != nil || app != replyCheckpointApp {
		return ErrJournal
	}
	if e = j.db.QueryRow("PRAGMA user_version").Scan(&version); e != nil || version != 1 {
		return ErrJournal
	}
	rows, e := j.db.Query("SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 4")
	if e != nil {
		return e
	}
	defer rows.Close()
	expected := []string{"identity", "manifests", "state"}
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
func (j *OriginalReplyCheckpoint) load(tx *sql.Tx) (*OriginalReplySnapshot, []replySaved, error) {
	var count int
	for _, table := range []string{"identity", "state"} {
		if e := tx.QueryRow("SELECT count(*) FROM " + table).Scan(&count); e != nil || count != 1 {
			return nil, nil, ErrJournal
		}
	}
	var pin, fingerprint, scope []byte
	if e := tx.QueryRow("SELECT CASE WHEN length(root)=94 THEN root END,CASE WHEN length(fingerprint)=32 THEN fingerprint END,CASE WHEN length(scope)=32 THEN scope END FROM identity WHERE id=1").Scan(&pin, &fingerprint, &scope); e != nil || !bytes.Equal(pin, j.pin) || !bytes.Equal(fingerprint, j.fingerprint) || !bytes.Equal(scope, j.scope[:]) {
		return nil, nil, ErrJournal
	}
	snap := &OriginalReplySnapshot{}
	if e := tx.QueryRow("SELECT revision,comparison FROM state WHERE id=1").Scan(&snap.Revision, &snap.Comparison); e != nil || snap.Revision == 0 || snap.Revision > 0x7fffffffffffffff || snap.Comparison == 0 || snap.Comparison > 0x7fffffffffffffff {
		return nil, nil, ErrJournal
	}
	values, e := tx.Query("SELECT version,comparison,CASE WHEN length(signed) BETWEEN 364 AND 9751 THEN signed END FROM manifests ORDER BY version LIMIT 65")
	if e != nil {
		return nil, nil, e
	}
	rows := []replySaved{}
	for values.Next() {
		var r replySaved
		if e = values.Scan(&r.version, &r.comparison, &r.raw); e != nil {
			values.Close()
			return nil, nil, e
		}
		rows = append(rows, r)
	}
	e = values.Err()
	values.Close()
	if e != nil {
		return nil, nil, e
	}
	snap.History, e = replyVerify(rows, j.pin, j.fingerprint, snap.Comparison)
	return snap, rows, e
}

// Snapshot re-verifies at now, but does not publish a new durable comparison.
// Accept must commit fresh comparison before a caller exposes plaintext or effects.
func (j *OriginalReplyCheckpoint) Snapshot(scope OriginalScope, now uint64) (*OriginalReplySnapshot, error) {
	h, e := replyScopeHash(scope)
	if e != nil || h != j.scope {
		return nil, ErrJournal
	}
	if e = j.check(); e != nil {
		return nil, e
	}
	tx, e := j.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	s, rows, e := j.load(tx)
	if e != nil {
		return nil, e
	}
	if now < s.Comparison {
		return nil, ErrJournal
	}
	s.History, e = replyVerify(rows, j.pin, j.fingerprint, now)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return s, nil
}

// Accept atomically keeps original signed prefix, appends successors and advances clock/CAS.
// Fence is a trusted adapter recheck under the write lock, not network provenance.
func (j *OriginalReplyCheckpoint) Accept(scope OriginalScope, history []*Manifest, expected, now uint64, fence func(*Manifest, uint64) (uint64, error)) (*OriginalReplySnapshot, error) {
	h, e := replyScopeHash(scope)
	if e != nil || h != j.scope {
		return nil, ErrJournal
	}
	proposed, e := replyCapture(history)
	if e != nil {
		return nil, e
	}
	if e = j.check(); e != nil {
		return nil, e
	}
	tx, e := j.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	saved, old, e := j.load(tx)
	if e != nil {
		return nil, e
	}
	if expected != saved.Revision {
		return nil, ErrJournalConflict
	}
	if saved.Revision == 0x7fffffffffffffff || now < saved.Comparison || len(proposed) < len(old) {
		return nil, ErrJournal
	}
	if _, e = replyVerify(proposed, j.pin, j.fingerprint, now); e != nil {
		return nil, e
	}
	for i, r := range old {
		if !bytes.Equal(r.raw[:len(r.raw)-64], proposed[i].raw[:len(proposed[i].raw)-64]) {
			return nil, ErrJournal
		}
		proposed[i] = r
	}
	tokens, e := replyVerify(proposed, j.pin, j.fingerprint, now)
	if e != nil {
		return nil, e
	}
	if fence != nil {
		checked, e := fence(tokens[len(tokens)-1], now)
		if e != nil {
			return nil, e
		}
		if checked < now {
			return nil, ErrJournal
		}
		now = checked
		tokens, e = replyVerify(proposed, j.pin, j.fingerprint, now)
		if e != nil {
			return nil, e
		}
	}
	for _, r := range proposed[len(old):] {
		if _, e = tx.Exec("INSERT INTO manifests VALUES (?,?,?)", r.version, r.comparison, r.raw); e != nil {
			return nil, e
		}
	}
	if _, e = tx.Exec("UPDATE state SET revision=?,comparison=? WHERE id=1", saved.Revision+1, now); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return &OriginalReplySnapshot{Revision: saved.Revision + 1, Comparison: now, History: tokens}, nil
}
