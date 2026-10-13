//go:build windows

package hpke

import (
	"bytes"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// OutboundJournal holds exact ciphertext for retries, never a dispatch grant.
// Keep its parent directory private; initialize it before concurrent callers.
type OutboundJournal struct {
	db               *sql.DB
	path             string
	identity         os.FileInfo
	pin, fingerprint []byte
}

func OpenOutboundJournal(path string, pin, fingerprint []byte) (*OutboundJournal, error) {
	if _, e := EnrollRoot(pin, fingerprint); e != nil {
		return nil, e
	}
	path, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	created := false
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e == nil {
		created = true
		e = f.Close()
		if e != nil {
			return nil, e
		}
	} else if !errors.Is(e, os.ErrExist) {
		return nil, e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() {
		return nil, ErrJournal
	}
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	q.Set("mode", "rw")
	q.Set("_txlock", "immediate")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "trusted_schema(OFF)")
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	j := &OutboundJournal{db, path, info, append([]byte(nil), pin...), append([]byte(nil), fingerprint...)}
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	if created {
		tx, e := db.Begin()
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		for _, query := range []string{"PRAGMA application_id=1515474483", "PRAGMA user_version=1", "CREATE TABLE identity(id INTEGER PRIMARY KEY CHECK(id=1),root BLOB NOT NULL,fingerprint BLOB NOT NULL,comparison INTEGER NOT NULL) STRICT", "CREATE TABLE outbound(identity BLOB PRIMARY KEY,intent BLOB NOT NULL,envelope BLOB NOT NULL) STRICT"} {
			if _, e = tx.Exec(query); e != nil {
				return nil, e
			}
		}
		if _, e = tx.Exec("INSERT INTO identity VALUES(1,?,?,0)", j.pin, j.fingerprint); e != nil {
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
	}
	if e = j.check(); e != nil {
		return nil, e
	}
	var mode string
	if e = db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); e != nil || mode != "wal" {
		return nil, ErrJournal
	}
	if _, e = db.Exec("PRAGMA synchronous=FULL"); e != nil {
		return nil, e
	}
	ok = true
	return j, nil
}
func (j *OutboundJournal) Close() error { return j.db.Close() }
func (j *OutboundJournal) check() error {
	info, e := os.Lstat(j.path)
	if e != nil || !info.Mode().IsRegular() || !os.SameFile(info, j.identity) {
		return ErrJournal
	}
	var app, version, count int
	if e = j.db.QueryRow("PRAGMA application_id").Scan(&app); e != nil || app != 1515474483 {
		return ErrJournal
	}
	if e = j.db.QueryRow("PRAGMA user_version").Scan(&version); e != nil || version != 1 {
		return ErrJournal
	}
	rows, e := j.db.Query("SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 3")
	if e != nil {
		return e
	}
	names := []string{"identity", "outbound"}
	i := 0
	for rows.Next() {
		var kind, name string
		if e = rows.Scan(&kind, &name); e != nil || i >= 2 || kind != "table" || name != names[i] {
			rows.Close()
			return ErrJournal
		}
		i++
	}
	e = rows.Err()
	rows.Close()
	if e != nil || i != 2 {
		return ErrJournal
	}
	if e = j.db.QueryRow("SELECT count(*) FROM identity").Scan(&count); e != nil || count != 1 {
		return ErrJournal
	}
	var pin, fp []byte
	if e = j.db.QueryRow("SELECT CASE WHEN length(root)=94 THEN root END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM identity WHERE id=1").Scan(&pin, &fp); e != nil || !bytes.Equal(pin, j.pin) || !bytes.Equal(fp, j.fingerprint) {
		return ErrJournal
	}
	return nil
}

// ComposeOrReplay reauthorizes before/after the durable commit and every replay.
// A returned error after commit is ambiguous: retry only the same immutable intent.
func (j *OutboundJournal) ComposeOrReplay(request ComposeRequest) ([]byte, error) {
	r := captureCompose(request)
	p, e := authorizeCompose(r)
	if e != nil {
		return nil, e
	}
	defer clear(p.text)
	root, e := EnrollRoot(j.pin, j.fingerprint)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(root.account[:], r.Manifest.account[:]) || !bytes.Equal(root.point[:], r.Manifest.root[:]) {
		return nil, ErrAuthentication
	}
	if e = j.check(); e != nil {
		return nil, e
	}
	tx, e := j.db.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var count int
	if e = tx.QueryRow("SELECT count(*) FROM outbound").Scan(&count); e != nil || count > 256 {
		return nil, ErrJournal
	}
	if e = outboundFloor(tx, p.now); e != nil {
		return nil, e
	}
	identity := p.prefix[10:74]
	var intent, envelope []byte
	e = tx.QueryRow("SELECT CASE WHEN length(intent)=32 THEN intent END,CASE WHEN length(envelope) BETWEEN 557 AND 34213 THEN envelope END FROM outbound WHERE identity=?", identity).Scan(&intent, &envelope)
	if e == nil {
		if !bytes.Equal(intent, p.intent) {
			return nil, ErrJournalConflict
		}
		verified, e := VerifyEnvelope(envelope, p.public, 3)
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(envelope[:verified.prefix], p.prefix) || int(envelope[verified.bodyEnd]) != len(p.recipients) {
			return nil, ErrAuthentication
		}
		for i, k := range p.recipients {
			if !bytes.Equal(envelope[verified.bodyEnd+1+i*146:verified.bodyEnd+34+i*146], k[:33]) {
				return nil, ErrAuthentication
			}
		}
		if e = recheckCompose(r, p); e != nil {
			return nil, e
		}
		if _, e = tx.Exec("UPDATE identity SET comparison=? WHERE id=1", p.now); e != nil {
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
		if e = j.finalize(r, p); e != nil {
			return nil, e
		}
		return envelope, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	if count >= 256 {
		return nil, ErrJournal
	}
	envelope, e = composeProtected(r, p)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec("INSERT INTO outbound VALUES(?,?,?)", identity, p.intent, envelope); e != nil {
		return nil, e
	}
	if _, e = tx.Exec("UPDATE identity SET comparison=? WHERE id=1", p.now); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	if e = j.finalize(r, p); e != nil {
		return nil, e
	}
	return envelope, nil
}

func outboundFloor(tx *sql.Tx, now uint64) error {
	var floor int64
	if e := tx.QueryRow("SELECT comparison FROM identity WHERE id=1").Scan(&floor); e != nil || floor < 0 || now < uint64(floor) {
		return ErrJournal
	}
	return nil
}
func (j *OutboundJournal) finalize(r ComposeRequest, p *composePlan) error {
	if e := recheckCompose(r, p); e != nil {
		return e
	}
	tx, e := j.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = outboundFloor(tx, p.now); e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE identity SET comparison=? WHERE id=1", p.now); e != nil {
		return e
	}
	return tx.Commit()
}
