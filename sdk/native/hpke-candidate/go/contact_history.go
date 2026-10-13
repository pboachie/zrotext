package hpke

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrContactHistory = errors.New("contact local history unavailable")
var errContactRootMismatch = errors.New("contact root mismatch")

const contactHistoryApp = 0x5a544348

var contactHistories atomic.Int32

// ContactHistoryMetadata is local metadata, never a verified integrity token or permission.
type ContactHistoryMetadata struct {
	Contact                  [16]byte
	Revision                 uint64
	Digest                   [32]byte
	Request                  [16]byte
	Routing, StatementDigest [32]byte
	Name, Notes              ContactSlot
	ManifestVersion          uint64
	ManifestDigest, ReaderID [32]byte
	ReaderGeneration         uint64
	RootWriterID             [32]byte
	Comparison, RootVersion  uint64
	RootDigest               [32]byte
	RootTime                 uint64
}

// ContactLocalToken is bound to one live adapter and an exact observed row.
type ContactLocalToken struct {
	owner *ContactHistory
	raw   []byte
}
type ContactHistoryResult struct {
	Kind, Reason string
	Record       *ContactLocalToken
	Metadata     *ContactHistoryMetadata
}
type ContactHistory struct {
	admitted                 bool
	db                       *sql.DB
	path, rootPath, origin   string
	identity                 os.FileInfo
	pin, fingerprint, header []byte
	maximum                  int
	reduction                bool
	born                     time.Time
	busy                     sync.Mutex
	closed, released         atomic.Bool
	tokens                   map[[16]byte]*ContactLocalToken
}

func (h *ContactHistory) release() {
	if h.admitted && h.closed.Load() && h.released.CompareAndSwap(false, true) {
		contactHistories.Add(-1)
	}
}
func (h *ContactHistory) Close() {
	if h == nil {
		return
	}
	h.closed.Store(true)
	if h.busy.TryLock() {
		defer h.busy.Unlock()
		if h.db != nil {
			_ = h.db.Close()
		}
		h.tokens = nil
		h.release()
	}
}
func (h *ContactHistory) live(ctx context.Context) error {
	if h != nil && time.Since(h.born) >= 30*time.Minute {
		h.closed.Store(true)
	}
	if h == nil || h.closed.Load() || time.Since(h.born) >= 30*time.Minute || ctx.Err() != nil {
		return ErrContactHistory
	}
	return nil
}
func (h *ContactHistory) enter(parent context.Context) (context.Context, func(), error) {
	if h == nil || parent == nil || !h.busy.TryLock() {
		return nil, nil, ErrContactHistory
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	done := func() {
		cancel()
		if h.closed.Load() {
			if h.db != nil {
				_ = h.db.Close()
			}
			h.tokens = nil
			h.release()
		}
		h.busy.Unlock()
	}
	if e := h.live(ctx); e != nil {
		done()
		return nil, nil, e
	}
	return ctx, done, nil
}
func contactDB(path string) (*sql.DB, error) {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {"busy_timeout(5000)", "trusted_schema(OFF)"}}
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e == nil {
		db.SetMaxOpenConns(1)
	}
	return db, e
}

// OpenContactHistory requires explicit creation and independent enrollment.
// rootPath names an existing native Journal; metadata never supplies its own root.
func OpenContactHistory(path, rootPath string, pin, fingerprint []byte, origin string, maximum int, create, reduction bool) (result *ContactHistory, err error) {
	defer func() {
		if err != nil {
			err = ErrContactHistory
		}
	}()
	if _, e := EnrollRoot(pin, fingerprint); e != nil {
		return nil, ErrContactHistory
	}
	if !contactOrigin(origin) || maximum < 1 || maximum > 256 || create && reduction {
		return nil, ErrContactHistory
	}
	p, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	rp := ""
	if rootPath != "" {
		rp, e = filepath.Abs(rootPath)
		if e != nil {
			return nil, e
		}
	}
	if p == rp || !reduction && rp == "" {
		return nil, ErrContactHistory
	}
	for {
		n := contactHistories.Load()
		if n >= 4 {
			return nil, ErrContactHistory
		}
		if contactHistories.CompareAndSwap(n, n+1) {
			break
		}
	}
	h := &ContactHistory{admitted: true, path: p, rootPath: rp, origin: origin, pin: append([]byte(nil), pin...), fingerprint: append([]byte(nil), fingerprint...), maximum: maximum, reduction: reduction, born: time.Now(), tokens: map[[16]byte]*ContactLocalToken{}}
	success := false
	defer func() {
		if !success {
			h.Close()
		}
	}()
	h.header = append([]byte("ZTCH\x01"), pin...)
	h.header = append(h.header, fingerprint...)
	h.header = binary.BigEndian.AppendUint16(h.header, uint16(len(origin)))
	h.header = append(h.header, origin...)
	h.header = binary.BigEndian.AppendUint16(h.header, uint16(maximum))
	if !reduction {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, e = h.rootSnapshot(ctx)
		cancel()
		if e != nil {
			return nil, e
		}
	}
	if create {
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		e = f.Close()
		if e != nil {
			return nil, e
		}
	}
	h.identity, e = os.Lstat(p)
	if e != nil || !h.identity.Mode().IsRegular() {
		return nil, ErrContactHistory
	}
	h.db, e = contactDB(p)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, e := h.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if create {
		for _, s := range []string{"PRAGMA application_id=1515471688", "CREATE TABLE header (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL, count INTEGER NOT NULL) STRICT", "CREATE TABLE contacts (id BLOB PRIMARY KEY, payload BLOB NOT NULL) STRICT"} {
			if _, e = tx.ExecContext(ctx, s); e != nil {
				return nil, e
			}
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO header VALUES(1,?,0)", h.header); e != nil {
			return nil, e
		}
	}
	if _, e = h.read(ctx, tx); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	var mode string
	if e = h.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); e != nil || mode != "wal" {
		return nil, ErrContactHistory
	}
	if _, e = h.db.ExecContext(ctx, "PRAGMA synchronous=FULL"); e != nil {
		return nil, e
	}
	success = true
	return h, nil
}
func historyBytes(m *ContactHistoryMetadata) []byte {
	b := append([]byte{1}, m.Contact[:]...)
	b = binary.BigEndian.AppendUint64(b, m.Revision)
	b = append(b, m.Digest[:]...)
	b = append(b, m.Request[:]...)
	b = append(b, m.Routing[:]...)
	for _, s := range []ContactSlot{m.Name, m.Notes} {
		b = append(b, s.Tag)
		b = binary.BigEndian.AppendUint64(b, s.SealRevision)
		b = append(b, s.Digest[:]...)
	}
	b = append(b, m.StatementDigest[:]...)
	b = binary.BigEndian.AppendUint64(b, m.ManifestVersion)
	b = append(b, m.ManifestDigest[:]...)
	b = append(b, m.ReaderID[:]...)
	b = binary.BigEndian.AppendUint64(b, m.ReaderGeneration)
	b = append(b, m.RootWriterID[:]...)
	b = binary.BigEndian.AppendUint64(b, m.Comparison)
	b = binary.BigEndian.AppendUint64(b, m.RootVersion)
	b = append(b, m.RootDigest[:]...)
	return binary.BigEndian.AppendUint64(b, m.RootTime)
}
func historyRow(b []byte) (*ContactHistoryMetadata, error) {
	if len(b) == 17 && b[0] == 0 && contactNonzero(b[1:], 16) {
		return nil, nil
	}
	if len(b) != 387 || b[0] != 1 {
		return nil, ErrContactHistory
	}
	m := &ContactHistoryMetadata{}
	at := 1
	take := func(n int) []byte { v := b[at : at+n]; at += n; return v }
	num := func() uint64 { return binary.BigEndian.Uint64(take(8)) }
	copy(m.Contact[:], take(16))
	m.Revision = num()
	copy(m.Digest[:], take(32))
	copy(m.Request[:], take(16))
	copy(m.Routing[:], take(32))
	for _, s := range []*ContactSlot{&m.Name, &m.Notes} {
		s.Tag = take(1)[0]
		s.SealRevision = num()
		copy(s.Digest[:], take(32))
		if !contactSlotValid(*s, m.Revision) {
			return nil, ErrContactHistory
		}
	}
	copy(m.StatementDigest[:], take(32))
	m.ManifestVersion = num()
	copy(m.ManifestDigest[:], take(32))
	copy(m.ReaderID[:], take(32))
	m.ReaderGeneration = num()
	copy(m.RootWriterID[:], take(32))
	m.Comparison = num()
	m.RootVersion = num()
	copy(m.RootDigest[:], take(32))
	m.RootTime = num()
	for _, v := range []uint64{m.Revision, m.ManifestVersion, m.ReaderGeneration, m.Comparison, m.RootVersion} {
		if !contactPositive(v) {
			return nil, ErrContactHistory
		}
	}
	if m.RootTime > 0x7fffffffffffffff {
		return nil, ErrContactHistory
	}
	for _, v := range [][]byte{m.Contact[:], m.Digest[:], m.Request[:], m.Routing[:], m.StatementDigest[:], m.ManifestDigest[:], m.ReaderID[:], m.RootWriterID[:], m.RootDigest[:]} {
		if !contactNonzero(v, len(v)) {
			return nil, ErrContactHistory
		}
	}
	return m, nil
}
func (h *ContactHistory) read(ctx context.Context, tx *sql.Tx) (map[[16]byte][]byte, error) {
	if e := h.live(ctx); e != nil {
		return nil, e
	}
	fi, e := os.Lstat(h.path)
	if e != nil || !fi.Mode().IsRegular() || !os.SameFile(fi, h.identity) {
		return nil, ErrContactHistory
	}
	var app int
	if e = tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); e != nil || app != contactHistoryApp {
		return nil, ErrContactHistory
	}
	var names string
	if e = tx.QueryRowContext(ctx, "SELECT group_concat(type||':'||name,',') FROM (SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name)").Scan(&names); e != nil || names != "table:contacts,table:header" {
		return nil, ErrContactHistory
	}
	var header []byte
	var count, n int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM header").Scan(&n); e != nil || n != 1 {
		return nil, ErrContactHistory
	}
	if e = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(payload)<=647 THEN payload END,count FROM header WHERE id=1").Scan(&header, &count); e != nil || !bytes.Equal(header, h.header) || count < 0 || count > h.maximum {
		return nil, ErrContactHistory
	}
	rows, e := tx.QueryContext(ctx, "SELECT CASE WHEN length(id)=16 THEN id END,CASE WHEN length(payload)<=387 THEN payload END FROM contacts LIMIT 257")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[[16]byte][]byte{}
	for rows.Next() {
		var id, b []byte
		if e = rows.Scan(&id, &b); e != nil {
			return nil, e
		}
		if _, e = historyRow(b); e != nil || len(id) != 16 || !bytes.Equal(id, b[1:17]) {
			return nil, ErrContactHistory
		}
		var key [16]byte
		copy(key[:], id)
		if _, ok := out[key]; ok {
			return nil, ErrContactHistory
		}
		out[key] = b
	}
	if e = rows.Err(); e != nil || len(out) != count {
		return nil, ErrContactHistory
	}
	return out, nil
}

type contactRootSnapshot struct {
	manifests      []*Manifest
	version, clock uint64
	digest, exact  [32]byte
}

func (h *ContactHistory) rootSnapshot(ctx context.Context) (*contactRootSnapshot, error) {
	if e := h.live(ctx); e != nil {
		return nil, e
	}
	fi, e := os.Lstat(h.rootPath)
	if e != nil || !fi.Mode().IsRegular() {
		return nil, ErrContactHistory
	}
	db, e := contactDB(h.rootPath)
	if e != nil {
		return nil, e
	}
	defer db.Close()
	tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var app, version, n int
	if e = tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); e != nil || app != journalApp {
		return nil, ErrContactHistory
	}
	if e = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil || version != 2 {
		return nil, ErrContactHistory
	}
	var names string
	if e = tx.QueryRowContext(ctx, "SELECT group_concat(type||':'||name,',') FROM (SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name)").Scan(&names); e != nil || names != "table:elections,table:identity,table:manifests,table:transitions" {
		return nil, ErrContactHistory
	}
	if e = tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM transitions)+(SELECT count(*) FROM elections)").Scan(&n); e != nil || n != 0 {
		return nil, ErrContactHistory
	}
	var pin, fp []byte
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM identity").Scan(&n); e != nil || n != 1 {
		return nil, ErrContactHistory
	}
	if e = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(root)=94 THEN root END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM identity WHERE id=1").Scan(&pin, &fp); e != nil {
		return nil, ErrContactHistory
	}
	if !bytes.Equal(pin, h.pin) || !bytes.Equal(fp, h.fingerprint) {
		return nil, errContactRootMismatch
	}
	rows, e := tx.QueryContext(ctx, "SELECT revision,comparison,CASE WHEN length(signed)<=9751 THEN signed END FROM manifests ORDER BY revision LIMIT 65")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	root, e := EnrollRoot(h.pin, h.fingerprint)
	if e != nil {
		return nil, e
	}
	out := &contactRootSnapshot{}
	hash := sha256.New()
	var prior *Manifest
	for rows.Next() {
		var rev, clock uint64
		var raw []byte
		if e = rows.Scan(&rev, &clock, &raw); e != nil || rev != out.version+1 || rev > 64 || clock < out.clock {
			return nil, ErrContactHistory
		}
		if e = h.live(ctx); e != nil {
			return nil, e
		}
		m, e := VerifyManifest(raw, root, prior, 2, clock)
		if e != nil || m.generation != 1 || m.version != rev {
			return nil, ErrContactHistory
		}
		out.manifests = append(out.manifests, m)
		out.version = rev
		out.clock = clock
		out.digest = m.digest
		prior = m
		hash.Write(binary.BigEndian.AppendUint64(nil, clock))
		hash.Write(raw)
	}
	if rows.Err() != nil || out.version == 0 {
		return nil, ErrContactHistory
	}
	copy(out.exact[:], hash.Sum(nil))
	return out, nil
}
func (h *ContactHistory) evidence(ctx context.Context, m *ContactHistoryMetadata, st *ContactStatement) (*contactRootSnapshot, error) {
	before, e := h.rootSnapshot(ctx)
	if e != nil {
		return nil, e
	}
	if m.RootVersion > 0 {
		found := false
		for _, v := range before.manifests {
			if v.version == m.RootVersion && v.digest == m.RootDigest {
				found = true
			}
		}
		if !found {
			return nil, ErrContactHistory
		}
	}
	if before.version < m.RootVersion || before.clock < m.RootTime || before.version == m.RootVersion && before.digest != m.RootDigest {
		return nil, ErrContactHistory
	}
	var selected *Manifest
	for _, v := range before.manifests {
		if v.version == m.ManifestVersion && v.digest == m.ManifestDigest {
			selected = v
		}
	}
	if selected == nil {
		return nil, ErrContactHistory
	}
	previous := *selected
	previous.comparison = 0
	root := selected.rootTrust()
	root.comparison = 0
	v, e := VerifyManifest(selected.raw, root, &previous, 2, m.Comparison)
	if e != nil {
		return nil, e
	}
	reader := manifestKey(v, 2, m.ReaderID[:])
	writer := manifestKey(v, 6, m.RootWriterID[:])
	if !activeKey(reader, m.Comparison, 12) || !activeKey(writer, m.Comparison, 0) || binary.BigEndian.Uint16(reader[130:132]) != 12 || binary.BigEndian.Uint16(writer[130:132]) != 0 || !bytes.Equal(writer[33:98], h.pin[29:]) {
		return nil, ErrContactHistory
	}
	if st != nil {
		verified, e := VerifyContactStatement02(st.raw, selected, h.pin[5:21], h.origin, h.fingerprint)
		if e != nil || !bytes.Equal(verified.raw, st.raw) {
			return nil, ErrContactHistory
		}
	}
	after, e := h.rootSnapshot(ctx)
	if e != nil || after.exact != before.exact {
		return nil, ErrContactHistory
	}
	return before, nil
}
func (h *ContactHistory) token(raw []byte) *ContactLocalToken {
	var id [16]byte
	copy(id[:], raw[1:17])
	if old := h.tokens[id]; old != nil && bytes.Equal(old.raw, raw) {
		return old
	}
	t := &ContactLocalToken{h, append([]byte(nil), raw...)}
	h.tokens[id] = t
	return t
}
func (h *ContactHistory) expected(t *ContactLocalToken, raw []byte) bool {
	if t == nil {
		return raw == nil
	}
	if t.owner != h || len(t.raw) < 17 {
		return false
	}
	var id [16]byte
	copy(id[:], t.raw[1:17])
	return h.tokens[id] == t && bytes.Equal(t.raw, raw)
}
func (h *ContactHistory) Lookup(parent context.Context, id [16]byte) (result ContactHistoryResult, err error) {
	defer func() {
		if err != nil {
			err = ErrContactHistory
		}
	}()
	ctx, done, e := h.enter(parent)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	defer done()
	if !contactNonzero(id[:], 16) {
		return ContactHistoryResult{}, ErrContactHistory
	}
	tx, e := h.db.BeginTx(ctx, nil)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	defer tx.Rollback()
	rows, e := h.read(ctx, tx)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	if e = tx.Commit(); e != nil {
		return ContactHistoryResult{}, e
	}
	raw := rows[id]
	if raw == nil {
		delete(h.tokens, id)
		return ContactHistoryResult{Kind: "unavailable", Reason: "unobserved"}, nil
	}
	m, _ := historyRow(raw)
	t := h.token(raw)
	reason := ""
	if m == nil {
		reason = "local_stop"
	} else if h.reduction {
		reason = "reduction_only"
	} else if _, e = h.evidence(ctx, m, nil); e != nil {
		reason = "history_missing"
		if errors.Is(e, errContactRootMismatch) {
			reason = "root_mismatch"
		}
	}
	if e = h.live(ctx); e != nil {
		return ContactHistoryResult{}, e
	}
	if reason != "" {
		return ContactHistoryResult{Kind: "unavailable", Reason: reason, Record: t}, nil
	}
	return ContactHistoryResult{Kind: "accepted_local_history", Record: t, Metadata: m}, nil
}
func (h *ContactHistory) Accept(parent context.Context, expected *ContactLocalToken, t *ContactTransition, st *ContactStatement) (result ContactHistoryResult, err error) {
	defer func() {
		if err != nil {
			err = ErrContactHistory
		}
	}()
	ctx, done, e := h.enter(parent)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	defer done()
	if h.reduction || t == nil || t.mutation == nil || len(t.mutation.raw) != 368 || st == nil || len(st.raw) == 0 || !bytes.Equal(t.mutation.statement.raw, st.raw) || !bytes.Equal(st.account[:], h.pin[5:21]) || st.origin != h.origin || !bytes.Equal(st.rootPoint[:], h.pin[29:]) || !bytes.Equal(st.fingerprint[:], h.fingerprint) {
		return ContactHistoryResult{}, ErrContactHistory
	}
	mutation := t.mutation
	n := mutation.input
	m := &ContactHistoryMetadata{Revision: n.Revision, Digest: mutation.digest, Request: n.RequestID, Name: n.Name, Notes: n.Notes, StatementDigest: st.digest, ManifestVersion: st.version, ManifestDigest: st.manifestDigest, ReaderID: st.readerID, ReaderGeneration: st.readerGeneration, RootWriterID: st.rootWriterID, Comparison: st.issued}
	copy(m.Contact[:], mutation.raw[22:38])
	copy(m.Routing[:], mutation.raw[182:214])
	initial, e := h.rootSnapshot(ctx)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	m.RootVersion = initial.version
	m.RootDigest = initial.digest
	m.RootTime = initial.clock
	before, e := h.evidence(ctx, m, st)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	tx, e := h.db.BeginTx(ctx, nil)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	defer tx.Rollback()
	rows, e := h.read(ctx, tx)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	old := rows[m.Contact]
	if !h.expected(expected, old) {
		return ContactHistoryResult{}, ErrContactHistory
	}
	if old == nil {
		if n.Operation != 1 && n.Operation != 3 || m.Revision != 1 || len(rows) >= h.maximum {
			return ContactHistoryResult{}, ErrContactHistory
		}
	} else {
		p, e := historyRow(old)
		if e != nil || p == nil {
			return ContactHistoryResult{}, ErrContactHistory
		}
		if _, e = h.evidence(ctx, p, nil); e != nil {
			return ContactHistoryResult{}, e
		}
		if p.Revision == m.Revision {
			m.RootVersion = p.RootVersion
			m.RootDigest = p.RootDigest
			m.RootTime = p.RootTime
			if !bytes.Equal(historyBytes(m), old) {
				return ContactHistoryResult{}, ErrContactHistory
			}
		} else if n.Operation != 2 || p.Revision == 0x7fffffffffffffff || m.Revision != p.Revision+1 || n.PreviousDigest != p.Digest || m.Routing != p.Routing || m.ManifestVersion < p.ManifestVersion || m.ManifestVersion == p.ManifestVersion && m.ManifestDigest != p.ManifestDigest || m.ReaderGeneration < p.ReaderGeneration || m.ReaderGeneration == p.ReaderGeneration && m.ReaderID != p.ReaderID {
			return ContactHistoryResult{}, ErrContactHistory
		}
	}
	raw := historyBytes(m)
	if _, e = historyRow(raw); e != nil {
		return ContactHistoryResult{}, e
	}
	if e = h.live(ctx); e != nil {
		return ContactHistoryResult{}, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT OR REPLACE INTO contacts VALUES(?,?)", m.Contact[:], raw); e != nil {
		return ContactHistoryResult{Kind: "write_unknown"}, nil
	}
	count := len(rows)
	if old == nil {
		count++
	}
	if _, e = tx.ExecContext(ctx, "UPDATE header SET count=? WHERE id=1", count); e != nil {
		return ContactHistoryResult{Kind: "write_unknown"}, nil
	}
	if e = tx.Commit(); e != nil || h.live(ctx) != nil {
		return ContactHistoryResult{Kind: "write_unknown"}, nil
	}
	after, e := h.rootSnapshot(ctx)
	if h.live(ctx) != nil {
		return ContactHistoryResult{Kind: "write_unknown"}, nil
	}
	if e != nil || after.exact != before.exact {
		return ContactHistoryResult{Kind: "recorded_needs_recheck"}, nil
	}
	return ContactHistoryResult{Kind: "accepted_local_history", Record: h.token(raw), Metadata: m}, nil
}
func (h *ContactHistory) MarkUnavailable(parent context.Context, expected *ContactLocalToken) (result ContactHistoryResult, err error) {
	defer func() {
		if err != nil {
			err = ErrContactHistory
		}
	}()
	ctx, done, e := h.enter(parent)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	defer done()
	if expected == nil || expected.owner != h || len(expected.raw) < 17 {
		return ContactHistoryResult{}, ErrContactHistory
	}
	var id [16]byte
	copy(id[:], expected.raw[1:17])
	tx, e := h.db.BeginTx(ctx, nil)
	if e != nil {
		return ContactHistoryResult{}, e
	}
	defer tx.Rollback()
	rows, e := h.read(ctx, tx)
	if e != nil || !h.expected(expected, rows[id]) {
		return ContactHistoryResult{}, ErrContactHistory
	}
	raw := append([]byte{0}, id[:]...)
	if e = h.live(ctx); e != nil {
		return ContactHistoryResult{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE contacts SET payload=? WHERE id=?", raw, id[:]); e != nil {
		return ContactHistoryResult{Kind: "write_unknown"}, nil
	}
	if e = tx.Commit(); e != nil || h.live(ctx) != nil {
		return ContactHistoryResult{Kind: "write_unknown"}, nil
	}
	return ContactHistoryResult{Kind: "unavailable", Reason: "local_stop", Record: h.token(raw)}, nil
}
