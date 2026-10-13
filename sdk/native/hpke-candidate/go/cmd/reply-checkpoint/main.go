package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func refused(e error) {
	if e == nil {
		panic("unexpected checkpoint acceptance")
	}
}
func main() {
	var f map[string]json.RawMessage
	must(json.NewDecoder(os.Stdin).Decode(&f))
	b := func(n string) []byte {
		var s string
		must(json.Unmarshal(f[n], &s))
		v, e := base64.StdEncoding.Strict().DecodeString(s)
		must(e)
		return v
	}
	root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
	must(e)
	prior, e := hpke.VerifyManifest(b("predecessor"), root, nil, 2, 10000)
	must(e)
	active, e := hpke.VerifyManifest(b("activation"), root, prior, 2, 10000)
	must(e)
	successor, e := hpke.VerifyManifest(b("successor"), root, active, 2, 10000)
	must(e)
	revoked, e := hpke.VerifyManifest(b("revoked"), root, active, 2, 10000)
	must(e)
	scope := hpke.OriginalScope{Peer: "+12"}
	copy(scope.Account[:], b("account"))
	copy(scope.Device[:], b("device"))
	copy(scope.Line[:], b("line"))
	copy(scope.Interval[:], b("interval"))
	copy(scope.Connector[:], b("connector"))
	copy(scope.ReadGrant[:], b("readGrant"))
	copy(scope.Reader[:], b("originalReader"))
	if len(os.Args) == 3 && os.Args[1] == "--crash" {
		db, e := sql.Open("sqlite", os.Args[2])
		must(e)
		tx, e := db.Begin()
		must(e)
		_, e = tx.Exec("UPDATE state SET comparison=12000")
		must(e)
		_, e = tx.Exec("DELETE FROM manifests WHERE version=2")
		must(e)
		os.Exit(19) // Abrupt termination deliberately bypasses rollback/close.
	}
	if len(os.Args) == 3 && os.Args[1] == "--reopen" {
		j, e := hpke.OpenOriginalReplyCheckpoint(os.Args[2], b("rootPin"), b("fingerprint"), scope)
		must(e)
		defer j.Close()
		_, e = j.Snapshot(scope, 11000)
		must(e)
		_, e = j.Snapshot(scope, 10000)
		refused(e)
		fmt.Println("restart clock preserved")
		return
	}
	dir, e := os.MkdirTemp("", "zrotext-reply-checkpoint-")
	must(e)
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "reply.db")
	open := func() (*hpke.OriginalReplyCheckpoint, error) {
		return hpke.OpenOriginalReplyCheckpoint(path, b("rootPin"), b("fingerprint"), scope)
	}
	_, e = open()
	refused(e)
	_, e = hpke.CreateOriginalReplyCheckpoint(path, b("rootPin"), b("fingerprint"), scope, []*hpke.Manifest{active}, 10000)
	refused(e)
	j, e := hpke.CreateOriginalReplyCheckpoint(path, b("rootPin"), b("fingerprint"), scope, []*hpke.Manifest{prior, active}, 10000)
	must(e)
	_, e = hpke.CreateOriginalReplyCheckpoint(path, b("rootPin"), b("fingerprint"), scope, []*hpke.Manifest{prior, active}, 10000)
	refused(e)
	wrong := scope
	wrong.Connector[0] ^= 1
	_, e = hpke.OpenOriginalReplyCheckpoint(path, b("rootPin"), b("fingerprint"), wrong)
	refused(e)
	badPin := b("rootPin")
	badPin[5] ^= 1
	_, e = hpke.OpenOriginalReplyCheckpoint(path, badPin, b("fingerprint"), scope)
	refused(e)
	s, e := j.Snapshot(scope, 10000)
	must(e)
	if s.Revision != 1 || len(s.History) != 2 {
		panic("initial history")
	}
	_, e = j.Accept(scope, []*hpke.Manifest{prior, active, successor}, 1, 11000, func(*hpke.Manifest, uint64) (uint64, error) { return 0, errors.New("synthetic fence refusal") })
	refused(e)
	s, e = j.Snapshot(scope, 10000)
	must(e)
	if s.Revision != 1 || len(s.History) != 2 {
		panic("failed transaction exposed")
	}
	s, e = j.Accept(scope, []*hpke.Manifest{prior, active, successor}, 1, 10000, func(*hpke.Manifest, uint64) (uint64, error) { return 11000, nil })
	must(e)
	if s.Revision != 2 || s.Comparison != 11000 || len(s.History) != 3 {
		panic("commit scope")
	}
	_, e = j.Accept(scope, []*hpke.Manifest{prior, active, revoked}, 2, 11000, nil)
	refused(e)
	_, e = j.Accept(scope, []*hpke.Manifest{prior, active}, 2, 11000, nil)
	refused(e)
	_, e = j.Accept(scope, s.History, 1, 11000, nil)
	if !errors.Is(e, hpke.ErrJournalConflict) {
		panic("stale CAS")
	}
	must(j.Close())
	j, e = open()
	must(e)
	encoded, e := json.Marshal(f)
	must(e)
	child := exec.Command(os.Args[0], "--reopen", path)
	child.Stdin = bytes.NewReader(encoded)
	output, e := child.CombinedOutput()
	if e != nil {
		panic(string(output))
	}
	// Distinct connections contend for the same revision: exactly one wins.
	other, e := open()
	must(e)
	defer other.Close()
	a, e := j.Snapshot(scope, 11000)
	must(e)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, db := range []*hpke.OriginalReplyCheckpoint{j, other} {
		wait.Add(1)
		go func(db *hpke.OriginalReplyCheckpoint) {
			defer wait.Done()
			<-start
			_, e := db.Accept(scope, a.History, 2, 11000, nil)
			results <- e
		}(db)
	}
	close(start)
	wait.Wait()
	close(results)
	wins, conflicts := 0, 0
	for e := range results {
		if e == nil {
			wins++
		} else if errors.Is(e, hpke.ErrJournalConflict) {
			conflicts++
		} else {
			panic(e)
		}
	}
	if wins != 1 || conflicts != 1 {
		panic("CAS race")
	}
	// Abrupt process termination cannot publish the uncommitted state update.
	child = exec.Command(os.Args[0], "--crash", path)
	child.Stdin = bytes.NewReader(encoded)
	e = child.Run()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 19 {
		panic("crash process boundary")
	}
	state, e := j.Snapshot(scope, 11000)
	must(e)
	if state.Comparison != 11000 {
		panic("rollback clock")
	}
	var event [16]byte
	copy(event[:], b("event"))
	selected, e := hpke.VerifyOriginalReplySelection02(b("selection"), b("approval"), b("installation"), state.History[1], 10000, scope)
	must(e)
	// Each fresh comparison is durably accepted before the reader sees authority.
	current := func() (hpke.OriginalAuthority, error) {
		snap, e := j.Snapshot(scope, 11000)
		if e != nil {
			return hpke.OriginalAuthority{}, e
		}
		saved, e := j.Accept(scope, snap.History, snap.Revision, 11000, nil)
		if e != nil {
			return hpke.OriginalAuthority{}, e
		}
		return hpke.OriginalAuthority{Scope: scope, Revision: "synthetic-current", Now: 11000, Expires: 19000, Manifest: saved.History[2]}, nil
	}
	text, e := hpke.OpenSoftwareOriginalReply02(b("inbound"), event, state.History[1], selected, scope, b("originalScalar"), current)
	must(e)
	var expected string
	must(json.Unmarshal(f["text"], &expected))
	if text != expected {
		panic("restored reader plaintext")
	}
	must(j.Close())
	must(other.Close())
	raw, e := sql.Open("sqlite", path)
	must(e)
	_, e = raw.Exec("UPDATE manifests SET signed=zeroblob(length(signed)) WHERE version=2")
	must(e)
	must(raw.Close())
	_, e = open()
	refused(e)
	fmt.Println("Original checkpoint restart, CAS, rollback, scope, signed-history and restored reader passed")
}
