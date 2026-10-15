package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

func need(ok bool) {
	if !ok {
		panic("root transition control")
	}
}
func main() {
	input, e := io.ReadAll(os.Stdin)
	if e != nil {
		panic(e)
	}
	var f map[string]json.RawMessage
	need(json.Unmarshal(input, &f) == nil)
	decode := func(raw json.RawMessage) []byte {
		var s string
		need(json.Unmarshal(raw, &s) == nil)
		b, e := base64.StdEncoding.Strict().DecodeString(s)
		need(e == nil)
		return b
	}
	b := func(n string) []byte { return decode(f[n]) }
	var point [65]byte
	copy(point[:], b("newPoint"))
	roots := map[uint64][65]byte{2: point}
	open := func(path string) *hpke.Journal {
		j, e := hpke.OpenJournalWithTransitions(path, b("rootPin"), b("fingerprint"), roots)
		if e != nil {
			panic(e)
		}
		return j
	}
	if len(os.Args) > 2 {
		path := os.Args[2]
		if os.Args[1] == "crash" {
			db, e := sql.Open("sqlite", path)
			need(e == nil)
			tx, e := db.Begin()
			need(e == nil)
			_, e = tx.Exec("INSERT INTO manifests VALUES(2,11000,?)", b("newManifest"))
			need(e == nil)
			os.Exit(17)
		}
		j := open(path)
		defer j.Close()
		_, e := j.AppendTransition02(b("transition"), b("newManifest"), 1, 11000)
		if e == nil {
			fmt.Println("committed")
		} else if errors.Is(e, hpke.ErrJournalConflict) {
			fmt.Println("conflict")
		} else {
			panic(e)
		}
		return
	}
	root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
	need(e == nil)
	old, e := hpke.VerifyManifest(b("manifest"), root, nil, 2, 10000)
	need(e == nil)
	nextRoot, e := hpke.VerifyRootTransition02(b("transition"), old, b("newPoint"), 11000)
	need(e == nil)
	next, e := hpke.VerifyManifest(b("newManifest"), nextRoot, nil, 2, 11000)
	need(e == nil && next.Generation() == 2)
	for _, name := range []string{"highOld", "highNew"} {
		_, e := hpke.VerifyRootTransition02(b(name), old, b("newPoint"), 11000)
		need(e != nil)
	}
	for i := 0; i < 343; i++ {
		bad := b("transition")
		bad[i] ^= 1
		_, e := hpke.VerifyRootTransition02(bad, old, b("newPoint"), 11000)
		need(e != nil)
	}
	for _, n := range []uint64{9999, 90000, 0} {
		_, e := hpke.VerifyRootTransition02(b("transition"), old, b("newPoint"), n)
		need(e != nil)
	}
	_, e = hpke.VerifyRootTransition02(b("transition"), old, b("rootPin")[29:], 11000)
	need(e != nil)
	_, e = hpke.VerifyRootTransition02(b("transition"), next, b("newPoint"), 11000)
	need(e != nil)
	_, e = hpke.VerifyManifest(b("newManifest"), root, nil, 2, 11000)
	need(e != nil)
	_, e = hpke.VerifyManifest(b("manifest"), nextRoot, nil, 2, 11000)
	need(e != nil)
	var rotation map[string]json.RawMessage
	need(json.Unmarshal(f["rotation"], &rotation) == nil)
	v := func(n string) []byte { return decode(rotation[n]) }
	var now uint64
	need(json.Unmarshal(rotation["now_ms"], &now) == nil)
	publicRoot, e := hpke.EnrollRoot(v("old_root_pin_b64"), v("old_root_fingerprint_b64"))
	need(e == nil)
	publicOld, e := hpke.VerifyManifest(v("old_manifest_b64"), publicRoot, nil, 2, now)
	need(e == nil)
	publicNext, e := hpke.VerifyRootTransition02(v("transition_b64"), publicOld, v("new_root_point_b64"), now)
	need(e == nil)
	_, e = hpke.VerifyManifest(v("new_manifest_b64"), publicNext, nil, 2, now)
	need(e == nil)
	dir, e := os.MkdirTemp("", "zrotext-root-")
	need(e == nil)
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "checkpoint.db")
	j := open(path)
	_, e = j.AppendManifest(b("manifest"), 0, 10000, nil)
	need(e == nil)
	j.Close()
	child := func(mode string) *exec.Cmd {
		exe, e := os.Executable()
		need(e == nil)
		c := exec.Command(exe, mode, path)
		c.Stdin = bytes.NewReader(input)
		return c
	}
	need(child("crash").Run() != nil)
	j = open(path)
	snap, e := j.Snapshot(11000, nil)
	need(e == nil && snap.Revision == 1)
	j.Close()
	a, c := child("race"), child("race")
	var ao, co bytes.Buffer
	a.Stdout = &ao
	c.Stdout = &co
	need(a.Start() == nil && c.Start() == nil)
	need(a.Wait() == nil && c.Wait() == nil)
	need((ao.String() == "committed\n" && co.String() == "conflict\n") || (co.String() == "committed\n" && ao.String() == "conflict\n"))
	j = open(path)
	snap, e = j.Snapshot(11000, nil)
	need(e == nil && snap.Revision == 2 && snap.Manifest.Generation() == 2)
	context := hpke.ArchiveContext{Account: b("account"), Device: b("device"), Line: b("line"), Reader: b("reader"), Peer: "+12", Now: 11000}
	opened, e := hpke.OpenSoftwareArchive02(b("newInbound"), snap.Manifest, snap.Manifest, b("archiveScalar"), context)
	var expected string
	need(json.Unmarshal(f["text"], &expected) == nil)
	need(e == nil && opened == expected)
	_, e = hpke.OpenSoftwareArchive02(b("inbound"), old, snap.Manifest, b("archiveScalar"), context)
	need(e != nil)
	_, e = j.AppendManifest(b("newSuccessor"), 2, 11000, nil)
	need(e == nil)
	latest, e := j.Snapshot(11000, nil)
	need(e == nil && latest.Revision == 3)
	opened, e = hpke.OpenSoftwareArchive02(b("newInbound"), snap.Manifest, latest.Manifest, b("archiveScalar"), context)
	need(e == nil && opened == expected)
	_, e = j.Snapshot(10999, nil)
	need(e != nil)
	j.Close()
	plain, e := hpke.OpenJournal(path, b("rootPin"), b("fingerprint"))
	need(e == nil)
	_, e = plain.Snapshot(11000, nil)
	need(e != nil)
	plain.Close()
	badRoots := map[uint64][65]byte{2: {}}
	wrong, e := hpke.OpenJournalWithTransitions(path, b("rootPin"), b("fingerprint"), badRoots)
	need(e == nil)
	_, e = wrong.Snapshot(11000, nil)
	need(e != nil)
	wrong.Close()
	db, e := sql.Open("sqlite", path)
	need(e == nil)
	bad := b("transition")
	bad[215] ^= 1
	_, e = db.Exec("UPDATE transitions SET signed=?", bad)
	need(e == nil)
	db.Close()
	j = open(path)
	_, e = j.Snapshot(11000, nil)
	need(e != nil)
	j.Close()
	db, e = sql.Open("sqlite", path)
	need(e == nil)
	_, e = db.Exec("UPDATE transitions SET signed=?", b("transition"))
	need(e == nil)
	_, e = db.Exec("PRAGMA user_version=1")
	need(e == nil)
	db.Close()
	_, e = hpke.OpenJournalWithTransitions(path, b("rootPin"), b("fingerprint"), roots)
	need(e != nil)
	fmt.Println("Go root transitions, public vectors, atomic crash/CAS restore and current reader passed")
}
