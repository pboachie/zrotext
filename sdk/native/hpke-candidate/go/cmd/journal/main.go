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

func main() {
	var f map[string]json.RawMessage
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	if e := json.Unmarshal(input, &f); e != nil {
		panic(e)
	}
	b := func(name string) []byte {
		var s string
		if e := json.Unmarshal(f[name], &s); e != nil {
			panic(e)
		}
		v, e := base64.StdEncoding.Strict().DecodeString(s)
		if e != nil {
			panic(e)
		}
		return v
	}
	record := func(name string) hpke.ElectionRecord {
		var raw map[string]json.RawMessage
		if e := json.Unmarshal(f[name], &raw); e != nil {
			panic(e)
		}
		r := hpke.ElectionRecord{Bytes: map[string][]byte{}, Numbers: map[string]uint64{}}
		for k, v := range raw {
			if v[0] == '"' {
				var s string
				if e := json.Unmarshal(v, &s); e != nil {
					panic(e)
				}
				x, e := base64.StdEncoding.Strict().DecodeString(s)
				if e != nil {
					panic(e)
				}
				r.Bytes[k] = x
			} else {
				var n uint64
				if e := json.Unmarshal(v, &n); e != nil {
					panic(e)
				}
				r.Numbers[k] = n
			}
		}
		return r
	}

	expect := &hpke.ElectionExpectations{Core: b("core"), Accepted: record("accepted"), DevicePoint: b("deviceSigningPoint"), OwnerPoint: b("ownerApprovalPoint")}
	open := func(path string) *hpke.Journal {
		j, e := hpke.OpenJournal(path, b("rootPin"), b("fingerprint"))
		if e != nil {
			panic(e)
		}
		return j
	}
	if len(os.Args) > 2 {
		path := os.Args[2]
		if os.Args[1] == "crash" {
			db, e := sql.Open("sqlite", path)
			if e != nil {
				panic(e)
			}
			tx, e := db.Begin()
			if e != nil {
				panic(e)
			}
			if _, e = tx.Exec("INSERT INTO manifests VALUES(2,10000,?)", b("signed03")); e != nil {
				panic(e)
			}
			os.Exit(17)
		}
		j := open(path)
		defer j.Close()
		_, e := j.AppendElection(b("signed03"), b("bundle"), 1, expect)
		if errors.Is(e, hpke.ErrJournalConflict) {
			fmt.Println("conflict")
			return
		}
		if e != nil {
			panic(e)
		}
		fmt.Println("committed")
		return
	}
	dir, e := os.MkdirTemp("", "zrotext-journal-")
	if e != nil {
		panic(e)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "journal.db")
	j := open(path)
	if _, e = j.AppendManifest(b("signed02"), 0, 10000, nil); e != nil {
		panic(e)
	}
	if _, e = j.AppendManifest(b("signed03"), 1, 10000, nil); e == nil {
		panic("non-atomic election")
	}
	if e = j.Close(); e != nil {
		panic(e)
	}
	exe, e := os.Executable()
	if e != nil {
		panic(e)
	}
	crash := exec.Command(exe, "crash", path)
	crash.Stdin = bytes.NewReader(input)
	if e = crash.Run(); e == nil {
		panic("crash expected")
	} else {
		var exit *exec.ExitError
		if !errors.As(e, &exit) || exit.ExitCode() != 17 {
			panic("crash process did not reach transaction")
		}
	}
	j = open(path)
	snapshot, e := j.Snapshot(10000, nil)
	if e != nil || snapshot.Revision != 1 {
		panic("crash rollback")
	}
	j.Close()
	children := make([]*exec.Cmd, 2)
	outputs := make([]bytes.Buffer, 2)
	for i := range children {
		children[i] = exec.Command(exe, "race", path)
		children[i].Stdin = bytes.NewReader(input)
		children[i].Stdout = &outputs[i]
		children[i].Stderr = &outputs[i]
		if e = children[i].Start(); e != nil {
			panic(e)
		}
	}
	wins := 0
	conflicts := 0
	for i, c := range children {
		if e = c.Wait(); e != nil {
			panic(outputs[i].String())
		}
		switch outputs[i].String() {
		case "committed\n":
			wins++
		case "conflict\n":
			conflicts++
		default:
			panic("child result")
		}
	}
	if wins != 1 || conflicts != 1 {
		panic("CAS race")
	}
	j = open(path)
	defer j.Close()
	snapshot, e = j.Snapshot(30000, expect)
	if e != nil || snapshot.Revision != 2 || snapshot.Proof == nil {
		panic("restore")
	}
	plain, e := hpke.OpenSoftwareElected03(b("envelope"), snapshot.Manifest, snapshot.Proof, record("authority"), b("readerScalar"), hpke.ElectedContext{Message: b("message"), Peer: "+12", Now: 30000})
	if e != nil {
		panic(e)
	}
	var expected string
	json.Unmarshal(f["bodyText"], &expected)
	if plain != expected {
		panic("plaintext")
	}
	if _, e = j.Snapshot(30000, nil); e == nil {
		panic("missing independent evidence")
	}
	for _, now := range []uint64{0, 9999, 100000, 1 << 63} {
		if _, e = j.Snapshot(now, expect); e == nil {
			panic("clock")
		}
	}
	for _, kind := range []string{"core", "accepted", "device", "owner"} {
		x := *expect
		x.Core = append([]byte(nil), expect.Core...)
		x.Accepted = record("accepted")
		x.DevicePoint = append([]byte(nil), expect.DevicePoint...)
		x.OwnerPoint = append([]byte(nil), expect.OwnerPoint...)
		switch kind {
		case "core":
			x.Core[0] ^= 1
		case "accepted":
			x.Accepted.Bytes["newBindingId"][0] ^= 1
		case "device":
			x.DevicePoint[1] ^= 1
		case "owner":
			x.OwnerPoint[1] ^= 1
		}
		if _, e = j.Snapshot(30000, &x); e == nil {
			panic("independent substitution")
		}
	}
	if _, e = j.AppendElection(b("signed03"), b("bundle"), 1, expect); !errors.Is(e, hpke.ErrJournalConflict) {
		panic("stale revision")
	}
	j.Close()
	mutate := func(query string, args ...any) {
		db, e := sql.Open("sqlite", path)
		if e != nil {
			panic(e)
		}
		defer db.Close()
		if _, e = db.Exec(query, args...); e != nil {
			panic(e)
		}
	}
	bad := b("bundle")
	bad[500] ^= 1
	mutate("UPDATE elections SET bundle=?", bad)
	j = open(path)
	if _, e = j.Snapshot(30000, expect); e == nil {
		panic("corrupt signed evidence")
	}
	j.Close()
	mutate("UPDATE elections SET bundle=?", b("bundle"))
	mutate("UPDATE identity SET fingerprint=zeroblob(32)")
	if other, e := hpke.OpenJournal(path, b("rootPin"), b("fingerprint")); e == nil {
		other.Close()
		panic("root substitution")
	}
	mutate("UPDATE identity SET fingerprint=?", b("fingerprint"))
	mutate("PRAGMA user_version=3")
	if other, e := hpke.OpenJournal(path, b("rootPin"), b("fingerprint")); e == nil {
		other.Close()
		panic("schema version")
	}
	mutate("PRAGMA user_version=2")
	empty := filepath.Join(dir, "empty.db")
	if e = os.WriteFile(empty, nil, 0600); e != nil {
		panic(e)
	}
	if other, e := hpke.OpenJournal(empty, b("rootPin"), b("fingerprint")); e == nil {
		other.Close()
		panic("implicit initialization")
	}
	fmt.Println("native journal: crash rollback, two-process CAS, actual ciphertext restore and refusal controls passed")
}
