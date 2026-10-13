//go:build windows

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const content = "Native composed sample"

func decode(d map[string]json.RawMessage, name string) []byte {
	var s string
	if e := json.Unmarshal(d[name], &s); e != nil {
		panic(e)
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func request(d map[string]json.RawMessage, signer *hpke.HardwareSigner) (hpke.ComposeRequest02, error) {
	b := func(n string) []byte { return decode(d, n) }
	root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
	if e != nil {
		return hpke.ComposeRequest02{}, e
	}
	m, e := hpke.VerifyManifest(b("manifest"), root, nil, 2, 10000)
	if e != nil {
		return hpke.ComposeRequest02{}, e
	}
	raw := b("manifest")
	var recipients []hpke.ComposeRecipient
	for i := 0; i < int(raw[150]); i++ {
		k := raw[151+i*149 : 151+(i+1)*149]
		if k[0] == 1 || k[0] == 2 {
			recipients = append(recipients, hpke.ComposeRecipient{Role: k[0], ID: append([]byte(nil), k[1:33]...)})
		}
	}
	return hpke.ComposeRequest02{Manifest: m, Current: func() (*hpke.Manifest, uint64, error) { return m, 30000, nil }, Comparison: func() (uint64, error) { return 30000, nil }, Message: bytes.Repeat([]byte{49}, 16), Device: b("device"), Line: b("line"), Observed: 30000, Expires: 40000, Peer: "+12", Content: content, Signer: signer, Recipients: recipients}, nil
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "--probe" {
		if e := hpke.ProbeHardwareSigner(); e != nil {
			os.Exit(77)
		}
		return
	}
	var e error
	if len(os.Args) > 1 && os.Args[1] == "--replay" {
		e = child()
	} else {
		e = exercise()
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func child() error {
	var control struct {
		Fixture     map[string]json.RawMessage
		Alias, Path string
	}
	if e := json.NewDecoder(io.LimitReader(os.Stdin, 1000000)).Decode(&control); e != nil {
		return e
	}
	key, e := hpke.OpenHardwareSigner(control.Alias, decode(control.Fixture, "signerPoint"))
	if e != nil {
		return e
	}
	defer key.Close()
	r, e := request(control.Fixture, key)
	if e != nil {
		return e
	}
	j, e := hpke.OpenOutboundJournal(control.Path, decode(control.Fixture, "rootPin"), decode(control.Fixture, "fingerprint"))
	if e != nil {
		return e
	}
	defer func() { _ = j.Close() }()
	out, e := j.ComposeOrReplay02(r)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"envelope": base64.StdEncoding.EncodeToString(out)})
}
func exercise() (result error) {
	if e := hpke.ProbeHardwareSigner(); e != nil {
		return e
	}
	receipt, e := os.CreateTemp("", "zrotext-native-sign-pending-*.json")
	if e != nil {
		return e
	}
	defer receipt.Close()
	key, e := hpke.CreateHardwareSigner(func(name string) error {
		if e := json.NewEncoder(receipt).Encode(map[string]string{"pending_alias": name}); e != nil {
			return e
		}
		return receipt.Sync()
	})
	if e != nil {
		return e
	}
	var public []byte
	defer func() {
		alias := key.Alias()
		if e := key.DeleteCreated(); e != nil {
			result = errors.Join(result, e)
			key.Close()
			return
		}
		if other, e := hpke.OpenHardwareSigner(alias, public); e == nil {
			other.Close()
			result = errors.Join(result, errors.New("deleted signer reopened"))
			return
		}
		if e := receipt.Truncate(0); e != nil {
			result = errors.Join(result, e)
			return
		}
		receipt.Seek(0, 0)
		if e := json.NewEncoder(receipt).Encode(map[string]bool{"owned_key_deleted": true}); e != nil {
			result = errors.Join(result, e)
			return
		}
		result = errors.Join(result, receipt.Sync())
	}()
	public, e = key.PublicPoint()
	if e != nil {
		return e
	}
	if e = json.NewEncoder(os.Stdout).Encode(map[string]string{"public": hex.EncodeToString(public)}); e != nil {
		return e
	}
	var d map[string]json.RawMessage
	if e = json.NewDecoder(io.LimitReader(os.Stdin, 1000000)).Decode(&d); e != nil {
		return e
	}
	if _, ok := d["envelope"]; ok {
		return errors.New("external signer producer expected")
	}
	if !bytes.Equal(public, decode(d, "signerPoint")) {
		return errors.New("external signer binding")
	}
	reopened, e := hpke.OpenHardwareSigner(key.Alias(), public)
	if e != nil {
		return e
	}
	defer reopened.Close()
	if e = reopened.DeleteCreated(); e == nil {
		return errors.New("opened signer deleted")
	}
	r, e := request(d, reopened)
	if e != nil {
		return e
	}
	dir, e := os.MkdirTemp("", "zrotext-native-outbound-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "outbound.db")
	clock := uint64(30000)
	currentManifest := r.Manifest
	r.Current = func() (*hpke.Manifest, uint64, error) { return currentManifest, clock, nil }
	open := func() *hpke.OutboundJournal {
		j, e := hpke.OpenOutboundJournal(path, decode(d, "rootPin"), decode(d, "fingerprint"))
		if e != nil {
			panic(e)
		}
		return j
	}
	j := open()
	out, e := j.ComposeOrReplay02(r)
	if e != nil {
		return e
	}
	again, e := j.ComposeOrReplay02(r)
	if e != nil || !bytes.Equal(out, again) {
		return errors.New("exact replay")
	}
	j.Close()
	j = open()
	defer func() { _ = j.Close() }()
	again, e = j.ComposeOrReplay02(r)
	if e != nil || !bytes.Equal(out, again) {
		return errors.New("restart replay")
	}
	changed := r
	changed.Content = "Different synthetic intent"
	if _, e = j.ComposeOrReplay02(changed); !errors.Is(e, hpke.ErrJournalConflict) {
		return errors.New("intent conflict")
	}
	clock = uint64(31000)
	r.Comparison = func() (uint64, error) { return clock, nil }
	if _, e = j.ComposeOrReplay02(r); e != nil {
		return e
	}
	j.Close()
	j = open()
	clock = 30000
	if _, e = j.ComposeOrReplay02(r); e == nil {
		return errors.New("restart clock rollback")
	}
	clock = 31000
	for _, text := range []string{"", "\x00", "\ufeffbad", string([]byte{0xff}), string(bytes.Repeat([]byte{'x'}, 32769))} {
		bad := r
		bad.Content = text
		if _, e = hpke.ComposeProtected02(bad); e == nil {
			return errors.New("strict text")
		}
	}
	for _, peer := range []string{"+1", "bad", "+000"} {
		bad := r
		bad.Peer = peer
		if _, e = hpke.ComposeProtected02(bad); e == nil {
			return errors.New("peer")
		}
	}
	for _, expires := range []uint64{30000, 930001, 1 << 63} {
		bad := r
		bad.Expires = expires
		if _, e = hpke.ComposeProtected02(bad); e == nil {
			return errors.New("expiry")
		}
	}
	zero := r
	zero.Signer = &hpke.HardwareSigner{}
	if _, e = hpke.ComposeProtected02(zero); e == nil {
		return errors.New("unqualified zero signer")
	}
	bad := r
	bad.Recipients = r.Recipients[:1]
	if _, e = hpke.ComposeProtected02(bad); e == nil {
		return errors.New("recipient count")
	}
	// Restore the initial comparison for separate-process replay; persisted high-water remains31000.
	r.Comparison = func() (uint64, error) { return 31000, nil }
	// Children use the same independently authenticated record with comparison30000,
	// so use a distinct initialized journal for the concurrent first composition.
	racePath := filepath.Join(dir, "race.db")
	race, e := hpke.OpenOutboundJournal(racePath, decode(d, "rootPin"), decode(d, "fingerprint"))
	if e != nil {
		return e
	}
	race.Close()
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	payload, _ := json.Marshal(map[string]any{"Fixture": d, "Alias": key.Alias(), "Path": racePath})
	var commands [2]*exec.Cmd
	var outputs [2]bytes.Buffer
	for i := range commands {
		commands[i] = exec.Command(exe, "--replay")
		commands[i].Stdin = bytes.NewReader(payload)
		commands[i].Stdout = &outputs[i]
		commands[i].Stderr = &outputs[i]
		if e = commands[i].Start(); e != nil {
			return e
		}
	}
	for i, c := range commands {
		if e = c.Wait(); e != nil {
			return errors.New("replay child failed")
		}
		if i == 1 && !bytes.Equal(outputs[0].Bytes(), outputs[1].Bytes()) {
			return errors.New("concurrent ciphertext mismatch")
		}
	}
	// Successful ciphertext commit followed by comparison loss must withhold output.
	uncertain := r
	uncertain.Message = append([]byte(nil), r.Message...)
	uncertain.Message[0] ^= 1
	calls := 0
	uncertain.Comparison = func() (uint64, error) {
		calls++
		if calls == 3 {
			return 0, errors.New("synthetic comparison revoked")
		}
		return 31000, nil
	}
	if _, e = j.ComposeOrReplay02(uncertain); e == nil || calls != 3 {
		return errors.New("postcommit comparison")
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return e
	}
	identity := bytes.Join([][]byte{decode(d, "account"), uncertain.Message, decode(d, "device"), decode(d, "line")}, nil)
	var saved []byte
	e = db.QueryRow("SELECT envelope FROM outbound WHERE identity=?", identity).Scan(&saved)
	db.Close()
	if e != nil {
		return e
	}
	uncertain.Comparison = r.Comparison
	recovered, e := j.ComposeOrReplay02(uncertain)
	if e != nil || !bytes.Equal(saved, recovered) {
		return errors.New("ambiguous exact recovery")
	}
	newer := r
	newer.Message = append([]byte(nil), r.Message...)
	newer.Message[0] ^= 2
	phase := 0
	newer.Current = func() (*hpke.Manifest, uint64, error) {
		at := uint64(31000)
		if phase == 3 {
			at = 32000
		}
		return r.Manifest, at, nil
	}
	newer.Comparison = func() (uint64, error) {
		phase++
		at := uint64(31000)
		if phase == 3 {
			at = 32000
		}
		return at, nil
	}
	if _, e = j.ComposeOrReplay02(newer); e != nil {
		return e
	}
	j.Close()
	j = open()
	newer.Comparison = r.Comparison
	newer.Current = r.Current
	if _, e = j.ComposeOrReplay02(newer); e == nil {
		return errors.New("postcommit comparison not persisted")
	}
	var boundary []string
	for _, observed := range []uint64{0, 1} {
		candidate := r
		candidate.Message = make([]byte, 16)
		candidate.Observed = observed
		candidate.Expires = observed + 1
		fresh, e := hpke.ComposeProtected02(candidate)
		if e != nil {
			return e
		}
		boundary = append(boundary, base64.StdEncoding.EncodeToString(fresh))
		if _, e = j.ComposeOrReplay02(candidate); e == nil {
			return errors.New("expired boundary persisted")
		}
	}
	rotatedRoot, e := hpke.VerifyRootTransition02(decode(d, "transition"), r.Manifest, decode(d, "newPoint"), 33000)
	if e != nil {
		return e
	}
	rotatedManifest, e := hpke.VerifyManifest(decode(d, "newManifest"), rotatedRoot, nil, 2, 33000)
	if e != nil {
		return e
	}
	rotated := r
	rotated.Manifest = rotatedManifest
	rotated.Message = append([]byte(nil), r.Message...)
	rotated.Message[0] ^= 4
	rotated.Comparison = func() (uint64, error) { return 33000, nil }
	rotated.Current = func() (*hpke.Manifest, uint64, error) { return rotatedManifest, 33000, nil }
	rotatedEnvelope, e := j.ComposeOrReplay02(rotated)
	if e != nil {
		return e
	}
	j.Close()
	j = open()
	replayed, e := j.ComposeOrReplay02(rotated)
	if e != nil || !bytes.Equal(replayed, rotatedEnvelope) {
		return errors.New("rotated exact replay")
	}
	clock = 33000
	r.Comparison = func() (uint64, error) { return clock, nil }
	root, e := hpke.EnrollRoot(decode(d, "rootPin"), decode(d, "fingerprint"))
	if e != nil {
		return e
	}
	currentManifest, e = hpke.VerifyManifest(decode(d, "currentRetained"), root, r.Manifest, 2, 33000)
	if e != nil {
		return e
	}
	kept, e := j.ComposeOrReplay02(r)
	if e != nil || !bytes.Equal(kept, out) {
		return errors.New("retained current replay")
	}
	currentManifest, e = hpke.VerifyManifest(decode(d, "currentRevoked"), root, r.Manifest, 2, 33000)
	if e != nil {
		return e
	}
	if _, e = j.ComposeOrReplay02(r); e == nil {
		return errors.New("revoked current replay")
	}
	noCurrent := r
	noCurrent.Current = nil
	if _, e = j.ComposeOrReplay02(noCurrent); e == nil {
		return errors.New("missing current evidence")
	}
	retained, e := hpke.VerifyManifest(decode(d, "currentRetained"), root, r.Manifest, 2, 33000)
	if e != nil {
		return e
	}
	revoked := currentManifest
	late := r
	late.Message = append([]byte(nil), r.Message...)
	late.Message[0] ^= 8
	checks := 0
	late.Current = func() (*hpke.Manifest, uint64, error) {
		checks++
		if checks == 3 {
			return revoked, 33000, nil
		}
		return retained, 33000, nil
	}
	if _, e = j.ComposeOrReplay02(late); e == nil {
		return errors.New("postcommit current revocation exposed")
	}
	db, e = sql.Open("sqlite", path)
	if e != nil {
		return e
	}
	lateIdentity := bytes.Join([][]byte{decode(d, "account"), late.Message, late.Device, late.Line}, nil)
	var lateSaved []byte
	e = db.QueryRow("SELECT envelope FROM outbound WHERE identity=?", lateIdentity).Scan(&lateSaved)
	db.Close()
	if e != nil {
		return e
	}
	late.Current = func() (*hpke.Manifest, uint64, error) { return retained, 33000, nil }
	lateReplay, e := j.ComposeOrReplay02(late)
	if e != nil || !bytes.Equal(lateSaved, lateReplay) {
		return errors.New("current revocation exact recovery")
	}
	other, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	if wrong, e := hpke.OpenHardwareSigner(key.Alias(), other.PublicKey().Bytes()); e == nil {
		wrong.Close()
		return errors.New("wrong signer point")
	}
	reopened.Close()
	if _, e = hpke.ComposeProtected02(r); e == nil {
		return errors.New("closed signer")
	}
	j.Close()
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"envelope": base64.StdEncoding.EncodeToString(out), "expectedText": content, "boundaries": boundary, "rotatedEnvelope": base64.StdEncoding.EncodeToString(rotatedEnvelope), "checks": "exact replay, process CAS, ambiguity, clock rollback, strict input and custody passed"})
}
