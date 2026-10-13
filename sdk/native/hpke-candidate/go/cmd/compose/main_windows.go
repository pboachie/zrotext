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
func record(d map[string]json.RawMessage, name string) hpke.ElectionRecord {
	var raw map[string]json.RawMessage
	if e := json.Unmarshal(d[name], &raw); e != nil {
		panic(e)
	}
	r := hpke.ElectionRecord{Bytes: map[string][]byte{}, Numbers: map[string]uint64{}}
	for k, v := range raw {
		if v[0] == '"' {
			r.Bytes[k] = decode(raw, k)
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
func request(d map[string]json.RawMessage, signer *hpke.HardwareSigner) (hpke.ComposeRequest, error) {
	b := func(s string) []byte { return decode(d, s) }
	root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
	if e != nil {
		return hpke.ComposeRequest{}, e
	}
	prior, e := hpke.VerifyManifest(b("signed02"), root, nil, 2, 10000)
	if e != nil {
		return hpke.ComposeRequest{}, e
	}
	proof, e := hpke.VerifyAcceptedElection03(b("bundle"), b("core"), record(d, "accepted"), prior, b("signed02"), b("signed03"), b("deviceSigningPoint"), b("ownerApprovalPoint"))
	if e != nil {
		return hpke.ComposeRequest{}, e
	}
	raw := b("signed03")
	var archive []byte
	for i := 0; i < int(raw[152]); i++ {
		k := raw[153+i*149 : 153+(i+1)*149]
		if k[0] == 2 {
			archive = append([]byte(nil), k[1:33]...)
		}
	}
	return hpke.ComposeRequest{Manifest: proof.AcceptedManifest(), Proof: proof, Authority: func() (hpke.ElectionRecord, uint64, error) { return record(d, "authority"), 30000, nil }, Message: b("message"), Observed: 30000, Expires: 40000, Peer: "+12", Content: content, Signer: signer, Recipients: []hpke.ComposeRecipient{{Role: 1, ID: record(d, "accepted").Bytes["selectedReaderKeyId"]}, {Role: 2, ID: archive}}}, nil
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
	out, e := j.ComposeOrReplay(r)
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
	open := func() *hpke.OutboundJournal {
		j, e := hpke.OpenOutboundJournal(path, decode(d, "rootPin"), decode(d, "fingerprint"))
		if e != nil {
			panic(e)
		}
		return j
	}
	j := open()
	out, e := j.ComposeOrReplay(r)
	if e != nil {
		return e
	}
	again, e := j.ComposeOrReplay(r)
	if e != nil || !bytes.Equal(out, again) {
		return errors.New("exact replay")
	}
	j.Close()
	j = open()
	defer func() { _ = j.Close() }()
	again, e = j.ComposeOrReplay(r)
	if e != nil || !bytes.Equal(out, again) {
		return errors.New("restart replay")
	}
	changed := r
	changed.Content = "Different synthetic intent"
	if _, e = j.ComposeOrReplay(changed); !errors.Is(e, hpke.ErrJournalConflict) {
		return errors.New("intent conflict")
	}
	clock := uint64(31000)
	r.Authority = func() (hpke.ElectionRecord, uint64, error) { return record(d, "authority"), clock, nil }
	if _, e = j.ComposeOrReplay(r); e != nil {
		return e
	}
	j.Close()
	j = open()
	clock = 30000
	if _, e = j.ComposeOrReplay(r); e == nil {
		return errors.New("restart clock rollback")
	}
	clock = 31000
	for _, text := range []string{"", "\x00", "\ufeffbad", string([]byte{0xff}), string(bytes.Repeat([]byte{'x'}, 32769))} {
		bad := r
		bad.Content = text
		if _, e = hpke.ComposeProtected03(bad); e == nil {
			return errors.New("strict text")
		}
	}
	for _, peer := range []string{"+1", "bad", "+000"} {
		bad := r
		bad.Peer = peer
		if _, e = hpke.ComposeProtected03(bad); e == nil {
			return errors.New("peer")
		}
	}
	for _, expires := range []uint64{30000, 100001, 1 << 63} {
		bad := r
		bad.Expires = expires
		if _, e = hpke.ComposeProtected03(bad); e == nil {
			return errors.New("expiry")
		}
	}
	zero := r
	zero.Signer = &hpke.HardwareSigner{}
	if _, e = hpke.ComposeProtected03(zero); e == nil {
		return errors.New("unqualified zero signer")
	}
	bad := r
	bad.Recipients = r.Recipients[:1]
	if _, e = hpke.ComposeProtected03(bad); e == nil {
		return errors.New("recipient count")
	}
	// Restore the initial comparison for separate-process replay; persisted high-water remains31000.
	r.Authority = func() (hpke.ElectionRecord, uint64, error) { return record(d, "authority"), 31000, nil }
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
	// Successful ciphertext commit followed by authority loss must withhold output.
	uncertain := r
	uncertain.Message = append([]byte(nil), r.Message...)
	uncertain.Message[0] ^= 1
	calls := 0
	uncertain.Authority = func() (hpke.ElectionRecord, uint64, error) {
		calls++
		if calls == 3 {
			return hpke.ElectionRecord{}, 0, errors.New("synthetic authority revoked")
		}
		return record(d, "authority"), 31000, nil
	}
	if _, e = j.ComposeOrReplay(uncertain); e == nil || calls != 3 {
		return errors.New("postcommit authority")
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return e
	}
	identity := bytes.Join([][]byte{record(d, "authority").Bytes["accountId"], uncertain.Message, record(d, "authority").Bytes["deviceId"], record(d, "authority").Bytes["lineId"]}, nil)
	var saved []byte
	e = db.QueryRow("SELECT envelope FROM outbound WHERE identity=?", identity).Scan(&saved)
	db.Close()
	if e != nil {
		return e
	}
	uncertain.Authority = r.Authority
	recovered, e := j.ComposeOrReplay(uncertain)
	if e != nil || !bytes.Equal(saved, recovered) {
		return errors.New("ambiguous exact recovery")
	}
	newer := r
	newer.Message = append([]byte(nil), r.Message...)
	newer.Message[0] ^= 2
	phase := 0
	newer.Authority = func() (hpke.ElectionRecord, uint64, error) {
		phase++
		at := uint64(31000)
		if phase == 3 {
			at = 32000
		}
		return record(d, "authority"), at, nil
	}
	if _, e = j.ComposeOrReplay(newer); e != nil {
		return e
	}
	j.Close()
	j = open()
	newer.Authority = r.Authority
	if _, e = j.ComposeOrReplay(newer); e == nil {
		return errors.New("postcommit comparison not persisted")
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
	if _, e = hpke.ComposeProtected03(r); e == nil {
		return errors.New("closed signer")
	}
	j.Close()
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"envelope": base64.StdEncoding.EncodeToString(out), "expectedText": content, "checks": "exact replay, process CAS, ambiguity, clock rollback, strict input and custody passed"})
}
