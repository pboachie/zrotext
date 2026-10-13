//go:build windows

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"io"
	"os"
)

func exercise() (result error) {
	if e := hpke.ProbeHardware(); e != nil {
		return e
	}
	receipt, e := os.CreateTemp("", "zrotext-native-cng-pending-*.json")
	if e != nil {
		return e
	}
	defer receipt.Close()
	record := func(name string) error {
		if e := json.NewEncoder(receipt).Encode(map[string]string{"pending_alias": name}); e != nil {
			return e
		}
		return receipt.Sync()
	}
	key, e := hpke.CreateHardware(record)
	if e != nil {
		return e
	}
	defer func() {
		if e := key.Delete(); e != nil {
			result = errors.Join(result, e)
			key.Close()
		} else {
			if e = receipt.Truncate(0); e == nil {
				_, e = receipt.Seek(0, 0)
			}
			if e == nil {
				e = json.NewEncoder(receipt).Encode(map[string]bool{"owned_key_deleted": true})
			}
			if e == nil {
				e = receipt.Sync()
			}
			result = errors.Join(result, e)
		}
	}()
	public, e := key.PublicPoint()
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
	getString := func(name string) string {
		var value string
		if e := json.Unmarshal(d[name], &value); e != nil {
			panic(e)
		}
		return value
	}
	b := func(name string) []byte {
		v, e := base64.StdEncoding.Strict().DecodeString(getString(name))
		if e != nil {
			panic(e)
		}
		return v
	}
	if _, ok := d["archiveScalar"]; ok {
		return errors.New("producer exported recipient scalar")
	}
	var now uint64
	if e = json.Unmarshal(d["now"], &now); e != nil {
		return e
	}
	root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
	if e != nil {
		return e
	}
	m, e := hpke.VerifyManifest(b("manifest"), root, nil, 2, now)
	if e != nil {
		return e
	}
	context := hpke.ArchiveContext{Account: b("account"), Device: b("device"), Line: b("line"), Reader: b("reader"), Peer: "+12", Now: now}
	reopened, e := hpke.OpenHardware(key.Alias(), public)
	if e != nil {
		return e
	}
	defer reopened.Close()
	value, e := hpke.OpenHardwareArchive02(b("inbound"), m, m, reopened, context)
	if e != nil {
		return e
	}
	if value != getString("text") {
		return errors.New("plaintext mismatch")
	}
	other, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	if wrong, e := hpke.OpenHardware(key.Alias(), other.PublicKey().Bytes()); e == nil {
		wrong.Close()
		return errors.New("wrong public binding accepted")
	}
	reopened.Close()
	if _, e = hpke.OpenHardwareArchive02(b("inbound"), m, m, reopened, context); e == nil {
		return errors.New("closed provider accepted")
	}
	return nil
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--probe" {
		if e := hpke.ProbeHardware(); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(77)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "unsupported arguments")
		os.Exit(1)
	}
	if e := exercise(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("native Windows hardware archive read, reopen and exact owned-key cleanup passed")
}
