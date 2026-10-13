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

func exercise(elected bool) (result error) {
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
	var public []byte
	defer func() {
		alias := key.Alias()
		if e := key.Delete(); e != nil {
			result = errors.Join(result, e)
			key.Close()
		} else {
			if len(public) == 65 {
				if reopened, err := hpke.OpenHardware(alias, public); err == nil {
					reopened.Close()
					result = errors.Join(result, errors.New("deleted key reopened"))
					return
				}
			}
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
	getString := func(name string) string {
		var value string
		if e := json.Unmarshal(d[name], &value); e != nil {
			panic(e)
		}
		return value
	}
	privateField := "archiveScalar"
	textField := "text"
	if elected {
		privateField = "readerScalar"
		textField = "bodyText"
	}
	if _, ok := d[privateField]; ok {
		return errors.New("producer exported selected recipient scalar")
	}
	reopened, e := hpke.OpenHardware(key.Alias(), public)
	if e != nil {
		return e
	}
	defer reopened.Close()
	value, e := openFixture(d, reopened, elected, "+12")
	if e != nil {
		return e
	}
	if value != getString(textField) {
		return errors.New("plaintext mismatch")
	}
	if elected {
		if _, e = openFixture(d, reopened, true, "+13"); e == nil {
			return errors.New("wrong peer accepted")
		}
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
	if _, e = openFixture(d, reopened, elected, "+12"); e == nil {
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
	elected := len(os.Args) == 2 && os.Args[1] == "--elected"
	if len(os.Args) != 1 && !elected {
		fmt.Fprintln(os.Stderr, "unsupported arguments")
		os.Exit(1)
	}
	if e := exercise(elected); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("native Windows hardware profile read, reopen and exact owned-key cleanup passed")
}

func openFixture(d map[string]json.RawMessage, custody *hpke.HardwareRecipient, elected bool, peer string) (string, error) {
	b := func(name string) []byte {
		var s string
		if e := json.Unmarshal(d[name], &s); e != nil {
			panic(e)
		}
		v, e := base64.StdEncoding.Strict().DecodeString(s)
		if e != nil {
			panic(e)
		}
		return v
	}
	root, e := hpke.EnrollRoot(b("rootPin"), b("fingerprint"))
	if e != nil {
		return "", e
	}
	if elected {
		record := func(name string) hpke.ElectionRecord {
			var raw map[string]json.RawMessage
			if e := json.Unmarshal(d[name], &raw); e != nil {
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
		prior, e := hpke.VerifyManifest(b("signed02"), root, nil, 2, 10000)
		if e != nil {
			return "", e
		}
		proof, e := hpke.VerifyAcceptedElection03(b("bundle"), b("core"), record("accepted"), prior, b("signed02"), b("signed03"), b("deviceSigningPoint"), b("ownerApprovalPoint"))
		if e != nil {
			return "", e
		}
		return hpke.OpenHardwareElected03(b("envelope"), proof.AcceptedManifest(), proof, record("authority"), custody, hpke.ElectedContext{Message: b("message"), Peer: peer, Now: 30000})
	}
	var now uint64
	if e = json.Unmarshal(d["now"], &now); e != nil {
		return "", e
	}
	m, e := hpke.VerifyManifest(b("manifest"), root, nil, 2, now)
	if e != nil {
		return "", e
	}
	return hpke.OpenHardwareArchive02(b("inbound"), m, m, custody, hpke.ArchiveContext{Account: b("account"), Device: b("device"), Line: b("line"), Reader: b("reader"), Peer: peer, Now: now})
}
