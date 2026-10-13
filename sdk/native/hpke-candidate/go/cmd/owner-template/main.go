package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
	"sync/atomic"
	"time"
)

func must(e error) {
	if e != nil {
		panic("fixture setup refused")
	}
}
func main() {
	var in struct {
		Fixture                                               map[string]json.RawMessage
		Origin, Roots, Cookie, CSRF, SessionOrigin, Mode      string
		Enabled                                               bool
		TimeoutMS, ValidForMS, SleepMS, SettleMS              uint64
		CurrentFailAt, CurrentSleepAt, SessionChangeAt, Reads int
		Now                                                   []uint64
	}
	must(json.NewDecoder(os.Stdin).Decode(&in))
	b := func(o map[string]json.RawMessage, k string) []byte {
		var s string
		must(json.Unmarshal(o[k], &s))
		v, e := base64.StdEncoding.Strict().DecodeString(s)
		must(e)
		return v
	}
	root, e := h.EnrollRoot(b(in.Fixture, "rootPin"), b(in.Fixture, "fingerprint"))
	must(e)
	m, e := h.VerifyManifest(b(in.Fixture, "manifest"), root, nil, 2, 10000)
	must(e)
	var raw map[string]json.RawMessage
	must(json.Unmarshal(in.Fixture["binding"], &raw))
	var binding h.OwnerBinding
	for k, p := range map[string][]byte{"account": binding.Account[:], "device": binding.Device[:], "line": binding.Line[:], "interval": binding.Interval[:], "session": binding.Session[:], "phoneReader": binding.PhoneReader[:], "archiveReader": binding.ArchiveReader[:]} {
		v := b(raw, k)
		if len(v) != len(p) {
			panic("fixture binding")
		}
		copy(p, v)
	}
	must(json.Unmarshal(raw["peer"], &binding.Peer))
	must(json.Unmarshal(raw["generation"], &binding.Generation))
	var scope map[string]json.RawMessage
	must(json.Unmarshal(in.Fixture["scope"], &scope))
	var template [16]byte
	copy(template[:], b(scope, "templateId"))
	var currents, sessions atomic.Int64
	current := func(context.Context) (h.OwnerTemplateAuthority, error) {
		n := int(currents.Add(1))
		if n == in.CurrentSleepAt {
			time.Sleep(time.Duration(in.SleepMS) * time.Millisecond)
		}
		if n == in.CurrentFailAt {
			return h.OwnerTemplateAuthority{}, h.ErrAuthentication
		}
		at := min(n-1, len(in.Now)-1)
		a := h.OwnerTemplateAuthority{Binding: binding, Manifest: m, Now: in.Now[at], ValidFor: time.Duration(in.ValidForMS) * time.Millisecond, OwnerSessionLive: in.Mode != "owner-dead", ConsentLive: in.Mode != "consent-dead", Active: in.Mode != "inactive"}
		if in.Mode == "binding" {
			a.Binding.Session[0] ^= 1
		}
		return a, nil
	}
	session := func(context.Context) (h.OwnerSession, error) {
		n := int(sessions.Add(1))
		origin := in.Origin
		if in.SessionOrigin != "" {
			origin = in.SessionOrigin
		}
		s := h.OwnerSession{Origin: origin, Cookie: in.Cookie, CSRF: in.CSRF}
		if n == in.SessionChangeAt {
			s.CSRF += "-changed"
		}
		return s, nil
	}
	reader, e := h.NewOwnerTemplateReader(h.OwnerTemplateOptions{Origin: in.Origin, Binding: binding, Template: template, Enabled: in.Enabled, Timeout: time.Duration(in.TimeoutMS) * time.Millisecond, AdditionalRootsPEM: []byte(in.Roots), Current: current, Session: session})
	start := time.Now()
	results := []any{}
	for i := 0; i < in.Reads; i++ {
		result := map[string]any{"accepted": false}
		if e == nil {
			snapshot, err := reader.ReadLatest(context.Background())
			if err == nil {
				result["accepted"] = true
				result["digest"] = snapshot.EncryptedDigest()
				result["ack"] = snapshot.RequestAcknowledged()
				result["pending"] = snapshot.MatchesPending()
				copy := snapshot.Envelope()
				copy[0] ^= 1
				if copy[0] == snapshot.Envelope()[0] {
					panic("snapshot aliases caller")
				}
			} else {
				result["error"] = err.Error()
				if typed, ok := err.(h.OwnerTemplateError); ok {
					result["unknown"] = typed.Unknown
					result["code"] = typed.Code
				}
			}
		} else {
			result["error"] = e.Error()
		}
		results = append(results, result)
	}
	elapsed := time.Since(start).Seconds()
	if reader != nil {
		defer reader.Close()
	}
	time.Sleep(time.Duration(in.SettleMS) * time.Millisecond)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"results": results, "elapsed": elapsed, "currentCalls": currents.Load(), "sessionCalls": sessions.Load()}))
}
