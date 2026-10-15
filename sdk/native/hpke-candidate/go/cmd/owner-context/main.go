package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
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
	if len(os.Args) == 2 && os.Args[1] == "--limits" {
		limits()
		return
	}
	var in struct {
		CurrentBlockAt                                        int
		Ops                                                   []string
		ReviewFail                                            bool
		ReviewSleepMS                                         uint64
		DelayMS                                               []uint64
		RequestID                                             string
		Expected                                              uint8
		Envelope                                              string
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
	var kind byte
	must(json.Unmarshal(scope["kind"], &kind))
	var template [16]byte
	copy(template[:], b(scope, "contextId"))
	var currents, sessions atomic.Int64
	currentEntered := make(chan struct{}, 1)
	currentRelease := make(chan struct{})
	current := func(context.Context) (h.OwnerTemplateAuthority, error) {
		n := int(currents.Add(1))
		if n == in.CurrentBlockAt {
			currentEntered <- struct{}{}
			<-currentRelease
		}
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
	reviewCount := 0
	reviewEntered := make(chan struct{}, 1)
	reviewRelease := make(chan struct{})
	race := false
	for _, op := range in.Ops {
		if op == "race-prepare" {
			race = true
		}
	}
	review := func(ctx context.Context, v h.ContextWriteReview) error {
		reviewCount++
		if race && reviewCount == 1 {
			reviewEntered <- struct{}{}
			<-reviewRelease
		}
		if in.ReviewSleepMS > 0 {
			time.Sleep(time.Duration(in.ReviewSleepMS) * time.Millisecond)
		}
		if in.ReviewFail {
			return h.ErrAuthentication
		}
		return nil
	}
	reader, e := h.NewOwnerWorkflowContextClient(h.OwnerContextOptions{Origin: in.Origin, Binding: binding, Context: template, Kind: kind, Enabled: in.Enabled, Timeout: time.Duration(in.TimeoutMS) * time.Millisecond, AdditionalRootsPEM: []byte(in.Roots), Current: current, Session: session, Review: review})
	start := time.Now()
	results := []any{}
	wire := b(in.Fixture, "envelope")
	if in.Envelope != "" {
		wire, e = base64.StdEncoding.Strict().DecodeString(in.Envelope)
		must(e)
	}
	var selected h.WorkflowContextScope
	if len(wire) >= 222 {
		selected.Kind = wire[5]
		for i, p := range [][]byte{selected.Account[:], selected.Device[:], selected.Line[:], selected.Interval[:], selected.Context[:]} {
			copy(p, wire[6+i*16:22+i*16])
		}
		for i, p := range []*uint64{&selected.BindingGeneration, &selected.Revision, &selected.Expires, &selected.TrustGeneration, &selected.ManifestVersion} {
			*p = binary.BigEndian.Uint64(wire[86+i*8 : 94+i*8])
		}
		for i, p := range [][]byte{selected.PeerDigest[:], selected.Reader[:], selected.ManifestDigest[:]} {
			copy(p, wire[126+i*32:158+i*32])
		}
	}
	var ticket *h.ContextTicket
	for i, op := range in.Ops {
		if i < len(in.DelayMS) {
			time.Sleep(time.Duration(in.DelayMS[i]) * time.Millisecond)
		}
		result := map[string]any{"accepted": false, "unknown": false, "ack": false, "matches": false}
		var err error = e
		if err == nil {
			switch op {
			case "race-prepare":
				type prepared struct {
					ticket *h.ContextTicket
					err    error
				}
				done := make(chan prepared, 1)
				go func() {
					t, e := reader.Prepare(context.Background(), in.RequestID, in.Expected, selected, wire)
					done <- prepared{t, e}
				}()
				select {
				case <-reviewEntered:
				case <-time.After(3 * time.Second):
					panic("review not entered")
				}
				_, rejected := reader.Prepare(context.Background(), in.RequestID, in.Expected, selected, wire)
				if rejected == nil {
					panic("concurrent prepare accepted")
				}
				close(reviewRelease)
				first := <-done
				ticket = first.ticket
				err = first.err
			case "prepare":
				var next *h.ContextTicket
				next, err = reader.Prepare(context.Background(), in.RequestID, in.Expected, selected, wire)
				if err == nil {
					ticket = next
				}
			case "close-commit":
				done := make(chan error, 1)
				go func() { _, e := reader.Commit(context.Background(), ticket); done <- e }()
				select {
				case <-currentEntered:
				case <-time.After(3 * time.Second):
					panic("current not entered")
				}
				reader.Close()
				close(currentRelease)
				err = <-done
			case "commit", "retry":
				var ack h.ContextReceipt
				if op == "commit" {
					ack, err = reader.Commit(context.Background(), ticket)
				} else {
					ack, err = reader.RetryUnknown(context.Background(), ticket)
				}
				if err == nil {
					result["ack"] = true
					result["digest"] = ack.EnvelopeDigest
				}
			case "verify":
				var receipt h.ContextReceipt
				receipt, err = reader.VerifyUnknown(context.Background(), ticket)
				if err == nil {
					result["ack"] = receipt.RequestAcknowledged
					result["digest"] = receipt.EnvelopeDigest
					result["matches"] = true
				}
			case "wrong":
				_, err = reader.Commit(context.Background(), &h.ContextTicket{})
			case "pending":
			case "mutate":
				wire[len(wire)-1] ^= 1
			case "close":
				reader.Close()
			default:
				panic("bad operation")
			}
		}
		if err == nil {
			result["accepted"] = true
		} else if v, ok := err.(h.OwnerContextError); ok {
			result["unknown"] = v.State == "unknown"
			result["code"] = v.Code
			result["state"] = v.State
		}
		if reader != nil {
			pending := reader.Pending()
			result["pending"] = pending != nil
			if pending != nil {
				result["pendingID"] = pending.RequestID
				result["pendingDigest"] = pending.EnvelopeDigest
			}
		}
		results = append(results, result)
	}
	elapsed := time.Since(start).Seconds()
	if reader != nil {
		defer reader.Close()
	}
	time.Sleep(time.Duration(in.SettleMS) * time.Millisecond)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"results": results, "elapsed": elapsed, "currentCalls": currents.Load(), "sessionCalls": sessions.Load(), "reviewCalls": reviewCount}))
}
