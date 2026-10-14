package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
	"sync"
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
		DelayMS                                                            uint64
		PriorSaved, PriorUnknown, ForeignReview                            bool
		ProbeExpired                                                       bool
		Commit                                                             bool
		Repeat                                                             int
		Decision                                                           bool
		EpochChanged, RevisionChanged, CustodyLost, OwnerLost, CSRFChanged bool
		CustodyLive                                                        bool
		ReviewSleepMS                                                      uint64
		Template                                                           string
		Values                                                             map[string]string
		ReviewBlock                                                        bool
		ClientCloseAt                                                      int
		Fixture                                                            map[string]json.RawMessage
		Origin, Roots, Cookie, CSRF, SessionOrigin, Mode                   string
		Enabled                                                            bool
		TimeoutMS, ValidForMS, SleepMS, SettleMS                           uint64
		CurrentFailAt, CurrentSleepAt, SessionChangeAt                     int
		Now                                                                []uint64
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
	var reviewed, metadata atomic.Int64
	var currents, sessions atomic.Int64
	var client *h.OwnerTemplateClient
	current := func(context.Context) (h.OwnerTemplateAuthority, error) {
		n := int(currents.Add(1))
		if n == in.ClientCloseAt && client != nil {
			client.Close()
		}
		if n == in.CurrentSleepAt {
			time.Sleep(time.Duration(in.SleepMS) * time.Millisecond)
		}
		if n == in.CurrentFailAt {
			return h.OwnerTemplateAuthority{}, h.ErrAuthentication
		}
		at := min(n-1, len(in.Now)-1)
		a := h.OwnerTemplateAuthority{Binding: binding, Manifest: m, Now: in.Now[at], ValidFor: time.Duration(in.ValidForMS) * time.Millisecond, OwnerSessionLive: in.Mode != "owner-dead" && !(in.OwnerLost && reviewed.Load() > 0), ConsentLive: in.Mode != "consent-dead", Active: in.Mode != "inactive"}
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
		if n == in.SessionChangeAt || (in.CSRFChanged && reviewed.Load() > 0) {
			s.CSRF += "-changed"
		}
		return s, nil
	}
	options := h.OwnerTemplateOptions{Origin: in.Origin, Binding: binding, Template: template, Enabled: in.Enabled, Timeout: time.Duration(in.TimeoutMS) * time.Millisecond, AdditionalRootsPEM: []byte(in.Roots), Current: current, Session: session}

	var barrier sync.WaitGroup
	if in.ReviewBlock {
		barrier.Add(1)
	}
	author, e := h.NewOwnerTemplateAuthoring(options, func(context.Context, h.TemplateCiphertextReview) error { metadata.Add(1); return nil }, func(context.Context) (h.TemplateDraftState, error) {
		v := h.TemplateDraftState{Epoch: 1, Revision: 1, CustodyLive: in.CustodyLive}
		if reviewed.Load() > 0 {
			if in.EpochChanged {
				v.Epoch++
			}
			if in.RevisionChanged {
				v.Revision++
			}
			if in.CustodyLost {
				v.CustodyLive = false
			}
		}
		return v, nil
	}, func(context.Context, h.TemplateDraftReview) (bool, error) {
		reviewed.Add(1)
		if in.ReviewBlock {
			barrier.Wait()
		}
		time.Sleep(time.Duration(in.ReviewSleepMS) * time.Millisecond)
		return in.Decision, nil
	})
	if e != nil {
		panic("author setup")
	}
	defer author.Close()
	client = author.Client()
	wire := b(in.Fixture, "envelope")
	var selected h.EncryptedTemplateScope
	for i, p := range [][]byte{selected.Account[:], selected.Device[:], selected.Line[:], selected.Interval[:], selected.Template[:]} {
		copy(p, wire[6+i*16:22+i*16])
	}
	for i, p := range []*uint64{&selected.BindingGeneration, &selected.Revision, &selected.Expires, &selected.TrustGeneration, &selected.ManifestVersion} {
		*p = binary.BigEndian.Uint64(wire[86+i*8 : 94+i*8])
	}
	for i, p := range [][]byte{selected.PeerDigest[:], selected.Reader[:], selected.ManifestDigest[:]} {
		copy(p, wire[126+i*32:158+i*32])
	}
	content, e := h.NewTemplateContent(in.Template, in.Values)

	var ticket *h.TemplateTicket
	if in.PriorSaved || in.PriorUnknown {
		ticket, e = client.PrepareSave(context.Background(), selected, "00000000-0000-0000-0000-000000000041", 0, wire)
		must(e)
		if in.PriorUnknown {
			_, err := client.Commit(context.Background(), ticket)
			if v, ok := err.(h.OwnerTemplateError); !ok || !v.Unknown {
				panic("expected unknown")
			}
		}
	}

	results := []bool{}
	start := time.Now()
	prepare := func() {
		if e != nil {
			results = append(results, false)
			return
		}
		next, err := author.Prepare(context.Background(), "00000000-0000-0000-0000-000000000041", 0, selected, content, 1, 1)
		results = append(results, err == nil)
		if err == nil {
			ticket = next
		}
	}
	if in.ReviewBlock {
		done := make(chan struct{})
		go func() { prepare(); close(done) }()
		for reviewed.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		if in.ForeignReview {
			ticket, e = client.PrepareSave(context.Background(), selected, "00000000-0000-0000-0000-000000000041", 0, wire)
			must(e)
		} else {
			_, err := author.Prepare(context.Background(), "00000000-0000-0000-0000-000000000041", 0, selected, content, 1, 1)
			if err == nil {
				panic("concurrent prepare accepted")
			}
		}
		barrier.Done()
		<-done
	} else {
		for i := 0; i < in.Repeat; i++ {
			prepare()
		}
	}
	elapsed := time.Since(start).Seconds()
	time.Sleep(time.Duration(in.DelayMS) * time.Millisecond)
	ack := false
	if in.Commit && ticket != nil {
		var err error
		if in.PriorUnknown {
			_, err = client.RetryUnknown(context.Background(), ticket)
		} else {
			_, err = client.Commit(context.Background(), ticket)
		}
		ack = err == nil
	}

	fresh, read := false, false
	if in.ProbeExpired {
		_, err := client.PrepareSave(context.Background(), selected, "00000000-0000-0000-0000-000000000042", 0, wire)
		fresh = err == nil
		_, err = client.ReadLatest(context.Background())
		read = err == nil
	}
	time.Sleep(time.Duration(in.SettleMS) * time.Millisecond)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"accepted": results, "ack": ack, "fresh": fresh, "read": read, "reviewed": reviewed.Load(), "metadata": metadata.Load(), "currentCalls": currents.Load(), "elapsed": elapsed}))
}
