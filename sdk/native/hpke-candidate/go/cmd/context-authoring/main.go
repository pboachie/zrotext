package main

import (
	"context"
	"encoding/base64"
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
		Ops                               []string
		Text                              *string
		Epoch, Revision                   uint64
		ReviewFail, ReviewBlock           bool
		Rotate, DraftChange               bool
		CurrentFailAt, SessionChangeAt    int
		DelayMS                           []uint64
		Origin, Roots, Cookie, CSRF, Mode string
		Enabled                           bool
		TimeoutMS, ValidForMS, SettleMS   uint64
		Fixture                           map[string]json.RawMessage
	}
	in.Epoch, in.Revision = 1, 1
	must(json.NewDecoder(os.Stdin).Decode(&in))
	text := "Synthetic reviewed facts 🌱"
	if in.Text != nil {
		text = *in.Text
	}
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
	var now, expires uint64
	must(json.Unmarshal(in.Fixture["now"], &now))
	must(json.Unmarshal(scope["expiresMs"], &expires))
	var contextID [16]byte
	copy(contextID[:], b(scope, "contextId"))
	var currents, sessions atomic.Int64
	state := struct {
		sync.Mutex
		csrf     string
		revision uint64
	}{csrf: in.CSRF, revision: in.Revision}
	current := func(context.Context) (h.ContextAuthoringCurrent, error) {
		n := int(currents.Add(1))
		if n == in.CurrentFailAt {
			return h.ContextAuthoringCurrent{}, h.ErrAuthentication
		}
		selected := binding
		if in.Mode == "binding" {
			selected.Session[0] ^= 1
		}
		return h.ContextAuthoringCurrent{Binding: selected, Manifest: m, Now: now, OwnerSessionLive: in.Mode != "owner-dead", ConsentLive: in.Mode != "consent-dead"}, nil
	}
	session := func(context.Context) (h.OwnerSession, error) {
		n := int(sessions.Add(1))
		state.Lock()
		csrf := state.csrf
		state.Unlock()
		if n == in.SessionChangeAt {
			csrf += "-changed"
		}
		return h.OwnerSession{Origin: in.Origin, Cookie: in.Cookie, CSRF: csrf}, nil
	}
	draft := func(context.Context) (h.TemplateDraftState, error) {
		state.Lock()
		defer state.Unlock()
		return h.TemplateDraftState{Epoch: in.Epoch, Revision: state.revision, CustodyLive: true}, nil
	}
	reviews := 0
	reviewEntered := make(chan struct{}, 1)
	reviewRelease := make(chan struct{})
	review := func(_ context.Context, v h.ContextAuthoringReview) (bool, error) {
		reviews++
		if in.ReviewBlock {
			reviewEntered <- struct{}{}
			<-reviewRelease
		}
		if in.ReviewFail {
			return false, nil
		}
		state.Lock()
		if in.Rotate {
			state.csrf += "-rotated"
		}
		if in.DraftChange {
			state.revision++
		}
		state.Unlock()
		return true, nil
	}
	authoring, e := h.NewOwnerContextAuthoring(h.ContextAuthoringOptions{Origin: in.Origin, Binding: binding, Context: contextID, Expires: expires, Enabled: in.Enabled, Timeout: time.Duration(in.TimeoutMS) * time.Millisecond, Observation: time.Duration(in.ValidForMS) * time.Millisecond, AdditionalRootsPEM: []byte(in.Roots), Current: current, Session: session, Draft: draft, Review: review})
	if e != nil {
		authoring = nil
	}
	start := time.Now()
	results := []any{}
	for i, op := range in.Ops {
		if i < len(in.DelayMS) {
			time.Sleep(time.Duration(in.DelayMS[i]) * time.Millisecond)
		}
		row := map[string]any{"phase": "closed", "pending": false, "source": false, "reviews": reviews}
		switch op {
		case "author":
			if authoring != nil {
				row["phase"] = authoring.Author(context.Background(), text, in.Epoch, in.Revision).Phase
			}
		case "retry":
			if authoring != nil {
				row["phase"] = authoring.RetryUnknown(context.Background()).Phase
			}
		case "verify":
			if authoring != nil {
				row["phase"] = authoring.VerifyUnknown(context.Background()).Phase
			}
		case "close":
			if authoring != nil {
				authoring.Close()
			}
		case "author-close-review":
			done := make(chan string, 1)
			go func() { done <- authoring.Author(context.Background(), text, in.Epoch, in.Revision).Phase }()
			select {
			case <-reviewEntered:
			case <-time.After(3 * time.Second):
				panic("review not entered")
			}
			authoring.Close()
			close(reviewRelease)
			row["phase"] = <-done
		default:
			panic("bad operation")
		}
		if authoring != nil {
			st := authoring.State()
			row["phase"] = st.Phase
			row["pending"] = st.Pending != nil
			row["source"] = authoring.SavedSource() != nil
		}
		row["reviews"] = reviews
		results = append(results, row)
	}
	elapsed := time.Since(start).Seconds()
	if authoring != nil {
		defer authoring.Close()
	}
	time.Sleep(time.Duration(in.SettleMS) * time.Millisecond)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"results": results, "elapsed": elapsed, "currentCalls": currents.Load(), "sessionCalls": sessions.Load(), "reviewCalls": reviews}))
}
