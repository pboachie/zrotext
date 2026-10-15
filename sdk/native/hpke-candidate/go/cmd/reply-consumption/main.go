package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
	"path/filepath"
	"time"
)

func must(e error) {
	if e != nil {
		panic("fixture setup refused")
	}
}
func main() {
	var input struct {
		Fixture                         map[string]json.RawMessage
		Origin, Roots, Grant            string
		Clock                           []uint64
		Resume, Status, Active, Invalid bool
		Directory                       string
		Corrupt                         int
	}
	must(json.NewDecoder(os.Stdin).Decode(&input))
	b := func(n string) []byte {
		var s string
		must(json.Unmarshal(input.Fixture[n], &s))
		v, e := base64.StdEncoding.DecodeString(s)
		must(e)
		return v
	}
	root, e := h.EnrollRoot(b("rootPin"), b("fingerprint"))
	must(e)
	prior, e := h.VerifyManifest(b("predecessor"), root, nil, 2, 10000)
	must(e)
	active, e := h.VerifyManifest(b("activation"), root, prior, 2, 10000)
	must(e)
	scope := h.OriginalScope{Peer: "+12"}
	copy(scope.Account[:], b("account"))
	copy(scope.Device[:], b("device"))
	copy(scope.Line[:], b("line"))
	copy(scope.Interval[:], b("interval"))
	copy(scope.Connector[:], b("connector"))
	copy(scope.ReadGrant[:], b("readGrant"))
	copy(scope.Reader[:], b("originalReader"))
	path := filepath.Join(input.Directory, "reply.db")
	var checkpoint *h.OriginalReplyCheckpoint
	if input.Resume {
		checkpoint, e = h.OpenOriginalReplyCheckpoint(path, b("rootPin"), b("fingerprint"), scope)
	} else {
		checkpoint, e = h.CreateOriginalReplyCheckpoint(path, b("rootPin"), b("fingerprint"), scope, []*h.Manifest{prior, active}, 10000)
	}
	must(e)
	defer checkpoint.Close()
	transport, e := h.NewOriginalHTTP(input.Origin, time.Second, []byte(input.Roots))
	must(e)
	client, e := h.NewOriginalCurrentClient(transport, checkpoint, b("rootPin"), b("fingerprint"), scope, 10000)
	must(e)
	var event, request, activeID [16]byte
	copy(event[:], b("event"))
	request[15] = 1
	activeID[15] = 2
	if input.Invalid {
		request = [16]byte{}
	}
	var intent *h.OriginalOwnerReviewIntent
	file := filepath.Join(input.Directory, "intent.bin")
	if !input.Resume {
		var selected *[16]byte
		if input.Active {
			selected = &activeID
		}
		intent, e = client.PrepareOwnerReview(event, request, selected)
		if e == nil {
			raw := intent.Bytes()
			snapshot := intent.Bytes()
			raw[0] ^= 1
			if string(intent.Bytes()) != string(snapshot) {
				panic("intent aliases returned bytes")
			}
			f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			must(err)
			_, err = f.Write(snapshot)
			must(err)
			must(f.Sync())
			must(f.Close())
		}
	}
	if e == nil {
		raw, err := os.ReadFile(file)
		must(err)
		if input.Corrupt >= 0 {
			raw[input.Corrupt] ^= 1
		} else if input.Corrupt == -2 {
			raw = raw[:len(raw)-1]
		}
		intent, e = client.RestoreOwnerReviewIntent(raw)
	}
	out := map[string]any{"ok": false, "unknown": false}
	if e == nil {
		out["record"] = fmt.Sprintf("%x", intent.Bytes())
		at := 0
		clock := func() uint64 {
			if at >= len(input.Clock) {
				return input.Clock[len(input.Clock)-1]
			}
			n := input.Clock[at]
			at++
			return n
		}
		var value *h.OriginalOwnerReviewConsumption
		if input.Status {
			value, e = client.StatusOwnerReview(context.Background(), input.Grant, intent, clock)
		} else {
			value, e = client.ConsumeOwnerReview(context.Background(), input.Grant, intent, clock)
		}
		out["ok"] = e == nil
		if e == nil {
			out["event"] = fmt.Sprintf("%x", value.Event)
			out["consumption"] = fmt.Sprintf("%x", value.Consumption)
			out["active"] = nil
			if value.ActiveRequest != nil {
				out["active"] = fmt.Sprintf("%x", *value.ActiveRequest)
			}
			out["now"] = value.Authority.Authority().Now
		}
	}
	if e != nil {
		v, ok := e.(h.OriginalHTTPError)
		if !ok {
			panic("unexpected error type")
		}
		out["unknown"] = v.Unknown
		out["error"] = v.Error()
	}
	snapshot, e := checkpoint.Snapshot(scope, 50000)
	must(e)
	out["revision"] = snapshot.Revision
	out["floor"] = snapshot.Comparison
	json.NewEncoder(os.Stdout).Encode(out)
}
