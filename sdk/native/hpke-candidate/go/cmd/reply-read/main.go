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

type reader func(*h.OriginalCurrentClient, context.Context, string, [16]byte, uint64, []byte, func() uint64) (*h.VerifiedOriginalRead, error)

func main() {
	read, cleanup := selectReader()
	defer cleanup()
	var input struct {
		Fixture              map[string]json.RawMessage
		Origin, Roots, Grant string
		Clock                []uint64
		Retry, Conflict      bool
		Baseline             uint64
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
	dir, e := os.MkdirTemp("", "zrotext-current-")
	must(e)
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "reply.db")
	checkpoint, e := h.CreateOriginalReplyCheckpoint(path, b("rootPin"), b("fingerprint"), scope, []*h.Manifest{prior, active}, 10000)
	must(e)
	transport, e := h.NewOriginalHTTP(input.Origin, time.Second, []byte(input.Roots))
	must(e)
	client, e := h.NewOriginalCurrentClient(transport, checkpoint, b("rootPin"), b("fingerprint"), scope, 10000)
	must(e)
	at := 0
	clock := func() uint64 {
		if input.Conflict && at == 2 {
			s, e := checkpoint.Snapshot(scope, 10000)
			must(e)
			_, e = checkpoint.Accept(scope, s.History, s.Revision, 10000, func(_ *h.Manifest, n uint64) (uint64, error) { return n, nil })
			must(e)
		}
		if at >= len(input.Clock) {
			return input.Clock[len(input.Clock)-1]
		}
		v := input.Clock[at]
		at++
		return v
	}
	var event [16]byte
	copy(event[:], b("event"))
	var scalar []byte
	if input.Fixture["originalScalar"] != nil {
		scalar = b("originalScalar")
	}
	current, e := read(client, context.Background(), input.Grant, event, input.Baseline, scalar, clock)
	out := map[string]any{"ok": e == nil}
	if e == nil {
		a := current.Authority
		out["plaintext"] = current.Plaintext
		out["digest"] = fmt.Sprintf("%x", current.EnvelopeDigest)
		out["baseline"] = current.AcceptedManifestVersion
		out["now"] = a.Now
		out["version"] = a.Manifest.Version()
	}
	if input.Retry {
		_, e = client.Current(context.Background(), input.Grant, func() uint64 { return 10000 })
		out["stale_refused"] = e != nil
	}
	must(checkpoint.Close())
	checkpoint, e = h.OpenOriginalReplyCheckpoint(path, b("rootPin"), b("fingerprint"), scope)
	must(e)
	defer checkpoint.Close()
	snapshot, e := checkpoint.Snapshot(scope, 50000)
	must(e)
	out["revision"] = snapshot.Revision
	out["floor"] = snapshot.Comparison
	out["history"] = len(snapshot.History)
	_, e = checkpoint.Snapshot(scope, snapshot.Comparison-1)
	out["rollback_refused"] = e != nil
	json.NewEncoder(os.Stdout).Encode(out)
}
