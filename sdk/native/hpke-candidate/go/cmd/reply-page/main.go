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
		Fixture              map[string]json.RawMessage
		Origin, Roots, Grant string
		Clock                []uint64
		Retry, Conflict      bool
		Limit                uint8
		Cursor               *h.OriginalReplyCursor
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
	current, e := client.Page(context.Background(), input.Grant, input.Cursor, input.Limit, clock)
	out := map[string]any{"ok": e == nil}
	if e == nil {
		a := current.Authority.Authority()
		rows := []any{}
		for _, r := range current.Events {
			ids := []string{}
			for _, id := range r.ActiveRequestIDs {
				ids = append(ids, fmt.Sprintf("%x", id))
			}
			rows = append(rows, map[string]any{"event": fmt.Sprintf("%x", r.Event), "at": r.AcceptedAt, "observed": r.ObservedAt, "historical": r.HistoricalManifestVersion, "activation": r.ActivationManifestVersion, "disposition": r.Disposition, "requests": ids})
		}
		out["events"] = rows
		out["next"] = nil
		if current.Next != nil {
			out["next"] = map[string]any{"event": fmt.Sprintf("%x", current.Next.Event), "at": current.Next.AcceptedAt}
		}
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
