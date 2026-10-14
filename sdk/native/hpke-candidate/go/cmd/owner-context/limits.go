package main

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Public installed APIs only. A held callback never supplies current authority.
func limits() {
	scope := h.WorkflowContextScope{Kind: 1, Account: [16]byte{1}, Device: [16]byte{1}, Line: [16]byte{1}, Interval: [16]byte{1}, Context: [16]byte{1}, BindingGeneration: 1, Revision: 1, Expires: 10000, TrustGeneration: 1, ManifestVersion: 1, PeerDigest: [32]byte{1}, Reader: [32]byte{1}, ManifestDigest: [32]byte{1}}
	wire, e := scope.AAD()
	must(e)
	scalar := make([]byte, 32)
	scalar[31] = 1
	key, e := ecdh.P256().NewPrivateKey(scalar)
	must(e)
	wire = append(wire, key.PublicKey().Bytes()...)
	wire = binary.BigEndian.AppendUint32(wire, 17)
	wire = append(wire, make([]byte, 17)...)
	binding := h.OwnerBinding{Account: scope.Account, Device: scope.Device, Line: scope.Line, Interval: scope.Interval, Session: [16]byte{1}, Generation: 1, Peer: "+12", PhoneReader: [32]byte{1}, ArchiveReader: scope.Reader}
	makeClient := func(source func(context.Context) (h.OwnerTemplateAuthority, error)) *h.OwnerWorkflowContextClient {
		c, e := h.NewOwnerWorkflowContextClient(h.OwnerContextOptions{Origin: "https://example.test", Binding: binding, Context: scope.Context, Kind: 1, Enabled: true, Timeout: 10 * time.Second, Current: source, Session: func(context.Context) (h.OwnerSession, error) {
			return h.OwnerSession{Origin: "https://example.test", Cookie: "synthetic-owner=opaque", CSRF: "synthetic-csrf"}, nil
		}, Review: func(context.Context, h.ContextWriteReview) error { return nil }})
		must(e)
		return c
	}
	request := "00000000-0000-0000-0000-000000000041"
	check := func(ok bool) {
		if !ok {
			panic("installed owner-context limits refused")
		}
	}
	checks := 0
	var called atomic.Int64
	closed := makeClient(func(context.Context) (h.OwnerTemplateAuthority, error) {
		called.Add(1)
		return h.OwnerTemplateAuthority{}, h.ErrAuthentication
	})
	closed.Close()
	_, e = closed.Prepare(context.Background(), request, 0, scope, wire)
	check(e != nil && called.Load() == 0)
	checks++
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	entered := make(chan struct{}, 8)
	var settled sync.WaitGroup
	settled.Add(8)
	source := func(context.Context) (h.OwnerTemplateAuthority, error) {
		entered <- struct{}{}
		<-release
		settled.Done()
		return h.OwnerTemplateAuthority{}, h.ErrAuthentication
	}
	type result struct {
		err     error
		elapsed time.Duration
	}
	clients := make([]*h.OwnerWorkflowContextClient, 8)
	results := make([]chan result, 8)
	for i := range clients {
		clients[i] = makeClient(source)
		results[i] = make(chan result, 1)
		go func(c *h.OwnerWorkflowContextClient, out chan result) {
			start := time.Now()
			_, err := c.Prepare(context.Background(), request, 0, scope, wire)
			out <- result{err, time.Since(start)}
		}(clients[i], results[i])
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			panic("authority callback not entered")
		}
	}
	for i := 1; i < 8; i++ {
		start := time.Now()
		clients[i].Close()
		select {
		case r := <-results[i]:
			check(r.err != nil && time.Since(start) < time.Second)
		case <-time.After(time.Second):
			panic("close blocked foreground")
		}
		checks++
	}
	ninth := makeClient(func(context.Context) (h.OwnerTemplateAuthority, error) {
		called.Add(1)
		return h.OwnerTemplateAuthority{}, h.ErrAuthentication
	})
	_, e = ninth.Prepare(context.Background(), request, 0, scope, wire)
	refusal, ok := e.(h.OwnerContextError)
	check(ok && refusal.Code == "capacity" && called.Load() == 0)
	ninth.Close()
	checks++
	select {
	case r := <-results[0]:
		check(r.err != nil && r.elapsed >= 9*time.Second && r.elapsed < 12*time.Second)
	case <-time.After(12 * time.Second):
		panic("deadline did not return")
	}
	checks++
	// All eight callbacks still hold admission, including the expired first call.
	ninth = makeClient(func(context.Context) (h.OwnerTemplateAuthority, error) {
		called.Add(1)
		return h.OwnerTemplateAuthority{}, h.ErrAuthentication
	})
	_, e = ninth.Prepare(context.Background(), request, 0, scope, wire)
	refusal, ok = e.(h.OwnerContextError)
	check(ok && refusal.Code == "capacity" && called.Load() == 0)
	ninth.Close()
	releaseOnce.Do(func() { close(release) })
	settled.Wait()
	end := time.Now().Add(2 * time.Second)
	for called.Load() == 0 && time.Now().Before(end) {
		recovered := makeClient(func(context.Context) (h.OwnerTemplateAuthority, error) {
			called.Add(1)
			return h.OwnerTemplateAuthority{}, h.ErrAuthentication
		})
		_, e = recovered.Prepare(context.Background(), request, 0, scope, wire)
		recovered.Close()
		check(e != nil)
		if called.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	check(called.Load() == 1)
	checks++
	check(checks == 11)
	must(json.NewEncoder(os.Stdout).Encode(map[string]int{"installed_owner_context_limits": checks}))
}
