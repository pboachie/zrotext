package main

import (
	"context"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Only public installed APIs are used. Blocked authority never supplies a grant.
func limits() {
	require := func(ok bool) {
		if !ok {
			panic("installed context limit control failed")
		}
	}
	checks := 0
	scope := h.WorkflowContextScope{Kind: 1, Account: [16]byte{1}, Device: [16]byte{1}, Line: [16]byte{1}, Interval: [16]byte{1}, Context: [16]byte{1}, BindingGeneration: 1, Revision: 1, Expires: 10000, TrustGeneration: 1, ManifestVersion: 1, PeerDigest: [32]byte{1}, Reader: [32]byte{1}, ManifestDigest: [32]byte{1}}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := h.SealBoundedWorkflowContext(cancelled, func() (*h.Manifest, uint64, error) { called = true; return nil, 0, h.ErrAuthentication }, scope, h.OwnerContextReader, []byte{1})
	require(err != nil && !called)
	checks++
	release := make(chan struct{})
	defer closeRelease(release)
	var settled sync.WaitGroup
	var first chan error
	start := time.Now()
	for i := 0; i < 4; i++ {
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		entered := make(chan struct{})
		result := make(chan error, 1)
		settled.Add(1)
		go func() {
			_, e := h.SealBoundedWorkflowContext(ctx, func() (*h.Manifest, uint64, error) {
				close(entered)
				<-release
				settled.Done()
				return nil, 0, h.ErrAuthentication
			}, scope, h.OwnerContextReader, []byte{1})
			result <- e
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			panic("authority did not start")
		}
		if i == 0 {
			first = result
		} else {
			stop()
			select {
			case e := <-result:
				require(e != nil)
				checks++
			case <-time.After(time.Second):
				panic("cancel did not return")
			}
		}
	}
	select {
	case e := <-first:
		require(e != nil)
	case <-time.After(12 * time.Second):
		panic("deadline did not return")
	}
	require(time.Since(start) >= 9*time.Second && time.Since(start) < 12*time.Second)
	checks++
	called = false
	_, err = h.SealBoundedWorkflowContext(context.Background(), func() (*h.Manifest, uint64, error) { called = true; return nil, 0, h.ErrAuthentication }, scope, h.OwnerContextReader, []byte{1})
	require(err != nil && !called)
	checks++
	close(release)
	settled.Wait()
	var recovered atomic.Bool
	end := time.Now().Add(2 * time.Second)
	for !recovered.Load() && time.Now().Before(end) {
		_, err = h.SealBoundedWorkflowContext(context.Background(), func() (*h.Manifest, uint64, error) { recovered.Store(true); return nil, 0, h.ErrAuthentication }, scope, h.OwnerContextReader, []byte{1})
		require(err != nil)
		if !recovered.Load() {
			time.Sleep(time.Millisecond)
		}
	}
	require(recovered.Load())
	checks++
	json.NewEncoder(os.Stdout).Encode(map[string]int{"installed_context_limits": checks})
}

func closeRelease(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}
