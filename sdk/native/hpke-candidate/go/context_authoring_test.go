package hpke

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func authoringFixture(current func(context.Context) (ContextAuthoringCurrent, error)) (*OwnerContextAuthoring, error) {
	binding := OwnerBinding{Account: [16]byte{1}, Device: [16]byte{1}, Line: [16]byte{1}, Interval: [16]byte{1}, Session: [16]byte{1}, Generation: 1, Peer: "+12", PhoneReader: [32]byte{1}, ArchiveReader: [32]byte{1}}
	return NewOwnerContextAuthoring(ContextAuthoringOptions{Origin: "https://owner.example.invalid", Binding: binding, Context: [16]byte{2}, Expires: 1 << 40, Enabled: true, Timeout: 2 * time.Second, Observation: 2 * time.Second, Current: current, Session: func(context.Context) (OwnerSession, error) {
		return OwnerSession{}, ErrAuthentication
	}, Draft: func(context.Context) (TemplateDraftState, error) {
		return TemplateDraftState{Epoch: 1, Revision: 1, CustodyLive: true}, nil
	}, Review: func(context.Context, ContextAuthoringReview) (bool, error) { return true, nil }})
}

// An unresolved host callback keeps this author's admission; a fifth
// concurrent author is refused before any callback, and admission frees
// once the blocked workers settle.
func TestAuthoringUnresolvedCallbacksRetainAdmission(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	block := func(context.Context) (ContextAuthoringCurrent, error) {
		entered <- struct{}{}
		<-release
		return ContextAuthoringCurrent{}, ErrAuthentication
	}
	states := make(chan ContextAuthoringState, 4)
	for i := 0; i < 4; i++ {
		authoring, e := authoringFixture(block)
		if e != nil {
			t.Fatal(e)
		}
		go func() { states <- authoring.Author(context.Background(), "Facts", 1, 1) }()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("host callback not entered")
		}
	}
	extra, e := authoringFixture(func(context.Context) (ContextAuthoringCurrent, error) {
		return ContextAuthoringCurrent{}, ErrAuthentication
	})
	if e != nil {
		t.Fatal(e)
	}
	if state := extra.Author(context.Background(), "Facts", 1, 1); state.Phase != "refused" {
		t.Fatalf("fifth author admitted: %+v", state)
	}
	close(release)
	for i := 0; i < 4; i++ {
		select {
		case <-states:
		case <-time.After(3 * time.Second):
			t.Fatal("blocked author did not settle")
		}
	}
	var currents atomic.Int32
	after, e := authoringFixture(func(context.Context) (ContextAuthoringCurrent, error) {
		currents.Add(1)
		return ContextAuthoringCurrent{}, ErrAuthentication
	})
	if e != nil {
		t.Fatal(e)
	}
	if state := after.Author(context.Background(), "Facts", 1, 1); currents.Load() != 1 || state.Phase != "closed" {
		t.Fatalf("admission not released: %+v currents=%d", state, currents.Load())
	}
}
