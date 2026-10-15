package hpke

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestContextRetainedWorkersAndOwnedCleanup(t *testing.T) {
	var cleaned atomic.Int32
	releases := []chan struct{}{}
	for i := 0; i < 4; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		entered := make(chan struct{})
		release := make(chan struct{})
		releases = append(releases, release)
		result := make(chan error, 1)
		go func() {
			_, e := contextExecute(ctx, func() { cleaned.Add(1) }, func(context.Context) ([]byte, error) { close(entered); <-release; return []byte("discarded"), nil })
			result <- e
		}()
		<-entered
		cancel()
		select {
		case e := <-result:
			if e == nil {
				t.Fatal("cancel accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("foreground hung")
		}
	}
	called := false
	_, e := contextExecute(context.Background(), func() { cleaned.Add(1) }, func(context.Context) ([]byte, error) { called = true; return nil, nil })
	if e == nil || called || cleaned.Load() != 1 {
		t.Fatal("unsettled workers released admission or refused cleanup lost")
	}
	for _, release := range releases {
		close(release)
	}
	deadline := time.Now().Add(time.Second)
	for cleaned.Load() != 5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if cleaned.Load() != 5 {
		t.Fatal("worker buffers retained after settlement")
	}
	owned := []byte("private bytes")
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	_, e = contextExecute(ctx, func() { clear(owned); close(done) }, func(context.Context) ([]byte, error) { cancel(); return owned, nil })
	if e == nil {
		t.Fatal("late result escaped")
	}
	<-done
	for _, b := range owned {
		if b != 0 {
			t.Fatal("discarded plaintext survived")
		}
	}
}

func TestContextTenSecondDeadlineRetainsSlot(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	settled := make(chan struct{})
	start := time.Now()
	_, e := contextExecute(context.Background(), func() { close(settled) }, func(context.Context) ([]byte, error) { close(entered); <-release; return nil, nil })
	if e == nil || time.Since(start) < 9*time.Second || time.Since(start) > 12*time.Second {
		close(release)
		t.Fatal("deadline not enforced")
	}
	<-entered
	if len(workflowContextAdmission) != 1 {
		close(release)
		t.Fatal("hung callback released slot")
	}
	close(release)
	<-settled
}
