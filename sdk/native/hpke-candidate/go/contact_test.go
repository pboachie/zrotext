package hpke

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestContactNonAdmissionOwnsCleanup(t *testing.T) {
	for _, ctx := range []context.Context{nil, func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }()} {
		cleaned := false
		called := false
		if _, e := contactProduce(ctx, nil, ContactExpected{}, nil, func(limited context.Context) ([]byte, error) { called = true; return nil, nil }, func() { cleaned = true }); e == nil || !cleaned || called {
			t.Fatal("non-admission retained key or signed")
		}
	}
}
func TestContactCancellationRetainsAdmissionUntilSettlement(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var entered sync.WaitGroup
	entered.Add(4)
	finished := make(chan struct{}, 4)
	returns := make(chan error, 4)
	var cancels []context.CancelFunc
	for i := 0; i < 4; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		go func() {
			_, e := contactProduce(ctx, nil, ContactExpected{}, nil, func(limited context.Context) ([]byte, error) { entered.Done(); <-release; return nil, ErrShape }, func() { finished <- struct{}{} })
			returns <- e
		}()
		t.Cleanup(cancel)
	}
	entered.Wait()
	for _, cancel := range cancels {
		cancel()
	}
	for i := 0; i < 4; i++ {
		select {
		case e := <-returns:
			if e == nil {
				t.Fatal("cancel accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("cancel blocked")
		}
	}
	// All workers are blocked in the actual operation, so capacity must refuse.
	cleaned := false
	called := false
	if _, e := contactProduce(context.Background(), nil, ContactExpected{}, nil, func(limited context.Context) ([]byte, error) { called = true; return nil, nil }, func() { cleaned = true }); e == nil || !cleaned || called {
		t.Fatal("capacity was not retained")
	}
}
func TestContactLateCancellationSuppressesOutput(t *testing.T) {
	// Wait for prior test workers to settle before requesting the shared bounded lane.
	deadline := time.Now().Add(time.Second)
	for len(contactAdmission) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := contactProduce(ctx, nil, ContactExpected{}, nil, func(limited context.Context) ([]byte, error) { close(entered); <-release; return nil, ErrShape }, func() { close(finished) })
		done <- e
	}()
	<-entered
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("late output exposed")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
	select {
	case <-finished:
		t.Fatal("cleaned an outstanding signer")
	default:
	}
	if len(contactAdmission) != 1 {
		t.Fatal("slot released before settlement")
	}
	close(release)
	<-finished
}

func TestContactFixedDeadlineRetainsOutstandingSigner(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	for len(contactAdmission) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, e := contactProduce(context.Background(), nil, ContactExpected{}, nil, func(limited context.Context) ([]byte, error) { close(entered); <-release; return nil, ErrShape }, func() { close(finished) })
		done <- e
	}()
	<-entered
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("deadline exposed output")
		}
	case <-time.After(12 * time.Second):
		close(release)
		t.Fatal("fixed deadline did not settle")
	}
	if time.Since(start) < 9*time.Second || len(contactAdmission) != 1 {
		t.Fatal("incorrect deadline/admission")
	}
	close(release)
	<-finished
}
