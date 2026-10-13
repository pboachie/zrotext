package hpke

import (
	"context"
	"time"
)

var workflowContextAdmission = make(chan struct{}, 4)

// contextExecute bounds foreground waiting, not native provider execution. A
// timed-out worker retains its admission slot and owned buffers until settlement.
func contextExecute(ctx context.Context, cleanup func(), work func(context.Context) ([]byte, error)) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		cleanup()
		return nil, ErrShape
	}
	select {
	case workflowContextAdmission <- struct{}{}:
	default:
		cleanup()
		return nil, ErrShape
	}
	limited, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	type result struct {
		bytes []byte
		err   error
	}
	done := make(chan result)
	go func() {
		defer func() { cleanup(); <-workflowContextAdmission }()
		if limited.Err() != nil {
			return
		}
		out, err := work(limited)
		if limited.Err() != nil {
			clear(out)
			return
		}
		select {
		case done <- result{out, err}:
		case <-limited.Done():
			clear(out)
		}
	}()
	select {
	case r := <-done:
		if limited.Err() != nil {
			clear(r.bytes)
			return nil, ErrAuthentication
		}
		return r.bytes, r.err
	case <-limited.Done():
		return nil, ErrAuthentication
	}
}

func limitedContextSource(ctx context.Context, source ContextAuthoritySource) ContextAuthoritySource {
	return func() (*Manifest, uint64, error) {
		if source == nil || ctx.Err() != nil {
			return nil, 0, ErrAuthentication
		}
		m, now, e := source()
		if ctx.Err() != nil {
			return nil, 0, ErrAuthentication
		}
		return m, now, e
	}
}

// SealBoundedWorkflowContext adds four-slot admission and a ten-second maximum
// wait to current-authority sealing. The caller still owns review and persistence.
func SealBoundedWorkflowContext(ctx context.Context, source ContextAuthoritySource, s WorkflowContextScope, role WorkflowContextRole, content []byte) ([]byte, error) {
	if len(content) < 1 || len(content) > 32768 {
		return nil, ErrShape
	}
	owned := append([]byte(nil), content...)
	return contextExecute(ctx, func() { clear(owned) }, func(limited context.Context) ([]byte, error) {
		return SealCurrentWorkflowContext(limitedContextSource(limited, source), s, role, owned)
	})
}

// OpenBoundedSoftwareWorkflowContext is explicitly exportable-key custody.
// Successful plaintext is caller-owned; discarded worker plaintext is cleared.
func OpenBoundedSoftwareWorkflowContext(ctx context.Context, source ContextAuthoritySource, s WorkflowContextScope, role WorkflowContextRole, scalar, envelope []byte) ([]byte, error) {
	if len(scalar) != 32 || len(envelope) < 308 || len(envelope) > 33075 {
		return nil, ErrShape
	}
	ownedScalar := append([]byte(nil), scalar...)
	wire := append([]byte(nil), envelope...)
	return contextExecute(ctx, func() { clear(ownedScalar) }, func(limited context.Context) ([]byte, error) {
		return OpenCurrentSoftwareWorkflowContext(limitedContextSource(limited, source), s, role, ownedScalar, wire)
	})
}
