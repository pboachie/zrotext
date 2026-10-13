//go:build windows

package hpke

import (
	"bytes"
	"context"
)

func OpenProtectedWorkflowContext(m *Manifest, s WorkflowContextScope, role WorkflowContextRole, now uint64, recipient *HardwareRecipient, envelope []byte) ([]byte, error) {
	if recipient == nil {
		return nil, ErrProtectedUnavailable
	}
	return openContext(m, s, role, now, envelope, recipient.openContent)
}

func OpenCurrentProtectedWorkflowContext(source ContextAuthoritySource, s WorkflowContextScope, role WorkflowContextRole, recipient *HardwareRecipient, envelope []byte) ([]byte, error) {
	if recipient == nil {
		return nil, ErrProtectedUnavailable
	}
	var selected []byte
	out, e := openCurrentContext(source, s, role, envelope, func(point, enc, info, aad, ct []byte) ([]byte, error) {
		selected = append([]byte(nil), point...)
		return recipient.openContent(point, enc, info, aad, ct)
	})
	if e != nil {
		return nil, e
	}
	point, e := recipient.PublicPoint()
	if e != nil || !bytes.Equal(point, selected) {
		clear(out)
		return nil, ErrProtectedUnavailable
	}
	return out, nil
}

// OpenBoundedProtectedWorkflowContext borrows a qualified provider. It never
// deletes the caller's key or substitutes software custody. No provider call
// occurs before admission; timed-out native work keeps its slot until settled.
func OpenBoundedProtectedWorkflowContext(ctx context.Context, source ContextAuthoritySource, s WorkflowContextScope, role WorkflowContextRole, recipient *HardwareRecipient, envelope []byte) ([]byte, error) {
	if recipient == nil {
		return nil, ErrProtectedUnavailable
	}
	if len(envelope) < 308 || len(envelope) > 33075 {
		return nil, ErrShape
	}
	wire := append([]byte(nil), envelope...)
	return contextExecute(ctx, func() {}, func(limited context.Context) ([]byte, error) {
		return OpenCurrentProtectedWorkflowContext(limitedContextSource(limited, source), s, role, recipient, wire)
	})
}
