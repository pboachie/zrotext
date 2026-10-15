//go:build !windows

package main

import (
	"context"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func selectReader() (opener, func()) {
	if len(os.Args) != 1 {
		panic("Windows hardware required")
	}
	return func(source h.ContextAuthoritySource, s h.WorkflowContextScope, r h.WorkflowContextRole, scalar, wire []byte, _ byte) ([]byte, error) {
		return h.OpenBoundedSoftwareWorkflowContext(context.Background(), source, s, r, scalar, wire)
	}, func() {}
}
