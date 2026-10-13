//go:build !windows

package main

import (
	"context"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func selectCustody() (producer, func()) {
	if len(os.Args) != 1 {
		panic("Windows protected provider required")
	}
	return func(ctx context.Context, scalar []byte, st *h.ContactStatement, e h.ContactExpected, f h.ContactFieldInput, _ bool) (*h.ContactProduction, error) {
		return h.ProduceSoftwareContactField01(ctx, scalar, st, e, f)
	}, func() {}
}
