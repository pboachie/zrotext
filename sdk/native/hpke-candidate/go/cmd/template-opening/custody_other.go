//go:build !windows

package main

import (
	"context"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func selectReader() (opener, func(), func()) {
	if len(os.Args) != 1 {
		panic("Windows hardware required")
	}
	return func(o *h.OwnerTemplateOpening, s []byte) (*h.TemplateOpenedPreview, error) {
		return o.OpenLatestSoftware(context.Background(), s)
	}, func() {}, func() {}
}
