//go:build !windows

package main

import (
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func selectReader() (opener, func()) {
	if len(os.Args) != 1 {
		panic("Windows hardware required")
	}
	return h.OpenCurrentSoftwareEncryptedTemplate, func() {}
}
