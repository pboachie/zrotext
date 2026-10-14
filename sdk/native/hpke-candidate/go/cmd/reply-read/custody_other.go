//go:build !windows

package main

import (
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func selectReader() (reader, func()) {
	if len(os.Args) != 1 {
		panic("Windows protected provider required")
	}
	return (*h.OriginalCurrentClient).ReadSoftware, func() {}
}
