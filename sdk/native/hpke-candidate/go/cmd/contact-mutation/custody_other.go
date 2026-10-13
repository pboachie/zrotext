//go:build !windows

package main

import "os"

func hardware() bool {
	if len(os.Args) != 1 {
		panic("Windows protected provider required")
	}
	return false
}
