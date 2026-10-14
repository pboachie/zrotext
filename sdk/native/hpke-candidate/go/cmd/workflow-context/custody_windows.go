package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func selectReader() (opener, func()) {
	if len(os.Args) == 1 {
		return func(source h.ContextAuthoritySource, s h.WorkflowContextScope, r h.WorkflowContextRole, scalar, wire []byte, _ byte) ([]byte, error) {
			return h.OpenBoundedSoftwareWorkflowContext(context.Background(), source, s, r, scalar, wire)
		}, func() {}
	}
	if len(os.Args) != 2 || os.Args[1] != "--hardware" {
		panic("unsupported arguments")
	}
	must(h.ProbeHardware())
	receipt, e := os.CreateTemp("", "zrotext-template-owned-*.json")
	must(e)
	key, e := h.CreateHardware(func(alias string) error {
		if e := json.NewEncoder(receipt).Encode(map[string]string{"pending_alias": alias}); e != nil {
			return e
		}
		return receipt.Sync()
	})
	must(e)
	cleanup := func() {
		alias := key.Alias()
		point, e := key.PublicPoint()
		must(key.Delete())
		must(e)
		if reopened, e := h.OpenHardware(alias, point); e == nil {
			reopened.Close()
			panic("deleted key reopened")
		}
		must(receipt.Truncate(0))
		_, e = receipt.Seek(0, 0)
		must(e)
		must(json.NewEncoder(receipt).Encode(map[string]bool{"owned_key_deleted": true}))
		must(receipt.Sync())
		must(receipt.Close())
		must(json.NewEncoder(os.Stdout).Encode(map[string]bool{"owned_key_deleted": true}))
	}
	point, e := key.PublicPoint()
	if e != nil {
		cleanup()
		must(e)
	}
	if e = json.NewEncoder(os.Stdout).Encode(map[string]string{"public": hex.EncodeToString(point)}); e != nil {
		cleanup()
		must(e)
	}
	return func(source h.ContextAuthoritySource, scope h.WorkflowContextScope, role h.WorkflowContextRole, scalar, envelope []byte, providerMode byte) ([]byte, error) {
		if len(scalar) != 0 {
			panic("selected scalar exposed")
		}
		if providerMode != 0 {
			borrowed, e := h.OpenHardware(key.Alias(), point)
			must(e)
			defer borrowed.Close()
			original := source
			calls := 0
			source = func() (*h.Manifest, uint64, error) {
				m, now, e := original()
				calls++
				if calls == 2 {
					borrowed.Close()
				}
				return m, now, e
			}
			if providerMode == 1 {
				return h.OpenCurrentProtectedWorkflowContext(source, scope, role, borrowed, envelope)
			}
			return h.OpenBoundedProtectedWorkflowContext(context.Background(), source, scope, role, borrowed, envelope)
		}
		return h.OpenBoundedProtectedWorkflowContext(context.Background(), source, scope, role, key, envelope)
	}, cleanup
}
