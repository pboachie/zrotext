package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func must(e error) {
	if e != nil {
		panic("contact fixture operation failed")
	}
}
func selectCustody() (producer, func()) {
	if len(os.Args) == 1 {
		return func(ctx context.Context, scalar []byte, st *h.ContactStatement, e h.ContactExpected, f h.ContactFieldInput, _ bool) (*h.ContactProduction, error) {
			return h.ProduceSoftwareContactField01(ctx, scalar, st, e, f)
		}, func() {}
	}
	if len(os.Args) != 2 || os.Args[1] != "--hardware" {
		panic("unsupported arguments")
	}
	receipt, e := os.CreateTemp("", "zrotext-contact-owned-*.json")
	must(e)
	key, e := h.CreateContactRootSigner(func(alias string) error {
		if e := json.NewEncoder(receipt).Encode(map[string]string{"pending_alias": alias}); e != nil {
			return e
		}
		return receipt.Sync()
	})
	if e != nil {
		_ = receipt.Close()
		must(e)
	}
	cleanup := func() {
		alias := key.Alias()
		point, e := key.PublicPoint()
		must(key.DeleteCreated())
		must(e)
		if reopened, e := h.OpenContactRootSigner(alias, point); e == nil {
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
	// A setup panic also follows the exact owned-key cleanup path.
	ready := false
	defer func() {
		if !ready {
			cleanup()
		}
	}()
	point, e := key.PublicPoint()
	must(e)
	if wrong, e := h.OpenHardwareSigner(key.Alias(), point); e == nil {
		wrong.Close()
		panic("contact alias entered envelope capability")
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]string{"alias": key.Alias(), "public": base64.StdEncoding.EncodeToString(point)}))
	ready = true
	return func(ctx context.Context, _ []byte, st *h.ContactStatement, e h.ContactExpected, f h.ContactFieldInput, closed bool) (*h.ContactProduction, error) {
		borrowed, err := h.OpenContactRootSigner(key.Alias(), point)
		if err != nil {
			return nil, err
		}
		defer borrowed.Close()
		if borrowed.DeleteCreated() == nil {
			panic("borrowed handle deleted owner key")
		}
		if closed {
			borrowed.Close()
		}
		return h.ProduceProtectedContactField01(ctx, borrowed, st, e, f)
	}, cleanup
}
