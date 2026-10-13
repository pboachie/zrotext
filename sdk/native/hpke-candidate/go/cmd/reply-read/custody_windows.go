package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	h "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"os"
)

func selectReader() (reader, func()) {
	if len(os.Args) == 1 {
		return (*h.OriginalCurrentClient).ReadSoftware, func() {}
	}
	if len(os.Args) != 2 || os.Args[1] != "--hardware" {
		panic("unsupported arguments")
	}
	must(h.ProbeHardware())
	receipt, e := os.CreateTemp("", "zrotext-read-owned-*.json")
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
	return func(c *h.OriginalCurrentClient, ctx context.Context, g string, event [16]byte, b uint64, s []byte, clock func() uint64) (*h.VerifiedOriginalRead, error) {
		if len(s) != 0 {
			panic("selected scalar exposed")
		}
		return c.ReadHardware(ctx, g, event, b, key, clock)
	}, cleanup
}
