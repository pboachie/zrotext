package hpke

import (
	"context"
	"testing"
)

func TestRejectedOpeningWorkClearsOwnedInput(t *testing.T) {
	for _, kind := range []string{"nil-client", "nil-context", "busy", "capacity"} {
		owned := []byte{1, 2, 3}
		cleaned := 0
		var client *OwnerTemplateClient
		ctx := context.Background()
		if kind != "nil-client" {
			client = &OwnerTemplateClient{reader: &OwnerTemplateReader{}}
		}
		if kind == "nil-context" {
			ctx = nil
		}
		if kind == "busy" {
			client.reader.busy.Store(true)
		}
		if kind == "capacity" {
			for i := 0; i < cap(ownerTemplateAdmission); i++ {
				ownerTemplateAdmission <- struct{}{}
			}
		}
		_, e := client.executeOwned(ctx, func(context.Context, *ownerTemplateWork) (ownerSaveResult, error) {
			t.Fatal("non-admitted work ran")
			return ownerSaveResult{}, nil
		}, func() { clear(owned); cleaned++ })
		if kind == "capacity" {
			for i := 0; i < cap(ownerTemplateAdmission); i++ {
				<-ownerTemplateAdmission
			}
		}
		if e == nil || cleaned != 1 || owned[0] != 0 || owned[1] != 0 || owned[2] != 0 {
			t.Fatalf("%s retained owned bytes", kind)
		}
	}
}
