package hpke

import (
	"context"
	"testing"
	"time"
)

func TestOwnerCallbackRetainsAdmissionUntilActualSettlement(t *testing.T) {
	var b OwnerBinding
	for _, p := range [][]byte{b.Account[:], b.Device[:], b.Line[:], b.Interval[:], b.Session[:], b.PhoneReader[:], b.ArchiveReader[:]} {
		p[0] = 1
	}
	b.Generation = 1
	b.Peer = "+12"
	stop := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(stop)
		}
	}()
	makeReader := func() *OwnerTemplateReader {
		r, e := NewOwnerTemplateReader(OwnerTemplateOptions{Origin: "https://owner.example.invalid", Binding: b, Template: b.Account, Enabled: true, Timeout: 100 * time.Millisecond, Current: func(context.Context) (OwnerTemplateAuthority, error) {
			<-stop
			return OwnerTemplateAuthority{}, ErrAuthentication
		}, Session: func(context.Context) (OwnerSession, error) {
			return OwnerSession{Origin: "https://owner.example.invalid", Cookie: "synthetic=owner", CSRF: "synthetic"}, nil
		}})
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	readers := []*OwnerTemplateReader{}
	for i := 0; i < 8; i++ {
		r := makeReader()
		readers = append(readers, r)
		if _, e := r.ReadLatest(context.Background()); e == nil {
			t.Fatal("stalled callback returned")
		}
	}
	if len(ownerTemplateAdmission) != 8 {
		t.Fatal("unsettled worker admission released")
	}
	if _, e := readers[0].ReadLatest(context.Background()); e == nil || e.(OwnerTemplateError).Code != "busy" {
		t.Fatal("unsettled reader not busy", e)
	}
	ninth := makeReader()
	if _, e := ninth.ReadLatest(context.Background()); e == nil || e.(OwnerTemplateError).Code != "capacity" {
		t.Fatal("capacity not bounded", e)
	}
	// Let every retained worker settle before later tests use the global gate.
	close(stop)
	released = true
	until := time.Now().Add(time.Second)
	for len(ownerTemplateAdmission) > 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if len(ownerTemplateAdmission) != 0 {
		t.Fatal("settled admission leaked")
	}
}
