package hpke

import (
	"context"
	"testing"
)

func TestUninitializedContactHistoryCannotReleaseAdmission(t *testing.T) {
	before := contactHistories.Load()
	var h ContactHistory
	h.Close()
	if _, e := h.Lookup(context.Background(), [16]byte{1}); e != ErrContactHistory {
		t.Fatal("uninitialized history accepted")
	}
	h.Close()
	if contactHistories.Load() != before {
		t.Fatal("uninitialized close changed admission")
	}
}
