package outbox

import (
	"testing"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

func mk(id string) protocol.SignedResult {
	return protocol.SignedResult{Content: protocol.ResultContent{CheckID: id}}
}

func TestOutboxBoundsAndAging(t *testing.T) {
	o := New(2, time.Minute)
	now := time.Unix(1000, 0)
	o.now = func() time.Time { return now }

	o.Add(mk("a"))
	o.Add(mk("b"))
	o.Add(mk("c")) // evicts "a" (max 2)
	if got := o.Recent(); len(got) != 2 || got[0].Content.CheckID != "b" || got[1].Content.CheckID != "c" {
		t.Fatalf("expected [b c], got %+v", got)
	}

	// Advance past the age window: everything prunes.
	now = now.Add(2 * time.Minute)
	if got := o.Recent(); len(got) != 0 {
		t.Fatalf("expected empty after aging, got %d", len(got))
	}
}

func TestOutboxNilSafe(t *testing.T) {
	var o *Outbox
	o.Add(mk("x"))
	if got := o.Recent(); got != nil {
		t.Fatalf("nil outbox should return nil, got %+v", got)
	}
}
