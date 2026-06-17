package interest

import (
	"testing"

	"github.com/mwgg/libreping/hub/shard"
)

func TestNilAndUnreadyHoldEverything(t *testing.T) {
	var s *Set
	if !s.Holds("anycheck") {
		t.Fatal("nil Set must hold everything")
	}
	fresh := New()
	if !fresh.Holds("anycheck") {
		t.Fatal("un-updated Set must hold everything (fail-open at startup)")
	}
}

func TestHoldsByShardAndPin(t *testing.T) {
	s := New()
	// Find two check IDs in different shards.
	var inShard, outShard string
	for _, c := range []string{"0000aaaa", "ffff1111", "1234abcd", "deadbeef", "00ff00ff"} {
		if shard.Of(c) == shard.Of("0000aaaa") {
			inShard = c
		} else {
			outShard = c
		}
	}
	held := map[uint32]bool{shard.Of(inShard): true}
	s.Update(false, held, map[string]bool{"pinned-check": true})

	if !s.Holds(inShard) {
		t.Fatal("should hold a check in an assigned shard")
	}
	if s.Holds(outShard) {
		t.Fatal("should not hold a check outside assigned shards and not pinned")
	}
	if !s.Holds("pinned-check") {
		t.Fatal("should hold an explicitly pinned check")
	}
}

func TestArchiveHoldsEverything(t *testing.T) {
	s := New()
	s.Update(true, nil, nil)
	if !s.Holds("whatever") {
		t.Fatal("archive must hold everything")
	}
}
