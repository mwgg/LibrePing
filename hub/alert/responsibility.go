package alert

import (
	"crypto/sha256"
	"encoding/binary"
)

// Responsible decides whether this hub is the one that should evaluate and fire
// a given alert rule, using rendezvous (highest-random-weight) hashing over the
// set of candidate hubs (self + verified peers). Exactly one hub wins for a
// given key, with no coordinator; when the winning hub disappears from the set
// (its announcement goes stale), the next-highest takes over automatically.
//
// key is the rule's identity (check+owner+channel+destination). selfHubID is
// always included as a candidate even if it isn't in peerHubIDs.
func Responsible(selfHubID string, peerHubIDs []string, key string) bool {
	best := selfHubID
	bestScore := score(selfHubID, key)
	for _, h := range peerHubIDs {
		if h == selfHubID {
			continue
		}
		s := score(h, key)
		// Higher score wins; ties broken by larger ID for determinism.
		if s > bestScore || (s == bestScore && h > best) {
			best, bestScore = h, s
		}
	}
	return best == selfHubID
}

func score(hubID, key string) uint64 {
	sum := sha256.Sum256([]byte(hubID + "|" + key))
	return binary.BigEndian.Uint64(sum[:8])
}

// ResponsibleAmong restricts responsibility to an explicit candidate set —
// the hubs that can actually decrypt the destination (the rule's recipients
// that are currently live). self must be one of the candidates and the
// rendezvous winner among them.
func ResponsibleAmong(self string, candidates []string, key string) bool {
	inSet := false
	best := ""
	var bestScore uint64
	for _, h := range candidates {
		if h == self {
			inSet = true
		}
		s := score(h, key)
		if best == "" || s > bestScore || (s == bestScore && h > best) {
			best, bestScore = h, s
		}
	}
	return inSet && best == self
}
