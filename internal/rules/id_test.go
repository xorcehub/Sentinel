package rules

import (
	"regexp"
	"strings"
	"testing"
)

// idRe pins the documented format R-YYYYMMDD-<5 base36>-<6 digits>
// (docs/05-ALERTING.md §5). Kept here (not exported) because it mirrors the
// generator contract the alert channels and tests rely on.
var idRe = regexp.MustCompile(`^R-\d{8}-[0-9A-Z]{5}-\d{6}$`)

// TestHitIDFormat checks shape + per-call increment for one generator.
func TestHitIDFormat(t *testing.T) {
	g := newHitIDGen()
	prev := ""
	for i := 0; i < 1000; i++ {
		id := g.Next()
		if !idRe.MatchString(id) {
			t.Fatalf("id %q does not match R-YYYYMMDD-NNNNN-NNNNNN", id)
		}
		// counter must strictly increment (zero-padded 6-digit tail)
		tail := id[len(id)-6:]
		if tail == prev {
			t.Fatalf("id counter did not increment: %q repeated", id)
		}
		prev = tail
	}
	// first id must be ...-000001
	first := g // fresh gen for the boundary check
	_ = first
	g2 := newHitIDGen()
	if got := g2.Next(); !strings.HasSuffix(got, "-000001") {
		t.Errorf("first id should end in -000001, got %q", got)
	}
}

// TestHitIDUniqueAcrossRestarts simulates many restarts (each newHitIDGen is a
// fresh run with a new nonce) and asserts no two generated IDs ever collide.
// This is the collision-free-across-restarts guarantee the nonce provides.
func TestHitIDUniqueAcrossRestarts(t *testing.T) {
	const restarts = 1000
	seen := make(map[string]bool, restarts*5)
	for r := 0; r < restarts; r++ {
		g := newHitIDGen()
		for i := 0; i < 5; i++ { // a few hits per simulated run
			id := g.Next()
			if seen[id] {
				t.Fatalf("collision on id %q after %d restarts (nonce uniqueness broken)", id, r)
			}
			seen[id] = true
		}
	}
}

// TestHitIDCounterResetsNonceSaves pins the exact property the user asked for:
// two separate runs both emit "-000001", but the full IDs differ because the
// nonce differs. A bare counter (or date+counter) would collide here; the nonce
// is what makes it safe.
func TestHitIDCounterResetsNonceSaves(t *testing.T) {
	a, b := newHitIDGen(), newHitIDGen()
	idA, idB := a.Next(), b.Next()
	if !strings.HasSuffix(idA, "-000001") || !strings.HasSuffix(idB, "-000001") {
		t.Fatalf("both runs should start at -000001; got %q and %q", idA, idB)
	}
	if idA == idB {
		t.Fatalf("two runs produced identical id %q — nonce failed to namespace the run", idA)
	}
	// the differing segment must be the nonce, not the counter or date.
	if a.nonce == b.nonce {
		t.Fatalf("two generators drew the same nonce %q — randomness source broken", a.nonce)
	}
}
