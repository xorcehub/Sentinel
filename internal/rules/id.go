package rules

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"time"
)

// hitIDGen mints per-run alert correlation IDs of the form
// R-YYYYMMDD-<nonce>-<NNNNNN> (see docs/05-ALERTING.md §5 "Alert correlation
// ID"). The same ID is emitted by every alert channel — the msg=HIT /
// msg=suppressed line in sentinel.log, the ALERTS.log header, the popup caption,
// and the EventLog body — so the structured log and the alert log join on an
// exact string match instead of a colliding timestamp.
//
// Collision design: the counter resets each startup, so two runs can both emit
// "...-000001". That is safe because the nonce (generated ONCE at construction
// from crypto/rand) namespaces the run — a same-day restart produces a different
// nonce and therefore a different full ID, with no dependence on state.db
// surviving (which the same-user adversary in 03-RULES.md §8 can reset).
type hitIDGen struct {
	nonce   string        // 5-char base36, generated once per process
	date    string        // YYYYMMDD captured at startup; date-first so IDs sort chronologically
	counter atomic.Uint64 // per-run sequence starting at 1
}

// newHitIDGen constructs a generator with a fresh random nonce and the current
// date. The date is frozen at startup (not recomputed per ID) so all IDs from
// one run share the same date even across midnight — keeping them groupable as
// "this run" rather than split by calendar rollover mid-run.
func newHitIDGen() *hitIDGen {
	return &hitIDGen{nonce: randomNonce(5), date: time.Now().Format("20060102")}
}

// Next returns the next hit ID. Thread-safe via atomic counter.
func (g *hitIDGen) Next() string {
	n := g.counter.Add(1)
	return fmt.Sprintf("R-%s-%s-%06d", g.date, g.nonce, n)
}

// randomNonce returns n base36 characters drawn from crypto/rand (CSPRNG). 5
// chars gives ~60M combos → a birthday collision becomes likely only after
// ~9000 restarts (sqrt(36^5)≈7776), i.e. years of use. rand.Read failing is
// unrecoverable and never expected on a functioning host, so it panics rather
// than silently degrading ID uniqueness.
func randomNonce(n int) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" // base36, lexical for readability
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("sentinel: crypto/rand Read failed: " + err.Error())
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
