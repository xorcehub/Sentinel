// Package state implements Sentinel's dedup persistence on bbolt
// (docs/03-RULES.md §6 — two distinct mechanisms):
//
//  1. RT/sweep overlap dedup by RecordID. The hourly sweep re-feeds the last
//     65 min; the per-rule time-window is NOT enough (events older than the
//     window would get a second MessageBox each sweep). We track a high-water
//     maxRecordIDSeen and skip sweep events at or below it. RT events always
//     pass through (and raise the high-water).
//
//  2. Genuine re-alert dedup — the per-rule `dedup` window. A new event that
//     repeats the same (RuleID, target_key) is suppressed within the window so
//     the 60s task firing again doesn't spam.
//
// Both are persisted across restarts (otherwise a Sentinel restart would
// re-alert the whole 65-min sweep window). bbolt gives us serializable
// single-writer transactions, so read-then-decide-then-write in one Update is
// atomic and race-free.
package state

import (
	"encoding/binary"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

var (
	bucketRecordID = []byte("recordid")
	bucketDedup    = []byte("dedup")
	keyMax         = []byte("max")
)

// State is the persistent dedup store. Methods are safe for concurrent use
// (bbolt serializes writers; View/Update handle locking).
type State struct {
	db *bbolt.DB
}

// Open opens (or creates) the state file and its buckets.
func Open(path string) (*State, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open state %s: %w", path, err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bucketRecordID, bucketDedup} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("create bucket %s: %w", b, err)
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &State{db: db}, nil
}

// Close releases the underlying file lock.
func (s *State) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SweepSeen reports whether recordID was already observed (via RT or an
// earlier sweep). Only meaningful to call for sweep-source events.
func (s *State) SweepSeen(recordID uint64) bool {
	var seen bool
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRecordID)
		seen = recordID > 0 && recordID <= readU64(b.Get(keyMax))
		return nil
	})
	return seen
}

// MarkSeen raises the high-water-mark to recordID if it is greater than the
// current value. Called for every processed event with a RecordID (RT and
// sweep) so a later sweep of the same event is skipped.
func (s *State) MarkSeen(recordID uint64) {
	if recordID == 0 {
		return
	}
	_ = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRecordID)
		if recordID > readU64(b.Get(keyMax)) {
			return b.Put(keyMax, u64(recordID))
		}
		return nil
	})
}

// MaxRecordID returns the current high-water-mark (0 if none). Diagnostic.
func (s *State) MaxRecordID() uint64 {
	var v uint64
	_ = s.db.View(func(tx *bbolt.Tx) error {
		v = readU64(tx.Bucket(bucketRecordID).Get(keyMax))
		return nil
	})
	return v
}

// ReAlert reports whether (ruleID, targetKey) is allowed to alert now, given a
// suppression window. If allowed, it records the current time atomically so a
// concurrent evaluation of the same key cannot also pass. First-ever call for a
// key always returns true.
func (s *State) ReAlert(ruleID, targetKey string, window time.Duration) bool {
	if window <= 0 {
		window = 15 * time.Minute
	}
	key := []byte(ruleID + "|" + targetKey)
	var allowed bool
	_ = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketDedup)
		now := time.Now().UnixNano()
		if raw := b.Get(key); raw != nil {
			last := int64(binary.BigEndian.Uint64(raw))
			if time.Duration(now-last) >= window {
				allowed = true
				return b.Put(key, u64(uint64(now)))
			}
			allowed = false
			return nil
		}
		allowed = true
		return b.Put(key, u64(uint64(now)))
	})
	return allowed
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// readU64 decodes a big-endian uint64, returning 0 for a missing or short
// value (bbolt returns nil for absent keys; binary.BigEndian.Uint64(nil)
// would panic).
func readU64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
