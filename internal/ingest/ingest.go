// Package ingest defines the event-source interface and the Event channel
// contract shared by all ingestion feeds (real-time Sysmon, sweep, baseline,
// firewall). Implementations:
//
//   - mock.MockIngester: deterministic replay, for tests + first-run smoke
//   - sysmon_rt (windows): native EvtSubscribe pull-subscription (production)
//
// Every Ingester returns a single channel of event.Event and is driven by a
// context: cancel the context to stop the feed. The Ingester closes the channel
// when it has finished (e.g. the mock after replay, or a terminating feed).
package ingest

import (
	"context"

	"sentinel/internal/event"
)

// Ingester is the contract every event source implements.
type Ingester interface {
	// Start begins ingestion and returns the channel events arrive on. It must
	// return promptly (do the subscription setup synchronously, then spawn a
	// reader goroutine). On context cancellation the implementation should stop
	// emitting and close the channel.
	Start(ctx context.Context) (<-chan event.Event, error)
}
