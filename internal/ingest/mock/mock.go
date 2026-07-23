// Package mock provides a deterministic Ingester for tests and first-run
// smoke checks. It replays a fixed slice of events, then closes the channel —
// so the app's drain loop runs to completion and returns, which makes the whole
// skeleton testable without a live Sysmon feed.
package mock

import (
	"context"
	"time"

	"sentinel/internal/event"
)

// Ingester replays Events in order, then closes the channel. If EmitDelay is
// non-zero, it sleeps between emits (useful for testing cancellation/concurrency).
type Ingester struct {
	Events    []event.Event
	EmitDelay time.Duration
}

// New returns an Ingester that replays the given events.
func New(events ...event.Event) *Ingester {
	return &Ingester{Events: events}
}

// Start implements ingest.Ingester.
func (m *Ingester) Start(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)
	go func() {
		defer close(out)
		for _, ev := range m.Events {
			if m.EmitDelay > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(m.EmitDelay):
				}
			} else {
				// cooperative yield so context cancellation is checked even at zero delay
				select {
				case <-ctx.Done():
					return
				default:
				}
			}
			select {
			case <-ctx.Done():
				return
			case out <- ev:
			}
		}
	}()
	return out, nil
}
