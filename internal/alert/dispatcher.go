package alert

import (
	"context"
	"log/slog"
	"sync/atomic"

	"sentinel/internal/event"
)

// Dispatcher fans Hits out to the alerters named in each Hit.AlertTo.
//
// Concurrency model (05-ALERTING.md §1, §9):
//   - A single reader goroutine drains the inbound Hit channel and dispatches.
//   - "popup" hits go to a BOUNDED popup queue consumed by a worker goroutine,
//     because MessageBox blocks until the user dismisses it. Bounded = if the
//     operator walks away and popups pile up, excess are counted+dropped (not
//     infinitely buffered) and reported via Dropped().
//   - All other alerters (log, eventlog, toast, webhook) are called inline from
//     the reader; each is wrapped in a recover so one panicking alerter can't
//     kill the dispatcher.
type Dispatcher struct {
	alerters map[string]Alerter
	log      *slog.Logger

	in      chan event.Hit
	popupCh chan event.Hit

	dropped   atomic.Uint64 // popup queue overflow counter
	delivered atomic.Uint64
}

// popupQueueSize bounds how many blocking popups can be queued at once. Beyond
// this, excess popups are logged-only (still audited via ALERTS.log) and the
// dropped counter increments.
const popupQueueSize = 16

// New builds a dispatcher over the given alerters (keyed by Alerter.Name()).
// The Hit sink channel is buffered (bufferHits); push non-blocking or use
// TrySubmit to avoid blocking the engine on a slow popup queue.
func New(alerters []Alerter, bufferHits int, log *slog.Logger) *Dispatcher {
	m := map[string]Alerter{}
	for _, a := range alerters {
		if a != nil {
			m[a.Name()] = a
		}
	}
	if bufferHits <= 0 {
		bufferHits = 256
	}
	return &Dispatcher{
		alerters: m,
		log:      logOf(log),
		in:       make(chan event.Hit, bufferHits),
		popupCh:  make(chan event.Hit, popupQueueSize),
	}
}

// Sink returns the channel the engine pushes Hits to.
func (d *Dispatcher) Sink() chan<- event.Hit { return d.in }

// Submit pushes a hit non-blocking; returns false (and increments dropped) if
// the inbound buffer is full. Use from the engine path so a flood never blocks
// ingestion.
func (d *Dispatcher) Submit(h event.Hit) bool {
	select {
	case d.in <- h:
		return true
	default:
		d.dropped.Add(1)
		d.log.Warn("dispatcher inbound buffer full; hit dropped (logged in engine)",
			"rule", h.RuleID, "severity", h.Severity)
		return false
	}
}

// Dropped returns the count of popup-queue / inbound-buffer overflows since
// start. Surface this in the heartbeat (05-ALERTING.md §5).
func (d *Dispatcher) Dropped() uint64 { return d.dropped.Load() }

// Delivered returns the count of successfully-dispatched hits.
func (d *Dispatcher) Delivered() uint64 { return d.delivered.Load() }

// Run drives dispatch until ctx is cancelled. Spawns the popup worker.
// Returns when ctx is done and the inbound channel is drained.
func (d *Dispatcher) Run(ctx context.Context) {
	// popup worker: serializes blocking MessageBoxes (one at a time) so we never
	// paint two at once, and overflow is counted not infinite-buffered.
	popupDone := make(chan struct{})
	go func() {
		defer close(popupDone)
		for h := range d.popupCh {
			d.callAlerter("popup", h)
		}
	}()

	defer func() {
		close(d.popupCh) // stops the popup worker (range exits)
		<-popupDone
	}()

	for {
		select {
		case <-ctx.Done():
			d.log.Info("alert dispatcher stopping (context cancelled)")
			return
		case h, ok := <-d.in:
			if !ok {
				return
			}
			d.dispatch(h)
		}
	}
}

// dispatch fans one hit out to each named alerter.
func (d *Dispatcher) dispatch(h event.Hit) {
	for _, name := range h.AlertTo {
		if name == "popup" {
			// If no popup alerter is registered (operator ran -popup=false),
			// skip silently: do NOT route to the popup queue (which would back
			// up and spuriously increment Dropped on a burst, surfacing as a
			// fake health problem in the heartbeat). The engine still lists
			// "popup" in AlertTo because that's the rule's delivery INTENT;
			// the dispatcher delivers only what's wired.
			if _, ok := d.alerters["popup"]; !ok {
				continue
			}
			// route through the bounded popup queue so a blocking MessageBox
			// never stalls the reader or other alerters.
			select {
			case d.popupCh <- h:
			default:
				d.dropped.Add(1)
				d.log.Warn("popup queue full; popup dropped (hit still logged via 'log' alerter)",
					"rule", h.RuleID)
			}
			continue
		}
		d.callAlerter(name, h)
	}
	d.delivered.Add(1)
}

// callAlerter invokes the named alerter, recovering from any panic so a faulty
// alerter can never crash the dispatcher. Unknown alerter names are warned.
func (d *Dispatcher) callAlerter(name string, h event.Hit) {
	al, ok := d.alerters[name]
	if !ok {
		d.log.Debug("alerter not registered; skipping", "name", name, "rule", h.RuleID)
		return
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				d.log.Error("alerter panic (recovered)", "name", name, "rule", h.RuleID, "panic", r)
			}
		}()
		if err := al.Alert(h); err != nil {
			d.log.Warn("alerter error", "name", name, "rule", h.RuleID, "err", err)
		}
	}()
}

// Close drains and closes the inbound channel (graceful shutdown helper).
func (d *Dispatcher) Close() {
	close(d.in)
}
