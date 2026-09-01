package alert

import (
	"context"
	"log/slog"
	"sync"
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

	closedMu sync.RWMutex
	closed   bool

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
// the inbound buffer is full, and also returns false after Close (no-op).
// The closed check and send share a lock with Close so a submit can never
// race close(d.in) into a panic. Use from the engine path so a flood never
// blocks ingestion.
func (d *Dispatcher) Submit(h event.Hit) bool {
	d.closedMu.RLock()
	defer d.closedMu.RUnlock()
	if d.closed {
		return false
	}
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

// Delivered returns the count of hits for which at least one registered
// alerter was actually invoked since start ("delivered" = an attempt reached a
// wired channel; hits routed only to unregistered channels don't count).
func (d *Dispatcher) Delivered() uint64 { return d.delivered.Load() }

// Run drives dispatch until ctx is cancelled. Spawns the popup worker.
// NOTE: on ctx cancellation it returns immediately — buffered inbound hits are
// dropped, not drained (shutdown is best-effort; everything already dispatched
// is in ALERTS.log/the event log). The popup worker likewise drops QUEUED boxes
// on cancel: a blocking MessageBox waits for a human click, so joining it would
// stall interrupt shutdown (and the single-instance mutex release) for
// unbounded wall-clock. At most ONE already-on-screen box can still delay exit —
// a shown MessageBox cannot be interrupted. On the clean path (Close, no
// cancel) the deferred close(d.popupCh) lets the popup worker finish every
// queued box before Run's callers proceed.
func (d *Dispatcher) Run(ctx context.Context) {
	// popup worker: serializes blocking MessageBoxes (one at a time) so we never
	// paint two at once, and overflow is counted not infinite-buffered.
	popupDone := make(chan struct{})
	go func() {
		defer close(popupDone)
		for {
			// Pre-check BEFORE the select: once ctx is cancelled, do not take on
			// another queued box even if one is ready — after a blocking box is
			// dismissed, a bare select would race ctx.Done vs a queued popup and
			// show one more box ~half the time. Bounded exit beats that.
			if ctx.Err() != nil {
				return // queued popups drop on cancel — §9 best-effort shutdown
			}
			select {
			case <-ctx.Done():
				return
			case h, ok := <-d.popupCh:
				if !ok {
					return
				}
				d.callAlerter("popup", h)
			}
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
			if d.dispatch(h) {
				d.delivered.Add(1)
			}
		}
	}
}

// dispatch fans one hit out to each named alerter. Reports whether at least
// one registered alerter was invoked.
func (d *Dispatcher) dispatch(h event.Hit) (sent bool) {
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
				sent = true
			default:
				d.dropped.Add(1)
				d.log.Warn("popup queue full; popup dropped (hit still logged via 'log' alerter)",
					"rule", h.RuleID)
			}
			continue
		}
		if d.callAlerter(name, h) {
			sent = true
		}
	}
	return sent
}

// callAlerter invokes the named alerter, recovering from any panic so a faulty
// alerter can never crash the dispatcher. Unknown alerter names are warned.
// Reports whether a registered alerter was invoked.
func (d *Dispatcher) callAlerter(name string, h event.Hit) (called bool) {
	al, ok := d.alerters[name]
	if !ok {
		d.log.Debug("alerter not registered; skipping", "name", name, "rule", h.RuleID)
		return false
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
	return true
}

// Close drains-and-closes semantics for producers: after Close, Submit is a
// no-op. The write lock serializes against Submit's read lock, so close(d.in)
// can never race an in-flight send.
func (d *Dispatcher) Close() {
	d.closedMu.Lock()
	defer d.closedMu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	close(d.in)
}
