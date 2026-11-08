//go:build windows

// Real-time Sysmon ingester: a native EvtSubscribe pull subscription to
// Microsoft-Windows-Sysmon/Operational (the only production ingester).
//
// EvtSubscribe takes exactly one delivery mechanism: a callback (push model)
// or an event handle the service signals when new records arrive (pull model).
// Passing NULL for both fails with ERROR_INVALID_PARAMETER (87), which is what
// sank the first binding. This ingester uses the pull model.
//
// Flow:
//  1. Backlog: EvtQuery the channel newest-first and render up to backlogMax
//     records. They are emitted oldest-first: after a restart the daemon
//     re-evaluates recent events, so anything that fired while it was down is
//     still alerted (fail open to duplicates, never to silence; per-rule dedup
//     is persisted in state.db). This is deliberate — do not replace it with a
//     persisted "last seen" position that skips the downtime.
//  2. A bookmark is set on the newest backlog record and the subscription
//     starts after it, so nothing logged between the query and the subscribe
//     is lost. With an empty channel it subscribes to future events.
//  3. Read loop: wait on the signal event (1s timeout so ctx and the log-clear
//     check stay responsive), reset it, then drain EvtNext until
//     ERROR_NO_MORE_ITEMS. EvtNext on a subscription never blocks, so waiting
//     on the event is what keeps the loop from spinning.
//  4. The bookmark follows every delivered record. If EvtNext fails (channel
//     recreated, eventlog service restart), the subscription is reopened after
//     the bookmark with backoff.
//  5. Every clearCheckInterval the System log is queried for EID 104 (log
//     cleared, logclear.go); a clear of our channel raises TELEMETRY-002. A
//     clear does NOT restart RecordIds, so the rewind check alone never sees
//     one. A RecordId going backwards (channel recreated) raises it too.
//  6. Helper processes of sentinel's own binaries are filtered (selfParents)
//     and undecodable records are counted and WARNed (dropCounter).
//
// Reading the Sysmon channel requires an elevated token; the installed task
// runs as SYSTEM.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinel/internal/event"
)

// --- wevtapi.dll bindings (the Event Log API; not in x/sys/windows) ---

var (
	wevtapi = windows.NewLazyDLL("wevtapi.dll")

	procEvtSubscribe      = wevtapi.NewProc("EvtSubscribe")
	procEvtQuery          = wevtapi.NewProc("EvtQuery")
	procEvtNext           = wevtapi.NewProc("EvtNext")
	procEvtRender         = wevtapi.NewProc("EvtRender")
	procEvtClose          = wevtapi.NewProc("EvtClose")
	procEvtCreateBookmark = wevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = wevtapi.NewProc("EvtUpdateBookmark")
)

// EvtHandle is the opaque subscription/query/event/bookmark handle.
type EvtHandle uintptr

const (
	evtSubscribeToFutureEvents     = 1
	evtSubscribeStartAfterBookmark = 3

	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200

	evtRenderEventXml = 1

	// evtQueryTimeoutMs bounds one EvtNext on a query result set (synchronous
	// read of records already on disk).
	evtQueryTimeoutMs = 10_000
	// evtWaitMs is the longest the read loop sleeps on the signal event.
	evtWaitMs = 1000
	// evtBatch is how many handles one EvtNext may return.
	evtBatch = 64
	// resubscribeBackoff is the wait between attempts to reopen a failed
	// subscription.
	resubscribeBackoff = 5 * time.Second
	// backlogMax caps the records re-read at start (newest first).
	backlogMax = 2000
)

// sysmonRT is the EvtSubscribe-based Sysmon ingester.
type sysmonRT struct {
	channel  string
	query    string
	maxBack  int
	log      *slog.Logger
	parents  *selfParents
	clears   clearTracker
	lastScan time.Time // last System EID 104 query

	dropCounter

	signal   windows.Handle
	sub      EvtHandle
	bookmark EvtHandle
	marked   bool     // bookmark points at a real record
	highID   int64    // newest RecordId delivered (-1 = none yet)
	backlog  [][]byte // rendered by Start, handed to readLoop
	backlogN int      // len(backlog) at Start (for logs and tests)
	handles  []EvtHandle
}

// NewSysmonRT constructs the Sysmon ingester. query overrides the default
// EID filter (an XPath expression, or a structured XML query); "" uses
// defaultEIDQuery.
func NewSysmonRT(channel, query string, log *slog.Logger) (Ingester, error) {
	if query == "" {
		query = defaultEIDQuery()
	}
	return &sysmonRT{
		channel: channel,
		query:   query,
		maxBack: backlogMax,
		log:     log,
		parents: newSelfParents(),
		highID:  -1,
		handles: make([]EvtHandle, evtBatch),
	}, nil
}

// noteDropped records one undecodable event (see dropCounter).
func (s *sysmonRT) noteDropped(err error) { s.dropCounter.note(s.log, err) }

// isSelfChild reports whether ev is a helper process of sentinel's own
// binaries (see selfParents.isSelfChild).
func (s *sysmonRT) isSelfChild(ev event.Event) bool { return s.parents.isSelfChild(ev) }

// Start implements Ingester. The backlog query and the subscription happen
// here, so a bad channel, query or missing privilege fails Start loudly.
func (s *sysmonRT) Start(ctx context.Context) (<-chan event.Event, error) {
	var err error
	// Manual-reset, initially signaled: the loop resets it BEFORE draining, so
	// a record that arrives mid-drain re-signals it and is never stranded.
	s.signal, err = windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateEvent: %w", err)
	}
	s.bookmark, err = evtCreateBookmark()
	if err != nil {
		s.closeAll()
		return nil, err
	}
	if err := s.readBacklog(); err != nil {
		s.closeAll()
		return nil, fmt.Errorf("backlog query %s [query=%s]: %w", s.channel, s.query, err)
	}
	if err := s.subscribe(); err != nil {
		s.closeAll()
		return nil, fmt.Errorf("EvtSubscribe %s [query=%s]: %w", s.channel, s.query, err)
	}
	backlog := s.backlog
	s.backlog, s.backlogN = nil, len(backlog)
	s.log.Info("sysmon subscription active",
		"channel", s.channel, "query", s.query, "backlog", s.backlogN)
	out := make(chan event.Event, 4096)
	go s.readLoop(ctx, backlog, out)
	return out, nil
}

// channelArg returns the ChannelPath argument. A structured XML query (from
// -sysmon-query) names its own channels, and the API then requires a NULL
// channel path.
func (s *sysmonRT) channelArg() (*uint16, error) {
	if strings.HasPrefix(strings.TrimSpace(s.query), "<") {
		return nil, nil
	}
	return windows.UTF16PtrFromString(s.channel)
}

// readBacklog renders the newest maxBack matching records (newest first) and
// points the bookmark at the newest one.
func (s *sysmonRT) readBacklog() error {
	ch, err := s.channelArg()
	if err != nil {
		return err
	}
	q, err := windows.UTF16PtrFromString(s.query)
	if err != nil {
		return err
	}
	flags := uintptr(evtQueryReverseDirection)
	if ch != nil {
		flags |= evtQueryChannelPath
	}
	rs, err := evtQuery(ch, q, flags)
	if err != nil {
		return err
	}
	defer evtClose(rs)
	for len(s.backlog) < s.maxBack {
		want := min(evtBatch, s.maxBack-len(s.backlog))
		got, err := evtNext(rs, s.handles[:want], evtQueryTimeoutMs)
		if errors.Is(err, errEvtNoMore) {
			break
		}
		if err != nil {
			return err
		}
		for _, h := range s.handles[:got] {
			if !s.marked {
				if err := evtUpdateBookmark(s.bookmark, h); err == nil {
					s.marked = true
				}
			}
			xml, rerr := evtRenderXML(h)
			evtClose(h)
			if rerr != nil {
				s.noteDropped(rerr)
				continue
			}
			s.backlog = append(s.backlog, xml)
		}
	}
	return nil
}

// subscribe opens the pull subscription after the bookmark, or at future
// events when no record has been seen yet.
func (s *sysmonRT) subscribe() error {
	ch, err := s.channelArg()
	if err != nil {
		return err
	}
	q, err := windows.UTF16PtrFromString(s.query)
	if err != nil {
		return err
	}
	bm, flags := EvtHandle(0), uintptr(evtSubscribeToFutureEvents)
	if s.marked {
		bm, flags = s.bookmark, evtSubscribeStartAfterBookmark
	}
	sub, err := evtSubscribe(s.signal, ch, q, bm, flags)
	if err != nil {
		return err
	}
	s.sub = sub
	return nil
}

func (s *sysmonRT) closeAll() {
	if s.sub != 0 {
		evtClose(s.sub)
		s.sub = 0
	}
	if s.bookmark != 0 {
		evtClose(s.bookmark)
		s.bookmark = 0
	}
	if s.signal != 0 {
		_ = windows.CloseHandle(s.signal)
		s.signal = 0
	}
}

func (s *sysmonRT) readLoop(ctx context.Context, backlog [][]byte, out chan<- event.Event) {
	defer close(out)
	defer s.closeAll()

	// Backlog oldest-first, like the poller's first poll.
	for i := len(backlog) - 1; i >= 0; i-- {
		if !s.emitXML(ctx, backlog[i], out) {
			return
		}
	}

	for {
		if ctx.Err() != nil {
			s.log.Info("sysmon ingester stopping (context cancelled)")
			return
		}
		if !s.checkClears(ctx, out) {
			return
		}
		if s.sub == 0 {
			if err := s.subscribe(); err != nil {
				s.log.Warn("sysmon resubscribe failed; retrying", "err", err, "in", resubscribeBackoff)
				if !sleepCtx(ctx, resubscribeBackoff) {
					return
				}
				continue
			}
			s.log.Info("sysmon subscription reopened", "after_bookmark", s.marked)
		}
		if _, err := windows.WaitForSingleObject(s.signal, evtWaitMs); err != nil {
			s.log.Warn("WaitForSingleObject failed", "err", err)
			if !sleepCtx(ctx, time.Second) {
				return
			}
		}
		// Drain on a signal AND on a timeout: draining an empty subscription is
		// one cheap call, and it guarantees nothing waits on a missed signal.
		_ = windows.ResetEvent(s.signal)
		if !s.drain(ctx, out) {
			return
		}
	}
}

// drain reads every record the subscription has queued. It returns false only
// when ctx was cancelled.
func (s *sysmonRT) drain(ctx context.Context, out chan<- event.Event) bool {
	for {
		got, err := evtNext(s.sub, s.handles, 0)
		if errors.Is(err, errEvtNoMore) || errors.Is(err, errEvtTimeout) {
			return true
		}
		if err != nil {
			// Subscription is broken (channel recreated, eventlog service
			// restarted, ...). Reopen it after the bookmark on the next pass.
			s.log.Warn("sysmon EvtNext failed; reopening subscription", "err", err)
			evtClose(s.sub)
			s.sub = 0
			return sleepCtx(ctx, time.Second)
		}
		for i := uint32(0); i < got; i++ {
			h := s.handles[i]
			if err := evtUpdateBookmark(s.bookmark, h); err == nil {
				s.marked = true
			}
			xml, rerr := evtRenderXML(h)
			evtClose(h)
			if rerr != nil {
				s.noteDropped(rerr)
				continue
			}
			if !s.emitXML(ctx, xml, out) {
				// Close the rest of this batch before leaving.
				for _, rest := range s.handles[i+1 : got] {
					evtClose(rest)
				}
				return false
			}
		}
	}
}

// emitXML parses one rendered record, runs the rewind check and the
// self-ingestion filter, and sends it. It returns false only when ctx was
// cancelled.
func (s *sysmonRT) emitXML(ctx context.Context, xml []byte, out chan<- event.Event) bool {
	ev, err := parseRenderedXML(s.log, xml)
	if err != nil {
		s.noteDropped(err)
		return true
	}
	id := int64(ev.RecordID)
	// A subscription delivers in RecordId order, so an id below the newest one
	// already delivered means the channel was recreated (RecordIds restarted).
	if recordIDsRewound(id, s.highID) {
		s.log.Warn("sysmon channel RecordId rewound (channel recreated)",
			"channel", s.channel, "record_id", id, "high_water", s.highID)
		if !send(ctx, out, rewoundEvent(s.channel, id, s.highID)) {
			return false
		}
		s.highID = -1
	}
	if id > s.highID {
		s.highID = id
	}
	if s.isSelfChild(ev) {
		return true
	}
	return send(ctx, out, ev)
}

// checkClears queries System EID 104 (log cleared) on the first pass and then
// every clearCheckInterval, emitting each clear of our channel once.
func (s *sysmonRT) checkClears(ctx context.Context, out chan<- event.Event) bool {
	now := time.Now()
	if !s.lastScan.IsZero() && now.Sub(s.lastScan) < clearCheckInterval {
		return true
	}
	s.lastScan = now
	clears, err := queryLogClears()
	if err != nil {
		s.log.Warn("System EID 104 (log cleared) query failed", "err", err)
		return true
	}
	for _, lc := range s.clears.fresh(clears, s.channel, now) {
		s.log.Warn("sysmon log was cleared (System log EID 104)",
			"channel", lc.Channel, "by", lc.User, "cleared_at", lc.Time.Local(),
			"backup", lc.Backup, "client_pid", lc.ClientPID, "system_record_id", lc.RecordID)
		if !send(ctx, out, logClearedEvent(lc)) {
			return false
		}
	}
	return true
}

// logClearsQuery selects System EID 104 records from the last clearLookback.
func logClearsQuery() string {
	return fmt.Sprintf(
		"*[System[Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=104 and TimeCreated[timediff(@SystemTime) <= %d]]]",
		clearLookback.Milliseconds())
}

// queryLogClears reads up to 50 recent System EID 104 records.
func queryLogClears() ([]logClear, error) {
	ch, _ := windows.UTF16PtrFromString("System")
	q, err := windows.UTF16PtrFromString(logClearsQuery())
	if err != nil {
		return nil, err
	}
	rs, err := evtQuery(ch, q, evtQueryChannelPath|evtQueryReverseDirection)
	if err != nil {
		return nil, err
	}
	defer evtClose(rs)
	handles := make([]EvtHandle, 50)
	got, err := evtNext(rs, handles, evtQueryTimeoutMs)
	if errors.Is(err, errEvtNoMore) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var clears []logClear
	for _, h := range handles[:got] {
		raw, rerr := evtRenderXML(h)
		evtClose(h)
		if rerr != nil {
			continue
		}
		x, derr := decodeUTF16LE(raw)
		if derr != nil {
			continue
		}
		if lc, perr := parseLogCleared([]byte(x)); perr == nil {
			clears = append(clears, lc)
		}
	}
	return clears, nil
}

func send(ctx context.Context, out chan<- event.Event, ev event.Event) bool {
	select {
	case <-ctx.Done():
		return false
	case out <- ev:
		return true
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// --- thin wevtapi wrappers ---

func evtSubscribe(signal windows.Handle, channel, query *uint16, bookmark EvtHandle, flags uintptr) (EvtHandle, error) {
	// Session, SignalEvent, ChannelPath, Query, Bookmark, Context, Callback, Flags.
	// Pull model: SignalEvent set, Callback NULL (exactly one must be set).
	r1, _, lastErr := procEvtSubscribe.Call(
		0, uintptr(signal),
		uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(query)),
		uintptr(bookmark), 0, 0,
		flags,
	)
	if r1 == 0 {
		return 0, fmt.Errorf("EvtSubscribe: %w", lastErr)
	}
	return EvtHandle(r1), nil
}

func evtQuery(channel, query *uint16, flags uintptr) (EvtHandle, error) {
	r1, _, lastErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(query)),
		flags,
	)
	if r1 == 0 {
		return 0, fmt.Errorf("EvtQuery: %w", lastErr)
	}
	return EvtHandle(r1), nil
}

func evtCreateBookmark() (EvtHandle, error) {
	r1, _, lastErr := procEvtCreateBookmark.Call(0)
	if r1 == 0 {
		return 0, fmt.Errorf("EvtCreateBookmark: %w", lastErr)
	}
	return EvtHandle(r1), nil
}

func evtUpdateBookmark(bookmark, ev EvtHandle) error {
	r1, _, lastErr := procEvtUpdateBookmark.Call(uintptr(bookmark), uintptr(ev))
	if r1 == 0 {
		return fmt.Errorf("EvtUpdateBookmark: %w", lastErr)
	}
	return nil
}

var (
	errEvtNoMore  = errors.New("EvtNext: ERROR_NO_MORE_ITEMS")
	errEvtTimeout = errors.New("EvtNext: ERROR_TIMEOUT")

	// errInvalidOperation is ERROR_INVALID_OPERATION (4317, "The operation
	// identifier is not valid.").
	errInvalidOperation = syscall.Errno(4317)
)

func evtNext(rs EvtHandle, handles []EvtHandle, timeoutMs uint32) (uint32, error) {
	var got uint32
	r1, _, lastErr := procEvtNext.Call(
		uintptr(rs), uintptr(len(handles)),
		uintptr(unsafe.Pointer(&handles[0])),
		uintptr(timeoutMs), 0,
		uintptr(unsafe.Pointer(&got)),
	)
	if r1 == 0 {
		switch {
		case errors.Is(lastErr, windows.ERROR_NO_MORE_ITEMS):
			return 0, errEvtNoMore
		case errors.Is(lastErr, errInvalidOperation) && got == 0:
			// A pull subscription that already reported ERROR_NO_MORE_ITEMS
			// and has nothing new answers the next EvtNext with
			// ERROR_INVALID_OPERATION, not ERROR_NO_MORE_ITEMS. It is idle,
			// not broken; treating it as broken tore the subscription down
			// and reopened it every few seconds.
			return 0, errEvtNoMore
		case errors.Is(lastErr, windows.ERROR_TIMEOUT):
			return 0, errEvtTimeout
		default:
			return 0, fmt.Errorf("EvtNext: %w", lastErr)
		}
	}
	return got, nil
}

func evtRenderXML(h EvtHandle) ([]byte, error) {
	var used, count uint32
	// First call sizes the buffer (fails with ERROR_INSUFFICIENT_BUFFER).
	_, _, _ = procEvtRender.Call(
		0, uintptr(h), evtRenderEventXml, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)),
	)
	if used == 0 {
		return nil, errors.New("EvtRender zero-length")
	}
	buf := make([]byte, used)
	r1, _, lastErr := procEvtRender.Call(
		0, uintptr(h), evtRenderEventXml, uintptr(used),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("EvtRender: %w", lastErr)
	}
	buf = buf[:used]
	for len(buf) >= 2 && buf[len(buf)-1] == 0 && buf[len(buf)-2] == 0 {
		buf = buf[:len(buf)-2]
	}
	return buf, nil
}

func evtClose(h EvtHandle) { _, _, _ = procEvtClose.Call(uintptr(h)) }
