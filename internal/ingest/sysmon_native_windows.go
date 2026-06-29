//go:build windows

// Experimental native EvtSubscribe ingester (NOT the default path).
//
// STATUS: BROKEN — returns ERROR_INVALID_PARAMETER (87) on EvtSubscribe despite
// the channel being readable by the same process via Get-WinEvent (verified:
// elevated cmd can Get-WinEvent the Sysmon Operational channel but EvtSubscribe
// in this binding fails). The binding looks textbook-correct; the failure cause
// is not yet isolated. Kept here behind the -sysmon-native flag so it can be
// revived and fixed properly without blocking Phase 1.
//
// The DEFAULT ingester is the PowerShell Get-WinEvent poller in
// sysmon_rt_windows.go, which is proven to read the channel.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinel/internal/event"
	"sentinel/internal/sysmonxml"
)

// --- wevtapi.dll bindings (the Event Log API; not in x/sys/windows) ---

var (
	wevtapi = windows.NewLazyDLL("wevtapi.dll")

	procEvtSubscribe = wevtapi.NewProc("EvtSubscribe")
	procEvtNext      = wevtapi.NewProc("EvtNext")
	procEvtRender    = wevtapi.NewProc("EvtRender")
	procEvtClose     = wevtapi.NewProc("EvtClose")
)

// EvtHandle is the opaque subscription/event handle.
type EvtHandle uintptr

const (
	evtSubscribeToFutureEvents = 0x1
	evtRenderEventXml          = 1
	evtNextTimeoutMs           = 1000
)

// sysmonNative is the EvtSubscribe-based ingester (experimental).
type sysmonNative struct {
	channel string
	query   string
	log     *slog.Logger
}

// NewSysmonRTNative constructs the experimental native ingester. Use via
// `sentinel -sysmon-native`. Prefer NewSysmonRT (the poller) for now.
func NewSysmonRTNative(channel, query string, log *slog.Logger) (Ingester, error) {
	if query == "" {
		query = defaultEIDQuery()
	}
	return &sysmonNative{channel: channel, query: query, log: log}, nil
}

func (s *sysmonNative) Start(ctx context.Context) (<-chan event.Event, error) {
	chW, err := windows.UTF16PtrFromString(s.channel)
	if err != nil {
		return nil, fmt.Errorf("utf16 channel: %w", err)
	}
	qW, err := windows.UTF16PtrFromString(s.query)
	if err != nil {
		return nil, fmt.Errorf("utf16 query: %w", err)
	}
	sub, err := evtSubscribe(chW, qW)
	if err != nil {
		return nil, fmt.Errorf("EvtSubscribe %s [query=%s]: %w", s.channel, s.query, err)
	}
	s.log.Info("sysmon NATIVE subscription active", "channel", s.channel, "query", s.query)
	out := make(chan event.Event, 4096)
	go s.readLoop(ctx, sub, out)
	return out, nil
}

func evtSubscribe(channel, query *uint16) (EvtHandle, error) {
	r1, _, lastErr := procEvtSubscribe.Call(
		0, 0,
		uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(query)),
		0, 0, 0,
		evtSubscribeToFutureEvents,
	)
	if r1 == 0 {
		return 0, fmt.Errorf("EvtSubscribe: %w", lastErr)
	}
	return EvtHandle(r1), nil
}

func (s *sysmonNative) readLoop(ctx context.Context, sub EvtHandle, out chan<- event.Event) {
	defer close(out)
	defer evtClose(sub)
	const batchSize = 32
	handles := make([]EvtHandle, batchSize)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		got, err := evtNext(sub, handles, evtNextTimeoutMs)
		if err != nil {
			if !errors.Is(err, errEvtNoMore) && !errors.Is(err, errEvtTimeout) {
				s.log.Warn("EvtNext error", "err", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
			continue
		}
		for i := uint32(0); i < got; i++ {
			xmlUTF16, err := evtRenderXML(handles[i])
			evtClose(handles[i])
			if err != nil {
				s.log.Warn("render failed", "err", err)
				continue
			}
			xmlStr, err := decodeUTF16LE(xmlUTF16)
			if err != nil {
				continue
			}
			ev, err := sysmonxml.Parse([]byte(xmlStr), event.SrcSysmonRT)
			if err != nil {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case out <- ev:
			}
		}
	}
}

var (
	errEvtNoMore  = fmt.Errorf("EvtNext: ERROR_NO_MORE_ITEMS")
	errEvtTimeout = fmt.Errorf("EvtNext: ERROR_TIMEOUT")
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
			return got, errEvtNoMore
		case errors.Is(lastErr, windows.ERROR_TIMEOUT):
			return got, errEvtTimeout
		default:
			return got, fmt.Errorf("EvtNext: %w", lastErr)
		}
	}
	return got, nil
}

func evtRenderXML(h EvtHandle) ([]byte, error) {
	var used, count uint32
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
	for len(buf) >= 2 && buf[len(buf)-1] == 0 && buf[len(buf)-2] == 0 {
		buf = buf[:len(buf)-2]
	}
	return buf, nil
}

func evtClose(h EvtHandle) { _, _, _ = procEvtClose.Call(uintptr(h)) }
