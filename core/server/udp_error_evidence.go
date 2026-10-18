package server

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// The dimensions are fixed: no error string, address or child-session registry.
var udpErrorClasses = [...]string{
	"dns_timeout", "dns_not_found", "dns_other", "address_invalid",
	"no_ipv4", "no_ipv6", "no_address", "outbound_mode_invalid",
	"closed", "cancelled", "timeout", "address_unavailable",
	"network_unreachable", "host_unreachable", "permission_denied",
	"message_too_large", "connection_refused", "would_block", "no_buffer", "other",
}

var udpErrorPhases = [...]string{"init", "target_write"}

type udpErrorCell struct {
	count, firstUS, lastUS uint64
}

type udpErrorRecord struct {
	class, layer, family string
	atUS, elapsedUS      int64
	durationKnown        bool
	requested, written   int
	entryClosing, ended  bool
}

type udpErrorState struct {
	mu       sync.Mutex // error path and bounded snapshot only; never successful WriteTo
	sequence uint64
	cells    [2][len(udpErrorClasses)]udpErrorCell
	latest   [2]udpErrorRecord
	seen     [2]bool
}

type UDPErrorCounter struct {
	Phase          string `json:"phase"`
	Class          string `json:"class"`
	Count          uint64 `json:"count"`
	FirstAuthAgeUS uint64 `json:"first_auth_age_us"`
	LastAuthAgeUS  uint64 `json:"last_auth_age_us"`
}

type UDPErrorLast struct {
	Phase              string `json:"phase"`
	Class              string `json:"class"`
	Layer              string `json:"layer"`
	ErrorAddressFamily string `json:"error_address_family"`
	CompletedAuthAgeUS int64  `json:"completed_auth_age_us"`
	DurationUS         *int64 `json:"duration_us"`
	RequestedBytes     int    `json:"requested_bytes"`
	WrittenBytes       int    `json:"written_bytes"`
	UDPEntryClosing    bool   `json:"udp_entry_closing"`
	QUICEnded          bool   `json:"quic_ended"`
}

type UDPErrorDetail struct {
	Version                          int               `json:"version"`
	Sequence                         uint64            `json:"sequence"`
	SampleUnixMS                     int64             `json:"sample_unix_ms"`
	SampleAuthAgeUS                  int64             `json:"sample_auth_age_us"`
	BestEffort                       bool              `json:"best_effort"`
	PostCloseUpdatesMayBeUnpublished bool              `json:"post_close_updates_may_be_unpublished"`
	Counters                         []UDPErrorCounter `json:"counters"`
	Latest                           []UDPErrorLast    `json:"latest"`
}

// extras/outbounds implements this on its existing private error types. This
// preserves Error/Unwrap and avoids a core -> extras import cycle. Unknown
// values are ignored, never serialized as caller-controlled labels.
type udpErrorClassHint interface{ UDPErrorClass() string }

func classifyUDPError(err error) (class, layer, family string) {
	class, layer, family = "other", "outbound_other", "unknown"
	var dns *net.DNSError
	if errors.As(err, &dns) {
		switch {
		case dns.IsTimeout:
			return "dns_timeout", "resolve", family
		case dns.IsNotFound:
			return "dns_not_found", "resolve", family
		default:
			return "dns_other", "resolve", family
		}
	}
	var addr *net.AddrError
	var number *strconv.NumError
	if errors.As(err, &addr) || errors.As(err, &number) {
		return "address_invalid", "address_parse", family
	}
	var hint udpErrorClassHint
	if errors.As(err, &hint) {
		switch hint.UDPErrorClass() {
		case "dns_other":
			return "dns_other", "resolve", family
		case "no_ipv4":
			return "no_ipv4", "address_selection", family
		case "no_ipv6":
			return "no_ipv6", "address_selection", family
		case "no_address":
			return "no_address", "address_selection", family
		case "outbound_mode_invalid":
			return "outbound_mode_invalid", "address_selection", family
		}
	}
	// Addr describes the destination in this error, not the actual socket family.
	// A dual-stack socket can report an IPv4 destination.
	var op *net.OpError
	if errors.As(err, &op) && op != nil && op.Op == "write" {
		layer = "socket_write"
		if a, ok := op.Addr.(*net.UDPAddr); ok && a != nil && a.IP != nil {
			if a.IP.To4() != nil {
				family = "ipv4"
			} else if a.IP.To16() != nil {
				family = "ipv6"
			}
		}
	}
	switch {
	case errors.Is(err, net.ErrClosed), errors.Is(err, os.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		return "closed", "connection_state", family
	case errors.Is(err, context.Canceled):
		return "cancelled", layer, family
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		class = "address_unavailable"
	case errors.Is(err, syscall.ENETUNREACH):
		class = "network_unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		class = "host_unreachable"
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		class = "permission_denied"
	case errors.Is(err, syscall.EMSGSIZE):
		class = "message_too_large"
	case errors.Is(err, syscall.ECONNREFUSED):
		class = "connection_refused"
	case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EWOULDBLOCK):
		class = "would_block"
	case errors.Is(err, syscall.ENOBUFS):
		class = "no_buffer"
	default:
		var timeout net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
			class = "timeout"
		}
	}
	return
}

func (u *udpEvidence) recordError(phase uint32, err error, requested, written int, op *udpOperation, entryClosing bool) {
	if u == nil || err == nil {
		return
	}
	phaseIndex := 0
	if phase == udpPhaseTargetWrite {
		phaseIndex = 1
	} else if phase != udpPhaseInit {
		return
	}
	now := time.Now()
	r := udpErrorRecord{atUS: max(0, now.Sub(u.connection.authAt).Microseconds()), requested: requested, written: written, entryClosing: entryClosing, ended: u.connection.ended.Load()}
	// The caller still owns the operation slot, before complete releases it.
	if op != nil {
		r.durationKnown = true
		r.elapsedUS = max(0, (now.Sub(u.connection.created) - time.Duration(op.started.Load())).Microseconds())
	}
	r.class, r.layer, r.family = classifyUDPError(err)
	index := len(udpErrorClasses) - 1
	for i, name := range udpErrorClasses {
		if name == r.class {
			index = i
			break
		}
	}
	s := &u.errors
	s.mu.Lock()
	s.sequence++
	c := &s.cells[phaseIndex][index]
	at := uint64(r.atUS)
	if c.count == 0 || at < c.firstUS {
		c.firstUS = at
	}
	if c.count == 0 || at > c.lastUS {
		c.lastUS = at
	}
	c.count++
	if !s.seen[phaseIndex] || r.atUS >= s.latest[phaseIndex].atUS {
		s.latest[phaseIndex] = r
		s.seen[phaseIndex] = true
	}
	s.mu.Unlock()
}

func (u *udpEvidence) errorSnapshot() *UDPErrorDetail {
	// Copy fixed state while holding the error-only lock; allocate/encode after
	// release. This is coherent internally, not atomic with the legacy counters.
	s := &u.errors
	s.mu.Lock()
	sequence, cells, latest, seen := s.sequence, s.cells, s.latest, s.seen
	captured := time.Now()
	s.mu.Unlock()
	e := &UDPErrorDetail{Version: 1, Sequence: sequence, SampleUnixMS: captured.UnixMilli(), SampleAuthAgeUS: max(0, captured.Sub(u.connection.authAt).Microseconds()), BestEffort: true, PostCloseUpdatesMayBeUnpublished: true, Counters: []UDPErrorCounter{}, Latest: []UDPErrorLast{}}
	for phase := range cells {
		for class, c := range cells[phase] {
			if c.count != 0 {
				e.Counters = append(e.Counters, UDPErrorCounter{udpErrorPhases[phase], udpErrorClasses[class], c.count, c.firstUS, c.lastUS})
			}
		}
		if seen[phase] {
			r := latest[phase]
			v := UDPErrorLast{Phase: udpErrorPhases[phase], Class: r.class, Layer: r.layer, ErrorAddressFamily: r.family, CompletedAuthAgeUS: r.atUS, RequestedBytes: r.requested, WrittenBytes: r.written, UDPEntryClosing: r.entryClosing, QUICEnded: r.ended}
			if r.durationKnown {
				d := r.elapsedUS
				v.DurationUS = &d
			}
			e.Latest = append(e.Latest, v)
		}
	}
	return e
}
