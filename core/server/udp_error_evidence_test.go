package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

type udpDiagnosticHint struct {
	class string
	cause error
}

func (e udpDiagnosticHint) Error() string         { return "PRIVATE synthetic target/account" }
func (e udpDiagnosticHint) Unwrap() error         { return e.cause }
func (e udpDiagnosticHint) UDPErrorClass() string { return e.class }

type udpPanicError struct{}

func (udpPanicError) Error() string { panic("error text must never be read") }

func TestUDPErrorClassifier(t *testing.T) {
	for _, tc := range []struct {
		err          error
		class, layer string
	}{
		{&net.DNSError{IsTimeout: true}, "dns_timeout", "resolve"},
		{&net.DNSError{IsNotFound: true}, "dns_not_found", "resolve"},
		{&net.DNSError{}, "dns_other", "resolve"},
		{udpDiagnosticHint{"dns_other", &net.DNSError{IsTimeout: true}}, "dns_timeout", "resolve"},
		{&net.OpError{Op: "write", Err: &net.DNSError{IsNotFound: true}}, "dns_not_found", "resolve"},
		{&net.AddrError{Err: "PRIVATE", Addr: "PRIVATE"}, "address_invalid", "address_parse"},
		{&strconv.NumError{Func: "Atoi", Num: "PRIVATE", Err: strconv.ErrSyntax}, "address_invalid", "address_parse"},
		{udpDiagnosticHint{"no_ipv4", nil}, "no_ipv4", "address_selection"},
		{udpDiagnosticHint{"no_ipv6", nil}, "no_ipv6", "address_selection"},
		{udpDiagnosticHint{"no_address", nil}, "no_address", "address_selection"},
		{udpDiagnosticHint{"outbound_mode_invalid", nil}, "outbound_mode_invalid", "address_selection"},
		{udpDiagnosticHint{"dns_other", nil}, "dns_other", "resolve"},
		{udpDiagnosticHint{"PRIVATE unexpected enum", nil}, "other", "outbound_other"},
		{net.ErrClosed, "closed", "connection_state"},
		{context.Canceled, "cancelled", "outbound_other"},
		{context.DeadlineExceeded, "timeout", "outbound_other"},
		{syscall.ETIMEDOUT, "timeout", "outbound_other"},
		{syscall.EADDRNOTAVAIL, "address_unavailable", "outbound_other"},
		{syscall.ENETUNREACH, "network_unreachable", "outbound_other"},
		{syscall.EHOSTUNREACH, "host_unreachable", "outbound_other"},
		{syscall.EACCES, "permission_denied", "outbound_other"},
		{syscall.EPERM, "permission_denied", "outbound_other"},
		{syscall.EMSGSIZE, "message_too_large", "outbound_other"},
		{syscall.ECONNREFUSED, "connection_refused", "outbound_other"},
		{syscall.EAGAIN, "would_block", "outbound_other"},
		{syscall.ENOBUFS, "no_buffer", "outbound_other"},
		{udpPanicError{}, "other", "outbound_other"},
	} {
		class, layer, family := classifyUDPError(tc.err)
		if class != tc.class || layer != tc.layer || family != "unknown" {
			t.Fatalf("class=%s layer=%s family=%s; want %s/%s", class, layer, family, tc.class, tc.layer)
		}
		// Wrapping cannot erase type/errno information.
		class, layer, family = classifyUDPError(&os.SyscallError{Syscall: "PRIVATE", Err: tc.err})
		if class != tc.class || layer != tc.layer || family != "unknown" {
			t.Fatal("wrapped classification changed")
		}
	}
	for _, tc := range []struct{ ip, family string }{{"192.0.2.1", "ipv4"}, {"2001:db8::1", "ipv6"}} {
		err := &net.OpError{Op: "write", Net: "udp", Addr: &net.UDPAddr{IP: net.ParseIP(tc.ip), Port: 1234}, Err: &os.SyscallError{Syscall: "sendto", Err: syscall.EMSGSIZE}}
		class, layer, family := classifyUDPError(err)
		if class != "message_too_large" || layer != "socket_write" || family != tc.family {
			t.Fatal("UDP family/class not preserved")
		}
	}
	var nilAddress *net.UDPAddr
	class, layer, family := classifyUDPError(&net.OpError{Op: "write", Addr: nilAddress, Err: syscall.EACCES})
	if class != "permission_denied" || layer != "socket_write" || family != "unknown" {
		t.Fatal("missing socket address must remain unknown")
	}
}

func TestUDPErrorRecordsBoundedPrivateAndSnapshotImmutable(t *testing.T) {
	m, u := newTestUDP(t)
	before := u.errorSnapshot()
	if before.Version != 1 || before.Sequence != 0 || len(before.Counters) != 0 || len(before.Latest) != 0 || !before.PostCloseUpdatesMayBeUnpublished {
		t.Fatal("bad empty/detail coverage")
	}
	err := &net.OpError{Op: "write", Net: "udp", Addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234}, Err: udpPanicError{}}
	for i := 0; i < 1000; i++ {
		u.recordError(udpPhaseTargetWrite, err, 5, 2, nil, false)
	}
	a := u.errorSnapshot()
	if a.Sequence != 1000 || len(a.Counters) != 1 || a.Counters[0].Count != 1000 || len(a.Latest) != 1 || a.Latest[0].DurationUS != nil || a.Latest[0].WrittenBytes != 2 {
		t.Fatal("error record contract")
	}
	if a.Counters[0].FirstAuthAgeUS > a.Counters[0].LastAuthAgeUS || a.Counters[0].LastAuthAgeUS > uint64(a.SampleAuthAgeUS) {
		t.Fatal("capture clock/order")
	}
	if len(m.events) != 0 {
		t.Fatal("fast errors created per-error events")
	}
	u.recordError(udpPhaseTargetWrite, net.ErrClosed, 5, 0, nil, true)
	if a.Sequence != 1000 || a.Counters[0].Count != 1000 || a.Latest[0].UDPEntryClosing {
		t.Fatal("published snapshot mutated")
	}
	b, errJSON := json.Marshal(a)
	if errJSON != nil || strings.Contains(string(b), "192.0.2.1") || strings.Contains(string(b), "PRIVATE") {
		t.Fatal("private error/endpoint leaked")
	}
	if unsafe.Sizeof(udpErrorState{}) > 2048 {
		t.Fatal("fixed error state exceeds 2 KiB")
	}
	// Every cell occupied remains fixed-size; no error text or variable labels.
	u.errors.mu.Lock()
	for phase := range u.errors.cells {
		for class := range u.errors.cells[phase] {
			u.errors.cells[phase][class] = udpErrorCell{1, 0, 0}
		}
	}
	u.errors.mu.Unlock()
	full := u.errorSnapshot()
	encoded, _ := json.Marshal(full)
	if len(full.Counters) != 40 || len(full.Latest) > 2 || len(encoded) > 12*1024 {
		t.Fatal("snapshot bound")
	}
}

func TestUDPErrorFeedPreservesReturnAndNextDatagram(t *testing.T) {
	_, u := newTestUDP(t)
	errWrite := fmt.Errorf("PRIVATE: %w", syscall.EADDRNOTAVAIL)
	conn := newMockUDPConn(t)
	conn.EXPECT().WriteTo([]byte("hello"), "synthetic.invalid:1").Return(2, errWrite).Once()
	conn.EXPECT().WriteTo([]byte("fail-manager"), "synthetic.invalid:1").Return(0, errWrite).Once()
	conn.EXPECT().WriteTo([]byte("again"), "synthetic.invalid:1").Return(5, nil).Once()
	conn.EXPECT().WriteTo([]byte{}, "synthetic.invalid:1").Return(0, nil).Once()
	e := newUDPSessionEntry(1, nil, nil, func(error) { t.Error("Feed error closed entry") })
	e.conn = conn
	e.Evidence = u
	n, err := e.Feed(&protocol.UDPMessage{SessionID: 1, FragCount: 1, Addr: "synthetic.invalid:1", Data: []byte("hello")})
	if n != 2 || err != errWrite || u.targetWriteCalls.Load() != 1 || u.targetWrittenBytes.Load() != 2 || u.targetWriteErrors.Load() != 1 {
		t.Fatal("Feed error return/counters changed")
	}
	a := u.errorSnapshot()
	if a.Sequence != 1 || a.Counters[0].Class != "address_unavailable" || a.Latest[0].DurationUS == nil || a.Latest[0].UDPEntryClosing {
		t.Fatal("Feed error detail")
	}
	// Run the real manager's ignore-and-continue path, without spawning a read loop.
	m := newUDPSessionManager(nil, nil, time.Minute)
	m.m[1] = e
	m.feed(&protocol.UDPMessage{SessionID: 1, FragCount: 1, Addr: "synthetic.invalid:1", Data: []byte("fail-manager")})
	m.feed(&protocol.UDPMessage{SessionID: 1, FragCount: 1, Addr: "synthetic.invalid:1", Data: []byte("again")})
	m.feed(&protocol.UDPMessage{SessionID: 1, FragCount: 1, Addr: "synthetic.invalid:1", Data: []byte{}})
	if m.Count() != 1 || u.targetWriteCalls.Load() != 4 || u.targetWrittenBytes.Load() != 7 || u.targetWriteErrors.Load() != 2 || u.errorSnapshot().Sequence != 2 {
		t.Fatal("next/empty datagram changed")
	}
}

func TestUDPErrorInitAndDisabledSemantics(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			var u *udpEvidence
			if enabled {
				_, u = newTestUDP(t)
			}
			errInit := errors.New("PRIVATE synthetic hook/ACL refusal")
			closes := 0
			e := newUDPSessionEntry(1, nil, func(string, []byte) (UDPConn, string, error) { return nil, "", errInit }, func(err error) {
				if err != errInit {
					t.Error("init error identity changed")
				}
				closes++
			})
			e.Evidence = u
			n, err := e.Feed(&protocol.UDPMessage{FragCount: 1, Addr: "synthetic.invalid:1", Data: []byte("a")})
			if n != 0 || err != errInit || closes != 1 {
				t.Fatal("init fail-fast behavior changed")
			}
			if enabled {
				a := u.errorSnapshot()
				if a.Sequence != 1 || a.Counters[0].Phase != "init" || !a.Latest[0].UDPEntryClosing || u.targetWriteCalls.Load() != 0 || u.targetWriteErrors.Load() != 0 {
					t.Fatal("init mislabeled as target write")
				}
			} else if e.evidenceClosing.Load() {
				t.Fatal("disabled observer did work")
			}
		})
	}
}

func TestUDPErrorCountsWithoutOperationSlot(t *testing.T) {
	_, u := newTestUDP(t)
	var ops []*udpOperation
	for i := 0; i < 8; i++ {
		ops = append(ops, u.begin(udpPhaseSendDatagram, 1))
	}
	conn := newMockUDPConn(t)
	conn.EXPECT().WriteTo([]byte("a"), "synthetic.invalid:1").Return(0, net.ErrClosed).Once()
	e := newUDPSessionEntry(1, nil, nil, nil)
	e.conn = conn
	e.Evidence = u
	_, _ = e.Feed(&protocol.UDPMessage{FragCount: 1, Addr: "synthetic.invalid:1", Data: []byte("a")})
	a := u.errorSnapshot()
	if a.Sequence != 1 || a.Latest[0].DurationUS != nil || u.untrackedOperations.Load() != 1 || u.targetWriteErrors.Load() != 1 {
		t.Fatal("slot cap lost error or invented duration")
	}
	for _, op := range ops {
		op.complete(0, nil)
	}
}

func TestUDPErrorDisabledWritePreservesOutcome(t *testing.T) {
	errWrite := fmt.Errorf("synthetic: %w", syscall.EMSGSIZE)
	conn := newMockUDPConn(t)
	conn.EXPECT().WriteTo([]byte("hello"), "synthetic.invalid:1").Return(2, errWrite).Once()
	e := newUDPSessionEntry(1, nil, nil, func(error) { t.Error("write error closed disabled entry") })
	e.conn = conn
	n, err := e.Feed(&protocol.UDPMessage{FragCount: 1, Addr: "synthetic.invalid:1", Data: []byte("hello")})
	if n != 2 || err != errWrite || e.Evidence != nil || e.evidenceClosing.Load() {
		t.Fatal("disabled WriteTo behavior changed")
	}
}

type udpCloseRaceConn struct {
	started, release chan struct{}
	once             sync.Once
	closes           atomic.Int32
}

func (c *udpCloseRaceConn) WriteTo([]byte, string) (int, error) {
	close(c.started)
	<-c.release
	return 0, net.ErrClosed
}
func (c *udpCloseRaceConn) ReadFrom([]byte) (int, string, error) { return 0, "", net.ErrClosed }
func (c *udpCloseRaceConn) Close() error {
	c.closes.Add(1)
	c.once.Do(func() { close(c.release) })
	return nil
}

func TestUDPErrorCloseRaceAndLateFinalCoverage(t *testing.T) {
	_, u := newTestUDP(t)
	c := &udpCloseRaceConn{started: make(chan struct{}), release: make(chan struct{})}
	var exits atomic.Int32
	e := newUDPSessionEntry(1, nil, nil, func(error) { exits.Add(1) })
	e.conn = c
	e.Evidence = u
	done := make(chan error, 1)
	go func() {
		_, err := e.Feed(&protocol.UDPMessage{FragCount: 1, Addr: "synthetic.invalid:1", Data: []byte("a")})
		done <- err
	}()
	<-c.started
	u.connection.ended.Store(true)
	// A connection-close snapshot can precede completion of an in-flight UDP
	// call. It must not claim final completeness or get mutated retrospectively.
	final := u.snapshot(time.Now()).ErrorDetail
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = u.snapshot(time.Now())
		}
	}()
	e.CloseWithErr(nil)
	if err := <-done; err != net.ErrClosed {
		t.Fatal("concurrent close changed error")
	}
	e.CloseWithErr(nil)
	wg.Wait()
	a := u.errorSnapshot()
	if final.Sequence != 0 || !final.PostCloseUpdatesMayBeUnpublished || a.Sequence != 1 || !a.Latest[0].UDPEntryClosing || !a.Latest[0].QUICEnded || c.closes.Load() != 1 || exits.Load() != 1 {
		t.Fatal("late-error/close contract")
	}
}
