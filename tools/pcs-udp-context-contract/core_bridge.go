//go:build pcs_udp_context_contract

// This test-only bridge is copied into a disposable source archive. It is never
// added to runtime source or an application build. It opens no socket.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/logging"
)

type pcsContractLogger struct{}

func (pcsContractLogger) LogQUICEvidence(QUICEvidence) {}

type pcsContractConn struct{ write func([]byte) (int, error) }

func (c pcsContractConn) WriteTo(p []byte, _ string) (int, error) { return c.write(p) }
func (pcsContractConn) ReadFrom([]byte) (int, string, error)      { return 0, "", net.ErrClosed }
func (pcsContractConn) Close() error                              { return nil }

// PCSUDPContract connects the actual Feed/error aggregation/snapshot path to a
// supplied pure outbound function. No worker, dialer, QUIC session or CLI runs.
type PCSUDPContract struct {
	manager *quicEvidence
	udp     *udpEvidence
	entry   *udpSessionEntry
}

func NewPCSUDPContract(write func([]byte) (int, error)) (*PCSUDPContract, error) {
	m, err := newQUICEvidence(QUICEvidenceConfig{Enabled: true, UDPEvidence: true}, pcsContractLogger{})
	if err != nil {
		return nil, err
	}
	ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1))
	if m.tracer(ctx, logging.PerspectiveServer, quic.ConnectionID{}) == nil {
		return nil, errors.New("missing tracer")
	}
	if m.traceUDP(ctx) != nil {
		return nil, errors.New("pre-auth evidence leaked")
	}
	m.authenticate(ctx, 1, 0)
	select {
	case <-m.events:
	default:
		return nil, errors.New("missing auth event")
	}
	u := m.traceUDP(ctx)
	if u == nil {
		return nil, errors.New("missing authenticated UDP evidence")
	}
	e := newUDPSessionEntry(1, nil, nil, nil)
	e.Evidence, e.conn = u, pcsContractConn{write: write}
	return &PCSUDPContract{manager: m, udp: u, entry: e}, nil
}

func (p *PCSUDPContract) Feed(payload []byte) (int, error) {
	return p.entry.Feed(&protocol.UDPMessage{SessionID: 1, FragCount: 1, Addr: "synthetic.invalid:1", Data: payload})
}

func (p *PCSUDPContract) SnapshotJSON() ([]byte, error) {
	// Actual typed QUICEvidence and its JSON tags. The outer envelope follows
	// the existing message/evidence shape; this is not a Zap logger benchmark.
	return json.Marshal(struct {
		Message  string       `json:"msg"`
		Evidence QUICEvidence `json:"evidence"`
	}{"quic_evidence", p.manager.connectionSnapshot(p.udp.connection, "sample", time.Now())})
}
