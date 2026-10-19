package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/frag"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/server"
)

// All listeners are ephemeral loopback sockets. This fixture needs no external
// network, production credentials, persistent keys or production test hooks.
type completedIDAuth struct{}

func (completedIDAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == "local-regression", "local-regression"
}

func completedIDCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "defrag.test"},
		DNSNames: []string{"defrag.test"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pool
}

func TestCompletedPacketIDLoopback(t *testing.T) {
	defer goleak.VerifyNone(t)
	cert, roots := completedIDCertificate(t)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.NewServer(&server.Config{
		Conn: socket, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{cert}},
		Authenticator: completedIDAuth{},
	})
	if err != nil {
		socket.Close()
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()
	connect := func(pool *x509.CertPool, name, auth string) (Client, error) {
		c, _, err := NewClient(&Config{ServerAddr: socket.LocalAddr(), Auth: auth,
			TLSConfig: TLSConfig{RootCAs: pool, ServerName: name}})
		return c, err
	}
	for _, test := range []struct {
		name             string
		roots            *x509.CertPool
		serverName, auth string
	}{
		{"untrusted_certificate", x509.NewCertPool(), "defrag.test", "local-regression"},
		{"wrong_server_name", roots, "wrong.test", "local-regression"},
		{"wrong_auth", roots, "defrag.test", "incorrect"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, err := connect(test.roots, test.serverName, test.auth)
			if c != nil {
				c.Close()
				t.Fatal("invalid credential unexpectedly connected")
			}
			if err == nil {
				t.Fatal("invalid credential unexpectedly accepted")
			}
			if test.name == "wrong_auth" {
				var authErr coreErrs.AuthError
				if !errors.As(err, &authErr) {
					t.Fatalf("expected authentication rejection, got %T", err)
				}
			} else {
				var certErr *tls.CertificateVerificationError
				if !errors.As(err, &certErr) {
					t.Fatalf("expected certificate verification failure, got %T: %v", err, err)
				}
			}
		})
	}
	c, err := connect(roots, "defrag.test", "local-regression")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Run("tcp_integrity", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			peer, err := listener.Accept()
			if err != nil {
				return
			}
			defer peer.Close()
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			io.Copy(peer, peer)
		}()
		stream, err := c.TCP(listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		stream.SetDeadline(time.Now().Add(3 * time.Second))
		want := bytes.Repeat([]byte("verified-tcp"), 512)
		if _, err := stream.Write(want); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(stream, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("TCP payload corrupt")
		}
	})
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := echo.WriteTo(buf[:n], peer); err != nil {
				return
			}
		}
	}()
	// Two independent UDP sessions deliberately reuse the same legal wire ID.
	// Both logical messages contain 1200 bytes and two fragments, just as in
	// the retained failing workload. No random collision is needed.
	for session := 0; session < 2; session++ {
		name := []string{"same_id_and_duplicate", "independent_session"}[session]
		t.Run(name, func(t *testing.T) {
			association, err := c.UDP()
			if err != nil {
				t.Fatal(err)
			}
			defer association.Close()
			u := association.(*udpConn)
			for message := 0; message < 2; message++ {
				want := bytes.Repeat([]byte{byte(31 + session*2 + message)}, 1200)
				m := &protocol.UDPMessage{SessionID: u.ID, PacketID: 17, FragCount: 1,
					Addr: echo.LocalAddr().String(), Data: want}
				parts := frag.FragUDPMessage(m, m.HeaderSize()+600)
				order := []int{0, 0, 1}
				if message == 1 {
					order = []int{1, 0}
				}
				for _, index := range order {
					if err := u.SendFunc(u.SendBuf, &parts[index]); err != nil {
						t.Fatal(err)
					}
				}
				type answer struct {
					data []byte
					addr string
					err  error
				}
				done := make(chan answer, 1)
				go func() { data, addr, err := u.Receive(); done <- answer{data, addr, err} }()
				select {
				case got := <-done:
					if got.err != nil {
						t.Fatal(got.err)
					}
					if !bytes.Equal(got.data, want) || got.addr != m.Addr {
						t.Fatal("UDP payload or target identity corrupt")
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("message %d timeout after completed PacketID reuse", message)
				}
			}
		})
	}
}
