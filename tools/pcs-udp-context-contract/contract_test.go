//go:build pcs_udp_context_contract

// Pure fixture shared unchanged by the baseline and candidate archives.
package outbounds

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

var pcsPayload = bytes.Repeat([]byte{0x5a}, 64)

func pcsCPU() int64 {
	var r syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
		panic(err)
	}
	return r.Utime.Nano() + r.Stime.Nano()
}

func pcsContractPath(kind string) (func([]byte) (int, error), bool, error) {
	addr := &AddrEx{Host: "synthetic.invalid", Port: 1}
	cache := newUDPResolveCache(func(a *AddrEx) { a.ResolveInfo = &ResolveInfo{IPv6: net.ParseIP("2001:db8::1")} })
	now := time.Now()
	cache.now = func() time.Time { return now }
	u := &directOutboundUDPConn{directOutbound: &directOutbound{Mode: DirectOutboundMode4}, State: udpConnStateDualStack}
	switch kind {
	case "success_cache":
		if _, _, err := cache.resolve(addr); err != nil {
			return nil, false, err
		}
		return func(p []byte) (int, error) {
			if _, _, err := cache.resolve(addr); err != nil {
				return 0, err
			}
			// Pure success sink, not a socket send/delivery or TLS benchmark.
			return len(p), nil
		}, false, nil
	case "supplied_no_ipv4_error":
		addr.ResolveInfo = &ResolveInfo{IPv6: net.ParseIP("2001:db8::1")}
	case "cache_fill_then_failed_write":
		u.resolveCache = cache
		return func(p []byte) (int, error) {
			if _, _, err := cache.resolve(addr); err != nil {
				return 0, err
			}
			return u.WriteTo(p, addr)
		}, true, nil
	case "dns_timeout":
		addr.ResolveInfo = &ResolveInfo{Err: &net.DNSError{Name: "PRIVATE-CANARY.invalid", IsTimeout: true}}
	case "no_address":
		addr.ResolveInfo = &ResolveInfo{Err: noAddressError{IPv4: true, IPv6: true}}
	default:
		return nil, false, fmt.Errorf("unknown pure case")
	}
	return func(p []byte) (int, error) { return u.WriteTo(p, addr) }, true, nil
}

func pcsContractNew(kind string) (*server.PCSUDPContract, bool, error) {
	write, fails, err := pcsContractPath(kind)
	if err != nil {
		return nil, false, err
	}
	bridge, err := server.NewPCSUDPContract(write)
	return bridge, fails, err
}

func TestPCSUDPContextContract(t *testing.T) {
	path := os.Getenv("PCS_CONTRACT_OUTPUT")
	if path == "" {
		t.Fatal("explicit unique output is required")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	for _, spec := range []struct {
		kind       string
		population int
	}{
		{"success_cache", 1}, {"supplied_no_ipv4_error", 1},
		{"cache_fill_then_failed_write", 1}, {"dns_timeout", 1}, {"no_address", 1},
		{"success_cache", 128}, {"cache_fill_then_failed_write", 128},
	} {
		t.Run(fmt.Sprintf("%s_%d", spec.kind, spec.population), func(t *testing.T) {
			for member := 0; member < spec.population; member++ {
				bridge, fails, err := pcsContractNew(spec.kind)
				if err != nil {
					t.Fatal(err)
				}
				for phase := 0; phase < 2; phase++ {
					if phase == 1 {
						for i := 0; i < 8; i++ {
							before := sha256.Sum256(pcsPayload)
							n, err := bridge.Feed(pcsPayload)
							if (err != nil) != fails || (fails && n != 0) || (!fails && n != len(pcsPayload)) || sha256.Sum256(pcsPayload) != before {
								t.Fatal("return/payload changed")
							}
							if spec.kind == "supplied_no_ipv4_error" || spec.kind == "cache_fill_then_failed_write" {
								var e noAddressError
								if !errors.As(err, &e) || !e.IPv4 {
									t.Fatal("no-IPv4 error identity lost")
								}
							}
						}
					}
					raw, err := bridge.SnapshotJSON()
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(raw, []byte("PRIVATE-CANARY")) || bytes.Contains(raw, []byte("synthetic.invalid")) || bytes.Contains(raw, []byte("2001:db8")) || len(raw) > 16384 {
						t.Fatal("privacy/row bound")
					}
					if err := encoder.Encode(struct {
						Case          string          `json:"case"`
						Population    int             `json:"population"`
						Member        int             `json:"member"`
						Phase         int             `json:"phase"`
						ErrorExpected bool            `json:"error_expected"`
						Raw           json.RawMessage `json:"raw"`
					}{spec.kind, spec.population, member, phase, fails, raw}); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if stat, err := f.Stat(); err != nil || stat.Size() > 8*1024*1024 {
		t.Fatal("corpus bound")
	}
}

func BenchmarkPCSUDPContextPipeline(b *testing.B) {
	for _, kind := range []string{"success_cache", "supplied_no_ipv4_error", "cache_fill_then_failed_write"} {
		b.Run("feed_"+kind, func(b *testing.B) {
			bridge, fails, err := pcsContractNew(kind)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			beforeCPU := pcsCPU()
			for i := 0; i < b.N; i++ {
				n, err := bridge.Feed(pcsPayload)
				if (err != nil) != fails || (fails && n != 0) || (!fails && n != len(pcsPayload)) {
					b.Fatal("return changed")
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(pcsCPU()-beforeCPU)/float64(b.N), "cpu-ns/op")
		})
		b.Run("snapshot_"+kind, func(b *testing.B) {
			bridge, _, err := pcsContractNew(kind)
			if err != nil {
				b.Fatal(err)
			}
			_, _ = bridge.Feed(pcsPayload)
			b.ReportAllocs()
			b.ResetTimer()
			beforeCPU := pcsCPU()
			for i := 0; i < b.N; i++ {
				if _, err := bridge.SnapshotJSON(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(pcsCPU()-beforeCPU)/float64(b.N), "cpu-ns/op")
		})
	}
}
