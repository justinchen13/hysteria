package outbounds

import (
	"net"
	"testing"
	"time"
)

// The exact same pure fixture is copied into both pinned source archives.
// It never opens a socket, performs DNS or executes an application binary.
func BenchmarkUDPResolutionContextCost(b *testing.B) {
	b.Run("cache_hit", func(b *testing.B) {
		c := newUDPResolveCache(func(a *AddrEx) {
			a.ResolveInfo = &ResolveInfo{IPv6: net.ParseIP("2001:db8::1")}
		})
		c.now = func() time.Time { return time.Unix(100, 0) }
		addr := &AddrEx{Host: "synthetic.invalid", Port: 1}
		_, _, _ = c.resolve(addr)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := c.resolve(addr); err != nil {
				b.Fatal("unexpected cache error")
			}
		}
	})
	b.Run("supplied_no_ipv4_error", func(b *testing.B) {
		u := &directOutboundUDPConn{directOutbound: &directOutbound{Mode: DirectOutboundMode4}, State: udpConnStateDualStack}
		addr := &AddrEx{Host: "synthetic.invalid", Port: 1, ResolveInfo: &ResolveInfo{IPv6: net.ParseIP("2001:db8::1")}}
		payload := []byte("synthetic")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if n, err := u.WriteTo(payload, addr); n != 0 || err == nil {
				b.Fatal("expected pre-socket address-selection error")
			}
		}
	})
	b.Run("cache_fill_then_failed_write", func(b *testing.B) {
		c := newUDPResolveCache(func(a *AddrEx) {
			a.ResolveInfo = &ResolveInfo{IPv6: net.ParseIP("2001:db8::1")}
		})
		u := &directOutboundUDPConn{directOutbound: &directOutbound{Mode: DirectOutboundMode4}, State: udpConnStateDualStack, resolveCache: c}
		addr := &AddrEx{Host: "synthetic.invalid", Port: 1}
		payload := []byte("synthetic")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := c.resolve(addr); err != nil {
				b.Fatal("unexpected cache error")
			}
			if n, err := u.WriteTo(payload, addr); n != 0 || err == nil {
				b.Fatal("expected pre-socket address-selection error")
			}
		}
	})
}
