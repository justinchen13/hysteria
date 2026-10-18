package outbounds

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

func contextOfUDPError(t *testing.T, err error) server.UDPOutboundErrorContext {
	t.Helper()
	var v *udpOutboundContextError
	if !errors.As(err, &v) {
		t.Fatal("outbound error context missing")
	}
	return v.UDPOutboundErrorContext()
}

func TestUDPOutboundContextFamiliesAndErrorIdentity(t *testing.T) {
	for _, item := range []struct{ host, kind string }{
		{"example.invalid", "hostname"}, {"192.0.2.1", "ipv4_literal"},
		{"2001:db8::1", "ipv6_literal"}, {"fe80::1%synthetic", "ipv6_literal"},
	} {
		t.Run(item.kind+item.host, func(t *testing.T) {
			err := &net.OpError{Op: "write", Net: "udp", Addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}, Err: syscall.EADDRNOTAVAIL}
			original := &AddrEx{Host: item.host, Port: 1}
			resolved := &AddrEx{ResolveInfo: &ResolveInfo{IPv6: net.ParseIP("2001:db8::1")}}
			got := withUDPOutboundContext(err, original, resolved, "system", nil, nil, time.Time{})
			var same *net.OpError
			if got.Error() != err.Error() || !errors.Is(got, syscall.EADDRNOTAVAIL) || !errors.As(got, &same) || same != err {
				t.Fatal("original Error/Is/As changed")
			}
			v := contextOfUDPError(t, got)
			if v.TargetKind != item.kind || *v.ResolvedIPv4Present || !*v.ResolvedIPv6Present || v.SelectedFamily != "ipv6" || v.ResolutionErrorClass != "none" {
				t.Fatal("input kind/result/failure-family evidence")
			}
			encoded, _ := json.Marshal(v)
			if strings.Contains(string(encoded), item.host) || strings.Contains(string(encoded), "2001:db8") {
				t.Fatal("destination leaked")
			}
		})
	}
	if withUDPOutboundContext(nil, nil, nil, "system", nil, nil, time.Time{}) != nil {
		t.Fatal("successful return changed")
	}
}

func TestUDPOutboundContextActualNoAddressAndDNSBranches(t *testing.T) {
	// Real WriteTo control flow, but supplied results fail before any socket/DNS IO.
	u := &directOutboundUDPConn{directOutbound: &directOutbound{Mode: DirectOutboundMode4}, State: udpConnStateDualStack}
	addr := &AddrEx{Host: "example.invalid", ResolveInfo: &ResolveInfo{IPv6: net.ParseIP("2001:db8::1")}}
	n, err := u.WriteTo([]byte("payload"), addr)
	var unavailable noAddressError
	if n != 0 || !errors.As(err, &unavailable) || !unavailable.IPv4 {
		t.Fatal("no-IPv4 branch semantics changed")
	}
	v := contextOfUDPError(t, err)
	if v.ResolutionPath != "supplied" || v.SelectedFamily != "unknown" || *v.ResolvedIPv4Present || !*v.ResolvedIPv6Present {
		t.Fatal("selection failure should not invent a selected family")
	}
	for _, item := range []struct {
		err   *net.DNSError
		class string
	}{
		{&net.DNSError{Name: "PRIVATE", IsTimeout: true}, "dns_timeout"},
		{&net.DNSError{Name: "PRIVATE", IsNotFound: true}, "dns_not_found"},
		{&net.DNSError{Name: "PRIVATE", IsTemporary: true}, "dns_temporary"},
		{&net.DNSError{Name: "PRIVATE"}, "dns_other"},
	} {
		addr.ResolveInfo = &ResolveInfo{Err: item.err}
		n, err = u.WriteTo([]byte("payload"), addr)
		var same *net.DNSError
		if n != 0 || !errors.As(err, &same) || same != item.err || contextOfUDPError(t, err).ResolutionErrorClass != item.class {
			t.Fatal("DNS error branch identity/class changed")
		}
	}
	addr.ResolveInfo = &ResolveInfo{Err: noAddressError{IPv4: true, IPv6: true}}
	n, err = u.WriteTo([]byte("payload"), addr)
	v = contextOfUDPError(t, err)
	if n != 0 || v.ResolutionErrorClass != "no_address" || *v.ResolvedIPv4Present || *v.ResolvedIPv6Present {
		t.Fatal("actual empty resolver result must remain distinct from missing evidence")
	}
}

func TestUDPOutboundContextPartialResultAndMissingEvidence(t *testing.T) {
	addr := &AddrEx{Host: "example.invalid", ResolveInfo: &ResolveInfo{
		IPv4: net.IPv4(192, 0, 2, 1), Err: &net.DNSError{Name: "PRIVATE", IsTemporary: true},
	}}
	err := &net.OpError{Op: "write", Net: "udp", Addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}, Err: syscall.EADDRNOTAVAIL}
	v := contextOfUDPError(t, withUDPOutboundContext(err, addr, addr, "supplied", nil, nil, time.Time{}))
	if !*v.ResolvedIPv4Present || *v.ResolvedIPv6Present || v.SelectedFamily != "ipv4" || v.ResolutionErrorClass != "dns_temporary" {
		t.Fatal("partially usable result and its resolver error must both survive")
	}
	v = contextOfUDPError(t, withUDPOutboundContext(net.ErrClosed, addr, nil, "cache_unavailable", nil, nil, time.Time{}))
	if v.ResolvedIPv4Present != nil || v.ResolvedIPv6Present != nil || v.CacheHit != nil || v.CacheAgeAtErrorMS != nil || v.SelectedFamily != "unknown" || v.ResolutionErrorClass != "unknown" {
		t.Fatal("missing resolver/cache/selection evidence must not become false or zero")
	}
}

func TestUDPOutboundContextCacheHitAgeAndExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	calls := 0
	c := newUDPResolveCache(func(addr *AddrEx) { calls++; addr.ResolveInfo = &ResolveInfo{IPv6: net.ParseIP("2001:db8::1")} })
	c.now = func() time.Time { return now }
	addr := &AddrEx{Host: "example.invalid", Port: 1}
	_, _, hit, err := c.resolveObserved(addr)
	if err != nil || hit || calls != 1 {
		t.Fatal("initial miss")
	}
	now = now.Add(3 * time.Second)
	resolved, entry, hit, err := c.resolveObserved(addr)
	if err != nil || !hit || calls != 1 {
		t.Fatal("hit performed lookup")
	}
	v := contextOfUDPError(t, withUDPOutboundContext(syscall.EADDRNOTAVAIL, addr, resolved, "cache_hit", &hit, entry, now))
	if v.CacheHit == nil || !*v.CacheHit || v.CacheAgeAtErrorMS == nil || *v.CacheAgeAtErrorMS != 3000 {
		t.Fatal("cache age/source")
	}
	now = time.Unix(100, 0).Add(udpResolveReuseLifetime)
	_, _, hit, err = c.resolveObserved(addr)
	if err != nil || hit || calls != 2 {
		t.Fatal("expiry changed")
	}
	c.close()
	_, _, hit, err = c.resolveObserved(addr)
	if hit || !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed cache semantics changed")
	}
}

func TestUDPOutboundContextRealCacheFailureEviction(t *testing.T) {
	calls := 0
	c := newUDPResolveCache(func(addr *AddrEx) { calls++; addr.ResolveInfo = &ResolveInfo{IPv6: net.ParseIP("2001:db8::1")} })
	addr := &AddrEx{Host: "example.invalid", Port: 1}
	_, _, _, err := c.resolveObserved(addr)
	if err != nil {
		t.Fatal(err)
	}
	u := &directOutboundUDPConn{directOutbound: &directOutbound{Mode: DirectOutboundMode4}, State: udpConnStateDualStack, resolveCache: c}
	_, err = u.WriteTo([]byte("payload"), addr)
	v := contextOfUDPError(t, err)
	if v.ResolutionPath != "cache_hit" || v.CacheHit == nil || !*v.CacheHit || v.CacheAgeAtErrorMS == nil || calls != 1 {
		t.Fatal("existing hit branch not captured")
	}
	_, err = u.WriteTo([]byte("payload"), addr)
	v = contextOfUDPError(t, err)
	if v.ResolutionPath != "cache_miss" || v.CacheHit == nil || *v.CacheHit || v.CacheAgeAtErrorMS != nil || calls != 2 {
		t.Fatal("failed write must keep legacy eviction and fresh miss")
	}
	if addr.ResolveInfo != nil {
		t.Fatal("caller mutated by cached path")
	}
}
