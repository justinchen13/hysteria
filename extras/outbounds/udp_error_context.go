package outbounds

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

// This wrapper is created only after an error. Error text and errors.Is/As are
// preserved; concrete type equality is not promised. No second DNS lookup,
// target substitution, retry, fallback or send is performed by this diagnostic.
type udpOutboundContextError struct {
	err     error
	context server.UDPOutboundErrorContext
}

func (e *udpOutboundContextError) Error() string { return e.err.Error() }
func (e *udpOutboundContextError) Unwrap() error { return e.err }
func (e *udpOutboundContextError) UDPOutboundErrorContext() server.UDPOutboundErrorContext {
	return e.context
}

func withUDPOutboundContext(err error, original, resolved *AddrEx, path string, hit *bool, entry *udpResolveEntry, now time.Time) error {
	if err == nil {
		return nil
	}
	v := server.UDPOutboundErrorContext{TargetKind: "unknown", ResolutionPath: path, ResolutionErrorClass: "unknown", SelectedFamily: "unknown", CacheHit: hit}
	if original != nil {
		v.TargetKind = "hostname"
		if ip, parseErr := netip.ParseAddr(original.Host); parseErr == nil {
			if ip.Unmap().Is4() {
				v.TargetKind = "ipv4_literal"
			} else {
				v.TargetKind = "ipv6_literal"
			}
		}
	}
	if resolved != nil && resolved.ResolveInfo != nil {
		r := resolved.ResolveInfo
		v4, v6 := r.IPv4 != nil, r.IPv6 != nil
		v.ResolvedIPv4Present, v.ResolvedIPv6Present = &v4, &v6
		switch {
		case r.Err == nil && (v4 || v6):
			v.ResolutionErrorClass = "none"
		case r.Err == nil:
			v.ResolutionErrorClass = "no_address"
		default:
			v.ResolutionErrorClass = "other"
			var dns *net.DNSError
			var noAddress noAddressError
			if errors.As(r.Err, &dns) {
				switch {
				case dns.IsTimeout:
					v.ResolutionErrorClass = "dns_timeout"
				case dns.IsNotFound:
					v.ResolutionErrorClass = "dns_not_found"
				case dns.IsTemporary:
					v.ResolutionErrorClass = "dns_temporary"
				default:
					v.ResolutionErrorClass = "dns_other"
				}
			} else if errors.As(r.Err, &noAddress) {
				v.ResolutionErrorClass = "no_address"
			}
		}
	}
	// The actual failed WriteTo's address determines selected family. A failed
	// resolve or selection has no selected-family evidence. It is not socket AF.
	var op *net.OpError
	if errors.As(err, &op) && op != nil && op.Op == "write" {
		if addr, ok := op.Addr.(*net.UDPAddr); ok && addr != nil {
			if addr.IP.To4() != nil {
				v.SelectedFamily = "ipv4"
			} else if addr.IP.To16() != nil {
				v.SelectedFamily = "ipv6"
			}
		}
	}
	if hit != nil && *hit && entry != nil {
		age := max(0, now.Sub(entry.expires.Add(-udpResolveReuseLifetime)).Milliseconds())
		v.CacheAgeAtErrorMS = &age
	}
	return &udpOutboundContextError{err: err, context: v}
}
