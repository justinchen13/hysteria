package server

import (
	"encoding/json"
	"errors"
	"strings"
	"syscall"
	"testing"
)

type outboundContextTestError struct{ value UDPOutboundErrorContext }

func (e outboundContextTestError) Error() string { return "PRIVATE destination detail" }
func (e outboundContextTestError) Unwrap() error { return syscall.EADDRNOTAVAIL }
func (e outboundContextTestError) UDPOutboundErrorContext() UDPOutboundErrorContext {
	return e.value
}

func TestUDPOutboundContextSanitizesAndOwnsValues(t *testing.T) {
	no, yes, age := false, true, int64(12)
	err := outboundContextTestError{UDPOutboundErrorContext{
		TargetKind: "PRIVATE", ResolutionPath: "cache_hit", ResolvedIPv4Present: &no,
		ResolvedIPv6Present: &yes, CacheHit: &yes, CacheAgeAtErrorMS: &age,
		ResolutionErrorClass: "PRIVATE", SelectedFamily: "ipv6",
	}}
	v := safeUDPOutboundErrorContext(err)
	if v.TargetKind != "unknown" || v.ResolutionErrorClass != "unknown" || *v.ResolvedIPv4Present || !*v.ResolvedIPv6Present || *v.CacheAgeAtErrorMS != 12 {
		t.Fatal("whitelist or valid fields")
	}
	no, yes, age = true, false, 99
	if *v.ResolvedIPv4Present || !*v.ResolvedIPv6Present || !*v.CacheHit || *v.CacheAgeAtErrorMS != 12 {
		t.Fatal("caller-owned pointer retained")
	}
	encoded, _ := json.Marshal(v)
	if strings.Contains(string(encoded), "PRIVATE") {
		t.Fatal("private label leaked")
	}
	if safeUDPOutboundErrorContext(errors.New("legacy")) != nil {
		t.Fatal("legacy error must remain unknown")
	}
}

func TestUDPOutboundContextUnknownAndInvalidCacheAge(t *testing.T) {
	yes, no, negative, positive := true, false, int64(-1), int64(3)
	for _, v := range []UDPOutboundErrorContext{
		{}, {CacheHit: &yes, CacheAgeAtErrorMS: &negative},
		{CacheHit: &no, CacheAgeAtErrorMS: &positive}, {CacheAgeAtErrorMS: &positive},
	} {
		got := safeUDPOutboundErrorContext(outboundContextTestError{v})
		if got.CacheAgeAtErrorMS != nil || got.ResolvedIPv4Present != nil || got.ResolvedIPv6Present != nil {
			t.Fatal("unknown is not zero/false; cache age requires a valid hit")
		}
	}
}

func TestUDPOutboundContextLatestSnapshotIsIndependent(t *testing.T) {
	_, u := newTestUDP(t)
	yes := true
	err := outboundContextTestError{UDPOutboundErrorContext{TargetKind: "ipv6_literal", ResolvedIPv6Present: &yes}}
	u.recordError(udpPhaseTargetWrite, err, 60, 0, nil, false)
	a := u.errorSnapshot()
	if a.Counters[0].Class != "address_unavailable" || len(a.Latest) != 1 || a.Latest[0].Outbound == nil {
		t.Fatal("existing class or new context lost")
	}
	a.Latest[0].Outbound.TargetKind = "changed"
	*a.Latest[0].Outbound.ResolvedIPv6Present = false
	z := u.errorSnapshot()
	if z.Latest[0].Outbound.TargetKind != "ipv6_literal" || !*z.Latest[0].Outbound.ResolvedIPv6Present {
		t.Fatal("snapshot exposed mutable state")
	}
}
