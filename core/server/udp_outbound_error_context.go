package server

import "errors"

// UDPOutboundErrorContext describes already available outbound decisions only.
// It deliberately contains no destination, identity, socket address or error text.
// Nil presence/cache fields mean unknown, not false or zero. Previous success is
// not tracked: a shared socket's aggregate bytes cannot establish target success.
type UDPOutboundErrorContext struct {
	TargetKind           string `json:"target_kind"`
	ResolutionPath       string `json:"resolution_path"`
	ResolvedIPv4Present  *bool  `json:"resolved_ipv4_present"`
	ResolvedIPv6Present  *bool  `json:"resolved_ipv6_present"`
	CacheHit             *bool  `json:"cache_hit"`
	CacheAgeAtErrorMS    *int64 `json:"cache_age_at_error_ms"`
	ResolutionErrorClass string `json:"resolution_error_class"`
	SelectedFamily       string `json:"selected_family"`
}

type udpOutboundErrorContextProvider interface {
	UDPOutboundErrorContext() UDPOutboundErrorContext
}

func safeUDPOutboundErrorContext(err error) *UDPOutboundErrorContext {
	var provider udpOutboundErrorContextProvider
	if !errors.As(err, &provider) {
		return nil
	}
	v := provider.UDPOutboundErrorContext()
	// Treat implementations as untrusted label sources. Retain only a fixed set
	// of labels and own all pointer values before storing a bounded latest record.
	keep := func(value string, allowed ...string) string {
		for _, candidate := range allowed {
			if value == candidate {
				return value
			}
		}
		return "unknown"
	}
	v.TargetKind = keep(v.TargetKind, "hostname", "ipv4_literal", "ipv6_literal")
	v.ResolutionPath = keep(v.ResolutionPath, "supplied", "literal_input", "system", "cache_hit", "cache_miss", "cache_unavailable")
	v.ResolutionErrorClass = keep(v.ResolutionErrorClass, "none", "no_address", "dns_timeout", "dns_not_found", "dns_temporary", "dns_other", "other")
	v.SelectedFamily = keep(v.SelectedFamily, "ipv4", "ipv6")
	if v.CacheAgeAtErrorMS != nil && (*v.CacheAgeAtErrorMS < 0 || v.CacheHit == nil || !*v.CacheHit) {
		v.CacheAgeAtErrorMS = nil
	}
	return cloneUDPOutboundErrorContext(&v)
}

func cloneUDPOutboundErrorContext(value *UDPOutboundErrorContext) *UDPOutboundErrorContext {
	if value == nil {
		return nil
	}
	v := *value
	copyBool := func(value *bool) *bool {
		if value == nil {
			return nil
		}
		x := *value
		return &x
	}
	v.ResolvedIPv4Present = copyBool(v.ResolvedIPv4Present)
	v.ResolvedIPv6Present = copyBool(v.ResolvedIPv6Present)
	v.CacheHit = copyBool(v.CacheHit)
	if v.CacheAgeAtErrorMS != nil {
		x := *v.CacheAgeAtErrorMS
		v.CacheAgeAtErrorMS = &x
	}
	return &v
}
