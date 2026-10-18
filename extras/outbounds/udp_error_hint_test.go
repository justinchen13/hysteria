package outbounds

import (
	"errors"
	"net"
	"testing"
)

func TestUDPErrorHintsPreserveExistingErrorIdentity(t *testing.T) {
	for _, tc := range []struct {
		err interface {
			error
			UDPErrorClass() string
		}
		class, text string
	}{
		{noAddressError{IPv4: true}, "no_ipv4", "no IPv4 address available"},
		{noAddressError{IPv6: true}, "no_ipv6", "no IPv6 address available"},
		{noAddressError{IPv4: true, IPv6: true}, "no_address", "no IPv4 or IPv6 address available"},
		{noAddressError{}, "no_address", "no address available"},
		{invalidOutboundModeError{}, "outbound_mode_invalid", "invalid outbound mode"},
		{resolveError{}, "dns_other", "resolve error"},
	} {
		if tc.err.UDPErrorClass() != tc.class || tc.err.Error() != tc.text {
			t.Fatal("existing error contract changed")
		}
	}
	cause := &net.DNSError{IsNotFound: true, Name: "synthetic.invalid"}
	err := resolveError{Err: cause}
	var typed *net.DNSError
	if err.UDPErrorClass() != "dns_other" || errors.Unwrap(err) != cause || !errors.As(err, &typed) || typed != cause {
		t.Fatal("wrapped DNS identity lost")
	}
}
