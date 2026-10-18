package frag

import (
	"bytes"
	"testing"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func completedFragments(id uint16, payload []byte, chunk int) []protocol.UDPMessage {
	m := protocol.UDPMessage{SessionID: 1, PacketID: id, FragCount: 1, Addr: "synthetic:1", Data: payload}
	return FragUDPMessage(&m, m.HeaderSize()+chunk)
}

func completedFeed(t *testing.T, d *Defragger, fragments []protocol.UDPMessage, order []int, want []byte) *protocol.UDPMessage {
	t.Helper()
	var got *protocol.UDPMessage
	for i, index := range order {
		value := d.Feed(&fragments[index])
		if i+1 < len(order) && value != nil {
			t.Fatal("datagram completed before all fragments arrived")
		}
		if value != nil {
			if got != nil {
				t.Fatal("more than one completion")
			}
			got = value
		}
	}
	if got == nil || !bytes.Equal(got.Data, want) || got.FragID != 0 || got.FragCount != 1 {
		t.Fatalf("complete datagram missing or corrupt: got=%v", got)
	}
	return got
}

// The old implementation deterministically returns nil for every fragment of
// the second complete message. No random seed, clock or network is involved.
func TestDefraggerCompletedIDCanBeReused(t *testing.T) {
	for _, secondOrder := range [][]int{{0, 1}, {1, 0}} {
		d := &Defragger{}
		first := completedFragments(17, []byte("abcdef"), 3)
		second := completedFragments(17, []byte("uvwxyz"), 3)
		completedFeed(t, d, first, []int{0, 1}, []byte("abcdef"))
		completedFeed(t, d, second, secondOrder, []byte("uvwxyz"))
	}
}

func TestDefraggerInflightDuplicateAndReorder(t *testing.T) {
	d := &Defragger{}
	parts := completedFragments(23, []byte("abcdefghi"), 3)
	if d.Feed(&parts[2]) != nil || d.Feed(&parts[2]) != nil || d.Feed(&parts[0]) != nil || d.Feed(&parts[0]) != nil {
		t.Fatal("duplicate fragments completed an incomplete datagram")
	}
	got := d.Feed(&parts[1])
	if got == nil || !bytes.Equal(got.Data, []byte("abcdefghi")) {
		t.Fatal("out-of-order completion missing or corrupt")
	}
}

func TestDefraggerCompletedBufferLifetime(t *testing.T) {
	d := &Defragger{}
	payload := []byte("abcdef")
	first := completedFragments(31, payload, 3)
	got := completedFeed(t, d, first, []int{0, 1}, []byte("abcdef"))
	// Feed returns the final input message itself. Mutate only the original
	// fragment backing payload, not that returned message's Data field.
	for i := range payload {
		payload[i] = 'x'
	}
	second := completedFragments(31, []byte("uvwxyz"), 3)
	completedFeed(t, d, second, []int{1, 0}, []byte("uvwxyz"))
	if !bytes.Equal(got.Data, []byte("abcdef")) || got.FragCount != 1 || got.FragID != 0 {
		t.Fatal("later datagram mutated the earlier returned message")
	}
}

func TestDefraggerCompletedReplayIsDatagramNotGlobalDedup(t *testing.T) {
	d := &Defragger{}
	for i := 0; i < 2; i++ {
		parts := completedFragments(41, []byte("abcdef"), 3)
		completedFeed(t, d, parts, []int{0, 1}, []byte("abcdef"))
	}
}

func TestDefraggerCompletionBoundaries(t *testing.T) {
	for _, size := range []int{2, 255, 65535} {
		d := &Defragger{}
		chunk := (size + 254) / 255
		firstPayload := bytes.Repeat([]byte{0x21}, size)
		secondPayload := bytes.Repeat([]byte{0x43}, size)
		for _, payload := range [][]byte{firstPayload, secondPayload} {
			parts := completedFragments(65535, payload, chunk)
			if len(parts) < 2 || len(parts) > 255 {
				t.Fatalf("invalid test fragment count %d", len(parts))
			}
			order := make([]int, len(parts))
			for i := range order {
				order[i] = len(parts) - 1 - i
			}
			completedFeed(t, d, parts, order, payload)
		}
	}
}

func TestDefraggerInvalidFragmentDoesNotDiscardInflight(t *testing.T) {
	d := &Defragger{}
	parts := completedFragments(53, []byte("abcdef"), 3)
	if d.Feed(&parts[0]) != nil {
		t.Fatal("premature completion")
	}
	bad := protocol.UDPMessage{PacketID: 53, FragID: 2, FragCount: 2, Data: []byte("bad")}
	if d.Feed(&bad) != nil {
		t.Fatal("invalid fragment was delivered")
	}
	got := d.Feed(&parts[1])
	if got == nil || !bytes.Equal(got.Data, []byte("abcdef")) {
		t.Fatal("invalid fragment changed existing assembly")
	}
}
