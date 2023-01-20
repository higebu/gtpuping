package main

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCreatePacket(t *testing.T) {
	ida := net.ParseIP("10.0.0.1")
	isa := net.ParseIP("10.0.1.1")
	got, err := CreatePacket(isa, ida, 12345, "DL")
	if err != nil {
		t.Fatal(err)
	}

	gtp := []byte{
		0x34,       // Flags
		0xff,       // Message Type: T-PDU (0xff)
		0x00, 0x5c, // Length
		0x00, 0x00, 0x30, 0x39, // TEID
		0x00, 0x00, 0x00,
		0x85, // Next extension header type: PDU Session container (0x85)
		0x01, // Extension Header Length: 1
		0x00, // PDU Type
		0x09, // ..00 1001 = QoS Flow Identifier (QFI): 9
		0x00, // Next extension header type: No more extension headers (0x00)
	}
	ip := []byte{0x45, 0x00, 0x00, 0x4c,
		0x04, 0x88, 0x40, 0x00,
		0x40, 0x01, 0x21, 0x28,
		0x0a, 0x00, 0x01, 0x01, // Destination Address
		0x0a, 0x00, 0x00, 0x01, // Source Address
		0x08, 0x00, 0x8c, 0x0e, 0x00, 0x01, 0x00, 0x01}
	want := append(gtp, ip...)
	want = append(want, icmpPayload...)
	t.Logf("%x", got)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
