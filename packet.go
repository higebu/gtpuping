package main

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	icmpPayload = []byte{
		0xa6, 0x1c, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	}
)

func CreatePacket(isa, ida net.IP, teid uint32, pduType string) ([]byte, error) {
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts,
		&layers.IPv4{
			Version: 4, Protocol: layers.IPProtocolICMPv4, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
			SrcIP: isa, DstIP: ida,
		},
		&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 1, Seq: 1},
		gopacket.Payload(icmpPayload),
	)
	if err != nil {
		return nil, err
	}
	gtp := []byte{
		0x38,       // Flags
		0xff,       // Message Type: T-PDU (0xff)
		0x00, 0x5c, // Length
		0x00, 0x00, 0x00, 0x00, // TEID
	}
	if pduType == "UL" || pduType == "DL" {
		pt := uint8(0x00)
		if pduType == "UL" {
			pt = uint8(0x10)
		}
		gtp = append(gtp, []byte{
			0x00, 0x00, 0x00,
			0x85, // Next extension header type: PDU Session container (0x85)
			0x01, // Extension Header Length: 1
			pt,   // PDU Type
			0x09, // ..00 1001 = QoS Flow Identifier (QFI): 9
			0x00, // Next extension header type: No more extension headers (0x00)
		}...)
		gtp[0] = 0x34
	}
	binary.BigEndian.PutUint32(gtp[4:8], teid)
	b := append(gtp, buf.Bytes()...)
	return b, nil
}
