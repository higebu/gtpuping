package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	listenAddr  = flag.String("listen-addr", "127.0.0.1:2152", "listen address for server")
	dstAddr     = flag.String("dst-addr", "127.0.0.1:2152", "destination address for GTPv1-U packet")
	icmpDstAddr = flag.String("icmp-dst-addr", "", "destination address for ICMP packet")
	icmpSrcAddr = flag.String("icmp-src-addr", "", "source address for ICMP packet")
	teid        = flag.Int("teid", 0, "teid")
	qfi         = flag.Int("qfi", 0, "qfi")
	pduType     = flag.String("pdu-type", "DL", "UL or DL") // DL: 0, UL: 1
	interval    = flag.Duration("interval", 1*time.Second, "send interval for client")

	icmpPayload = []byte{
		0xa6, 0x1c, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	}
)

func main() {
	flag.Parse()
	ida := net.ParseIP(*icmpDstAddr)
	isa := net.ParseIP(*icmpSrcAddr)
	log.Printf("icmp dst and src: %s, %s", ida, isa)
	laddr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	raddr, err := net.ResolveUDPAddr("udp", *dstAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	b, err := CreatePacket(isa, ida, uint32(*teid), *pduType)
	if err != nil {
		log.Fatalf("failed to create packet: %s", err)
	}
	for {
		conn.Write(b)

		buf := make([]byte, 1500)
		l, err := conn.Read(buf)
		if err != nil {
			log.Println(err)
		}
		log.Printf("%x", buf[:l])
		time.Sleep(1 * time.Second)
	}
}

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
	pt := uint8(0x00)
	if pduType == "UL" {
		pt = uint8(0x10)
	}
	gtp := []byte{
		0x34,       // Flags
		0xff,       // Message Type: T-PDU (0xff)
		0x00, 0x5c, // Length
		0x00, 0x00, 0x30, 0x39, // TEID
		0x00, 0x00, 0x00,
		0x85, // Next extension header type: PDU Session container (0x85)
		0x01, // Extension Header Length: 1
		pt,   // PDU Type
		0x09, // ..00 1001 = QoS Flow Identifier (QFI): 9
		0x00, // Next extension header type: No more extension headers (0x00)
	}
	b := append(gtp, buf.Bytes()...)
	return b, nil
}
