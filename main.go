package main

import (
	"flag"
	"log"
	"net"
	"time"
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
