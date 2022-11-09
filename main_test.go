package main

import (
	"net"
	"testing"
)

func TestCreatePacket(t *testing.T) {
	ida := net.ParseIP("10.0.0.1")
	isa := net.ParseIP("10.0.1.1")
	b, err := CreatePacket(isa, ida, 12345, "DL")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%x", b)
}
