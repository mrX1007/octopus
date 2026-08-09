package main

import (
	"bytes"
	"testing"
)

func TestWipeBytesZeroesBuffer(t *testing.T) {
	buffer := []byte{0x00, 0x01, 0x7f, 0xff}

	wipeBytes(buffer)

	if !bytes.Equal(buffer, make([]byte, len(buffer))) {
		t.Fatalf("wipeBytes() left non-zero data: %x", buffer)
	}
}

func TestXorMaskRoundTrip(t *testing.T) {
	original := []byte("sensitive fixture")
	masked := append([]byte(nil), original...)

	xorMask(masked, 0xa5)
	if bytes.Equal(masked, original) {
		t.Fatal("xorMask() did not alter the fixture")
	}

	xorMask(masked, 0xa5)
	if !bytes.Equal(masked, original) {
		t.Fatalf("xorMask() round trip = %x, want %x", masked, original)
	}
}
