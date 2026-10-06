package qr

import (
	"strings"
	"testing"
)

// Decoding was verified against zxing-cpp for all versions 1–10;
// these tests guard the structural invariants.
func TestEncodeVersions(t *testing.T) {
	cases := map[int]int{1: 21, 14: 21, 15: 25, 84: 37, 122: 45, 213: 57}
	for n, size := range cases {
		c, err := Encode([]byte(strings.Repeat("a", n)))
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if c.Size != size {
			t.Errorf("n=%d: size %d, want %d", n, c.Size, size)
		}
		// Top-left finder pattern: dark corner, light separator.
		if !c.Modules[0][0] || c.Modules[7][7] || !c.Modules[3][3] {
			t.Errorf("n=%d: finder pattern broken", n)
		}
	}
	if _, err := Encode(make([]byte, 214)); err != ErrTooLong {
		t.Errorf("expected ErrTooLong, got %v", err)
	}
}

func TestReedSolomon(t *testing.T) {
	// Example from ISO/IEC 18004 Annex I (version 1-M, "01234567").
	data := []byte{0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11}
	want := []byte{0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55}
	got := rsRemainder(data, rsDivisor(10))
	if string(got) != string(want) {
		t.Fatalf("ecc = % X, want % X", got, want)
	}
}

func TestSVG(t *testing.T) {
	c, _ := Encode([]byte("otpauth://totp/x"))
	svg := c.SVG()
	if !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, `viewBox="0 0 33 33"`) {
		t.Fatalf("unexpected svg: %.80s", svg)
	}
}
