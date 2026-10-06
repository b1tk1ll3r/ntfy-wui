// Package qr is a minimal QR code encoder (byte mode, error correction level M,
// versions 1–10) used to render otpauth:// URIs for 2FA enrollment.
// It follows ISO/IEC 18004 and the structure of Project Nayuki's reference encoder.
package qr

import (
	"errors"
	"fmt"
	"strings"
)

// Code is an encoded QR symbol. Modules[y][x] is true for dark modules.
type Code struct {
	Size    int
	Modules [][]bool
}

// ecc level M parameters per version: EC codewords per block, blocks.
var (
	eccPerBlock = [11]int{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26}
	numBlocks   = [11]int{0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5}
	alignPos    = [11][]int{nil, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50}}
)

const maxVersion = 10

// ErrTooLong is returned when the data does not fit into a version 10-M symbol.
var ErrTooLong = errors.New("qr: data too long")

func rawModules(ver int) int {
	res := (16*ver+128)*ver + 64
	if ver >= 2 {
		na := ver/7 + 2
		res -= (25*na-10)*na - 55
		if ver >= 7 {
			res -= 36
		}
	}
	return res
}

func dataCodewords(ver int) int {
	return rawModules(ver)/8 - eccPerBlock[ver]*numBlocks[ver]
}

// Encode encodes data in byte mode, choosing the smallest fitting version.
func Encode(data []byte) (*Code, error) {
	ver := 0
	for v := 1; v <= maxVersion; v++ {
		ccBits := 8
		if v >= 10 {
			ccBits = 16
		}
		if 4+ccBits+8*len(data) <= dataCodewords(v)*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, ErrTooLong
	}

	// Bit stream: mode (0100 = byte), count, data, terminator, padding.
	var bits []bool
	appendBits := func(val, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (val>>i)&1 == 1)
		}
	}
	appendBits(4, 4)
	if ver >= 10 {
		appendBits(len(data), 16)
	} else {
		appendBits(len(data), 8)
	}
	for _, b := range data {
		appendBits(int(b), 8)
	}
	capBits := dataCodewords(ver) * 8
	appendBits(0, min(4, capBits-len(bits)))
	appendBits(0, (8-len(bits)%8)%8)
	for pad := 0xEC; len(bits) < capBits; pad ^= 0xEC ^ 0x11 {
		appendBits(pad, 8)
	}
	cw := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			cw[i>>3] |= 1 << (7 - uint(i&7))
		}
	}

	q := newBuilder(ver)
	q.drawFunctionPatterns()
	q.drawCodewords(addECCAndInterleave(ver, cw))

	// Choose the mask with the lowest penalty.
	best, bestPenalty := 0, -1
	for m := 0; m < 8; m++ {
		q.applyMask(m)
		q.drawFormatBits(m)
		if p := q.penalty(); bestPenalty < 0 || p < bestPenalty {
			best, bestPenalty = m, p
		}
		q.applyMask(m) // undo (XOR)
	}
	q.applyMask(best)
	q.drawFormatBits(best)
	return &Code{Size: q.size, Modules: q.mod}, nil
}

// --- Reed–Solomon over GF(2^8) with polynomial 0x11D ---

func gfMul(x, y byte) byte {
	var z int
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ ((z >> 7) * 0x11D)
		z ^= int((y>>uint(i))&1) * int(x)
	}
	return byte(z)
}

func rsDivisor(degree int) []byte {
	res := make([]byte, degree)
	res[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := range res {
			res[j] = gfMul(res[j], root)
			if j+1 < len(res) {
				res[j] ^= res[j+1]
			}
		}
		root = gfMul(root, 0x02)
	}
	return res
}

func rsRemainder(data, divisor []byte) []byte {
	res := make([]byte, len(divisor))
	for _, b := range data {
		factor := b ^ res[0]
		copy(res, res[1:])
		res[len(res)-1] = 0
		for i := range res {
			res[i] ^= gfMul(divisor[i], factor)
		}
	}
	return res
}

func addECCAndInterleave(ver int, data []byte) []byte {
	nb := numBlocks[ver]
	eccLen := eccPerBlock[ver]
	raw := rawModules(ver) / 8
	numShort := nb - raw%nb
	shortLen := raw / nb

	div := rsDivisor(eccLen)
	blocks := make([][]byte, nb)
	k := 0
	for i := 0; i < nb; i++ {
		datLen := shortLen - eccLen
		if i >= numShort {
			datLen++
		}
		dat := data[k : k+datLen]
		k += datLen
		blk := append([]byte{}, dat...)
		if i < numShort {
			blk = append(blk, 0) // placeholder so all blocks have equal length
		}
		blk = append(blk, rsRemainder(dat, div)...)
		blocks[i] = blk
	}
	var out []byte
	for i := range blocks[0] {
		for j, blk := range blocks {
			// Skip the placeholder byte in short blocks.
			if i != shortLen-eccLen || j >= numShort {
				out = append(out, blk[i])
			}
		}
	}
	return out
}

// --- Matrix construction ---

type builder struct {
	ver  int
	size int
	mod  [][]bool
	fn   [][]bool
}

func newBuilder(ver int) *builder {
	size := ver*4 + 17
	b := &builder{ver: ver, size: size, mod: make([][]bool, size), fn: make([][]bool, size)}
	for i := range b.mod {
		b.mod[i] = make([]bool, size)
		b.fn[i] = make([]bool, size)
	}
	return b
}

func (b *builder) setFn(x, y int, dark bool) {
	b.mod[y][x] = dark
	b.fn[y][x] = true
}

func (b *builder) drawFunctionPatterns() {
	for i := 0; i < b.size; i++ {
		b.setFn(6, i, i%2 == 0)
		b.setFn(i, 6, i%2 == 0)
	}
	b.drawFinder(3, 3)
	b.drawFinder(b.size-4, 3)
	b.drawFinder(3, b.size-4)

	pos := alignPos[b.ver]
	n := len(pos)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					b.setFn(pos[i]+dx, pos[j]+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	b.drawFormatBits(0) // reserve area; overwritten later
	b.drawVersion()
}

func (b *builder) drawFinder(x, y int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			xx, yy := x+dx, y+dy
			if xx >= 0 && xx < b.size && yy >= 0 && yy < b.size {
				d := max(abs(dx), abs(dy))
				b.setFn(xx, yy, d != 2 && d != 4)
			}
		}
	}
}

func (b *builder) drawFormatBits(mask int) {
	data := 0<<3 | mask // ECC level M has format bits 00
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return (bits>>uint(i))&1 == 1 }

	for i := 0; i <= 5; i++ {
		b.setFn(8, i, bit(i))
	}
	b.setFn(8, 7, bit(6))
	b.setFn(8, 8, bit(7))
	b.setFn(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		b.setFn(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		b.setFn(b.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		b.setFn(8, b.size-15+i, bit(i))
	}
	b.setFn(8, b.size-8, true)
}

func (b *builder) drawVersion() {
	if b.ver < 7 {
		return
	}
	rem := b.ver
	for i := 0; i < 12; i++ {
		rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
	}
	bits := b.ver<<12 | rem
	for i := 0; i < 18; i++ {
		dark := (bits>>uint(i))&1 == 1
		a := b.size - 11 + i%3
		c := i / 3
		b.setFn(a, c, dark)
		b.setFn(c, a, dark)
	}
}

func (b *builder) drawCodewords(data []byte) {
	i := 0
	for right := b.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < b.size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				upward := (right+1)&2 == 0
				y := vert
				if upward {
					y = b.size - 1 - vert
				}
				if !b.fn[y][x] && i < len(data)*8 {
					b.mod[y][x] = (data[i>>3]>>(7-uint(i&7)))&1 == 1
					i++
				}
			}
		}
	}
}

func (b *builder) applyMask(m int) {
	for y := 0; y < b.size; y++ {
		for x := 0; x < b.size; x++ {
			if b.fn[y][x] {
				continue
			}
			var inv bool
			switch m {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if inv {
				b.mod[y][x] = !b.mod[y][x]
			}
		}
	}
}

// penalty implements the four mask evaluation rules of ISO/IEC 18004.
func (b *builder) penalty() int {
	n := b.size
	at := func(x, y int, vertical bool) bool {
		if vertical {
			return b.mod[x][y]
		}
		return b.mod[y][x]
	}
	p := 0
	for _, vertical := range []bool{false, true} {
		for y := 0; y < n; y++ {
			run := 1
			for x := 1; x <= n; x++ {
				if x < n && at(x, y, vertical) == at(x-1, y, vertical) {
					run++
					continue
				}
				if run >= 5 {
					p += 3 + run - 5
				}
				run = 1
			}
			// Finder-like patterns 1011101 with 4 light modules on either side.
			for x := 0; x+7 <= n; x++ {
				if !(at(x, y, vertical) && !at(x+1, y, vertical) && at(x+2, y, vertical) && at(x+3, y, vertical) &&
					at(x+4, y, vertical) && !at(x+5, y, vertical) && at(x+6, y, vertical)) {
					continue
				}
				light := func(from, to int) bool {
					for i := from; i < to; i++ {
						if i >= 0 && i < n && at(i, y, vertical) {
							return false
						}
					}
					return true
				}
				if light(x-4, x) || light(x+7, x+11) {
					p += 40
				}
			}
		}
	}
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if b.mod[y][x] {
				dark++
			}
			if x+1 < n && y+1 < n {
				c := b.mod[y][x]
				if c == b.mod[y][x+1] && c == b.mod[y+1][x] && c == b.mod[y+1][x+1] {
					p += 3
				}
			}
		}
	}
	total := n * n
	k := (abs(dark*20-total*10)+total-1)/total - 1
	if k > 0 {
		p += k * 10
	}
	return p
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// SVG renders the code as a standalone SVG with a 4-module quiet zone.
// Dark modules are drawn in black on a white background for reliable scanning
// regardless of the page theme.
func (c *Code) SVG() string {
	const quiet = 4
	dim := c.Size + 2*quiet
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="QR-Code">`, dim, dim)
	fmt.Fprintf(&sb, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, dim, dim)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Modules[y][x] {
				fmt.Fprintf(&sb, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	sb.WriteString(`"/></svg>`)
	return sb.String()
}
