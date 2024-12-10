package gnark_nimue

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-nimue/hash"
	_ "unsafe"
)

type Safe[U any, H hash.DuplexHash[U]] struct {
	sponge H
	ops    OpQueue
}

//go:linkname keccakF1600 golang.org/x/crypto/sha3.keccakF1600
func keccakF1600(a *[25]uint64)

func keccakF(a *[200]byte) {
	b := [25]uint64{}
	for i := 0; i < 25; i++ {
		for j := 0; j < 8; j++ {
			b[i] |= uint64(a[i*8+j]) << uint(j*8)
		}
	}
	keccakF1600(&b)
	for i := 0; i < 25; i++ {
		for j := 0; j < 8; j++ {
			a[i*8+j] = byte(b[i] >> uint(j*8))
		}
	}
}

func generateTag(io []byte) [32]byte {
	state := [200]byte{}
	absorbPos := 0
	R := 136
	for len(io) > 0 {
		if absorbPos == R {
			keccakF(&state)
			absorbPos = 0
		} else {
			chunkLen := min(len(io), R-absorbPos)
			chunk, rest := io[:chunkLen], io[chunkLen:]
			copy(state[absorbPos:], chunk)
			absorbPos += chunkLen
			io = rest
		}
	}
	keccakF(&state)
	tag := [32]byte{}
	copy(tag[:], state[:32])
	return tag
}

func NewSafe[U any, H hash.DuplexHash[U]](sponge H, ioStr []byte) (*Safe[U, H], error) {
	tag := generateTag(ioStr)
	sponge.Initialize(tag)

	io := IOPattern{}
	err := io.Parse(ioStr)
	if err != nil {
		return nil, err
	}
	return &Safe[U, H]{
		ops:    io.GetOpQueue(),
		sponge: sponge,
	}, nil
}

func (safe *Safe[U, H]) Squeeze(out []U) (err error) {
	err = safe.ops.Squeeze(uint64(len(out)))
	if err != nil {
		return
	}
	safe.sponge.Squeeze(out)
	return
}

func (safe *Safe[U, H]) Absorb(in []U) (err error) {
	err = safe.ops.Absorb(uint64(len(in)))
	if err != nil {
		return
	}
	safe.sponge.Absorb(in)
	return
}

func (safe *Safe[U, H]) PrintState(api frontend.API) {
	safe.sponge.PrintState(api)
}
