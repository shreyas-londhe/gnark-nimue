package gnark_nimue

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reilabs/gnark-nimue/hash"
)

type Safe[U any, H hash.DuplexHash[U]] struct {
	sponge H
	ops    OpQueue
}

func generateTag(api frontend.API, io []byte) [32]uints.U8 {
	k, _ := hash.NewKeccak(api)
	data := make([]uints.U8, len(io))
	for i := range io {
		data[i] = uints.NewU8(io[i])
	}
	k.Absorb(data)
	tag := [32]uints.U8{}
	k.Squeeze(tag[:])
	return tag
}

func NewSafe[U any, H hash.DuplexHash[U]](api frontend.API, sponge H, ioStr []byte) (*Safe[U, H], error) {
	tag := generateTag(api, ioStr)
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
