package gnark_nimue

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reilabs/gnark-nimue/hash"
)

type Safe[U any, H hash.DuplexHash[U]] struct {
	sponge H
	// TODO stack validation
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

func NewSafe[U any, H hash.DuplexHash[U]](api frontend.API, sponge H, io []byte) *Safe[U, H] {
	tag := generateTag(api, io)
	sponge.Initialize(tag)
	return &Safe[U, H]{
		sponge: sponge,
	}
}
