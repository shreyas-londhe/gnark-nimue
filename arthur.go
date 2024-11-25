package gnark_nimue

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reilabs/gnark-nimue/hash"
)

type Arthur struct {
	transcript []uints.U8
	safe       *Safe[uints.U8, hash.Keccak]
}

func NewArthur(api frontend.API, io []byte, transcript []uints.U8) *Arthur {
	sponge, _ := hash.NewKeccak(api)
	return &Arthur{
		transcript: transcript,
		safe:       NewSafe[uints.U8, hash.Keccak](api, sponge, io),
	}
}

func (arthur *Arthur) FillNextUnits(uints []uints.U8) {
	copy(uints, arthur.transcript)
	arthur.transcript = arthur.transcript[len(uints):]
	arthur.safe.sponge.Absorb(uints)
}

func (arthur *Arthur) FillChallengeUnits(uints []uints.U8) {
	arthur.safe.sponge.Squeeze(uints)
}
