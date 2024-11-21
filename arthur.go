package gnark_nimue

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"gnark-nimue/hash"
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

func (arthur *Arthur) FillNextUnits(units []uints.U8) {
	copy(units, arthur.transcript)
	arthur.transcript = arthur.transcript[len(units):]
	arthur.safe.sponge.Absorb(units)
}

func (arthur *Arthur) FillChallengeUnits(units []uints.U8) {
	arthur.safe.sponge.Squeeze(units)
}
