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

func NewArthur(api frontend.API, io []byte, transcript []uints.U8) (*Arthur, error) {
	sponge, _ := hash.NewKeccak(api)
	safe, err := NewSafe[uints.U8, hash.Keccak](api, sponge, io)
	if err != nil {
		return nil, err
	}
	return &Arthur{
		transcript,
		safe,
	}, nil
}

func (arthur *Arthur) FillNextUnits(uints []uints.U8) error {
	copy(uints, arthur.transcript)
	arthur.transcript = arthur.transcript[len(uints):]
	return arthur.safe.Absorb(uints)
}

func (arthur *Arthur) FillChallengeUnits(uints []uints.U8) error {
	return arthur.safe.Squeeze(uints)
}
