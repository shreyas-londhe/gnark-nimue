package gnark_nimue

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reilabs/gnark-nimue/hash"
	"math/big"
)

type Arthur interface {
	FillNextBytes(uints []uints.U8) error
	FillChallengeBytes(uints []uints.U8) error
	FillNextScalars(scalars []frontend.Variable) error
	FillChallengeScalars(scalars []frontend.Variable) error
}

type byteArthur[H hash.DuplexHash[uints.U8]] struct {
	api        frontend.API
	transcript []uints.U8
	safe       *Safe[uints.U8, H]
}

func NewByteArthur[S hash.DuplexHash[uints.U8]](api frontend.API, io []byte, transcript []uints.U8, hash S) (Arthur, error) {
	safe, err := NewSafe[uints.U8, S](hash, io)
	if err != nil {
		return nil, err
	}
	return &byteArthur[S]{
		api,
		transcript,
		safe,
	}, nil
}

func NewKeccakArthur(api frontend.API, io []byte, transcript []uints.U8) (Arthur, error) {
	sponge, err := hash.NewKeccak(api)
	if err != nil {
		return nil, err
	}
	return NewByteArthur[hash.Keccak](api, io, transcript, sponge)
}

func (arthur *byteArthur[H]) FillNextBytes(uints []uints.U8) error {
	copy(uints, arthur.transcript)
	arthur.transcript = arthur.transcript[len(uints):]
	err := arthur.safe.Absorb(uints)
	if err != nil {
		return err
	}
	return nil
}

func (arthur *byteArthur[H]) FillChallengeBytes(uints []uints.U8) error {
	return arthur.safe.Squeeze(uints)
}

func (arthur *byteArthur[H]) FillNextScalars(scalars []frontend.Variable) error {
	bytesToRead := (arthur.api.Compiler().FieldBitLen() + 7) / 8
	bytes := make([]uints.U8, bytesToRead)
	for i := range scalars {
		scalars[i] = frontend.Variable(0)
		err := arthur.FillNextBytes(bytes)
		if err != nil {
			return err
		}
		curMul := big.NewInt(1)
		for _, b := range bytes {
			scalars[i] = arthur.api.Add(scalars[i], arthur.api.Mul(b.Val, curMul))
			curMul.Mul(curMul, big.NewInt(256))
		}
	}
	return nil
}

func (arthur *byteArthur[H]) FillChallengeScalars(scalars []frontend.Variable) error {
	bytesToGenerate := (arthur.api.Compiler().FieldBitLen() + 128) / 8
	bytes := make([]uints.U8, bytesToGenerate)
	for i := range scalars {
		err := arthur.FillChallengeBytes(bytes)
		if err != nil {
			return err
		}
		scalars[i] = frontend.Variable(0)
		for _, b := range bytes {
			scalars[i] = arthur.api.Add(b.Val, arthur.api.Mul(scalars[i], 256))
		}
	}
	return nil
}
