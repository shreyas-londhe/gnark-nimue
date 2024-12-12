package gnark_nimue

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	bits2 "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reilabs/gnark-nimue/hash"
	skyscraper "github.com/reilabs/gnark-skyscraper"
	"math/big"
)

type Arthur interface {
	FillNextBytes(uints []uints.U8) error
	FillChallengeBytes(uints []uints.U8) error
	FillNextScalars(scalars []frontend.Variable) error
	FillChallengeScalars(scalars []frontend.Variable) error
	PrintState(api frontend.API)
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

func (arthur *byteArthur[H]) PrintState(api frontend.API) {
	msg := fmt.Sprintf("remaining transcript bytes: %d", len(arthur.transcript))
	api.Println(msg)
	arthur.safe.sponge.PrintState(api)
}

type nativeArthur[H hash.DuplexHash[frontend.Variable]] struct {
	api        frontend.API
	transcript []uints.U8
	safe       *Safe[frontend.Variable, H]
}

func (arthur *nativeArthur[H]) FillNextBytes(uints []uints.U8) error {
	copy(uints, arthur.transcript)
	for _, i := range uints {
		err := arthur.safe.Absorb([]frontend.Variable{i.Val})
		if err != nil {
			return err
		}
	}
	return nil
}

func randomBytesInModulus(api frontend.API) (int, error) {
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) == 0 {
		return 15, nil
	}
	return 0, fmt.Errorf("unsupported field")
}

func (arthur *nativeArthur[H]) FillChallengeBytes(out []uints.U8) error {
	numBytes, err := randomBytesInModulus(arthur.api)
	if err != nil {
		return err
	}
	if len(out) == 0 {
		return nil
	}
	lenGood := min(len(out), numBytes)
	tmp := make([]frontend.Variable, 1)
	for i := range (len(out) + lenGood - 1) / lenGood {
		err = arthur.FillNextScalars(tmp)
		if err != nil {
			return err
		}
		bits := bits2.ToBinary(arthur.api, tmp[0])
		for k := range lenGood {
			o := i*lenGood + k
			out[o] = uints.NewU8(0)
			curMul := 1
			for j := range 8 {
				out[o].Val = arthur.api.Add(arthur.api.Mul(curMul, bits[8*o+j]), out[o].Val)
				curMul *= 2
			}
		}
	}
	return nil
}

func (arthur *nativeArthur[H]) FillNextScalars(out []frontend.Variable) error {
	wordSize := (arthur.api.Compiler().FieldBitLen() + 7) / 8
	for i := range out {
		bytes := arthur.transcript[:wordSize]
		arthur.transcript = arthur.transcript[wordSize:]
		out[i] = frontend.Variable(0)
		curMul := big.NewInt(1)
		for _, b := range bytes {
			out[i] = arthur.api.Add(out[i], arthur.api.Mul(b.Val, curMul))
			curMul.Mul(curMul, big.NewInt(256))
		}
	}
	err := arthur.safe.Absorb(out)
	return err
}

func (arthur *nativeArthur[H]) FillChallengeScalars(out []frontend.Variable) error {
	return arthur.safe.Squeeze(out)
}

func (arthur *nativeArthur[H]) PrintState(api frontend.API) {
	arthur.safe.sponge.PrintState(api)
}

func NewSkyscraperArthur(api frontend.API, sc *skyscraper.Skyscraper, io []byte, transcript []uints.U8) (Arthur, error) {
	sponge, err := hash.NewSkyScraper(sc)
	if err != nil {
		return nil, err
	}
	safe, err := NewSafe[frontend.Variable, hash.Skyscraper](sponge, io)
	return &nativeArthur[hash.Skyscraper]{api, transcript, safe}, nil
}
