package hash

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/rangecheck"
	"math/big"
	"math/bits"
)

func bytesBeHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if field.Cmp(ecc.BN254.ScalarField()) != 0 {
		return fmt.Errorf("bytesHint: expected BN254 Fr, got %s", field)
	}
	if len(inputs) != 1 {
		return fmt.Errorf("bytesHint: expected 1 input, got %d", len(inputs))
	}
	if len(outputs) != 32 {
		return fmt.Errorf("bytesHint: expected 32 outputs, got %d", len(outputs))
	}
	bytes := make([]byte, 32)
	inputs[0].FillBytes(bytes)
	for i, o := range outputs {
		o.SetUint64(uint64(bytes[i]))
	}
	return nil
}

// outputs 1 if inputs[0] > inputs[1]
func gtHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("ltHint: expected 2 inputs, got %d", len(inputs))
	}
	if len(outputs) != 1 {
		return fmt.Errorf("ltHint: expected 1 output, got %d", len(outputs))
	}
	if inputs[0].Cmp(inputs[1]) == 1 {
		outputs[0].SetUint64(1)
	} else {
		outputs[0].SetUint64(0)
	}
	return nil
}

func init() {
	solver.RegisterHint(bytesBeHint)
	solver.RegisterHint(gtHint)
}

type Skyscraper struct {
	rc    [8]big.Int
	sigma big.Int
	sboxT *logderivlookup.Table
	rchk  frontend.Rangechecker
	api   frontend.API
}

func initSbox(api frontend.API) *logderivlookup.Table {
	t := logderivlookup.New(api)
	for i := range 256 {
		b := uint8(i)
		x := bits.RotateLeft8(^b, 1)
		y := bits.RotateLeft8(b, 2)
		z := bits.RotateLeft8(b, 3)
		t.Insert(bits.RotateLeft8(b^(x&y&z), 1))
	}
	return t
}

func NewSkyscraper(api frontend.API) *Skyscraper {
	rc := [8]big.Int{}
	rc[0].SetString("17829420340877239108687448009732280677191990375576158938221412342251481978692", 10)
	rc[1].SetString("5852100059362614845584985098022261541909346143980691326489891671321030921585", 10)
	rc[2].SetString("17048088173265532689680903955395019356591870902241717143279822196003888806966", 10)
	rc[3].SetString("71577923540621522166602308362662170286605786204339342029375621502658138039", 10)
	rc[4].SetString("1630526119629192105940988602003704216811347521589219909349181656165466494167", 10)
	rc[5].SetString("7807402158218786806372091124904574238561123446618083586948014838053032654983", 10)
	rc[6].SetString("13329560971460034925899588938593812685746818331549554971040309989641523590611", 10)
	rc[7].SetString("16971509144034029782226530622087626979814683266929655790026304723118124142299", 10)
	sigma := big.Int{}
	sigma.SetString("9915499612839321149637521777990102151350674507940716049588462388200839649614", 10)

	return &Skyscraper{
		rc,
		sigma,
		initSbox(api),
		rangecheck.New(api),
		api,
	}
}

func (s *Skyscraper) sbox(v frontend.Variable) frontend.Variable {
	return s.sboxT.Lookup(v)[0]
}

func (s *Skyscraper) square(v frontend.Variable) frontend.Variable {
	return s.api.Mul(s.api.Mul(v, v), s.sigma)
}

func (s *Skyscraper) varFromBytesBe(bytes []frontend.Variable) frontend.Variable {
	result := frontend.Variable(0)
	for _, b := range bytes {
		result = s.api.Mul(result, 256)
		result = s.api.Add(result, b)
	}
	return result
}

// This works by simulating the long subtraction of ((modulusHi, modulusLo) - 1) - (hi, lo)
// and assert the result is greater than or equal to 0.
// To do that, we produce the carry bit out of thin air and then assert that both digits of the result
// are non-negative (which is to say they are less than 2^128).
func (s *Skyscraper) assertLessThanModulus(hi, lo frontend.Variable) {
	var modulusHi, modulusLoMinusOne, pow128 big.Int
	modulusHi.SetString("30644e72e131a029b85045b68181585d", 16)
	modulusLoMinusOne.SetString("2833e84879b9709143e1f593f0000000", 16)
	pow128.SetInt64(1).Lsh(&pow128, 128)
	borrowS, _ := s.api.Compiler().NewHint(gtHint, 1, lo, modulusLoMinusOne)
	borrow := borrowS[0]
	s.api.AssertIsBoolean(borrow)
	resultLo := s.api.Add(s.api.Sub(modulusLoMinusOne, lo), s.api.Mul(borrow, pow128))
	resultHi := s.api.Sub(s.api.Sub(modulusHi, hi), borrow)
	s.rchk.Check(resultHi, 128)
	s.rchk.Check(resultLo, 128)
}

// the result is NOT rangechecked, but if it is in range, it is canonical
func (s *Skyscraper) canonicalDecompose(v frontend.Variable) [32]frontend.Variable {
	o, _ := s.api.Compiler().NewHint(bytesBeHint, 32, v)
	result := [32]frontend.Variable{}
	copy(result[:], o)
	s.api.AssertIsEqual(s.varFromBytesBe(result[:]), v)
	s.assertLessThanModulus(s.varFromBytesBe(result[:16]), s.varFromBytesBe(result[16:]))
	return result
}

func (s *Skyscraper) bar(v frontend.Variable) frontend.Variable {
	bytes := s.canonicalDecompose(v)
	tmp := [16]frontend.Variable{}
	copy(tmp[:], bytes[:16])
	copy(bytes[:], bytes[16:])
	copy(bytes[16:], tmp[:])
	for i := range bytes {
		// sbox implicitly rangechecks the input
		bytes[i] = s.sbox(bytes[i])
	}
	return s.varFromBytesBe(bytes[:])
}

func (s *Skyscraper) Permute(state *[2]frontend.Variable) {
	l, r := state[0], state[1]
	l, r = s.api.Add(r, s.square(l)), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc[0]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc[1]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc[2]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc[3]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc[4]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc[5]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc[6]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc[7]), l
	l, r = s.api.Add(r, s.square(l)), l
	state[0], state[1] = l, r
}

func (s *Skyscraper) Compress(l, r frontend.Variable) frontend.Variable {
	in := [2]frontend.Variable{l, r}
	s.Permute(&in)
	return s.api.Add(l, in[0])
}
