package gnark_nimue

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParser(t *testing.T) {
	pat := "👩‍💻🥷🏻👨‍💻 building 🔐🔒🗝️\u0000A10first\u0000S10second"
	patBytes := []byte(pat)
	fmt.Printf("patBytes: %s\n", patBytes)
	iopat := IOPattern{}
	err := iopat.Parse(patBytes)
	assert.Nil(t, err)
	fmt.Printf("iopat: %s\n", iopat.PPrint())
}

type TestCircuit struct {
	IO         []byte
	Transcript [24]uints.U8 `gnark:",public"`
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	arthur, err := NewKeccakArthur(api, circuit.IO, circuit.Transcript[:])
	if err != nil {
		return err
	}
	firstChallenge := make([]uints.U8, 8)
	err = arthur.FillChallengeBytes(firstChallenge)
	if err != nil {
		return err
	}
	firstReply := make([]uints.U8, 8)
	err = arthur.FillNextBytes(firstReply)
	if err != nil {
		return err
	}
	for i := range firstChallenge {
		api.AssertIsEqual(firstChallenge[i].Val, firstReply[i].Val)
	}
	return nil
}

func TestEndToEnd(t *testing.T) {
	// the protocol has two rounds in which the verifier sends 8/16 bytes of randomness and the prover must send it back
	badIOPat := "bad-protocol\u0000S8first challenge\u0000A8first reply\u0000S16second challenge\u0000A16second reply"
	io := IOPattern{}
	err := io.Parse([]byte(badIOPat))
	assert.Nil(t, err)
	fmt.Printf("io: %s\n", io.PPrint())

	circ := TestCircuit{
		IO: []byte(badIOPat),
	}

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circ)
	pk, vk, _ := groth16.Setup(ccs)

	transcriptBytes := []byte{9, 2, 243, 247, 30, 73, 172, 83, 203, 176, 231, 217, 99, 6, 2, 176, 93, 1, 93, 32, 162, 116, 211, 219}
	transcript := [24]uints.U8{}
	for i := range transcriptBytes {
		transcript[i] = uints.NewU8(transcriptBytes[i])
	}

	assignment := TestCircuit{
		IO:         []byte(badIOPat),
		Transcript: transcript,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := groth16.Prove(ccs, pk, witness)
	vErr := groth16.Verify(proof, vk, publicWitness)
	assert.Nil(t, vErr)

}
