package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	gnark_nimue "github.com/reilabs/gnark-nimue"
)

type TestCircuit struct {
	IO         []byte
	Transcript [24]uints.U8 `gnark:",public"`
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	arthur := gnark_nimue.NewArthur(api, circuit.IO, circuit.Transcript[:])

	firstChallenge := make([]uints.U8, 8)
	arthur.FillChallengeUnits(firstChallenge)
	firstReply := make([]uints.U8, 8)
	arthur.FillNextUnits(firstReply)
	for i := range firstChallenge {
		api.AssertIsEqual(firstChallenge[i].Val, firstReply[i].Val)
	}

	secondChallenge := make([]uints.U8, 16)
	arthur.FillChallengeUnits(secondChallenge)
	secondReply := make([]uints.U8, 16)
	arthur.FillNextUnits(secondReply)
	for i := range secondChallenge {
		api.AssertIsEqual(secondChallenge[i].Val, secondReply[i].Val)
	}

	return nil
}

func main() {
	// the protocol has two rounds in which the verifier sends 8/16 bytes of randomness and the prover must send it back
	badIOPat := "bad-protocol\u0000S8first challenge\u0000A8first reply\u0000S16second challenge\u0000A16second reply"
	io := gnark_nimue.IOPattern{}
	_ = io.Parse([]byte(badIOPat))
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
	fmt.Printf("%v\n", vErr)
}
