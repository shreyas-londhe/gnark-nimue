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
	arthur, err := gnark_nimue.NewArthur(api, circuit.IO, circuit.Transcript[:])

	if err != nil {
		return err
	}

	firstChallenge := make([]uints.U8, 8)
	err = arthur.FillChallengeUnits(firstChallenge)
	if err != nil {
		return err
	}
	firstReply := make([]uints.U8, 8)
	err = arthur.FillNextUnits(firstReply)
	if err != nil {
		return err
	}
	for i := range firstChallenge {
		api.AssertIsEqual(firstChallenge[i].Val, firstReply[i].Val)
	}

	secondChallenge := make([]uints.U8, 16)
	err = arthur.FillChallengeUnits(secondChallenge)
	if err != nil {
		return err
	}
	secondReply := make([]uints.U8, 16)
	err = arthur.FillNextUnits(secondReply)
	if err != nil {
		return err
	}
	for i := range secondChallenge {
		api.AssertIsEqual(secondChallenge[i].Val, secondReply[i].Val)
	}

	return nil
}

func Example1() {
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

	transcript := [24]uints.U8(uints.NewU8Array(transcriptBytes[:]))

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

type WhirCircuit struct {
	IO         []byte
	Transcript [560]uints.U8 `gnark:",public"`
}

func (circuit *WhirCircuit) Define(api frontend.API) error {
	arthur, err := gnark_nimue.NewArthur(api, circuit.IO, circuit.Transcript[:])
	if err != nil {
		return err
	}

	merkleRoot := make([]uints.U8, 32)
	err = arthur.FillNextUnits(merkleRoot)
	if err != nil {
		return err
	}

	oodChBytes := make([]uints.U8, 47)
	err = arthur.FillChallengeUnits(oodChBytes)
	if err != nil {
		return err
	}
	var oodCh frontend.Variable = 0
	for _, b := range oodChBytes {
		oodCh = api.Add(b.Val, api.Mul(oodCh, 256))
	}

	api.Println(oodCh)

	return nil
}

func ExampleWhir() {
	ioPat := "🌪\ufe0f\u0000A32merkle_digest\u0000S47ood_query\u0000A32ood_ans\u0000S47initial_combination_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A32merkle_digest\u0000S47ood_query\u0000A32ood_ans\u0000S32stir_queries_seed\u0000S32pow_queries\u0000A8pow-nonce\u0000S47combination_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A96sumcheck_poly\u0000S47folding_randomness\u0000A32final_coeffs\u0000S32final_queries_seed\u0000S32pow_queries\u0000A8pow-nonce"
	io := gnark_nimue.IOPattern{}
	_ = io.Parse([]byte(ioPat))
	fmt.Printf("io: %s\n", io.PPrint())

	circ := WhirCircuit{
		IO: []byte(ioPat),
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circ)
	if err != nil {
		fmt.Println(err)
		return
	}
	pk, vk, _ := groth16.Setup(ccs)

	transcriptBytes := []byte{86, 75, 127, 228, 31, 170, 126, 19, 179, 209, 30, 107, 197, 173, 186, 0, 131, 133, 127, 240, 217, 73, 50, 206, 238, 236, 139, 69, 35, 155, 79, 52, 34, 222, 231, 144, 26, 1, 111, 94, 211, 208, 9, 123, 2, 128, 115, 36, 22, 167, 134, 143, 221, 216, 151, 218, 157, 62, 24, 220, 237, 200, 176, 1, 10, 143, 212, 116, 96, 10, 226, 127, 95, 1, 246, 48, 167, 203, 62, 162, 81, 180, 163, 21, 86, 15, 90, 210, 104, 41, 43, 65, 57, 97, 216, 2, 16, 231, 231, 70, 86, 121, 22, 112, 238, 188, 214, 38, 191, 177, 218, 217, 15, 87, 199, 194, 137, 196, 39, 204, 50, 144, 170, 76, 4, 153, 217, 34, 178, 27, 127, 170, 216, 180, 22, 55, 14, 6, 94, 105, 187, 199, 27, 167, 68, 211, 132, 158, 3, 200, 53, 1, 134, 230, 255, 21, 71, 71, 70, 9, 220, 96, 19, 56, 152, 181, 63, 207, 103, 60, 8, 100, 22, 1, 165, 98, 58, 118, 96, 154, 94, 6, 165, 169, 236, 169, 193, 213, 102, 44, 138, 37, 42, 18, 253, 161, 116, 205, 150, 65, 85, 51, 244, 44, 181, 126, 51, 166, 64, 126, 159, 24, 100, 48, 60, 148, 63, 110, 25, 189, 178, 25, 46, 10, 239, 220, 57, 83, 59, 170, 35, 30, 164, 22, 107, 209, 226, 133, 13, 162, 187, 58, 81, 13, 197, 190, 41, 227, 201, 76, 169, 60, 177, 33, 113, 30, 58, 107, 66, 235, 56, 51, 242, 113, 19, 161, 88, 169, 3, 19, 148, 198, 203, 99, 180, 237, 215, 227, 237, 177, 254, 215, 105, 94, 32, 218, 14, 48, 213, 6, 31, 254, 249, 36, 42, 55, 223, 187, 1, 200, 255, 121, 213, 241, 184, 70, 177, 234, 131, 195, 16, 25, 49, 76, 127, 234, 41, 200, 173, 33, 0, 0, 0, 0, 0, 0, 0, 2, 36, 222, 57, 96, 229, 182, 10, 156, 146, 55, 203, 10, 82, 150, 28, 253, 37, 43, 111, 27, 253, 252, 181, 176, 186, 121, 112, 152, 120, 141, 24, 37, 12, 47, 14, 59, 235, 21, 232, 226, 218, 29, 7, 100, 248, 68, 74, 178, 117, 144, 11, 219, 204, 99, 251, 255, 12, 155, 35, 161, 100, 174, 39, 42, 71, 31, 180, 191, 83, 21, 145, 10, 45, 19, 220, 74, 19, 157, 46, 255, 166, 91, 150, 109, 181, 133, 65, 80, 227, 51, 112, 165, 48, 48, 215, 13, 59, 236, 36, 56, 125, 180, 76, 198, 37, 46, 34, 229, 97, 255, 170, 111, 193, 205, 54, 216, 123, 235, 177, 86, 41, 39, 98, 242, 119, 73, 50, 19, 10, 221, 44, 149, 102, 6, 104, 25, 165, 116, 244, 56, 16, 60, 17, 15, 165, 69, 119, 175, 249, 156, 36, 153, 0, 21, 38, 110, 193, 159, 173, 24, 95, 94, 210, 193, 96, 32, 213, 9, 214, 221, 89, 45, 240, 231, 183, 178, 174, 251, 51, 234, 165, 195, 177, 24, 209, 118, 90, 81, 240, 129, 246, 39, 219, 191, 5, 3, 52, 60, 254, 232, 154, 225, 179, 221, 81, 92, 183, 236, 160, 47, 247, 170, 216, 89, 18, 10, 65, 123, 6, 176, 84, 145, 183, 24, 0, 0, 0, 0, 0, 0, 0, 5}
	transcript := [560]uints.U8{}
	for i := range transcriptBytes {
		transcript[i] = uints.NewU8(transcriptBytes[i])
	}

	assignment := WhirCircuit{
		IO:         []byte(ioPat),
		Transcript: transcript,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := groth16.Prove(ccs, pk, witness)
	vErr := groth16.Verify(proof, vk, publicWitness)
	fmt.Printf("%v\n", vErr)
}

func main() {
	//Example1()
	ExampleWhir()
}
