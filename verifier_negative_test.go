package honk

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func loadTestProof(t *testing.T) []byte {
	t.Helper()
	proofHex, err := os.ReadFile("testdata/deposit_proof.hex")
	if err != nil {
		t.Fatalf("failed to read proof file: %v", err)
	}
	proofStr := strings.TrimSpace(string(proofHex))
	proofStr = strings.TrimPrefix(proofStr, "0x")
	proofBytes, err := hex.DecodeString(proofStr)
	if err != nil {
		t.Fatalf("failed to decode proof hex: %v", err)
	}
	return proofBytes
}

func loadTestPublicInputs() []fr.Element {
	publicInputHexes := []string{
		"0x2a711793ab8f5e5050f59b872365ad644e115ad50a23796e6bca4edfa98ac4cd",
		"0x0000000000000000000000000000000000000000000000000000000005f5e100",
		"0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"0x08713fa6478f01d97264d6b63057c51db3644dacae85f073fc9e68d56edd7a39",
		"0x0fe0bc47bbfa2938c678e4e9b6e87aba9d87547114d3d28df93105de46ec0fc2",
		"0x2ae8a77cbdb6294f1785ec7735fce12956a644dc88175f335dbb8ae23cc3753d",
		"0x0c15f247fa429fb2f738119f13369244713a380522ab4b88f0ed5ce55a25b639",
		"0x1fad7ff6e3ab1b384200a295c1c10bd4817c1e6d16bd77ef330006443d045d80",
	}
	inputs := make([]fr.Element, len(publicInputHexes))
	for i, h := range publicInputHexes {
		inputs[i].SetString(h)
	}
	return inputs
}

func TestVerify_NilVK(t *testing.T) {
	proofBytes := loadTestProof(t)
	inputs := loadTestPublicInputs()

	_, err := Verify(nil, proofBytes, inputs)
	if err == nil {
		t.Fatal("expected error for nil verification key")
	}
}

func TestVerify_WrongProofLength(t *testing.T) {
	vk := DepositVerificationKey()
	inputs := loadTestPublicInputs()

	_, err := Verify(&vk, make([]byte, 100), inputs)
	if err == nil {
		t.Fatal("expected error for wrong proof length")
	}
}

func TestVerify_WrongPublicInputsCount(t *testing.T) {
	proofBytes := loadTestProof(t)
	vk := DepositVerificationKey()

	// Pass wrong number of public inputs
	inputs := make([]fr.Element, 3) // should be 8
	_, err := Verify(&vk, proofBytes, inputs)
	if err == nil {
		t.Fatal("expected error for wrong number of public inputs")
	}
}

func TestVerify_TamperedProof(t *testing.T) {
	proofBytes := loadTestProof(t)
	vk := DepositVerificationKey()
	inputs := loadTestPublicInputs()

	// Tamper with the proof by flipping bytes
	tampered := make([]byte, len(proofBytes))
	copy(tampered, proofBytes)
	tampered[100] ^= 0xFF
	tampered[101] ^= 0xFF

	verified, err := Verify(&vk, tampered, inputs)
	// May return error or false — either means rejection
	if err == nil && verified {
		t.Fatal("tampered proof should not verify")
	}
}

func TestVerify_TamperedPublicInputs(t *testing.T) {
	proofBytes := loadTestProof(t)
	vk := DepositVerificationKey()
	inputs := loadTestPublicInputs()

	// Tamper with the first public input
	inputs[0].SetUint64(12345)

	verified, err := Verify(&vk, proofBytes, inputs)
	if err == nil && verified {
		t.Fatal("proof with tampered public inputs should not verify")
	}
}

func TestVerify_RandomProof(t *testing.T) {
	vk := DepositVerificationKey()
	inputs := loadTestPublicInputs()

	// Generate completely random proof bytes
	randomProof := make([]byte, ProofSize*32)
	rand.Read(randomProof)

	verified, err := Verify(&vk, randomProof, inputs)
	if err == nil && verified {
		t.Fatal("random proof should not verify")
	}
}

func TestVerify_ZeroPublicInputs(t *testing.T) {
	proofBytes := loadTestProof(t)
	vk := DepositVerificationKey()

	// All-zero public inputs (valid count but wrong values)
	inputs := make([]fr.Element, 8)

	verified, err := Verify(&vk, proofBytes, inputs)
	if err == nil && verified {
		t.Fatal("proof with zero public inputs should not verify")
	}
}
