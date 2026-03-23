package honk

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestLoadProof(t *testing.T) {
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

	proof, err := LoadProof(proofBytes)
	if err != nil {
		t.Fatalf("failed to load proof: %v", err)
	}

	// Basic sanity check: proof should have non-zero pairing point objects
	var zero fr.Element
	if proof.PairingPointObject[0] == zero {
		t.Error("pairing point object[0] should not be zero")
	}

	t.Logf("proof loaded successfully, %d bytes", len(proofBytes))
}

func TestVerifyDepositProof(t *testing.T) {
	// Load proof
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

	// Public inputs from deposit_public_inputs.json
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

	publicInputs := make([]fr.Element, len(publicInputHexes))
	for i, h := range publicInputHexes {
		publicInputs[i].SetString(h)
	}

	vk := depositVerificationKey()

	verified, err := Verify(&vk, proofBytes, publicInputs)
	if err != nil {
		t.Fatalf("verification returned error: %v", err)
	}
	if !verified {
		t.Fatal("deposit proof should verify but didn't")
	}

	t.Log("deposit proof verified successfully")
}
