package honk

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func loadFuzzSeedProof(f *testing.F) []byte {
	f.Helper()
	proofHex, err := os.ReadFile("testdata/deposit_proof.hex")
	if err != nil {
		f.Fatalf("failed to read proof file: %v", err)
	}
	proofStr := strings.TrimSpace(string(proofHex))
	proofStr = strings.TrimPrefix(proofStr, "0x")
	proofBytes, err := hex.DecodeString(proofStr)
	if err != nil {
		f.Fatalf("failed to decode proof hex: %v", err)
	}
	return proofBytes
}

// FuzzVerify confirms that no input can cause Verify to panic.
func FuzzVerify(f *testing.F) {
	f.Add(loadFuzzSeedProof(f))
	f.Add(make([]byte, ProofSize*32))

	vk := DepositVerificationKey()
	inputs := loadTestPublicInputs()

	f.Fuzz(func(t *testing.T, data []byte) {
		Verify(&vk, data, inputs)
	})
}

// FuzzDeserializeVK confirms that no input can cause DeserializeVK to panic.
func FuzzDeserializeVK(f *testing.F) {
	vk := DepositVerificationKey()
	validData, _ := SerializeVK(&vk)
	f.Add(validData)
	f.Add(make([]byte, VKSerializedSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		DeserializeVK(data)
	})
}

// FuzzLoadProof confirms that no input can cause LoadProof to panic.
func FuzzLoadProof(f *testing.F) {
	f.Add(make([]byte, ProofSize*32))

	f.Fuzz(func(t *testing.T, data []byte) {
		LoadProof(data)
	})
}

// FuzzVerifyWithInputs fuzzes both proof bytes and public input count.
func FuzzVerifyWithInputs(f *testing.F) {
	f.Add(loadFuzzSeedProof(f), uint8(8))

	vk := DepositVerificationKey()

	f.Fuzz(func(t *testing.T, data []byte, numInputs uint8) {
		inputs := make([]fr.Element, numInputs)
		Verify(&vk, data, inputs)
	})
}
