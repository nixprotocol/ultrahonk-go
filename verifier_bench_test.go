package honk

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func loadBenchProof(b *testing.B) []byte {
	b.Helper()
	proofHex, err := os.ReadFile("testdata/deposit_proof.hex")
	if err != nil {
		b.Fatalf("failed to read proof file: %v", err)
	}
	proofStr := strings.TrimSpace(string(proofHex))
	proofStr = strings.TrimPrefix(proofStr, "0x")
	proofBytes, err := hex.DecodeString(proofStr)
	if err != nil {
		b.Fatalf("failed to decode proof hex: %v", err)
	}
	return proofBytes
}

func BenchmarkVerify(b *testing.B) {
	proofBytes := loadBenchProof(b)
	vk := DepositVerificationKey()
	inputs := loadTestPublicInputs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(&vk, proofBytes, inputs)
	}
}

func BenchmarkLoadProof(b *testing.B) {
	proofBytes := loadBenchProof(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LoadProof(proofBytes)
	}
}

func BenchmarkGenerateTranscript(b *testing.B) {
	proofBytes := loadBenchProof(b)
	proof, _ := LoadProof(proofBytes)
	inputs := loadTestPublicInputs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generateTranscript(proof, inputs, 8192, 24, 1)
	}
}

func BenchmarkSerializeVK(b *testing.B) {
	vk := DepositVerificationKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SerializeVK(&vk)
	}
}
