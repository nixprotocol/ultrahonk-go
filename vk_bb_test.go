package honk

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// serializeVKToBarretenberg converts a VerificationKey to Barretenberg's binary format
// for round-trip testing. This is the inverse of DeserializeVKFromBarretenberg.
func serializeVKToBarretenberg(vk *VerificationKey) []byte {
	buf := make([]byte, BBVKSize)

	// Write 4 metadata fields as compact 8-byte big-endian uint64s.
	binary.BigEndian.PutUint64(buf[0:8], vk.CircuitSize)
	binary.BigEndian.PutUint64(buf[8:16], vk.LogCircuitSize)
	binary.BigEndian.PutUint64(buf[16:24], vk.PublicInputsSize) // BB includes pairing points in count
	binary.BigEndian.PutUint64(buf[24:32], 1) // pub_inputs_offset = 1

	// Barretenberg canonical G1 point order (differs from library's vkPoints order).
	bbOrder := vkPointPtrsBBOrder(vk)
	offset := bbVKHeaderSize
	for _, p := range bbOrder {
		raw := p.Marshal()
		copy(buf[offset:offset+64], raw)
		offset += 64
	}
	return buf
}

// vkPointPtrsBBOrder returns mutable pointers to all 27 G1Affine points in
// Barretenberg's canonical order. This differs from vkPointPtrs() which uses
// the library's internal order (Ql, Qr, Qo, Q4, Qm, Qc, ...).
func vkPointPtrsBBOrder(vk *VerificationKey) []*bn254.G1Affine {
	return []*bn254.G1Affine{
		&vk.Qm, &vk.Qc, &vk.Ql, &vk.Qr, &vk.Qo, &vk.Q4,
		&vk.QLookup, &vk.QArith, &vk.QDeltaRange, &vk.QElliptic, &vk.QAux,
		&vk.QPoseidon2External, &vk.QPoseidon2Internal,
		&vk.S1, &vk.S2, &vk.S3, &vk.S4,
		&vk.ID1, &vk.ID2, &vk.ID3, &vk.ID4,
		&vk.T1, &vk.T2, &vk.T3, &vk.T4,
		&vk.LagrangeFirst, &vk.LagrangeLast,
	}
}

func TestDeserializeVKFromBarretenberg_RoundTrip(t *testing.T) {
	vk := depositVerificationKey()
	bbData := serializeVKToBarretenberg(&vk)

	if len(bbData) != BBVKSize {
		t.Fatalf("expected %d bytes, got %d", BBVKSize, len(bbData))
	}

	vk2, err := DeserializeVKFromBarretenberg(bbData)
	if err != nil {
		t.Fatalf("DeserializeVKFromBarretenberg: %v", err)
	}

	if vk.CircuitSize != vk2.CircuitSize {
		t.Errorf("CircuitSize: got %d, want %d", vk2.CircuitSize, vk.CircuitSize)
	}
	if vk.LogCircuitSize != vk2.LogCircuitSize {
		t.Errorf("LogCircuitSize: got %d, want %d", vk2.LogCircuitSize, vk.LogCircuitSize)
	}
	if vk.PublicInputsSize != vk2.PublicInputsSize {
		t.Errorf("PublicInputsSize: got %d, want %d", vk2.PublicInputsSize, vk.PublicInputsSize)
	}

	// Verify the deserialized VK can actually verify a proof.
	proofBytes := loadTestProof(t)
	inputs := loadTestPublicInputs()
	verified, err := Verify(vk2, proofBytes, inputs)
	if err != nil {
		t.Fatalf("Verify with BB-deserialized VK: %v", err)
	}
	if !verified {
		t.Fatal("proof should verify with BB-deserialized VK")
	}
}

func TestDeserializeVKFromBarretenberg_RealBBFile(t *testing.T) {
	// Ground-truth test: parse an actual bb write_vk output file.
	bbData, err := os.ReadFile("testdata/deposit_vk_bb.bin")
	if err != nil {
		t.Fatalf("failed to read BB VK file: %v", err)
	}

	vk, err := DeserializeVKFromBarretenberg(bbData)
	if err != nil {
		t.Fatalf("DeserializeVKFromBarretenberg: %v", err)
	}

	// Verify metadata matches known deposit circuit parameters.
	if vk.CircuitSize != 8192 {
		t.Errorf("CircuitSize: got %d, want 8192", vk.CircuitSize)
	}
	if vk.LogCircuitSize != 13 {
		t.Errorf("LogCircuitSize: got %d, want 13", vk.LogCircuitSize)
	}

	// Verify this VK can verify the deposit proof.
	proofBytes := loadTestProof(t)
	inputs := loadTestPublicInputs()
	verified, err := Verify(vk, proofBytes, inputs)
	if err != nil {
		t.Fatalf("Verify with real BB VK: %v", err)
	}
	if !verified {
		t.Fatal("proof should verify with real BB VK file")
	}
}

func TestDeserializeVKFromBarretenberg_WrongSize(t *testing.T) {
	_, err := DeserializeVKFromBarretenberg(make([]byte, 100))
	if err == nil {
		t.Fatal("expected error for wrong size")
	}
}

func TestDeserializeVKFromBarretenberg_EmptyInput(t *testing.T) {
	_, err := DeserializeVKFromBarretenberg(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestDeserializeVKFromBarretenberg_OverflowLogCircuitSize(t *testing.T) {
	// logCircuitSize = 64 would overflow 1 << 64. Must be rejected.
	buf := make([]byte, BBVKSize)
	binary.BigEndian.PutUint64(buf[0:8], 0)   // circuit_size (will mismatch)
	binary.BigEndian.PutUint64(buf[8:16], 64)  // logCircuitSize = 64
	binary.BigEndian.PutUint64(buf[16:24], 8)  // num_public_inputs
	binary.BigEndian.PutUint64(buf[24:32], 1)  // pub_inputs_offset

	_, err := DeserializeVKFromBarretenberg(buf)
	if err == nil {
		t.Fatal("expected error for logCircuitSize=64 (overflow)")
	}
}

func TestDeserializeVKFromBarretenberg_LogCircuitSizeAboveMax(t *testing.T) {
	buf := make([]byte, BBVKSize)
	binary.BigEndian.PutUint64(buf[0:8], 1<<29)
	binary.BigEndian.PutUint64(buf[8:16], 29)  // max is 28
	binary.BigEndian.PutUint64(buf[16:24], 8)
	binary.BigEndian.PutUint64(buf[24:32], 1)

	_, err := DeserializeVKFromBarretenberg(buf)
	if err == nil {
		t.Fatal("expected error for logCircuitSize=29 (above max)")
	}
}

func TestDeserializeVKFromBarretenberg_CircuitSizeMismatch(t *testing.T) {
	vk := depositVerificationKey()
	buf := serializeVKToBarretenberg(&vk)
	// Set circuit_size to 9000 (not 2^13 = 8192)
	binary.BigEndian.PutUint64(buf[0:8], 9000)

	_, err := DeserializeVKFromBarretenberg(buf)
	if err == nil {
		t.Fatal("expected error for circuitSize != 2^logCircuitSize")
	}
}

func TestDeserializeVKFromBarretenberg_WrongPubInputsOffset(t *testing.T) {
	vk := depositVerificationKey()
	buf := serializeVKToBarretenberg(&vk)
	// Set pub_inputs_offset to 2 instead of 1
	binary.BigEndian.PutUint64(buf[24:32], 2)

	_, err := DeserializeVKFromBarretenberg(buf)
	if err == nil {
		t.Fatal("expected error for pub_inputs_offset != 1")
	}
}

func TestDeserializeVKFromJSON_RoundTrip(t *testing.T) {
	vk := depositVerificationKey()
	bbData := serializeVKToBarretenberg(&vk)

	// Build JSON envelope from binary data.
	// JSON format uses 32-byte hex strings: 4 metadata (zero-padded) + 54 G1 coordinates.
	fields := make([]string, 0, 58)

	// Metadata: pad each 8-byte uint64 to 32 bytes (24 zero bytes + 8 data bytes).
	for i := 0; i < 4; i++ {
		padded := make([]byte, 32)
		copy(padded[24:32], bbData[i*8:(i+1)*8])
		fields = append(fields, fmt.Sprintf("\"0x%s\"", hex.EncodeToString(padded)))
	}

	// G1 coordinates: each is already 32 bytes.
	for i := 0; i < vkG1Count*2; i++ {
		start := bbVKHeaderSize + i*32
		fields = append(fields, fmt.Sprintf("\"0x%s\"", hex.EncodeToString(bbData[start:start+32])))
	}

	jsonStr := fmt.Sprintf(`{"vk":[%s],"scheme":"ultra_honk"}`, strings.Join(fields, ","))

	vk2, err := DeserializeVKFromJSON([]byte(jsonStr))
	if err != nil {
		t.Fatalf("DeserializeVKFromJSON: %v", err)
	}

	// Verify the deserialized VK can actually verify a proof.
	proofBytes := loadTestProof(t)
	inputs := loadTestPublicInputs()
	verified, err := Verify(vk2, proofBytes, inputs)
	if err != nil {
		t.Fatalf("Verify with JSON-deserialized VK: %v", err)
	}
	if !verified {
		t.Fatal("proof should verify with JSON-deserialized VK")
	}
}

func TestDeserializeVKFromJSON_WrongScheme(t *testing.T) {
	jsonStr := `{"vk":[],"scheme":"groth16"}`
	_, err := DeserializeVKFromJSON([]byte(jsonStr))
	if err == nil {
		t.Fatal("expected error for wrong scheme")
	}
}

func TestDeserializeVKFromJSON_NoScheme(t *testing.T) {
	vk := depositVerificationKey()
	bbData := serializeVKToBarretenberg(&vk)

	fields := make([]string, 0, 58)
	for i := 0; i < 4; i++ {
		padded := make([]byte, 32)
		copy(padded[24:32], bbData[i*8:(i+1)*8])
		fields = append(fields, fmt.Sprintf("\"0x%s\"", hex.EncodeToString(padded)))
	}
	for i := 0; i < vkG1Count*2; i++ {
		start := bbVKHeaderSize + i*32
		fields = append(fields, fmt.Sprintf("\"0x%s\"", hex.EncodeToString(bbData[start:start+32])))
	}
	jsonStr := fmt.Sprintf(`{"vk":[%s]}`, strings.Join(fields, ","))

	_, err := DeserializeVKFromJSON([]byte(jsonStr))
	if err != nil {
		t.Fatalf("should accept JSON without scheme field: %v", err)
	}
}

func TestDeserializeVKFromJSON_WrongFieldCount(t *testing.T) {
	jsonStr := `{"vk":["0x01","0x02"],"scheme":"ultra_honk"}`
	_, err := DeserializeVKFromJSON([]byte(jsonStr))
	if err == nil {
		t.Fatal("expected error for wrong field count")
	}
}

func TestDeserializeVKFromJSON_InvalidJSON(t *testing.T) {
	_, err := DeserializeVKFromJSON([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParsePublicInputs(t *testing.T) {
	hexes := []string{
		"0x2a711793ab8f5e5050f59b872365ad644e115ad50a23796e6bca4edfa98ac4cd",
		"0x0000000000000000000000000000000000000000000000000000000005f5e100",
	}
	inputs, err := ParsePublicInputs(hexes)
	if err != nil {
		t.Fatalf("ParsePublicInputs: %v", err)
	}
	if len(inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(inputs))
	}
	// Verify the second input is 100_000_000 (0x5f5e100).
	var expected fr.Element
	expected.SetUint64(100_000_000)
	if inputs[1] != expected {
		t.Errorf("input[1]: got %s, want %s", inputs[1].String(), expected.String())
	}
}

func TestParsePublicInputs_VerifyProof(t *testing.T) {
	// End-to-end: parse inputs with the helper, then verify a proof.
	hexes := []string{
		"0x2a711793ab8f5e5050f59b872365ad644e115ad50a23796e6bca4edfa98ac4cd",
		"0x0000000000000000000000000000000000000000000000000000000005f5e100",
		"0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"0x08713fa6478f01d97264d6b63057c51db3644dacae85f073fc9e68d56edd7a39",
		"0x0fe0bc47bbfa2938c678e4e9b6e87aba9d87547114d3d28df93105de46ec0fc2",
		"0x2ae8a77cbdb6294f1785ec7735fce12956a644dc88175f335dbb8ae23cc3753d",
		"0x0c15f247fa429fb2f738119f13369244713a380522ab4b88f0ed5ce55a25b639",
		"0x1fad7ff6e3ab1b384200a295c1c10bd4817c1e6d16bd77ef330006443d045d80",
	}
	inputs, err := ParsePublicInputs(hexes)
	if err != nil {
		t.Fatalf("ParsePublicInputs: %v", err)
	}

	vk := depositVerificationKey()
	proofBytes := loadTestProof(t)
	verified, err := Verify(&vk, proofBytes, inputs)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verified {
		t.Fatal("proof should verify with parsed public inputs")
	}
}

func TestParsePublicInputs_InvalidHex(t *testing.T) {
	_, err := ParsePublicInputs([]string{"0xZZZZ"})
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestParsePublicInputs_WrongLength(t *testing.T) {
	_, err := ParsePublicInputs([]string{"0x01"})
	if err == nil {
		t.Fatal("expected error for wrong hex length")
	}
}

func TestParsePublicInputs_Empty(t *testing.T) {
	inputs, err := ParsePublicInputs(nil)
	if err != nil {
		t.Fatalf("ParsePublicInputs(nil): %v", err)
	}
	if len(inputs) != 0 {
		t.Fatalf("expected 0 inputs, got %d", len(inputs))
	}
}
