package honk

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	// vkG1Count is the number of G1Affine points in a VerificationKey.
	vkG1Count = 27
	// vkHeaderSize is 3 uint64s (CircuitSize, LogCircuitSize, PublicInputsSize).
	vkHeaderSize = 24
	// VKSerializedSize is the total byte length of a serialized VK.
	VKSerializedSize = vkHeaderSize + vkG1Count*64
)

const (
	// bbVKHeaderSize is 4 uint64 metadata fields (circuit_size, log_circuit_size,
	// num_public_inputs, pub_inputs_offset), each 8 bytes big-endian = 32 bytes total.
	bbVKHeaderSize = 4 * 8
	// BBVKSize is the expected byte length of a Barretenberg binary VK (32 + 27*64 = 1760).
	BBVKSize = bbVKHeaderSize + vkG1Count*64
)

// SerializeVK serializes a VerificationKey to bytes.
// Layout: 3×uint64 (big-endian) + 27×G1Affine (each 64 bytes via Marshal).
func SerializeVK(vk *VerificationKey) ([]byte, error) {
	buf := make([]byte, VKSerializedSize)

	binary.BigEndian.PutUint64(buf[0:8], vk.CircuitSize)
	binary.BigEndian.PutUint64(buf[8:16], vk.LogCircuitSize)
	binary.BigEndian.PutUint64(buf[16:24], vk.PublicInputsSize)

	points := vkPoints(vk)
	offset := vkHeaderSize
	for i, p := range points {
		raw := p.Marshal()
		if len(raw) != 64 {
			return nil, fmt.Errorf("G1Affine marshal: expected 64 bytes, got %d at index %d", len(raw), i)
		}
		copy(buf[offset:offset+64], raw)
		offset += 64
	}
	return buf, nil
}

// DeserializeVK deserializes a VerificationKey from bytes.
func DeserializeVK(data []byte) (*VerificationKey, error) {
	if len(data) != VKSerializedSize {
		return nil, fmt.Errorf("VK data must be %d bytes, got %d", VKSerializedSize, len(data))
	}

	vk := &VerificationKey{
		CircuitSize:      binary.BigEndian.Uint64(data[0:8]),
		LogCircuitSize:   binary.BigEndian.Uint64(data[8:16]),
		PublicInputsSize: binary.BigEndian.Uint64(data[16:24]),
	}

	ptrs := vkPointPtrs(vk)
	offset := vkHeaderSize
	for i, p := range ptrs {
		if err := p.Unmarshal(data[offset : offset+64]); err != nil {
			return nil, fmt.Errorf("G1Affine unmarshal at index %d: %w", i, err)
		}
		offset += 64
	}

	// Validate VK parameters
	if err := validateVK(vk); err != nil {
		return nil, fmt.Errorf("deserialized VK invalid: %w", err)
	}

	return vk, nil
}

// DeserializeVKFromBarretenberg deserializes a VerificationKey from Barretenberg's
// binary format as produced by `bb write_vk`. The data must be exactly 1760 bytes:
// 4 uint64 metadata fields (each 8 bytes big-endian) followed by 27 G1Affine points
// (each 64 bytes: 32-byte x, 32-byte y) in Barretenberg's canonical order.
//
// Binary layout:
//
//	[0:8]    circuit_size      (uint64 big-endian, must equal 1 << log_circuit_size)
//	[8:16]   log_circuit_size  (uint64 big-endian)
//	[16:24]  num_public_inputs (uint64 big-endian, includes pairing point elements)
//	[24:32]  pub_inputs_offset (uint64 big-endian, must be 1)
//	[32:1760] 27 G1Affine points in Barretenberg canonical order
//
// NOTE: Barretenberg writes raw X||Y coordinates without gnark-crypto's metadata
// bits. This works because BN254's Fp modulus (0x3064...) ensures all canonical
// field elements have their top 2 bits clear, matching gnark-crypto's
// "uncompressed" flag (0b00xxxxxx). Unmarshal also validates points are on-curve.
func DeserializeVKFromBarretenberg(data []byte) (*VerificationKey, error) {
	if len(data) != BBVKSize {
		return nil, fmt.Errorf("Barretenberg VK must be %d bytes, got %d", BBVKSize, len(data))
	}

	// Read 4 metadata fields as compact 8-byte big-endian uint64s.
	circuitSize := binary.BigEndian.Uint64(data[0:8])
	logCircuitSize := binary.BigEndian.Uint64(data[8:16])
	numPublicInputs := binary.BigEndian.Uint64(data[16:24])
	pubInputsOffset := binary.BigEndian.Uint64(data[24:32])

	// Validate logCircuitSize before shifting to prevent uint64 overflow.
	if logCircuitSize == 0 || logCircuitSize > ConstProofSizeLogN {
		return nil, fmt.Errorf("Barretenberg VK logCircuitSize %d out of range (must be 1..%d)", logCircuitSize, ConstProofSizeLogN)
	}

	// Validate circuit_size matches log_circuit_size.
	if circuitSize != (1 << logCircuitSize) {
		return nil, fmt.Errorf("Barretenberg VK circuitSize %d != 2^logCircuitSize (2^%d = %d)", circuitSize, logCircuitSize, 1<<logCircuitSize)
	}

	// Validate pub_inputs_offset matches the verifier's hardcoded expectation.
	if pubInputsOffset != 1 {
		return nil, fmt.Errorf("Barretenberg VK pub_inputs_offset %d != 1 (unsupported)", pubInputsOffset)
	}

	vk := &VerificationKey{
		CircuitSize:      circuitSize,
		LogCircuitSize:   logCircuitSize,
		PublicInputsSize: numPublicInputs, // BB v0.87+ includes pairing points in this count
	}

	// Barretenberg canonical G1 point order (differs from library's vkPoints order).
	bbOrder := []*bn254.G1Affine{
		&vk.Qm, &vk.Qc, &vk.Ql, &vk.Qr, &vk.Qo, &vk.Q4,
		&vk.QLookup, &vk.QArith, &vk.QDeltaRange, &vk.QElliptic, &vk.QAux,
		&vk.QPoseidon2External, &vk.QPoseidon2Internal,
		&vk.S1, &vk.S2, &vk.S3, &vk.S4,
		&vk.ID1, &vk.ID2, &vk.ID3, &vk.ID4,
		&vk.T1, &vk.T2, &vk.T3, &vk.T4,
		&vk.LagrangeFirst, &vk.LagrangeLast,
	}

	offset := bbVKHeaderSize
	for i, p := range bbOrder {
		if err := p.Unmarshal(data[offset : offset+64]); err != nil {
			return nil, fmt.Errorf("Barretenberg VK G1 point %d: %w", i, err)
		}
		offset += 64
	}

	if err := validateVK(vk); err != nil {
		return nil, fmt.Errorf("Barretenberg VK invalid: %w", err)
	}

	return vk, nil
}

// DeserializeVKFromJSON deserializes a VerificationKey from Barretenberg's JSON format
// as produced by `bb write_vk --output_format json`. The JSON must contain a "vk" array
// of exactly 58 hex strings (4 metadata + 27×2 G1 coordinates). If the "scheme" field
// is present, it must be "ultra_honk".
//
// Each hex string is a 32-byte big-endian value. The 4 metadata fields are
// circuit_size, log_circuit_size, num_public_inputs, pub_inputs_offset, followed
// by 27 G1 points as (x, y) coordinate pairs.
func DeserializeVKFromJSON(data []byte) (*VerificationKey, error) {
	// A valid BB JSON VK is ~5KB. Reject obviously oversized inputs early.
	const maxJSONSize = 65536
	if len(data) > maxJSONSize {
		return nil, fmt.Errorf("VK JSON too large: %d bytes (max %d)", len(data), maxJSONSize)
	}

	var envelope struct {
		VK     []string `json:"vk"`
		Scheme string   `json:"scheme,omitempty"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("VK JSON parse: %w", err)
	}

	if envelope.Scheme != "" && envelope.Scheme != "ultra_honk" {
		return nil, fmt.Errorf("VK JSON: unsupported scheme %q, expected \"ultra_honk\"", envelope.Scheme)
	}

	const expectedFields = 4 + vkG1Count*2 // 4 + 54 = 58
	if len(envelope.VK) != expectedFields {
		return nil, fmt.Errorf("VK JSON: expected %d field elements, got %d", expectedFields, len(envelope.VK))
	}

	// JSON format uses 32-byte hex strings per field element, but the binary format
	// uses compact 8-byte uint64s for metadata. Extract metadata from the first 4
	// hex strings, then build the binary buffer.
	buf := make([]byte, BBVKSize)

	// Parse the 4 metadata fields from 32-byte hex strings into compact 8-byte uint64s.
	for i := 0; i < 4; i++ {
		hexStr := strings.TrimPrefix(envelope.VK[i], "0x")
		if len(hexStr) != 64 {
			return nil, fmt.Errorf("VK JSON: metadata field %d hex length %d, expected 64", i, len(hexStr))
		}
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("VK JSON: metadata field %d: %w", i, err)
		}
		// Extract the low 8 bytes (bytes 24-31) from the 32-byte big-endian value.
		copy(buf[i*8:(i+1)*8], b[24:32])
	}

	// Parse the 54 G1 coordinate field elements (27 points × 2 coords).
	for i := 4; i < expectedFields; i++ {
		hexStr := strings.TrimPrefix(envelope.VK[i], "0x")
		if len(hexStr) != 64 {
			return nil, fmt.Errorf("VK JSON: field element %d hex length %d, expected 64", i, len(hexStr))
		}
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("VK JSON: field element %d: %w", i, err)
		}
		// G1 data starts at offset bbVKHeaderSize in the binary buffer.
		// Field element i (0-indexed from VK array) maps to binary offset:
		//   header(32) + (i-4)*32
		copy(buf[bbVKHeaderSize+(i-4)*32:bbVKHeaderSize+(i-3)*32], b)
	}

	vk, err := DeserializeVKFromBarretenberg(buf)
	if err != nil {
		return nil, fmt.Errorf("VK JSON: %w", err)
	}
	return vk, nil
}

// ParsePublicInputs parses hex-encoded public input strings into field elements.
// Each string should be a 0x-prefixed 32-byte hex value (64 hex chars after prefix).
func ParsePublicInputs(hexStrings []string) ([]fr.Element, error) {
	inputs := make([]fr.Element, len(hexStrings))
	for i, h := range hexStrings {
		h = strings.TrimPrefix(h, "0x")
		if len(h) != 64 {
			return nil, fmt.Errorf("public input %d: hex length %d, expected 64", i, len(h))
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("public input %d: %w", i, err)
		}
		inputs[i].SetBytes(b)
	}
	return inputs, nil
}

// vkPoints returns all 27 G1Affine points in deterministic order.
func vkPoints(vk *VerificationKey) []bn254.G1Affine {
	return []bn254.G1Affine{
		vk.Ql, vk.Qr, vk.Qo, vk.Q4, vk.Qm, vk.Qc,
		vk.QArith, vk.QDeltaRange, vk.QElliptic, vk.QAux,
		vk.QLookup, vk.QPoseidon2External, vk.QPoseidon2Internal,
		vk.S1, vk.S2, vk.S3, vk.S4,
		vk.ID1, vk.ID2, vk.ID3, vk.ID4,
		vk.T1, vk.T2, vk.T3, vk.T4,
		vk.LagrangeFirst, vk.LagrangeLast,
	}
}

// vkPointPtrs returns mutable pointers to all 27 G1Affine points.
func vkPointPtrs(vk *VerificationKey) []*bn254.G1Affine {
	return []*bn254.G1Affine{
		&vk.Ql, &vk.Qr, &vk.Qo, &vk.Q4, &vk.Qm, &vk.Qc,
		&vk.QArith, &vk.QDeltaRange, &vk.QElliptic, &vk.QAux,
		&vk.QLookup, &vk.QPoseidon2External, &vk.QPoseidon2Internal,
		&vk.S1, &vk.S2, &vk.S3, &vk.S4,
		&vk.ID1, &vk.ID2, &vk.ID3, &vk.ID4,
		&vk.T1, &vk.T2, &vk.T3, &vk.T4,
		&vk.LagrangeFirst, &vk.LagrangeLast,
	}
}
