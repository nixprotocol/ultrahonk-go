package honk

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	ConstProofSizeLogN             = 28
	NumberOfSubrelations           = 26
	BatchedRelationPartialLength   = 8
	NumberOfEntities               = 40
	NumberUnshifted                = 35
	NumberToBeShifted              = 5
	PairingPointsSize              = 16
	NumberOfAlphas                 = 25
	ProofSize                      = 456 // field elements
	TotalCommitmentsSize           = NumberOfEntities + ConstProofSizeLogN + 2
)

// WIRE indices into sumcheckEvaluations
const (
	WIRE_Q_M = iota
	WIRE_Q_C
	WIRE_Q_L
	WIRE_Q_R
	WIRE_Q_O
	WIRE_Q_4
	WIRE_Q_LOOKUP
	WIRE_Q_ARITH
	WIRE_Q_RANGE
	WIRE_Q_ELLIPTIC
	WIRE_Q_AUX
	WIRE_Q_POSEIDON2_EXTERNAL
	WIRE_Q_POSEIDON2_INTERNAL
	WIRE_SIGMA_1
	WIRE_SIGMA_2
	WIRE_SIGMA_3
	WIRE_SIGMA_4
	WIRE_ID_1
	WIRE_ID_2
	WIRE_ID_3
	WIRE_ID_4
	WIRE_TABLE_1
	WIRE_TABLE_2
	WIRE_TABLE_3
	WIRE_TABLE_4
	WIRE_LAGRANGE_FIRST
	WIRE_LAGRANGE_LAST
	WIRE_W_L
	WIRE_W_R
	WIRE_W_O
	WIRE_W_4
	WIRE_Z_PERM
	WIRE_LOOKUP_INVERSES
	WIRE_LOOKUP_READ_COUNTS
	WIRE_LOOKUP_READ_TAGS
	WIRE_W_L_SHIFT
	WIRE_W_R_SHIFT
	WIRE_W_O_SHIFT
	WIRE_W_4_SHIFT
	WIRE_Z_PERM_SHIFT
)

// G1ProofPoint represents a BN254 G1 affine point in split-limb encoding.
// Each coordinate is split into two 136-bit limbs: full = lo | (hi << 136).
type G1ProofPoint struct {
	X0, X1, Y0, Y1 fr.Element
}

// VerificationKey contains the circuit-specific verification parameters.
type VerificationKey struct {
	CircuitSize      uint64
	LogCircuitSize   uint64
	PublicInputsSize uint64

	Qm, Qc, Ql, Qr, Qo, Q4            bn254.G1Affine
	QLookup, QArith, QDeltaRange        bn254.G1Affine
	QElliptic, QAux                     bn254.G1Affine
	QPoseidon2External, QPoseidon2Internal bn254.G1Affine
	S1, S2, S3, S4                      bn254.G1Affine
	ID1, ID2, ID3, ID4                  bn254.G1Affine
	T1, T2, T3, T4                      bn254.G1Affine
	LagrangeFirst, LagrangeLast         bn254.G1Affine
}

// RelationParameters holds the Fiat-Shamir-derived challenges used in relation evaluations.
type RelationParameters struct {
	Eta, EtaTwo, EtaThree fr.Element
	Beta, Gamma           fr.Element
	PublicInputsDelta     fr.Element
}

// Proof represents a deserialized UltraHonk proof containing all commitments,
// sumcheck univariates/evaluations, Gemini fold data, and KZG quotient.
type Proof struct {
	PairingPointObject [PairingPointsSize]fr.Element

	W1, W2, W3, W4          G1ProofPoint
	ZPerm                    G1ProofPoint
	LookupReadCounts         G1ProofPoint
	LookupReadTags           G1ProofPoint
	LookupInverses           G1ProofPoint

	SumcheckUnivariates [ConstProofSizeLogN][BatchedRelationPartialLength]fr.Element
	SumcheckEvaluations [NumberOfEntities]fr.Element

	GeminiFoldComms     [ConstProofSizeLogN - 1]G1ProofPoint
	GeminiAEvaluations  [ConstProofSizeLogN]fr.Element

	ShplonkQ   G1ProofPoint
	KzgQuotient G1ProofPoint
}

// Transcript holds the complete Fiat-Shamir transcript generated during verification.
type Transcript struct {
	RelationParams    RelationParameters
	Alphas            [NumberOfAlphas]fr.Element
	GateChallenges    [ConstProofSizeLogN]fr.Element
	SumCheckUChallenges [ConstProofSizeLogN]fr.Element
	Rho               fr.Element
	GeminiR           fr.Element
	ShplonkNu         fr.Element
	ShplonkZ          fr.Element
}
