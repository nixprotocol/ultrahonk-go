package honk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// BN254 SRS G2 points for pairing (hardcoded from trusted setup).
var (
	srsG2x0  = mustBigInt("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2")
	srsG2x1  = mustBigInt("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed")
	srsG2y0  = mustBigInt("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b")
	srsG2y1  = mustBigInt("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")
	srsG2x0b = mustBigInt("260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1")
	srsG2x1b = mustBigInt("0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0")
	srsG2y0b = mustBigInt("04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4")
	srsG2y1b = mustBigInt("22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55")
)

// mustBigInt parses a hex string into a big.Int, panicking on failure.
func mustBigInt(hex string) *big.Int {
	v, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic(fmt.Sprintf("honk: invalid big.Int hex constant %q", hex))
	}
	return v
}

// LoadProof deserializes a proof from raw bytes (ProofSize * 32 bytes).
func LoadProof(proofBytes []byte) (*Proof, error) {
	if len(proofBytes) != ProofSize*32 {
		return nil, fmt.Errorf("proof must be %d bytes, got %d", ProofSize*32, len(proofBytes))
	}

	p := &Proof{}
	offset := 0

	readFr := func() fr.Element {
		var e fr.Element
		e.SetBytes(proofBytes[offset : offset+32])
		offset += 32
		return e
	}

	readG1ProofPoint := func() G1ProofPoint {
		return G1ProofPoint{
			X0: readFr(),
			X1: readFr(),
			Y0: readFr(),
			Y1: readFr(),
		}
	}

	// Pairing point object
	for i := 0; i < PairingPointsSize; i++ {
		p.PairingPointObject[i] = readFr()
	}

	// Commitments
	p.W1 = readG1ProofPoint()
	p.W2 = readG1ProofPoint()
	p.W3 = readG1ProofPoint()

	// Lookup / Permutation helpers
	p.LookupReadCounts = readG1ProofPoint()
	p.LookupReadTags = readG1ProofPoint()
	p.W4 = readG1ProofPoint()
	p.LookupInverses = readG1ProofPoint()
	p.ZPerm = readG1ProofPoint()

	// Sumcheck univariates
	for i := 0; i < ConstProofSizeLogN; i++ {
		for j := 0; j < BatchedRelationPartialLength; j++ {
			p.SumcheckUnivariates[i][j] = readFr()
		}
	}

	// Sumcheck evaluations
	for i := 0; i < NumberOfEntities; i++ {
		p.SumcheckEvaluations[i] = readFr()
	}

	// Gemini fold commitments
	for i := 0; i < ConstProofSizeLogN-1; i++ {
		p.GeminiFoldComms[i] = readG1ProofPoint()
	}

	// Gemini a evaluations
	for i := 0; i < ConstProofSizeLogN; i++ {
		p.GeminiAEvaluations[i] = readFr()
	}

	// Shplonk
	p.ShplonkQ = readG1ProofPoint()
	// KZG
	p.KzgQuotient = readG1ProofPoint()

	return p, nil
}

// Verify verifies an UltraHonk proof against the given verification key and public inputs.
// It returns (true, nil) if the proof is valid, (false, error) if verification fails or
// inputs are malformed. The vk must not be nil.
func Verify(vk *VerificationKey, proofBytes []byte, publicInputs []fr.Element) (bool, error) {
	if vk == nil {
		return false, fmt.Errorf("verification key must not be nil")
	}
	if len(proofBytes) != ProofSize*32 {
		return false, fmt.Errorf("proof length wrong: expected %d, got %d", ProofSize*32, len(proofBytes))
	}

	proof, err := LoadProof(proofBytes)
	if err != nil {
		return false, err
	}

	expectedPubInputs := vk.PublicInputsSize - PairingPointsSize
	if uint64(len(publicInputs)) != expectedPubInputs {
		return false, fmt.Errorf("public inputs length wrong: expected %d, got %d", expectedPubInputs, len(publicInputs))
	}

	// Generate Fiat-Shamir transcript
	t := GenerateTranscript(proof, publicInputs, vk.CircuitSize, vk.PublicInputsSize, 1)

	// Compute public input delta
	t.RelationParams.PublicInputsDelta = computePublicInputDelta(publicInputs, &proof.PairingPointObject, &t.RelationParams, vk)

	// Verify sumcheck
	sumcheckOk := verifySumcheck(proof, &t, vk.LogCircuitSize)
	if !sumcheckOk {
		return false, fmt.Errorf("sumcheck verification failed")
	}

	// Verify Shplemini/KZG
	shpleminiOk := verifyShplemini(proof, vk, &t)
	if !shpleminiOk {
		return false, fmt.Errorf("shplemini verification failed")
	}

	return true, nil
}

func computePublicInputDelta(publicInputs []fr.Element, pairingPointObject *[PairingPointsSize]fr.Element, rp *RelationParameters, vk *VerificationKey) fr.Element {
	one := frFrom(1)
	numerator := one
	denominator := one

	nPlusOffset := frFrom(N + 1) // offset = 1
	numeratorAcc := frAdd(rp.Gamma, frMul(rp.Beta, nPlusOffset))
	denominatorAcc := frSub(rp.Gamma, frMul(rp.Beta, frFrom(2))) // offset + 1 = 2

	numRealPubInputs := vk.PublicInputsSize - PairingPointsSize
	for i := uint64(0); i < numRealPubInputs; i++ {
		numerator = frMul(numerator, frAdd(numeratorAcc, publicInputs[i]))
		denominator = frMul(denominator, frAdd(denominatorAcc, publicInputs[i]))
		numeratorAcc = frAdd(numeratorAcc, rp.Beta)
		denominatorAcc = frSub(denominatorAcc, rp.Beta)
	}

	for i := uint64(0); i < PairingPointsSize; i++ {
		numerator = frMul(numerator, frAdd(numeratorAcc, pairingPointObject[i]))
		denominator = frMul(denominator, frAdd(denominatorAcc, pairingPointObject[i]))
		numeratorAcc = frAdd(numeratorAcc, rp.Beta)
		denominatorAcc = frSub(denominatorAcc, rp.Beta)
	}

	return frDiv(numerator, denominator)
}

func verifySumcheck(proof *Proof, tp *Transcript, logN uint64) bool {
	var roundTarget fr.Element
	powPartialEvaluation := frFrom(1)

	for round := uint64(0); round < logN; round++ {
		roundUnivariate := proof.SumcheckUnivariates[round]

		// Check sum: u(0) + u(1) = target
		totalSum := frAdd(roundUnivariate[0], roundUnivariate[1])
		if totalSum != roundTarget {
			return false
		}

		roundChallenge := tp.SumCheckUChallenges[round]
		roundTarget = computeNextTargetSum(&roundUnivariate, roundChallenge)
		powPartialEvaluation = partiallyEvaluatePOW(tp.GateChallenges[round], powPartialEvaluation, roundChallenge)
	}

	grandHonkRelationSum := AccumulateRelationEvaluations(
		&proof.SumcheckEvaluations,
		&tp.RelationParams,
		&tp.Alphas,
		powPartialEvaluation,
	)

	return grandHonkRelationSum == roundTarget
}

// Barycentric Lagrange denominators for degree-7 polynomial evaluation.
var barycentricLagrangeDenominators = [BatchedRelationPartialLength]fr.Element{
	mustFromHex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
	mustFromHex("0x00000000000000000000000000000000000000000000000000000000000002d0"),
	mustFromHex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11"),
	mustFromHex("0x0000000000000000000000000000000000000000000000000000000000000090"),
	mustFromHex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71"),
	mustFromHex("0x00000000000000000000000000000000000000000000000000000000000000f0"),
	mustFromHex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
	mustFromHex("0x00000000000000000000000000000000000000000000000000000000000013b0"),
}

func computeNextTargetSum(roundUnivariates *[BatchedRelationPartialLength]fr.Element, roundChallenge fr.Element) fr.Element {
	// Barycentric evaluation: compute numerator = prod(challenge - i) for i = 0..7
	numeratorValue := frFrom(1)
	for i := 0; i < BatchedRelationPartialLength; i++ {
		numeratorValue = frMul(numeratorValue, frSub(roundChallenge, frFrom(uint64(i))))
	}

	// Compute denominator inverses
	var denominatorInverses [BatchedRelationPartialLength]fr.Element
	for i := 0; i < BatchedRelationPartialLength; i++ {
		inv := frMul(barycentricLagrangeDenominators[i], frSub(roundChallenge, frFrom(uint64(i))))
		denominatorInverses[i] = frInv(inv)
	}

	var targetSum fr.Element
	for i := 0; i < BatchedRelationPartialLength; i++ {
		term := frMul(roundUnivariates[i], denominatorInverses[i])
		targetSum = frAdd(targetSum, term)
	}

	return frMul(targetSum, numeratorValue)
}

func partiallyEvaluatePOW(gateChallenge, currentEvaluation, roundChallenge fr.Element) fr.Element {
	one := frFrom(1)
	univariateEval := frAdd(one, frMul(roundChallenge, frSub(gateChallenge, one)))
	return frMul(currentEvaluation, univariateEval)
}

func computeSquares(r fr.Element) [ConstProofSizeLogN]fr.Element {
	var squares [ConstProofSizeLogN]fr.Element
	squares[0] = r
	for i := 1; i < ConstProofSizeLogN; i++ {
		squares[i] = frSqr(squares[i-1])
	}
	return squares
}

func computeFoldPosEvaluations(
	sumcheckUChallenges [ConstProofSizeLogN]fr.Element,
	batchedEvalAccumulator fr.Element,
	geminiEvaluations [ConstProofSizeLogN]fr.Element,
	geminiEvalChallengePowers [ConstProofSizeLogN]fr.Element,
	logSize uint64,
) [ConstProofSizeLogN]fr.Element {
	var foldPosEvaluations [ConstProofSizeLogN]fr.Element

	for i := ConstProofSizeLogN; i > 0; i-- {
		challengePower := geminiEvalChallengePowers[i-1]
		u := sumcheckUChallenges[i-1]

		// batchedEvalRoundAcc = (challengePower * batchedEvalAccumulator * 2 - geminiEvaluations[i-1] * (challengePower * (1 - u) - u))
		two := frFrom(2)
		one := frFrom(1)
		oneMinusU := frSub(one, u)

		numerator := frSub(
			frMul(frMul(challengePower, batchedEvalAccumulator), two),
			frMul(geminiEvaluations[i-1], frSub(frMul(challengePower, oneMinusU), u)),
		)

		denominator := frAdd(frMul(challengePower, oneMinusU), u)
		batchedEvalRoundAcc := frMul(numerator, frInv(denominator))

		if uint64(i) <= logSize {
			batchedEvalAccumulator = batchedEvalRoundAcc
			foldPosEvaluations[i-1] = batchedEvalRoundAcc
		}
	}

	return foldPosEvaluations
}

func verifyShplemini(proof *Proof, vk *VerificationKey, tp *Transcript) bool {
	powersOfEvalChallenge := computeSquares(tp.GeminiR)

	scalars := make([]fr.Element, TotalCommitmentsSize)
	commitments := make([]bn254.G1Affine, TotalCommitmentsSize)

	posInvDenom := frInv(frSub(tp.ShplonkZ, powersOfEvalChallenge[0]))
	negInvDenom := frInv(frAdd(tp.ShplonkZ, powersOfEvalChallenge[0]))

	unshiftedScalar := frAdd(posInvDenom, frMul(tp.ShplonkNu, negInvDenom))
	shiftedScalar := frMul(frInv(tp.GeminiR), frSub(posInvDenom, frMul(tp.ShplonkNu, negInvDenom)))

	// scalars[0] = 1, commitments[0] = shplonkQ
	scalars[0] = frFrom(1)
	commitments[0] = convertProofPoint(proof.ShplonkQ)

	batchingChallenge := frFrom(1)
	var batchedEvaluation fr.Element

	// Unshifted commitments (1..35)
	for i := 1; i <= NumberUnshifted; i++ {
		s := frNeg(frMul(unshiftedScalar, batchingChallenge))
		scalars[i] = s
		batchedEvaluation = frAdd(batchedEvaluation, frMul(proof.SumcheckEvaluations[i-1], batchingChallenge))
		batchingChallenge = frMul(batchingChallenge, tp.Rho)
	}

	// Shifted commitments (36..40)
	for i := NumberUnshifted + 1; i <= NumberOfEntities; i++ {
		s := frNeg(frMul(shiftedScalar, batchingChallenge))
		scalars[i] = s
		batchedEvaluation = frAdd(batchedEvaluation, frMul(proof.SumcheckEvaluations[i-1], batchingChallenge))
		batchingChallenge = frMul(batchingChallenge, tp.Rho)
	}

	// Assign VK commitments (indices 1..27)
	commitments[1] = vk.Qm
	commitments[2] = vk.Qc
	commitments[3] = vk.Ql
	commitments[4] = vk.Qr
	commitments[5] = vk.Qo
	commitments[6] = vk.Q4
	commitments[7] = vk.QLookup
	commitments[8] = vk.QArith
	commitments[9] = vk.QDeltaRange
	commitments[10] = vk.QElliptic
	commitments[11] = vk.QAux
	commitments[12] = vk.QPoseidon2External
	commitments[13] = vk.QPoseidon2Internal
	commitments[14] = vk.S1
	commitments[15] = vk.S2
	commitments[16] = vk.S3
	commitments[17] = vk.S4
	commitments[18] = vk.ID1
	commitments[19] = vk.ID2
	commitments[20] = vk.ID3
	commitments[21] = vk.ID4
	commitments[22] = vk.T1
	commitments[23] = vk.T2
	commitments[24] = vk.T3
	commitments[25] = vk.T4
	commitments[26] = vk.LagrangeFirst
	commitments[27] = vk.LagrangeLast

	// Proof commitments (28..34 unshifted, 35..39 shifted copies)
	commitments[28] = convertProofPoint(proof.W1)
	commitments[29] = convertProofPoint(proof.W2)
	commitments[30] = convertProofPoint(proof.W3)
	commitments[31] = convertProofPoint(proof.W4)
	commitments[32] = convertProofPoint(proof.ZPerm)
	commitments[33] = convertProofPoint(proof.LookupInverses)
	commitments[34] = convertProofPoint(proof.LookupReadCounts)
	commitments[35] = convertProofPoint(proof.LookupReadTags)

	// Shifted copies
	commitments[36] = convertProofPoint(proof.W1)
	commitments[37] = convertProofPoint(proof.W2)
	commitments[38] = convertProofPoint(proof.W3)
	commitments[39] = convertProofPoint(proof.W4)
	commitments[40] = convertProofPoint(proof.ZPerm)

	// Compute fold positive evaluations
	foldPosEvaluations := computeFoldPosEvaluations(
		tp.SumCheckUChallenges,
		batchedEvaluation,
		proof.GeminiAEvaluations,
		powersOfEvalChallenge,
		vk.LogCircuitSize,
	)

	// Constant term accumulator from A₀(±r)
	constantTermAccumulator := frMul(foldPosEvaluations[0], posInvDenom)
	constantTermAccumulator = frAdd(constantTermAccumulator, frMul(frMul(proof.GeminiAEvaluations[0], tp.ShplonkNu), negInvDenom))
	batchingChallenge = frSqr(tp.ShplonkNu)

	// Fold commitments and constant term accumulation
	for i := 0; i < ConstProofSizeLogN-1; i++ {
		dummyRound := uint64(i) >= (vk.LogCircuitSize - 1)

		if !dummyRound {
			posInvDenom = frInv(frSub(tp.ShplonkZ, powersOfEvalChallenge[i+1]))
			negInvDenom = frInv(frAdd(tp.ShplonkZ, powersOfEvalChallenge[i+1]))

			scalingFactorPos := frMul(batchingChallenge, posInvDenom)
			scalingFactorNeg := frMul(frMul(batchingChallenge, tp.ShplonkNu), negInvDenom)

			s := frAdd(frNeg(scalingFactorNeg), frNeg(scalingFactorPos))
			scalars[NumberOfEntities+1+i] = s

			accumContribution := frMul(scalingFactorNeg, proof.GeminiAEvaluations[i+1])
			accumContribution = frAdd(accumContribution, frMul(scalingFactorPos, foldPosEvaluations[i+1]))
			constantTermAccumulator = frAdd(constantTermAccumulator, accumContribution)

			batchingChallenge = frMul(batchingChallenge, frMul(tp.ShplonkNu, tp.ShplonkNu))
		} else {
			// scalar stays zero-initialized
		}

		commitments[NumberOfEntities+1+i] = convertProofPoint(proof.GeminiFoldComms[i])
	}

	// [1]₁ with constantTermAccumulator
	var g1Gen bn254.G1Affine
	g1Gen.X.SetOne()
	g1Gen.Y.SetUint64(2)
	commitments[NumberOfEntities+ConstProofSizeLogN] = g1Gen
	scalars[NumberOfEntities+ConstProofSizeLogN] = constantTermAccumulator

	// KZG quotient commitment * shplonkZ
	quotientCommitment := convertProofPoint(proof.KzgQuotient)
	commitments[NumberOfEntities+ConstProofSizeLogN+1] = quotientCommitment
	scalars[NumberOfEntities+ConstProofSizeLogN+1] = tp.ShplonkZ

	// Multi-scalar multiplication
	P0, err := batchMul(commitments, scalars)
	if err != nil {
		return false
	}

	P1 := negateG1(quotientCommitment)

	return pairingCheck(P0, P1)
}

func batchMul(points []bn254.G1Affine, scalars []fr.Element) (bn254.G1Affine, error) {
	var result bn254.G1Affine

	config := ecc.MultiExpConfig{}
	_, err := result.MultiExp(points, scalars, config)
	if err != nil {
		return result, fmt.Errorf("multi-exp failed: %w", err)
	}

	return result, nil
}

func pairingCheck(rhs, lhs bn254.G1Affine) bool {
	// Set up G2 points from SRS
	var g2Point1, g2Point2 bn254.G2Affine

	// G2 point 1 (fixed from SRS)
	// EIP-197 encoding: x_im(A1), x_re(A0), y_im(A1), y_re(A0)
	g2Point1.X.A1.SetBigInt(srsG2x0)
	g2Point1.X.A0.SetBigInt(srsG2x1)
	g2Point1.Y.A1.SetBigInt(srsG2y0)
	g2Point1.Y.A0.SetBigInt(srsG2y1)

	// G2 point 2 (from VK/SRS)
	g2Point2.X.A1.SetBigInt(srsG2x0b)
	g2Point2.X.A0.SetBigInt(srsG2x1b)
	g2Point2.Y.A1.SetBigInt(srsG2y0b)
	g2Point2.Y.A0.SetBigInt(srsG2y1b)

	// PairingCheck verifies e(rhs, g2Point1) * e(lhs, g2Point2) == 1
	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{rhs, lhs},
		[]bn254.G2Affine{g2Point1, g2Point2},
	)
	if err != nil {
		return false
	}
	return ok
}
