package honk

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

// splitChallenge splits a challenge into two 128-bit parts (lo and hi).
func splitChallenge(challenge fr.Element) (first, second fr.Element) {
	b := challenge.Bytes() // 32 bytes, big-endian

	// hi = top 128 bits (bytes 0..15), lo = bottom 128 bits (bytes 16..31)
	var loBuf, hiBuf [32]byte
	copy(loBuf[16:], b[16:32]) // lo in lower 16 bytes
	copy(hiBuf[16:], b[0:16])  // hi in lower 16 bytes

	first.SetBytes(loBuf[:])
	second.SetBytes(hiBuf[:])
	return
}

// keccakHash computes keccak256 over a slice of field elements packed as 32-byte big-endian words.
// This matches Solidity's abi.encodePacked for uint256[].
func keccakHash(elements []fr.Element) fr.Element {
	h := sha3.NewLegacyKeccak256()
	for _, e := range elements {
		b := e.Bytes() // 32 bytes big-endian
		h.Write(b[:])
	}
	var digest [32]byte
	h.Sum(digest[:0])
	var result fr.Element
	result.SetBytes(digest[:])
	return result
}

// keccakHashBytes computes keccak256 over raw byte slices (for mixed-type packing).
func keccakHashBytes(data []byte) fr.Element {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var digest [32]byte
	h.Sum(digest[:0])
	var result fr.Element
	result.SetBytes(digest[:])
	return result
}

// GenerateTranscript generates the full Fiat-Shamir transcript from a proof and public inputs.
func GenerateTranscript(proof *Proof, publicInputs []fr.Element, circuitSize, publicInputsSize, pubInputsOffset uint64) Transcript {
	var t Transcript
	var prevChallenge fr.Element

	t.RelationParams, prevChallenge = generateRelationParametersChallenges(proof, publicInputs, circuitSize, publicInputsSize, pubInputsOffset)
	t.Alphas, prevChallenge = generateAlphaChallenges(prevChallenge, proof)
	t.GateChallenges, prevChallenge = generateGateChallenges(prevChallenge)
	t.SumCheckUChallenges, prevChallenge = generateSumcheckChallenges(proof, prevChallenge)
	t.Rho, prevChallenge = generateRhoChallenge(proof, prevChallenge)
	t.GeminiR, prevChallenge = generateGeminiRChallenge(proof, prevChallenge)
	t.ShplonkNu, prevChallenge = generateShplonkNuChallenge(proof, prevChallenge)
	t.ShplonkZ, _ = generateShplonkZChallenge(proof, prevChallenge)

	return t
}

func generateRelationParametersChallenges(proof *Proof, publicInputs []fr.Element, circuitSize, publicInputsSize, pubInputsOffset uint64, ) (RelationParameters, fr.Element) {
	var rp RelationParameters
	var prevChallenge fr.Element

	rp.Eta, rp.EtaTwo, rp.EtaThree, prevChallenge = generateEtaChallenge(proof, publicInputs, circuitSize, publicInputsSize, pubInputsOffset)
	rp.Beta, rp.Gamma, prevChallenge = generateBetaAndGammaChallenges(prevChallenge, proof)

	return rp, prevChallenge
}

func generateEtaChallenge(proof *Proof, publicInputs []fr.Element, circuitSize, publicInputsSize, pubInputsOffset uint64) (eta, etaTwo, etaThree, prevChallenge fr.Element) {
	// round0: circuitSize, publicInputsSize, pubInputsOffset, publicInputs (non-pairing), pairing objects, w1-w3 commitments
	numRealPubInputs := publicInputsSize - PairingPointsSize
	round0Size := 3 + publicInputsSize + 12
	round0 := make([]fr.Element, round0Size)

	round0[0] = frFrom(circuitSize)
	round0[1] = frFrom(publicInputsSize)
	round0[2] = frFrom(pubInputsOffset)

	for i := uint64(0); i < numRealPubInputs; i++ {
		round0[3+i] = publicInputs[i]
	}
	for i := uint64(0); i < PairingPointsSize; i++ {
		round0[3+numRealPubInputs+i] = proof.PairingPointObject[i]
	}

	base := 3 + publicInputsSize
	round0[base+0] = proof.W1.X0
	round0[base+1] = proof.W1.X1
	round0[base+2] = proof.W1.Y0
	round0[base+3] = proof.W1.Y1
	round0[base+4] = proof.W2.X0
	round0[base+5] = proof.W2.X1
	round0[base+6] = proof.W2.Y0
	round0[base+7] = proof.W2.Y1
	round0[base+8] = proof.W3.X0
	round0[base+9] = proof.W3.X1
	round0[base+10] = proof.W3.Y0
	round0[base+11] = proof.W3.Y1

	prevChallenge = keccakHash(round0)
	eta, etaTwo = splitChallenge(prevChallenge)

	// Hash again for etaThree
	prevChallenge = keccakHash([]fr.Element{prevChallenge})
	etaThree, _ = splitChallenge(prevChallenge)
	return
}

func generateBetaAndGammaChallenges(prevChallenge fr.Element, proof *Proof) (beta, gamma, nextPrevChallenge fr.Element) {
	round1 := make([]fr.Element, 13)
	round1[0] = prevChallenge
	round1[1] = proof.LookupReadCounts.X0
	round1[2] = proof.LookupReadCounts.X1
	round1[3] = proof.LookupReadCounts.Y0
	round1[4] = proof.LookupReadCounts.Y1
	round1[5] = proof.LookupReadTags.X0
	round1[6] = proof.LookupReadTags.X1
	round1[7] = proof.LookupReadTags.Y0
	round1[8] = proof.LookupReadTags.Y1
	round1[9] = proof.W4.X0
	round1[10] = proof.W4.X1
	round1[11] = proof.W4.Y0
	round1[12] = proof.W4.Y1

	nextPrevChallenge = keccakHash(round1)
	beta, gamma = splitChallenge(nextPrevChallenge)
	return
}

func generateAlphaChallenges(prevChallenge fr.Element, proof *Proof) ([NumberOfAlphas]fr.Element, fr.Element) {
	var alphas [NumberOfAlphas]fr.Element

	alpha0 := make([]fr.Element, 9)
	alpha0[0] = prevChallenge
	alpha0[1] = proof.LookupInverses.X0
	alpha0[2] = proof.LookupInverses.X1
	alpha0[3] = proof.LookupInverses.Y0
	alpha0[4] = proof.LookupInverses.Y1
	alpha0[5] = proof.ZPerm.X0
	alpha0[6] = proof.ZPerm.X1
	alpha0[7] = proof.ZPerm.Y0
	alpha0[8] = proof.ZPerm.Y1

	nextPrev := keccakHash(alpha0)
	alphas[0], alphas[1] = splitChallenge(nextPrev)

	for i := 1; i < NumberOfAlphas/2; i++ {
		nextPrev = keccakHash([]fr.Element{nextPrev})
		alphas[2*i], alphas[2*i+1] = splitChallenge(nextPrev)
	}

	// Handle odd number of alphas
	if NumberOfAlphas&1 == 1 && NumberOfAlphas > 2 {
		nextPrev = keccakHash([]fr.Element{nextPrev})
		alphas[NumberOfAlphas-1], _ = splitChallenge(nextPrev)
	}

	return alphas, nextPrev
}

func generateGateChallenges(prevChallenge fr.Element) ([ConstProofSizeLogN]fr.Element, fr.Element) {
	var gateChallenges [ConstProofSizeLogN]fr.Element

	for i := 0; i < ConstProofSizeLogN; i++ {
		prevChallenge = keccakHash([]fr.Element{prevChallenge})
		gateChallenges[i], _ = splitChallenge(prevChallenge)
	}

	return gateChallenges, prevChallenge
}

func generateSumcheckChallenges(proof *Proof, prevChallenge fr.Element) ([ConstProofSizeLogN]fr.Element, fr.Element) {
	var challenges [ConstProofSizeLogN]fr.Element

	for i := 0; i < ConstProofSizeLogN; i++ {
		univariateChal := make([]fr.Element, BatchedRelationPartialLength+1)
		univariateChal[0] = prevChallenge
		for j := 0; j < BatchedRelationPartialLength; j++ {
			univariateChal[j+1] = proof.SumcheckUnivariates[i][j]
		}
		prevChallenge = keccakHash(univariateChal)
		challenges[i], _ = splitChallenge(prevChallenge)
	}

	return challenges, prevChallenge
}

func generateRhoChallenge(proof *Proof, prevChallenge fr.Element) (rho, nextPrev fr.Element) {
	elements := make([]fr.Element, NumberOfEntities+1)
	elements[0] = prevChallenge
	for i := 0; i < NumberOfEntities; i++ {
		elements[i+1] = proof.SumcheckEvaluations[i]
	}
	nextPrev = keccakHash(elements)
	rho, _ = splitChallenge(nextPrev)
	return
}

func generateGeminiRChallenge(proof *Proof, prevChallenge fr.Element) (geminiR, nextPrev fr.Element) {
	elements := make([]fr.Element, (ConstProofSizeLogN-1)*4+1)
	elements[0] = prevChallenge
	for i := 0; i < ConstProofSizeLogN-1; i++ {
		elements[1+i*4] = proof.GeminiFoldComms[i].X0
		elements[2+i*4] = proof.GeminiFoldComms[i].X1
		elements[3+i*4] = proof.GeminiFoldComms[i].Y0
		elements[4+i*4] = proof.GeminiFoldComms[i].Y1
	}
	nextPrev = keccakHash(elements)
	geminiR, _ = splitChallenge(nextPrev)
	return
}

func generateShplonkNuChallenge(proof *Proof, prevChallenge fr.Element) (shplonkNu, nextPrev fr.Element) {
	elements := make([]fr.Element, ConstProofSizeLogN+1)
	elements[0] = prevChallenge
	for i := 0; i < ConstProofSizeLogN; i++ {
		elements[i+1] = proof.GeminiAEvaluations[i]
	}
	nextPrev = keccakHash(elements)
	shplonkNu, _ = splitChallenge(nextPrev)
	return
}

func generateShplonkZChallenge(proof *Proof, prevChallenge fr.Element) (shplonkZ, nextPrev fr.Element) {
	elements := make([]fr.Element, 5)
	elements[0] = prevChallenge
	elements[1] = proof.ShplonkQ.X0
	elements[2] = proof.ShplonkQ.X1
	elements[3] = proof.ShplonkQ.Y0
	elements[4] = proof.ShplonkQ.Y1
	nextPrev = keccakHash(elements)
	shplonkZ, _ = splitChallenge(nextPrev)
	return
}
