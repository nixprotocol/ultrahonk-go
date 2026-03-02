package honk

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// wire indexes into the sumcheck evaluations array.
func wire(p *[NumberOfEntities]fr.Element, w int) fr.Element {
	return p[w]
}

// AccumulateRelationEvaluations computes the full Honk relation accumulator.
func AccumulateRelationEvaluations(
	p *[NumberOfEntities]fr.Element,
	rp *RelationParameters,
	alphas *[NumberOfAlphas]fr.Element,
	powPartialEval fr.Element,
) fr.Element {
	var evals [NumberOfSubrelations]fr.Element

	accumulateArithmeticRelation(p, &evals, powPartialEval)
	accumulatePermutationRelation(p, rp, &evals, powPartialEval)
	accumulateLogDerivativeLookupRelation(p, rp, &evals, powPartialEval)
	accumulateDeltaRangeRelation(p, &evals, powPartialEval)
	accumulateEllipticRelation(p, &evals, powPartialEval)
	accumulateAuxiliaryRelation(p, rp, &evals, powPartialEval)
	accumulatePoseidonExternalRelation(p, &evals, powPartialEval)
	accumulatePoseidonInternalRelation(p, &evals, powPartialEval)

	return scaleAndBatchSubrelations(&evals, alphas)
}

func accumulateArithmeticRelation(p *[NumberOfEntities]fr.Element, evals *[NumberOfSubrelations]fr.Element, domainSep fr.Element) {
	qArith := wire(p, WIRE_Q_ARITH)
	three := frFrom(3)
	one := frFrom(1)
	two := frFrom(2)

	// Relation 0
	{
		accum := frMul(frSub(qArith, three), frMul(frMul(wire(p, WIRE_Q_M), wire(p, WIRE_W_R)), wire(p, WIRE_W_L)))
		accum = frMul(accum, negHalfModP)
		accum = frAdd(accum, frMul(wire(p, WIRE_Q_L), wire(p, WIRE_W_L)))
		accum = frAdd(accum, frMul(wire(p, WIRE_Q_R), wire(p, WIRE_W_R)))
		accum = frAdd(accum, frMul(wire(p, WIRE_Q_O), wire(p, WIRE_W_O)))
		accum = frAdd(accum, frMul(wire(p, WIRE_Q_4), wire(p, WIRE_W_4)))
		accum = frAdd(accum, wire(p, WIRE_Q_C))
		accum = frAdd(accum, frMul(frSub(qArith, one), wire(p, WIRE_W_4_SHIFT)))
		accum = frMul(accum, qArith)
		accum = frMul(accum, domainSep)
		evals[0] = accum
	}

	// Relation 1
	{
		accum := frAdd(frAdd(wire(p, WIRE_W_L), wire(p, WIRE_W_4)), frSub(wire(p, WIRE_Q_M), wire(p, WIRE_W_L_SHIFT)))
		accum = frMul(accum, frSub(qArith, two))
		accum = frMul(accum, frSub(qArith, one))
		accum = frMul(accum, qArith)
		accum = frMul(accum, domainSep)
		evals[1] = accum
	}
}

func accumulatePermutationRelation(p *[NumberOfEntities]fr.Element, rp *RelationParameters, evals *[NumberOfSubrelations]fr.Element, domainSep fr.Element) {
	var grandProductNumerator, grandProductDenominator fr.Element

	{
		num := frAdd(frAdd(wire(p, WIRE_W_L), frMul(wire(p, WIRE_ID_1), rp.Beta)), rp.Gamma)
		num = frMul(num, frAdd(frAdd(wire(p, WIRE_W_R), frMul(wire(p, WIRE_ID_2), rp.Beta)), rp.Gamma))
		num = frMul(num, frAdd(frAdd(wire(p, WIRE_W_O), frMul(wire(p, WIRE_ID_3), rp.Beta)), rp.Gamma))
		num = frMul(num, frAdd(frAdd(wire(p, WIRE_W_4), frMul(wire(p, WIRE_ID_4), rp.Beta)), rp.Gamma))
		grandProductNumerator = num
	}
	{
		den := frAdd(frAdd(wire(p, WIRE_W_L), frMul(wire(p, WIRE_SIGMA_1), rp.Beta)), rp.Gamma)
		den = frMul(den, frAdd(frAdd(wire(p, WIRE_W_R), frMul(wire(p, WIRE_SIGMA_2), rp.Beta)), rp.Gamma))
		den = frMul(den, frAdd(frAdd(wire(p, WIRE_W_O), frMul(wire(p, WIRE_SIGMA_3), rp.Beta)), rp.Gamma))
		den = frMul(den, frAdd(frAdd(wire(p, WIRE_W_4), frMul(wire(p, WIRE_SIGMA_4), rp.Beta)), rp.Gamma))
		grandProductDenominator = den
	}

	// Contribution 2
	{
		acc := frMul(frAdd(wire(p, WIRE_Z_PERM), wire(p, WIRE_LAGRANGE_FIRST)), grandProductNumerator)
		sub := frMul(frAdd(wire(p, WIRE_Z_PERM_SHIFT), frMul(wire(p, WIRE_LAGRANGE_LAST), rp.PublicInputsDelta)), grandProductDenominator)
		acc = frSub(acc, sub)
		acc = frMul(acc, domainSep)
		evals[2] = acc
	}

	// Contribution 3
	{
		acc := frMul(frMul(wire(p, WIRE_LAGRANGE_LAST), wire(p, WIRE_Z_PERM_SHIFT)), domainSep)
		evals[3] = acc
	}
}

func accumulateLogDerivativeLookupRelation(p *[NumberOfEntities]fr.Element, rp *RelationParameters, evals *[NumberOfSubrelations]fr.Element, domainSep fr.Element) {
	writeTerm := frAdd(frAdd(frAdd(wire(p, WIRE_TABLE_1), rp.Gamma), frMul(wire(p, WIRE_TABLE_2), rp.Eta)), frAdd(frMul(wire(p, WIRE_TABLE_3), rp.EtaTwo), frMul(wire(p, WIRE_TABLE_4), rp.EtaThree)))

	derivedEntry1 := frAdd(frAdd(wire(p, WIRE_W_L), rp.Gamma), frMul(wire(p, WIRE_Q_R), wire(p, WIRE_W_L_SHIFT)))
	derivedEntry2 := frAdd(wire(p, WIRE_W_R), frMul(wire(p, WIRE_Q_M), wire(p, WIRE_W_R_SHIFT)))
	derivedEntry3 := frAdd(wire(p, WIRE_W_O), frMul(wire(p, WIRE_Q_C), wire(p, WIRE_W_O_SHIFT)))

	readTerm := frAdd(frAdd(derivedEntry1, frMul(derivedEntry2, rp.Eta)), frAdd(frMul(derivedEntry3, rp.EtaTwo), frMul(wire(p, WIRE_Q_O), rp.EtaThree)))

	readInverse := frMul(wire(p, WIRE_LOOKUP_INVERSES), writeTerm)
	writeInverse := frMul(wire(p, WIRE_LOOKUP_INVERSES), readTerm)

	inverseExistsXor := frSub(frAdd(wire(p, WIRE_LOOKUP_READ_TAGS), wire(p, WIRE_Q_LOOKUP)), frMul(wire(p, WIRE_LOOKUP_READ_TAGS), wire(p, WIRE_Q_LOOKUP)))

	accNone := frSub(frMul(frMul(readTerm, writeTerm), wire(p, WIRE_LOOKUP_INVERSES)), inverseExistsXor)
	accNone = frMul(accNone, domainSep)

	accOne := frSub(frMul(wire(p, WIRE_Q_LOOKUP), readInverse), frMul(wire(p, WIRE_LOOKUP_READ_COUNTS), writeInverse))

	evals[4] = accNone
	evals[5] = accOne
}

func accumulateDeltaRangeRelation(p *[NumberOfEntities]fr.Element, evals *[NumberOfSubrelations]fr.Element, domainSep fr.Element) {
	minusOne := frNeg(frFrom(1))
	minusTwo := frNeg(frFrom(2))
	minusThree := frNeg(frFrom(3))

	delta1 := frSub(wire(p, WIRE_W_R), wire(p, WIRE_W_L))
	delta2 := frSub(wire(p, WIRE_W_O), wire(p, WIRE_W_R))
	delta3 := frSub(wire(p, WIRE_W_4), wire(p, WIRE_W_O))
	delta4 := frSub(wire(p, WIRE_W_L_SHIFT), wire(p, WIRE_W_4))

	qRange := wire(p, WIRE_Q_RANGE)

	for i, d := range []fr.Element{delta1, delta2, delta3, delta4} {
		acc := d
		acc = frMul(acc, frAdd(d, minusOne))
		acc = frMul(acc, frAdd(d, minusTwo))
		acc = frMul(acc, frAdd(d, minusThree))
		acc = frMul(acc, qRange)
		acc = frMul(acc, domainSep)
		evals[6+i] = acc
	}
}

func accumulateEllipticRelation(p *[NumberOfEntities]fr.Element, evals *[NumberOfSubrelations]fr.Element, domainSep fr.Element) {
	x1 := wire(p, WIRE_W_R)
	y1 := wire(p, WIRE_W_O)
	x2 := wire(p, WIRE_W_L_SHIFT)
	y2 := wire(p, WIRE_W_4_SHIFT)
	y3 := wire(p, WIRE_W_O_SHIFT)
	x3 := wire(p, WIRE_W_R_SHIFT)

	qSign := wire(p, WIRE_Q_L)
	qIsDouble := wire(p, WIRE_Q_M)
	qElliptic := wire(p, WIRE_Q_ELLIPTIC)
	one := frFrom(1)
	notDouble := frSub(one, qIsDouble)

	// Grumpkin curve b = -17, so GRUMPKIN_CURVE_B_PARAMETER_NEGATED = 17
	grumpkinBNeg := frFrom(17)

	xDiff := frSub(x2, x1)
	y1Sqr := frMul(y1, y1)

	// Contribution 10: point addition x-coordinate check
	{
		y2Sqr := frMul(y2, y2)
		y1y2 := frMul(frMul(y1, y2), qSign)
		xAddIdentity := frMul(frAdd(frAdd(x3, x2), x1), frMul(xDiff, xDiff))
		xAddIdentity = frAdd(frSub(frSub(xAddIdentity, y2Sqr), y1Sqr), frAdd(y1y2, y1y2))
		evals[10] = frMul(frMul(frMul(xAddIdentity, domainSep), qElliptic), notDouble)
	}

	// Contribution 11: point addition y-coordinate check
	{
		y1PlusY3 := frAdd(y1, y3)
		yDiff := frSub(frMul(y2, qSign), y1)
		yAddIdentity := frAdd(frMul(y1PlusY3, xDiff), frMul(frSub(x3, x1), yDiff))
		evals[11] = frMul(frMul(frMul(yAddIdentity, domainSep), qElliptic), notDouble)
	}

	// Contribution 10 (doubling): x-coordinate check
	{
		xPow4 := frMul(frAdd(y1Sqr, grumpkinBNeg), x1)
		y1SqrMul4 := frAdd(y1Sqr, y1Sqr)
		y1SqrMul4 = frAdd(y1SqrMul4, y1SqrMul4)
		x1Pow4Mul9 := frMul(xPow4, frFrom(9))

		xDoubleIdentity := frSub(frMul(frAdd(frAdd(x3, x1), x1), y1SqrMul4), x1Pow4Mul9)
		acc := frMul(frMul(frMul(xDoubleIdentity, domainSep), qElliptic), qIsDouble)
		evals[10] = frAdd(evals[10], acc)
	}

	// Contribution 11 (doubling): y-coordinate check
	{
		x1SqrMul3 := frMul(frAdd(frAdd(x1, x1), x1), x1)
		yDoubleIdentity := frSub(frMul(x1SqrMul3, frSub(x1, x3)), frMul(frAdd(y1, y1), frAdd(y1, y3)))
		evals[11] = frAdd(evals[11], frMul(frMul(frMul(yDoubleIdentity, domainSep), qElliptic), qIsDouble))
	}
}

func accumulateAuxiliaryRelation(p *[NumberOfEntities]fr.Element, rp *RelationParameters, evals *[NumberOfSubrelations]fr.Element, domainSep fr.Element) {
	limbSize := mustFromHex("0x100000000000000000") // 1 << 68
	sublimbShift := mustFromHex("0x4000")            // 1 << 14
	minusOne := frNeg(frFrom(1))

	// Non-native field gate
	limbSubproduct := frAdd(
		frMul(wire(p, WIRE_W_L), wire(p, WIRE_W_R_SHIFT)),
		frMul(wire(p, WIRE_W_L_SHIFT), wire(p, WIRE_W_R)),
	)

	nonNativeFieldGate2 := frSub(frAdd(frMul(wire(p, WIRE_W_L), wire(p, WIRE_W_4)), frMul(wire(p, WIRE_W_R), wire(p, WIRE_W_O))), wire(p, WIRE_W_O_SHIFT))
	nonNativeFieldGate2 = frMul(nonNativeFieldGate2, limbSize)
	nonNativeFieldGate2 = frSub(nonNativeFieldGate2, wire(p, WIRE_W_4_SHIFT))
	nonNativeFieldGate2 = frAdd(nonNativeFieldGate2, limbSubproduct)
	nonNativeFieldGate2 = frMul(nonNativeFieldGate2, wire(p, WIRE_Q_4))

	limbSubproduct = frMul(limbSubproduct, limbSize)
	limbSubproduct = frAdd(limbSubproduct, frMul(wire(p, WIRE_W_L_SHIFT), wire(p, WIRE_W_R_SHIFT)))

	nonNativeFieldGate1 := limbSubproduct
	nonNativeFieldGate1 = frSub(nonNativeFieldGate1, frAdd(wire(p, WIRE_W_O), wire(p, WIRE_W_4)))
	nonNativeFieldGate1 = frMul(nonNativeFieldGate1, wire(p, WIRE_Q_O))

	nonNativeFieldGate3 := limbSubproduct
	nonNativeFieldGate3 = frAdd(nonNativeFieldGate3, wire(p, WIRE_W_4))
	nonNativeFieldGate3 = frSub(nonNativeFieldGate3, frAdd(wire(p, WIRE_W_O_SHIFT), wire(p, WIRE_W_4_SHIFT)))
	nonNativeFieldGate3 = frMul(nonNativeFieldGate3, wire(p, WIRE_Q_M))

	nonNativeFieldIdentity := frAdd(frAdd(nonNativeFieldGate1, nonNativeFieldGate2), nonNativeFieldGate3)
	nonNativeFieldIdentity = frMul(nonNativeFieldIdentity, wire(p, WIRE_Q_R))

	// Limb accumulator 1
	limbAccumulator1 := frMul(wire(p, WIRE_W_R_SHIFT), sublimbShift)
	limbAccumulator1 = frAdd(limbAccumulator1, wire(p, WIRE_W_L_SHIFT))
	limbAccumulator1 = frMul(limbAccumulator1, sublimbShift)
	limbAccumulator1 = frAdd(limbAccumulator1, wire(p, WIRE_W_O))
	limbAccumulator1 = frMul(limbAccumulator1, sublimbShift)
	limbAccumulator1 = frAdd(limbAccumulator1, wire(p, WIRE_W_R))
	limbAccumulator1 = frMul(limbAccumulator1, sublimbShift)
	limbAccumulator1 = frAdd(limbAccumulator1, wire(p, WIRE_W_L))
	limbAccumulator1 = frSub(limbAccumulator1, wire(p, WIRE_W_4))
	limbAccumulator1 = frMul(limbAccumulator1, wire(p, WIRE_Q_4))

	// Limb accumulator 2
	limbAccumulator2 := frMul(wire(p, WIRE_W_O_SHIFT), sublimbShift)
	limbAccumulator2 = frAdd(limbAccumulator2, wire(p, WIRE_W_R_SHIFT))
	limbAccumulator2 = frMul(limbAccumulator2, sublimbShift)
	limbAccumulator2 = frAdd(limbAccumulator2, wire(p, WIRE_W_L_SHIFT))
	limbAccumulator2 = frMul(limbAccumulator2, sublimbShift)
	limbAccumulator2 = frAdd(limbAccumulator2, wire(p, WIRE_W_4))
	limbAccumulator2 = frMul(limbAccumulator2, sublimbShift)
	limbAccumulator2 = frAdd(limbAccumulator2, wire(p, WIRE_W_O))
	limbAccumulator2 = frSub(limbAccumulator2, wire(p, WIRE_W_4_SHIFT))
	limbAccumulator2 = frMul(limbAccumulator2, wire(p, WIRE_Q_M))

	limbAccumulatorIdentity := frMul(frAdd(limbAccumulator1, limbAccumulator2), wire(p, WIRE_Q_O))

	// Memory record check
	memoryRecordCheck := frMul(wire(p, WIRE_W_O), rp.EtaThree)
	memoryRecordCheck = frAdd(memoryRecordCheck, frMul(wire(p, WIRE_W_R), rp.EtaTwo))
	memoryRecordCheck = frAdd(memoryRecordCheck, frMul(wire(p, WIRE_W_L), rp.Eta))
	memoryRecordCheck = frAdd(memoryRecordCheck, wire(p, WIRE_Q_C))
	partialRecordCheck := memoryRecordCheck
	memoryRecordCheck = frSub(memoryRecordCheck, wire(p, WIRE_W_4))

	// ROM consistency
	indexDelta := frSub(wire(p, WIRE_W_L_SHIFT), wire(p, WIRE_W_L))
	recordDelta := frSub(wire(p, WIRE_W_4_SHIFT), wire(p, WIRE_W_4))
	indexIsMonotonicallyIncreasing := frSub(frMul(indexDelta, indexDelta), indexDelta)
	adjacentValuesMatch := frMul(frAdd(frMul(indexDelta, minusOne), frFrom(1)), recordDelta)

	qlQr := frMul(wire(p, WIRE_Q_L), wire(p, WIRE_Q_R))
	qAuxDomainSep := frMul(wire(p, WIRE_Q_AUX), domainSep)

	evals[13] = frMul(frMul(adjacentValuesMatch, qlQr), qAuxDomainSep)
	evals[14] = frMul(frMul(indexIsMonotonicallyIncreasing, qlQr), qAuxDomainSep)

	romConsistencyCheckIdentity := frMul(memoryRecordCheck, qlQr)

	// RAM consistency
	accessType := frSub(wire(p, WIRE_W_4), partialRecordCheck)
	accessCheck := frSub(frMul(accessType, accessType), accessType)

	nextGateAccessType := frMul(wire(p, WIRE_W_O_SHIFT), rp.EtaThree)
	nextGateAccessType = frAdd(nextGateAccessType, frMul(wire(p, WIRE_W_R_SHIFT), rp.EtaTwo))
	nextGateAccessType = frAdd(nextGateAccessType, frMul(wire(p, WIRE_W_L_SHIFT), rp.Eta))
	nextGateAccessType = frSub(wire(p, WIRE_W_4_SHIFT), nextGateAccessType)

	valueDelta := frSub(wire(p, WIRE_W_O_SHIFT), wire(p, WIRE_W_O))
	adjValuesMatchRead := frMul(frMul(frAdd(frMul(indexDelta, minusOne), frFrom(1)), valueDelta), frAdd(frMul(nextGateAccessType, minusOne), frFrom(1)))

	nextGateAccessTypeIsBoolean := frSub(frMul(nextGateAccessType, nextGateAccessType), nextGateAccessType)

	qArith := wire(p, WIRE_Q_ARITH)

	evals[15] = frMul(frMul(adjValuesMatchRead, qArith), qAuxDomainSep)
	evals[16] = frMul(frMul(indexIsMonotonicallyIncreasing, qArith), qAuxDomainSep)
	evals[17] = frMul(frMul(nextGateAccessTypeIsBoolean, qArith), qAuxDomainSep)

	ramConsistencyCheckIdentity := frMul(accessCheck, qArith)

	// RAM timestamp
	timestampDelta := frSub(wire(p, WIRE_W_R_SHIFT), wire(p, WIRE_W_R))
	ramTimestampCheckIdentity := frSub(frMul(frAdd(frMul(indexDelta, minusOne), frFrom(1)), timestampDelta), wire(p, WIRE_W_O))

	// Complete contribution 12
	memoryIdentity := romConsistencyCheckIdentity
	memoryIdentity = frAdd(memoryIdentity, frMul(ramTimestampCheckIdentity, frMul(wire(p, WIRE_Q_4), wire(p, WIRE_Q_L))))
	memoryIdentity = frAdd(memoryIdentity, frMul(memoryRecordCheck, frMul(wire(p, WIRE_Q_M), wire(p, WIRE_Q_L))))
	memoryIdentity = frAdd(memoryIdentity, ramConsistencyCheckIdentity)

	auxiliaryIdentity := frAdd(frAdd(memoryIdentity, nonNativeFieldIdentity), limbAccumulatorIdentity)
	auxiliaryIdentity = frMul(auxiliaryIdentity, qAuxDomainSep)
	evals[12] = auxiliaryIdentity
}

func accumulatePoseidonExternalRelation(p *[NumberOfEntities]fr.Element, evals *[NumberOfSubrelations]fr.Element, domainSep fr.Element) {
	s1 := frAdd(wire(p, WIRE_W_L), wire(p, WIRE_Q_L))
	s2 := frAdd(wire(p, WIRE_W_R), wire(p, WIRE_Q_R))
	s3 := frAdd(wire(p, WIRE_W_O), wire(p, WIRE_Q_O))
	s4 := frAdd(wire(p, WIRE_W_4), wire(p, WIRE_Q_4))

	// s-box: x^5
	u1 := frMul(frMul(frMul(frMul(s1, s1), s1), s1), s1)
	u2 := frMul(frMul(frMul(frMul(s2, s2), s2), s2), s2)
	u3 := frMul(frMul(frMul(frMul(s3, s3), s3), s3), s3)
	u4 := frMul(frMul(frMul(frMul(s4, s4), s4), s4), s4)

	// External matrix multiplication
	t0 := frAdd(u1, u2)
	t1 := frAdd(u3, u4)
	t2 := frAdd(frAdd(u2, u2), t1)
	t3 := frAdd(frAdd(u4, u4), t0)
	v4 := frAdd(frAdd(t1, t1), t1)
	v4 = frAdd(v4, frAdd(t1, t3))
	v2 := frAdd(frAdd(t0, t0), t0)
	v2 = frAdd(v2, frAdd(t0, t2))
	v1 := frAdd(t3, v2)
	v3 := frAdd(t2, v4)

	qPosByScaling := frMul(wire(p, WIRE_Q_POSEIDON2_EXTERNAL), domainSep)
	evals[18] = frAdd(evals[18], frMul(qPosByScaling, frSub(v1, wire(p, WIRE_W_L_SHIFT))))
	evals[19] = frAdd(evals[19], frMul(qPosByScaling, frSub(v2, wire(p, WIRE_W_R_SHIFT))))
	evals[20] = frAdd(evals[20], frMul(qPosByScaling, frSub(v3, wire(p, WIRE_W_O_SHIFT))))
	evals[21] = frAdd(evals[21], frMul(qPosByScaling, frSub(v4, wire(p, WIRE_W_4_SHIFT))))
}

func accumulatePoseidonInternalRelation(p *[NumberOfEntities]fr.Element, evals *[NumberOfSubrelations]fr.Element, domainSep fr.Element) {
	internalMatrixDiagonal := [4]fr.Element{
		mustFromHex("0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7"),
		mustFromHex("0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b"),
		mustFromHex("0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15"),
		mustFromHex("0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b"),
	}

	s1 := frAdd(wire(p, WIRE_W_L), wire(p, WIRE_Q_L))
	u1 := frMul(frMul(frMul(frMul(s1, s1), s1), s1), s1)
	u2 := wire(p, WIRE_W_R)
	u3 := wire(p, WIRE_W_O)
	u4 := wire(p, WIRE_W_4)

	uSum := frAdd(frAdd(u1, u2), frAdd(u3, u4))

	qPosByScaling := frMul(wire(p, WIRE_Q_POSEIDON2_INTERNAL), domainSep)

	v1 := frAdd(frMul(u1, internalMatrixDiagonal[0]), uSum)
	evals[22] = frAdd(evals[22], frMul(qPosByScaling, frSub(v1, wire(p, WIRE_W_L_SHIFT))))

	v2 := frAdd(frMul(u2, internalMatrixDiagonal[1]), uSum)
	evals[23] = frAdd(evals[23], frMul(qPosByScaling, frSub(v2, wire(p, WIRE_W_R_SHIFT))))

	v3 := frAdd(frMul(u3, internalMatrixDiagonal[2]), uSum)
	evals[24] = frAdd(evals[24], frMul(qPosByScaling, frSub(v3, wire(p, WIRE_W_O_SHIFT))))

	v4 := frAdd(frMul(u4, internalMatrixDiagonal[3]), uSum)
	evals[25] = frAdd(evals[25], frMul(qPosByScaling, frSub(v4, wire(p, WIRE_W_4_SHIFT))))
}

func scaleAndBatchSubrelations(evals *[NumberOfSubrelations]fr.Element, alphas *[NumberOfAlphas]fr.Element) fr.Element {
	accumulator := evals[0]
	for i := 1; i < NumberOfSubrelations; i++ {
		accumulator = frAdd(accumulator, frMul(evals[i], alphas[i-1]))
	}
	return accumulator
}
