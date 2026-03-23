package honk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// mustG1FromHex parses hex-encoded x, y coordinates into a G1Affine point,
// panicking on invalid input or if the point is not on the curve.
// Used only for compile-time VK constants.
func mustG1FromHex(xHex, yHex string) bn254.G1Affine {
	var p bn254.G1Affine
	x, ok := new(big.Int).SetString(xHex[2:], 16)
	if !ok {
		panic(fmt.Sprintf("honk: invalid G1 x-coordinate hex %q", xHex))
	}
	y, ok := new(big.Int).SetString(yHex[2:], 16)
	if !ok {
		panic(fmt.Sprintf("honk: invalid G1 y-coordinate hex %q", yHex))
	}
	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)
	if !p.IsOnCurve() {
		panic(fmt.Sprintf("honk: G1 point (%s, %s) is not on BN254 curve", xHex, yHex))
	}
	return p
}

// depositVerificationKey returns the hardcoded verification key for the NixProtocol
// deposit circuit (N=8192, 8 public inputs). Generated from Barretenberg v0.63.
func depositVerificationKey() VerificationKey {
	return VerificationKey{
		CircuitSize:      8192,
		LogCircuitSize:   13,
		PublicInputsSize: 24,

		Ql: mustG1FromHex(
			"0x1122448e67fa4a9957b54e04cb5cc15589728508c7286b7c7691e9f4856b7875",
			"0x13a7cf08aebd79de0359d47709ad43d60afbfb839606dac5c25e3a1286069812",
		),
		Qr: mustG1FromHex(
			"0x152836896488b9df2381067587e619ec1d543c1b38ee70fe82c1fdbfc7a032d0",
			"0x2e3e6fe6f8c199a22ec00753f767ff1ef3017eb2a11333b4be99675b66d094fb",
		),
		Qo: mustG1FromHex(
			"0x04f1aa1e44c0a0f6c0b2a326f94660d2e30f284bb1091fc06922a89f19aa343a",
			"0x288b82d1dfb8908926195dfe5a8faa69ef5aeeaf167138f0c55ca9da34dbc29b",
		),
		Q4: mustG1FromHex(
			"0x2ec1225e3b9ee01a2c1a0eecce7ed752491842b67189e98d9fe00ac02d445c9e",
			"0x16b51231ea559db403e4a996bfded02dcce32a5085695695c3ec92957de02dd8",
		),
		Qm: mustG1FromHex(
			"0x14e0779f5befe4395fafe10b524baffe0031bf25cb7f61737991128c172a6819",
			"0x033e27037a9f965118b9ea13ab5cfe8b26099f715a1d76d5fd5564cdd14510e4",
		),
		Qc: mustG1FromHex(
			"0x212a04a9ec1e74bd9c75bf11751f74c1abc253d59b0a436e9b0f16e4f26ddd4f",
			"0x187272a8ba04df60fd463190539440ffc56c18c72e6bb8e57ba940116403c47a",
		),
		QArith: mustG1FromHex(
			"0x1f3fb57ca7484f75af72c026088184839055c00532917f87cd2d05036aa5c84d",
			"0x2f3495455b9a15e8a864b240b8e40045f17912e7adc733b0557aa435e8097232",
		),
		QDeltaRange: mustG1FromHex(
			"0x22391ebbf9256f05814d3c9d6c6562841be3bea3ae93dbc3308efb8c43834bc9",
			"0x1775b7a732d1d089159c5e70997be0f2ee9119b8cc14cb7924b72631898c8a0a",
		),
		QElliptic: mustG1FromHex(
			"0x199dada605905b49924b4c2cb7854b1af7e8f75f514adfa0ec88c67bcc4cd59d",
			"0x1dd51bdbcd6453f097ed4fd5d6e7edb971bff358c72f5d0fd51b1d6f1f935bd5",
		),
		QAux: mustG1FromHex(
			"0x1eec4a7dca1875476b2803750271713108d184cfdf53a35575b2b9b0887fe6df",
			"0x2c5122c9765b1d9af0ca8fffa99f93a45997e45d57ccf6196ad355fc041050bd",
		),
		QLookup: mustG1FromHex(
			"0x131342f1f7ba8c1218b01824d28190937da03bf8dea49d4d699c9a268871ea0b",
			"0x24bcefad8c9004741c53b103f782698c451cd5b7221b3817b3529cf1188278f3",
		),
		QPoseidon2External: mustG1FromHex(
			"0x14f71682f897a4bb67b09ecc6a9be7a05ee5a3693feb54f302d4926f98dcf627",
			"0x2fb8f30bc84cc02041cf98d4df0d54b23a0a143cbc8a027ccfa6a8e92e2e6823",
		),
		QPoseidon2Internal: mustG1FromHex(
			"0x1088d32356a3811ce42d67cc6242e3605c83941f746c38d526b2df452e75da15",
			"0x2e88265bac7093d7b0a28e296789a134930acaa1289686d83849c8f1d3887e89",
		),
		S1: mustG1FromHex(
			"0x2276170c4d7ddf9249238a0f4843bdbef282a239849f1bd101f920cded4b1d91",
			"0x1ae3909bbe260cfbf89962b00e938517a7b5fff3e1c2c49be30185de0c757a95",
		),
		S2: mustG1FromHex(
			"0x1d35307d4719ce619c1d9302aae121e76b56b6287229a84f9837cb5163d2a98c",
			"0x02aa5eb0f96184eea7c9623484658b4190a61b26a326bcdee510317accd94419",
		),
		S3: mustG1FromHex(
			"0x25cdbfc9c889925cf6ff3fa995a3a2cf0ecb8b54dc59ccee613f69400fd8be65",
			"0x09a1d4a9397554c37cff1f35d7dece009750440d59cf23a0cb12970519527b64",
		),
		S4: mustG1FromHex(
			"0x0400dae7f0ccb504ed34c4a29d21a7b874196929a5ffdc68f81c850ec529a552",
			"0x2eede35f43ef694364a20ea873c1d7608b1ad5f8764a12b77b3d826982eb2d04",
		),
		T1: mustG1FromHex(
			"0x198858e84430160eb36117e7444a0e23d139ccd4a31a5929a712cb12b1038616",
			"0x072803523168f27ffb30e2f58adc3adb8305d096e7cd9aca0e5c7c1f65ad4a58",
		),
		T2: mustG1FromHex(
			"0x2d7d64ded67330c3d1fc3b245134eac85b3b73516ae995630d11ddfe15d72f82",
			"0x296a553d1026d35a3e46676773bad65a181ccc0db176ed6a538742d7af2b020b",
		),
		T3: mustG1FromHex(
			"0x220de0736eb048e204fc3762cb552daa654d87b470f1db4e0e61713ce812eb9f",
			"0x0980596fd49b34c460dae2404d43a65105309b24f91c3c1657c919dbf978e207",
		),
		T4: mustG1FromHex(
			"0x0c0116cff256dce0dd567489189b79c660d738bd4cb45159e911ae2e567e7bb3",
			"0x14c09553e435b1349a61d7643954f2dae395002105253c55f1ad63af1145ce3c",
		),
		ID1: mustG1FromHex(
			"0x0ef21fcfe077be1418fbad1c1a52a1bc0d71b1f86ca83e010710fd235870777a",
			"0x302ecd9e7c83b0a48ac4c639bdab8c1b0c67223e36b21d4c5dea6dbda07b1338",
		),
		ID2: mustG1FromHex(
			"0x2143f702e1235e2ae9db88c8a4fe4fdd20a30ff5e0f0cc22c1afc48b694a51a1",
			"0x0f644bd306bdd45d710d0fef071fc4ec903e6a0db69f5f0c5a78297b7225d91a",
		),
		ID3: mustG1FromHex(
			"0x29044e1b86a6f9b991416929dc012e799a2e735ad6384bf03d0e8013ef5a1e0f",
			"0x133af22051f1a336474491ffadc19145a1040e3fbab0c0732ac188ec7001a37f",
		),
		ID4: mustG1FromHex(
			"0x28cc658cb62ed83a6e60825d65d1d26d004961325b1263b1d1b9b59b3a7b0a17",
			"0x0ef87d5794bc1ad37d9a9f938948566359ef67310963bebb18fc250d191c8234",
		),
		LagrangeFirst: mustG1FromHex(
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
		),
		LagrangeLast: mustG1FromHex(
			"0x13d5f83dc62fded1449a652c0959fea2d32875d99ad21b7691c2ee709ff2b5c9",
			"0x073f388751e6c3ec520231d0a9ac8cb9ee9803441da38101d90d798f20235f74",
		),
	}
}
