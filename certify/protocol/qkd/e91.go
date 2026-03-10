package qkd

import (
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// E91Protocol implements the Ekert 1991 entanglement-based QKD protocol.
// Security is based on Bell inequality (CHSH) violation.
//
// Uses maximally entangled Bell pairs: |Phi+> = (|00> + |11>)/sqrt(2)
// Alice measures in {0, pi/4, pi/2} bases
// Bob measures in {pi/4, pi/2, 3*pi/4} bases
//
// Type signature: (C(4))^n -> C(2)^m
// Where input is n entangled pairs, output is m key bits.
//
// Security: Verified by CHSH inequality S > 2 (classical bound)
// Quantum maximum: S = 2*sqrt(2) ~ 2.828
// Key rate: r = 1 - h((1 + sqrt((S/2)^2 - 1))/2)
type E91Protocol struct {
	// NumPairs is the number of entangled pairs to distribute.
	NumPairs int

	// CHSHThreshold is the minimum CHSH value required (must be > 2).
	CHSHThreshold *big.Rat
}

// NewE91 creates a new E91 protocol with the given number of pairs.
func NewE91(numPairs int) *E91Protocol {
	// Default CHSH threshold slightly above classical bound
	return &E91Protocol{
		NumPairs:      numPairs,
		CHSHThreshold: big.NewRat(21, 10), // 2.1
	}
}

// NewE91WithThreshold creates an E91 protocol with a custom CHSH threshold.
func NewE91WithThreshold(numPairs int, threshold *big.Rat) *E91Protocol {
	return &E91Protocol{
		NumPairs:      numPairs,
		CHSHThreshold: threshold,
	}
}

// Protocol returns the complete protocol specification.
func (p *E91Protocol) Protocol() *protocol.Protocol {
	return &protocol.Protocol{
		Name:        "E91",
		Description: "Ekert 1991 entanglement-based QKD protocol using CHSH inequality for security verification",
		Parties: []protocol.Party{
			{
				Name: "Alice",
				Role: protocol.RoleSender,
				Capabilities: []protocol.Capability{
					protocol.CapMeasure,
					protocol.CapClassicalCommunicate,
				},
			},
			{
				Name: "Bob",
				Role: protocol.RoleReceiver,
				Capabilities: []protocol.Capability{
					protocol.CapMeasure,
					protocol.CapClassicalCommunicate,
				},
			},
			{
				Name: "Source",
				Role: protocol.RoleArbiter, // Trusted entanglement source
				Capabilities: []protocol.Capability{
					protocol.CapPrepare,
					protocol.CapQuantumCommunicate,
				},
			},
		},
		Resources: []protocol.Resource{
			{
				Type:    protocol.ResourceEntangledPair,
				Parties: []string{"Alice", "Bob"},
				State: protocol.StateSpec{
					Dimension:   4, // 2-qubit system
					IsClassical: false,
					State:       RhoBellPhiPlus(), // |Phi+><Phi+|
				},
			},
			{
				Type:    protocol.ResourceAuthenticatedChannel,
				Parties: []string{"Alice", "Bob"},
				State: protocol.StateSpec{
					IsClassical: true,
				},
			},
		},
		Rounds: []protocol.Round{
			{
				Number:      1,
				Description: "Entanglement distribution: Source creates and distributes Bell pairs",
				Actions: []protocol.Action{
					{Actor: "Source", Type: protocol.ActionPrepare, Target: "bell-pair"},
					{Actor: "Source", Type: protocol.ActionSend, Target: "Alice"},
					{Actor: "Source", Type: protocol.ActionSend, Target: "Bob"},
				},
			},
			{
				Number:      2,
				Description: "Measurement: Both parties measure in randomly chosen bases",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionMeasure, Target: "qubit"},
					{Actor: "Bob", Type: protocol.ActionMeasure, Target: "qubit"},
				},
			},
			{
				Number:      3,
				Description: "Basis announcement and CHSH test",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "bases"},
					{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "bases"},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "chsh-correlator"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "chsh-correlator"},
				},
			},
			{
				Number:      4,
				Description: "Key extraction from matching bases",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "extract-key"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "extract-key"},
				},
			},
			{
				Number:      5,
				Description: "Error correction and privacy amplification",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "error-correct"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "error-correct"},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "privacy-amplify"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "privacy-amplify"},
				},
			},
		},
		Goal: protocol.KeyAgreement{
			KeyLength:    p.estimatedKeyLength(),
			ErrorRate:    &runtime.Rat{V: p.maxErrorRate()},
			SecrecyBound: &runtime.Rat{V: p.secrecyBound()},
		},
		Assumptions: []protocol.Assumption{
			{
				Name:        "No-Signaling",
				Description: "Measurement choices are space-like separated",
				Type:        protocol.AssumptionNoSideChannel,
			},
			{
				Name:        "Authenticated Classical Channel",
				Description: "Classical communication is authenticated",
				Type:        protocol.AssumptionAuthenticatedClassical,
			},
		},
		TypeSig: protocol.TypeSignature{
			Domain:   p.domainObject(),
			Codomain: p.codomainObject(),
		},
	}
}

// Synthesize generates the protocol circuit and stores it.
func (p *E91Protocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the E91 circuit

	// Create Bell pair preparation circuit
	bellPrepCircuit := p.synthesizeBellPrep(store)

	// Create measurement circuits for Alice and Bob
	aliceMeasureCircuit := p.synthesizeAliceMeasure(store)
	bobMeasureCircuit := p.synthesizeBobMeasure(store)

	// Create CHSH test circuit
	chshCircuit := p.synthesizeCHSHTest(store)

	// Create key extraction circuit
	keyExtractCircuit := p.synthesizeKeyExtract(store)

	// Compose the full protocol
	children := make([][32]byte, 5)
	children[0] = bellPrepCircuit
	children[1] = aliceMeasureCircuit
	children[2] = bobMeasureCircuit
	children[3] = chshCircuit
	children[4] = keyExtractCircuit

	mainCircuit := runtime.Circuit{
		Domain:   p.domainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimCompose,
		Data:     p.protocolMetadata(),
		Children: children,
	}

	return store.Put(mainCircuit), nil
}

// synthesizeBellPrep creates the Bell pair preparation circuit.
func (p *E91Protocol) synthesizeBellPrep(store *runtime.Store) [32]byte {
	// Prepare |Phi+> = (|00> + |11>)/sqrt(2)
	// Circuit: H on first qubit, then CNOT
	bellState := BellPhiPlus()

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{1}},    // trivial input (trigger)
		Codomain: runtime.Object{Blocks: []uint32{2, 2}}, // two qubits
		Prim:     runtime.PrimPrepare,
		Data: runtime.MakeSeq(
			StateToValue("phi-plus", bellState),
			runtime.MatrixToValue(RhoBellPhiPlus()),
		),
	}

	return store.Put(circuit)
}

// synthesizeAliceMeasure creates Alice's measurement circuit.
// Alice measures in three bases at angles 0, pi/4, pi/2.
func (p *E91Protocol) synthesizeAliceMeasure(store *runtime.Store) [32]byte {
	// Alice's measurement bases
	// a1 = 0 (Z-basis)
	// a2 = pi/4 (diagonal)
	// a3 = pi/2 (X-basis)

	aliceBases := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("a1-0"),
			runtime.MakeSeq(
				runtime.MatrixToValue(Rho0()),
				runtime.MatrixToValue(Rho1()),
			)),
		runtime.MakeTag(runtime.MakeText("a2-pi4"),
			runtime.MakeSeq(
				runtime.MatrixToValue(rotatedProjector(0)),
				runtime.MatrixToValue(rotatedProjector(1)),
			)),
		runtime.MakeTag(runtime.MakeText("a3-pi2"),
			runtime.MakeSeq(
				runtime.MatrixToValue(RhoPlus()),
				runtime.MatrixToValue(RhoMinus()),
			)),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 3}}, // qubit x basis-choice
		Codomain: runtime.Object{Blocks: []uint32{2}},    // classical bit
		Prim:     runtime.PrimInstrument,
		Data:     aliceBases,
	}

	return store.Put(circuit)
}

// synthesizeBobMeasure creates Bob's measurement circuit.
// Bob measures in three bases at angles pi/4, pi/2, 3*pi/4.
func (p *E91Protocol) synthesizeBobMeasure(store *runtime.Store) [32]byte {
	// Bob's measurement bases
	// b1 = pi/4
	// b2 = pi/2 (X-basis)
	// b3 = 3*pi/4

	bobBases := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("b1-pi4"),
			runtime.MakeSeq(
				runtime.MatrixToValue(rotatedProjector(0)),
				runtime.MatrixToValue(rotatedProjector(1)),
			)),
		runtime.MakeTag(runtime.MakeText("b2-pi2"),
			runtime.MakeSeq(
				runtime.MatrixToValue(RhoPlus()),
				runtime.MatrixToValue(RhoMinus()),
			)),
		runtime.MakeTag(runtime.MakeText("b3-3pi4"),
			runtime.MakeSeq(
				runtime.MatrixToValue(rotatedProjector3Pi4(0)),
				runtime.MatrixToValue(rotatedProjector3Pi4(1)),
			)),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 3}}, // qubit x basis-choice
		Codomain: runtime.Object{Blocks: []uint32{2}},    // classical bit
		Prim:     runtime.PrimInstrument,
		Data:     bobBases,
	}

	return store.Put(circuit)
}

// rotatedProjector returns a projector for angle pi/4.
// Uses rational approximation.
func rotatedProjector(outcome int) *runtime.Matrix {
	// |psi> = cos(pi/8)|0> + sin(pi/8)|1> for outcome 0
	// cos(pi/8) ~ 0.9239, sin(pi/8) ~ 0.3827
	// Using rational approximations
	cos := big.NewRat(9239, 10000)
	sin := big.NewRat(3827, 10000)

	ket := runtime.NewMatrix(2, 1)
	if outcome == 0 {
		ket.Set(0, 0, runtime.QI{Re: cos, Im: new(big.Rat)})
		ket.Set(1, 0, runtime.QI{Re: sin, Im: new(big.Rat)})
	} else {
		ket.Set(0, 0, runtime.QI{Re: new(big.Rat).Neg(sin), Im: new(big.Rat)})
		ket.Set(1, 0, runtime.QI{Re: cos, Im: new(big.Rat)})
	}

	return DensityMatrix(ket)
}

// rotatedProjector3Pi4 returns a projector for angle 3*pi/4.
func rotatedProjector3Pi4(outcome int) *runtime.Matrix {
	// |psi> = cos(3*pi/8)|0> + sin(3*pi/8)|1>
	// cos(3*pi/8) ~ 0.3827, sin(3*pi/8) ~ 0.9239
	cos := big.NewRat(3827, 10000)
	sin := big.NewRat(9239, 10000)

	ket := runtime.NewMatrix(2, 1)
	if outcome == 0 {
		ket.Set(0, 0, runtime.QI{Re: cos, Im: new(big.Rat)})
		ket.Set(1, 0, runtime.QI{Re: sin, Im: new(big.Rat)})
	} else {
		ket.Set(0, 0, runtime.QI{Re: new(big.Rat).Neg(sin), Im: new(big.Rat)})
		ket.Set(1, 0, runtime.QI{Re: cos, Im: new(big.Rat)})
	}

	return DensityMatrix(ket)
}

// synthesizeCHSHTest creates the CHSH test circuit.
func (p *E91Protocol) synthesizeCHSHTest(store *runtime.Store) [32]byte {
	// CHSH value: S = E(a1,b1) - E(a1,b3) + E(a3,b1) + E(a3,b3)
	// where E(a,b) = P(same) - P(different)
	//
	// For maximally entangled state with optimal angles:
	// S = 2*sqrt(2) ~ 2.828

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2, 3, 3}}, // a_outcome, b_outcome, a_basis, b_basis
		Codomain: runtime.Object{Blocks: []uint32{1}},          // CHSH pass/fail (scalar)
		Prim:     runtime.PrimAssert,
		Data: runtime.MakeTag(
			runtime.MakeText("chsh-test"),
			runtime.MakeSeq(
				runtime.MakeText("S > 2"),
				runtime.MakeBigRat(p.CHSHThreshold),
				runtime.MakeBigRat(big.NewRat(2828, 1000)), // quantum maximum
			),
		),
	}

	return store.Put(circuit)
}

// synthesizeKeyExtract creates the key extraction circuit.
func (p *E91Protocol) synthesizeKeyExtract(store *runtime.Store) [32]byte {
	// Extract key from rounds where Alice used a3 and Bob used b1 (matching pi/2 basis)
	// or where angles have maximal correlation

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2, 3, 3}}, // outcomes and bases
		Codomain: runtime.Object{Blocks: []uint32{2, 2}},       // keep_flag, key_bit
		Prim:     runtime.PrimBranch,
		Data:     runtime.MakeText("key-extract"),
	}

	return store.Put(circuit)
}

// KeyRate computes the key rate based on CHSH value.
// r = 1 - h((1 + sqrt((S/2)^2 - 1))/2)
func (p *E91Protocol) KeyRate(chshValue *big.Rat) *big.Rat {
	// Classical bound: S <= 2
	two := big.NewRat(2, 1)
	if chshValue.Cmp(two) <= 0 {
		return big.NewRat(0, 1) // No key if CHSH <= 2
	}

	// For S > 2, there's a positive key rate
	// Quantum maximum S = 2*sqrt(2) gives maximum rate

	// Simplified approximation: r ~ (S - 2) / 2*sqrt(2)
	diff := new(big.Rat).Sub(chshValue, two)
	maxDiff := big.NewRat(828, 1000) // 2*sqrt(2) - 2 ~ 0.828

	rate := new(big.Rat).Quo(diff, maxDiff)
	if rate.Cmp(big.NewRat(1, 1)) > 0 {
		rate = big.NewRat(1, 1)
	}
	return rate
}

// CHSHClassicalBound returns the classical bound for CHSH inequality.
func (p *E91Protocol) CHSHClassicalBound() *big.Rat {
	return big.NewRat(2, 1)
}

// CHSHQuantumMaximum returns the quantum maximum for CHSH inequality.
// S_max = 2*sqrt(2) ~ 2.828
func (p *E91Protocol) CHSHQuantumMaximum() *big.Rat {
	return big.NewRat(2828, 1000) // rational approximation
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *E91Protocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("e91-protocol"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(p.NumPairs)),
			runtime.MakeBigRat(p.CHSHThreshold),
			p.Protocol().ToValue(),
		),
	)
}

// E91FromValue deserializes an E91Protocol from a runtime.Value.
func E91FromValue(v runtime.Value) (*E91Protocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "e91-protocol" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 2 {
		return nil, false
	}

	numPairs, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return nil, false
	}
	threshold, ok := seq.Items[1].(runtime.Rat)
	if !ok {
		return nil, false
	}

	return &E91Protocol{
		NumPairs:      int(numPairs.V.Int64()),
		CHSHThreshold: new(big.Rat).Set(threshold.V),
	}, true
}

// Helper methods

func (p *E91Protocol) domainObject() runtime.Object {
	// n entangled pairs, each is a 4-dimensional system
	blocks := make([]uint32, p.NumPairs)
	for i := 0; i < p.NumPairs; i++ {
		blocks[i] = 4 // 2x2 = 4 dimensional Hilbert space per pair
	}
	return runtime.Object{Blocks: blocks}
}

func (p *E91Protocol) codomainObject() runtime.Object {
	// Output key bits
	keyLen := p.estimatedKeyLength()
	blocks := make([]uint32, keyLen)
	for i := 0; i < keyLen; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *E91Protocol) estimatedKeyLength() int {
	// Roughly: 1/9 of pairs have matching bases for key
	// Then apply key rate
	return p.NumPairs / 9
}

func (p *E91Protocol) maxErrorRate() *big.Rat {
	// Error rate derived from CHSH threshold
	// For S close to 2*sqrt(2), error rate is low
	return big.NewRat(7, 100) // ~7% for near-optimal CHSH
}

func (p *E91Protocol) secrecyBound() *big.Rat {
	return big.NewRat(1, 1000000)
}

func (p *E91Protocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("E91"),
			runtime.MakeText("Ekert 1991"),
			runtime.MakeInt(int64(p.NumPairs)),
			runtime.MakeBigRat(p.CHSHThreshold),
			runtime.MakeBigRat(p.CHSHClassicalBound()),
			runtime.MakeBigRat(p.CHSHQuantumMaximum()),
		),
	)
}

// E91MeasurementAngles returns the measurement angles used in E91.
// Alice: {0, pi/4, pi/2}, Bob: {pi/4, pi/2, 3*pi/4}
func E91MeasurementAngles() ([]string, []string) {
	alice := []string{"0", "pi/4", "pi/2"}
	bob := []string{"pi/4", "pi/2", "3*pi/4"}
	return alice, bob
}

// CHSHCorrelator computes the CHSH correlator E(a,b) for given measurement settings.
// E(a,b) = <A_a * B_b> = Tr(rho * (A_a tensor B_b))
// For |Phi+> state with optimal angles, returns values that maximize S.
func CHSHCorrelator(aliceBasis, bobBasis int) *big.Rat {
	// Pre-computed correlators for |Phi+> state with E91 angles
	// E(a1,b1) = cos(pi/4) = 1/sqrt(2) ~ 0.707
	// E(a1,b3) = cos(3*pi/4) = -1/sqrt(2) ~ -0.707
	// E(a3,b1) = cos(pi/4) = 1/sqrt(2) ~ 0.707
	// E(a3,b3) = cos(pi/4) = 1/sqrt(2) ~ 0.707

	correlators := map[[2]int]*big.Rat{
		{0, 0}: Sqrt2Inv,                         // E(a1,b1)
		{0, 2}: new(big.Rat).Neg(Sqrt2Inv),       // E(a1,b3)
		{2, 0}: Sqrt2Inv,                         // E(a3,b1)
		{2, 2}: Sqrt2Inv,                         // E(a3,b3)
		{1, 1}: big.NewRat(1, 1),                 // E(a2,b2) = 1 (used for key)
		{0, 1}: new(big.Rat).Set(Sqrt2Inv),       // Others
		{1, 0}: new(big.Rat).Set(Sqrt2Inv),       // for completeness
		{1, 2}: big.NewRat(0, 1),                 // orthogonal
		{2, 1}: big.NewRat(1, 1),                 // E(a3,b2) = 1 (key basis)
	}

	key := [2]int{aliceBasis, bobBasis}
	if c, ok := correlators[key]; ok {
		return c
	}
	return big.NewRat(0, 1)
}
