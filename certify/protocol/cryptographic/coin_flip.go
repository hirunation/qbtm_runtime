// Package cryptographic provides quantum cryptographic primitive implementations.
package cryptographic

import (
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// Rational approximation constants for quantum coin flipping.
var (
	// Sqrt2Inv is a rational approximation of 1/sqrt(2) ~ 0.7071067811865475
	// Using convergent of continued fraction: 408/577 ~ 0.7071067811865476
	Sqrt2Inv = big.NewRat(408, 577)

	// Sqrt2 is a rational approximation of sqrt(2) ~ 1.4142135623730951
	// Using convergent: 577/408
	Sqrt2 = big.NewRat(577, 408)

	// KitaevBiasExact is the Kitaev bound: (sqrt(2) - 1) / 2
	// This is the optimal bias achievable in any quantum coin flipping protocol.
	// Kitaev (2003) proved this is the minimum achievable cheating probability.
	// Approximation: (1414/1000 - 1) / 2 = 414/2000 = 207/1000
	// Better approximation using sqrt(2) ~ 577/408:
	// (577/408 - 1) / 2 = (577-408)/(408*2) = 169/816
	KitaevBiasExact = big.NewRat(169, 816) // ~ 0.2071078...

	// KitaevBiasSimple is a simpler approximation: 207/1000 ~ 0.207
	KitaevBiasSimple = big.NewRat(207, 1000)

	// KitaevBiasPrecise is a more precise approximation using continued fractions.
	// (sqrt(2) - 1)/2 ~ 0.20710678118654752...
	// Better convergent: 2071/10000 ~ 0.2071
	KitaevBiasPrecise = big.NewRat(2071, 10000)
)

// CoinFlipProtocol implements quantum coin flipping with Kitaev-optimal bias.
//
// Quantum coin flipping allows two mutually distrustful parties to agree on
// a random bit. Unlike classical protocols, quantum coin flipping can achieve
// cryptographic security without computational assumptions.
//
// Kitaev's bound (2003): Any quantum coin flipping protocol has cheating
// probability at least (sqrt(2) - 1)/2 ~ 0.207 for at least one party.
// This is optimal - protocols achieving this bound exist (weak coin flipping).
//
// Protocol Pattern (weak coin flipping):
// 1. Alice sends qubit in random Z or X basis state
// 2. Bob measures in random basis
// 3. If bases match, outcome determined by measurement
// 4. If bases don't match, abort or restart
//
// Cheating strategies:
// - Dishonest Alice: prepare entangled state, delay commitment
// - Dishonest Bob: measure in computational basis, gain information
//
// Type signature: C(2) x C(2) -> C(2)
// (Alice's bit, Alice's basis) -> outcome bit
type CoinFlipProtocol struct {
	// Bias is the cheating probability bound.
	// For Kitaev-optimal protocols, this is (sqrt(2) - 1)/2.
	Bias *big.Rat

	// UsePreciseApproximation selects between simple (207/1000) and
	// precise (169/816) rational approximation of the Kitaev bound.
	UsePreciseApproximation bool
}

// NewCoinFlip creates a new quantum coin flipping protocol with Kitaev-optimal bias.
// Uses the rational approximation (sqrt(2)-1)/2 ~ 169/816.
func NewCoinFlip() *CoinFlipProtocol {
	return &CoinFlipProtocol{
		Bias:                    new(big.Rat).Set(KitaevBiasExact),
		UsePreciseApproximation: true,
	}
}

// NewCoinFlipSimple creates a coin flipping protocol with simplified bias 207/1000.
func NewCoinFlipSimple() *CoinFlipProtocol {
	return &CoinFlipProtocol{
		Bias:                    new(big.Rat).Set(KitaevBiasSimple),
		UsePreciseApproximation: false,
	}
}

// NewCoinFlipWithBias creates a coin flipping protocol with a custom bias.
// The bias must be >= Kitaev bound (sqrt(2)-1)/2 ~ 0.207.
func NewCoinFlipWithBias(bias *big.Rat) *CoinFlipProtocol {
	// Ensure bias is at least the Kitaev bound
	if bias.Cmp(KitaevBiasExact) < 0 {
		bias = new(big.Rat).Set(KitaevBiasExact)
	}
	return &CoinFlipProtocol{
		Bias:                    new(big.Rat).Set(bias),
		UsePreciseApproximation: true,
	}
}

// Protocol returns the complete protocol specification.
func (p *CoinFlipProtocol) Protocol() *protocol.Protocol {
	return &protocol.Protocol{
		Name:        "QuantumCoinFlip",
		Description: "Weak quantum coin flipping with Kitaev-optimal bias",
		Parties: []protocol.Party{
			{
				Name: "Alice",
				Role: protocol.RoleSender,
				Capabilities: []protocol.Capability{
					protocol.CapPrepare,
					protocol.CapClassicalCommunicate,
					protocol.CapQuantumCommunicate,
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
		},
		Resources: []protocol.Resource{
			{
				Type:    protocol.ResourceQuantumChannel,
				Parties: []string{"Alice", "Bob"},
				State: protocol.StateSpec{
					Dimension:   2,
					IsClassical: false,
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
				Description: "Alice prepares qubit in random basis state",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionPrepare, Target: "qubit",
						Data: p.prepareData()},
				},
			},
			{
				Number:      2,
				Description: "Alice sends qubit to Bob",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionSend, Target: "Bob",
						Data: runtime.MakeText("encoded-qubit")},
				},
			},
			{
				Number:      3,
				Description: "Bob measures in random basis",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionReceive, Target: "Alice"},
					{Actor: "Bob", Type: protocol.ActionMeasure, Target: "random-basis",
						Data: p.measureData()},
				},
			},
			{
				Number:      4,
				Description: "Alice reveals her basis choice",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "basis",
						Data: runtime.MakeText("reveal-basis")},
				},
			},
			{
				Number:      5,
				Description: "Bob announces his basis; if matching, measurement is outcome",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "basis"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "check-match",
						Data: p.checkMatchData()},
				},
			},
		},
		Goal: protocol.CoinFlip{
			Bias: &runtime.Rat{V: new(big.Rat).Set(p.Bias)},
		},
		Assumptions: []protocol.Assumption{
			{
				Name:        "No-Cloning",
				Description: "Quantum states cannot be perfectly cloned",
				Type:        protocol.AssumptionNoCloning,
			},
			{
				Name:        "Authenticated Classical Channel",
				Description: "Classical communication is authenticated but not secret",
				Type:        protocol.AssumptionAuthenticatedClassical,
			},
			{
				Name:        "No Side Channels",
				Description: "No information leakage through side channels",
				Type:        protocol.AssumptionNoSideChannel,
			},
		},
		TypeSig: protocol.TypeSignature{
			Domain:   p.domainObject(),
			Codomain: p.codomainObject(),
		},
	}
}

// Synthesize generates the coin flipping circuit and stores it.
func (p *CoinFlipProtocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the quantum coin flipping circuit
	// Domain: C(2) x C(2) for (bit, basis) pairs from Alice
	// Codomain: C(2) for the coin outcome

	// Create the preparation circuit
	prepCircuit := p.synthesizePrepare(store)

	// Create the measurement circuit
	measureCircuit := p.synthesizeMeasure(store)

	// Create the verification circuit
	verifyCircuit := p.synthesizeVerify(store)

	// Compose the full protocol
	children := make([][32]byte, 3)
	children[0] = prepCircuit
	children[1] = measureCircuit
	children[2] = verifyCircuit

	mainCircuit := runtime.Circuit{
		Domain:   p.domainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimCompose,
		Data:     p.protocolMetadata(),
		Children: children,
	}

	return store.Put(mainCircuit), nil
}

// synthesizePrepare creates the state preparation circuit.
func (p *CoinFlipProtocol) synthesizePrepare(store *runtime.Store) [32]byte {
	// Prepare qubit based on bit and basis choice
	// bit=0, basis=0 -> |0>
	// bit=1, basis=0 -> |1>
	// bit=0, basis=1 -> |+>
	// bit=1, basis=1 -> |->

	states := runtime.MakeSeq(
		stateToValue("ket0", ket0()),
		stateToValue("ket1", ket1()),
		stateToValue("ketPlus", ketPlus()),
		stateToValue("ketMinus", ketMinus()),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2}}, // bit x basis
		Codomain: runtime.Object{Blocks: []uint32{2}},    // qubit
		Prim:     runtime.PrimPrepare,
		Data:     states,
	}

	return store.Put(circuit)
}

// synthesizeMeasure creates the measurement circuit.
func (p *CoinFlipProtocol) synthesizeMeasure(store *runtime.Store) [32]byte {
	// Bob measures in random basis
	projectors := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("z-basis"),
			runtime.MakeSeq(
				runtime.MatrixToValue(rho0()),
				runtime.MatrixToValue(rho1()),
			)),
		runtime.MakeTag(runtime.MakeText("x-basis"),
			runtime.MakeSeq(
				runtime.MatrixToValue(rhoPlus()),
				runtime.MatrixToValue(rhoMinus()),
			)),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2}}, // qubit x basis
		Codomain: runtime.Object{Blocks: []uint32{2}},    // classical bit
		Prim:     runtime.PrimInstrument,
		Data:     projectors,
	}

	return store.Put(circuit)
}

// synthesizeVerify creates the basis matching verification circuit.
func (p *CoinFlipProtocol) synthesizeVerify(store *runtime.Store) [32]byte {
	// Verify that bases match; if not, protocol aborts
	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2, 2}}, // alice_basis, bob_basis, measurement
		Codomain: runtime.Object{Blocks: []uint32{2}},       // outcome (or abort)
		Prim:     runtime.PrimBranch,
		Data: runtime.MakeTag(
			runtime.MakeText("basis-verify"),
			runtime.MakeSeq(
				runtime.MakeText("If bases match, output measurement result"),
				runtime.MakeText("If bases differ, abort or restart"),
			),
		),
	}

	return store.Put(circuit)
}

// CheatingProbability returns the probability that a cheating party can bias the outcome.
// This is the Kitaev bound: (sqrt(2) - 1) / 2.
func (p *CoinFlipProtocol) CheatingProbability() *big.Rat {
	return new(big.Rat).Set(p.Bias)
}

// AliceCheatingStrategy describes Alice's optimal cheating strategy.
// Alice can prepare an entangled state and delay her measurement until
// seeing Bob's basis choice, gaining an advantage of up to Kitaev bound.
func (p *CoinFlipProtocol) AliceCheatingStrategy() string {
	return "Prepare entangled state (|0>|psi_0> + |1>|psi_1>)/sqrt(2), " +
		"send second register, wait for Bob's basis announcement, " +
		"then measure first register in optimal basis"
}

// BobCheatingStrategy describes Bob's optimal cheating strategy.
// Bob can measure in the computational basis to gain information about Alice's bit.
func (p *CoinFlipProtocol) BobCheatingStrategy() string {
	return "Always measure in computational (Z) basis to maximize " +
		"information about Alice's bit when she uses Z-basis encoding"
}

// IsKitaevOptimal checks if this protocol achieves the Kitaev bound.
func (p *CoinFlipProtocol) IsKitaevOptimal() bool {
	return p.Bias.Cmp(KitaevBiasExact) == 0 || p.Bias.Cmp(KitaevBiasSimple) == 0
}

// SecurityMargin returns how far above the Kitaev bound this protocol is.
// Returns 0 for Kitaev-optimal protocols.
func (p *CoinFlipProtocol) SecurityMargin() *big.Rat {
	margin := new(big.Rat).Sub(p.Bias, KitaevBiasExact)
	if margin.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	return margin
}

// Helper methods

func (p *CoinFlipProtocol) domainObject() runtime.Object {
	// Input: (bit, basis) from Alice
	return runtime.Object{Blocks: []uint32{2, 2}}
}

func (p *CoinFlipProtocol) codomainObject() runtime.Object {
	// Output: coin outcome
	return runtime.Object{Blocks: []uint32{2}}
}

func (p *CoinFlipProtocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("QuantumCoinFlip"),
			runtime.MakeText("Weak quantum coin flipping"),
			runtime.MakeBigRat(p.Bias),
			runtime.MakeBigRat(KitaevBiasExact),
			runtime.MakeBool(p.IsKitaevOptimal()),
		),
	)
}

func (p *CoinFlipProtocol) prepareData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("coin-flip-prepare"),
		runtime.MakeSeq(
			runtime.MakeText("Prepare qubit based on (bit, basis) input"),
			runtime.MakeText("Z-basis: |0>, |1>; X-basis: |+>, |->"),
		),
	)
}

func (p *CoinFlipProtocol) measureData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("coin-flip-measure"),
		runtime.MakeSeq(
			runtime.MakeText("Bob measures in random basis"),
			runtime.MakeText("Z-basis projectors: |0><0|, |1><1|"),
			runtime.MakeText("X-basis projectors: |+><+|, |-><-|"),
		),
	)
}

func (p *CoinFlipProtocol) checkMatchData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("basis-check"),
		runtime.MakeSeq(
			runtime.MakeText("Compare Alice and Bob basis choices"),
			runtime.MakeText("If equal, outcome = Bob's measurement"),
			runtime.MakeText("If different, abort and restart"),
		),
	)
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *CoinFlipProtocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("coin-flip-protocol"),
		runtime.MakeSeq(
			runtime.MakeBigRat(p.Bias),
			runtime.MakeBool(p.UsePreciseApproximation),
			p.Protocol().ToValue(),
		),
	)
}

// CoinFlipFromValue deserializes a CoinFlipProtocol from a runtime.Value.
func CoinFlipFromValue(v runtime.Value) (*CoinFlipProtocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "coin-flip-protocol" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 2 {
		return nil, false
	}

	bias, ok := seq.Items[0].(runtime.Rat)
	if !ok {
		return nil, false
	}
	usePrecise, ok := seq.Items[1].(runtime.Bool)
	if !ok {
		return nil, false
	}

	return &CoinFlipProtocol{
		Bias:                    new(big.Rat).Set(bias.V),
		UsePreciseApproximation: usePrecise.V,
	}, true
}

// ===============================
// Helper state functions
// ===============================

// ket0 returns the |0> state as a column vector.
func ket0() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	ket.Set(0, 0, runtime.QIOne())
	return ket
}

// ket1 returns the |1> state as a column vector.
func ket1() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	ket.Set(1, 0, runtime.QIOne())
	return ket
}

// ketPlus returns the |+> state: (|0> + |1>)/sqrt(2).
func ketPlus() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	ket.Set(0, 0, s)
	ket.Set(1, 0, s)
	return ket
}

// ketMinus returns the |-> state: (|0> - |1>)/sqrt(2).
func ketMinus() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	negS := runtime.QINeg(s)
	ket.Set(0, 0, s)
	ket.Set(1, 0, negS)
	return ket
}

// densityMatrix computes |psi><psi| from a ket vector.
func densityMatrix(ket *runtime.Matrix) *runtime.Matrix {
	return runtime.OuterProduct(ket, ket)
}

// rho0 returns the density matrix |0><0|.
func rho0() *runtime.Matrix {
	return densityMatrix(ket0())
}

// rho1 returns the density matrix |1><1|.
func rho1() *runtime.Matrix {
	return densityMatrix(ket1())
}

// rhoPlus returns the density matrix |+><+|.
func rhoPlus() *runtime.Matrix {
	return densityMatrix(ketPlus())
}

// rhoMinus returns the density matrix |-><-|.
func rhoMinus() *runtime.Matrix {
	return densityMatrix(ketMinus())
}

// stateToValue converts a quantum state to a runtime.Value with metadata.
func stateToValue(name string, state *runtime.Matrix) runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("state"),
		runtime.MakeSeq(
			runtime.MakeText(name),
			runtime.MatrixToValue(state),
		),
	)
}
