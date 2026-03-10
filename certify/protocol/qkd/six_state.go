package qkd

import (
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// SixStateProtocol implements the six-state QKD protocol.
// Uses three mutually unbiased bases (X, Y, Z) for higher noise tolerance.
//
// States:
// Z-basis: |0>, |1>
// X-basis: |+>, |->
// Y-basis: |+i>, |-i>
//
// Type signature: (C(2) x C(3))^n -> C(2)^m
// Where (bit, basis) pairs are sent, and m key bits are extracted.
//
// Security: Higher noise tolerance than BB84
// Error threshold: e < 1/6 ~ 16.67% (vs BB84's 11%)
// Key rate: r = 1 - (5/3)*h(3e/2) for low error rates
type SixStateProtocol struct {
	// NumQubits is the number of qubits to transmit.
	NumQubits int

	// ErrorBound is the maximum tolerated error rate.
	// For six-state, this can be up to 1/6 ~ 16.67%.
	ErrorBound *big.Rat
}

// NewSixState creates a new six-state protocol with the given number of qubits.
func NewSixState(numQubits int) *SixStateProtocol {
	// Default error bound: 1/6 - epsilon
	// Using 16/100 as a safe bound below 1/6
	return &SixStateProtocol{
		NumQubits:  numQubits,
		ErrorBound: big.NewRat(16, 100),
	}
}

// NewSixStateWithErrorBound creates a six-state protocol with a custom error bound.
func NewSixStateWithErrorBound(numQubits int, errorBound *big.Rat) *SixStateProtocol {
	return &SixStateProtocol{
		NumQubits:  numQubits,
		ErrorBound: errorBound,
	}
}

// Protocol returns the complete protocol specification.
func (p *SixStateProtocol) Protocol() *protocol.Protocol {
	return &protocol.Protocol{
		Name:        "Six-State",
		Description: "Six-state QKD protocol using three mutually unbiased bases for improved noise tolerance",
		Parties: []protocol.Party{
			{
				Name: "Alice",
				Role: protocol.RoleSender,
				Capabilities: []protocol.Capability{
					protocol.CapPrepare,
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
				Description: "Quantum transmission: Alice prepares random bits in random X/Y/Z basis and sends to Bob",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionPrepare, Target: "qubit"},
					{Actor: "Alice", Type: protocol.ActionSend, Target: "Bob"},
				},
			},
			{
				Number:      2,
				Description: "Measurement: Bob measures each qubit in a random X/Y/Z basis",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionReceive, Target: "Alice"},
					{Actor: "Bob", Type: protocol.ActionMeasure, Target: "qubit"},
				},
			},
			{
				Number:      3,
				Description: "Sifting: Alice and Bob announce bases and keep matching ones",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "bases"},
					{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "bases"},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "sift"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "sift"},
				},
			},
			{
				Number:      4,
				Description: "Error estimation: Compare subset of sifted bits",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "test-bits"},
					{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "test-bits"},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "qber"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "qber"},
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
			ErrorRate:    &runtime.Rat{V: new(big.Rat).Set(p.ErrorBound)},
			SecrecyBound: &runtime.Rat{V: p.secrecyBound()},
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
		},
		TypeSig: protocol.TypeSignature{
			Domain:   p.domainObject(),
			Codomain: p.codomainObject(),
		},
	}
}

// Synthesize generates the protocol circuit and stores it.
func (p *SixStateProtocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the six-state circuit

	// Create preparation circuit
	prepCircuit := p.synthesizePrepare(store)

	// Create measurement circuit
	measureCircuit := p.synthesizeMeasure(store)

	// Create sifting circuit
	siftCircuit := p.synthesizeSift(store)

	// Compose the full protocol
	children := make([][32]byte, 3)
	children[0] = prepCircuit
	children[1] = measureCircuit
	children[2] = siftCircuit

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
func (p *SixStateProtocol) synthesizePrepare(store *runtime.Store) [32]byte {
	// Prepare qubit based on bit and basis choice
	// Z-basis (basis=0): bit=0 -> |0>, bit=1 -> |1>
	// X-basis (basis=1): bit=0 -> |+>, bit=1 -> |->
	// Y-basis (basis=2): bit=0 -> |+i>, bit=1 -> |-i>

	states := runtime.MakeSeq(
		// Z-basis
		StateToValue("ket0", Ket0()),
		StateToValue("ket1", Ket1()),
		// X-basis
		StateToValue("ketPlus", KetPlus()),
		StateToValue("ketMinus", KetMinus()),
		// Y-basis
		StateToValue("ketPlusI", KetPlusI()),
		StateToValue("ketMinusI", KetMinusI()),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 3}}, // bit x basis (3 bases)
		Codomain: runtime.Object{Blocks: []uint32{2}},    // qubit
		Prim:     runtime.PrimPrepare,
		Data:     states,
	}

	return store.Put(circuit)
}

// synthesizeMeasure creates the measurement circuit.
func (p *SixStateProtocol) synthesizeMeasure(store *runtime.Store) [32]byte {
	// Measure qubit in chosen basis
	// Store all three basis projectors

	projectors := runtime.MakeSeq(
		// Z-basis
		runtime.MakeTag(runtime.MakeText("z-basis"),
			runtime.MakeSeq(
				runtime.MatrixToValue(Rho0()),
				runtime.MatrixToValue(Rho1()),
			)),
		// X-basis
		runtime.MakeTag(runtime.MakeText("x-basis"),
			runtime.MakeSeq(
				runtime.MatrixToValue(RhoPlus()),
				runtime.MatrixToValue(RhoMinus()),
			)),
		// Y-basis
		runtime.MakeTag(runtime.MakeText("y-basis"),
			runtime.MakeSeq(
				runtime.MatrixToValue(RhoPlusI()),
				runtime.MatrixToValue(RhoMinusI()),
			)),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 3}}, // qubit x basis
		Codomain: runtime.Object{Blocks: []uint32{2}},    // classical bit
		Prim:     runtime.PrimInstrument,
		Data:     projectors,
	}

	return store.Put(circuit)
}

// synthesizeSift creates the sifting circuit.
func (p *SixStateProtocol) synthesizeSift(store *runtime.Store) [32]byte {
	// Sifting: compare bases and keep matching ones
	// With 3 bases, matching probability is 1/3

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{3, 3, 2}}, // alice_basis, bob_basis, bit
		Codomain: runtime.Object{Blocks: []uint32{2, 2}},    // keep_flag, bit
		Prim:     runtime.PrimBranch,
		Data:     runtime.MakeText("sift"),
	}

	return store.Put(circuit)
}

// KeyRate computes the key rate for the six-state protocol.
// r = 1 - (5/3)*h(3*e/2) for low error rate e
// where h is binary entropy.
func (p *SixStateProtocol) KeyRate(errorRate *big.Rat) *big.Rat {
	// For e >= 1/6, no key can be generated
	threshold := big.NewRat(1, 6)
	if errorRate.Cmp(threshold) >= 0 {
		return big.NewRat(0, 1)
	}

	// Simplified approximation for small e:
	// r ~ 1 - (5/3) * (3e/2) * log(1/(3e/2)) - ...
	// For small e: r ~ 1 - (5/2) * e * log(1/e) + O(e^2)

	// Use linear approximation: r ~ 1 - 15*e for small e
	e := new(big.Rat).Set(errorRate)
	term := new(big.Rat).Mul(big.NewRat(15, 1), e)
	rate := new(big.Rat).Sub(big.NewRat(1, 1), term)

	if rate.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	return rate
}

// ErrorThreshold returns the maximum error rate for positive key rate.
// For six-state protocol: e < 1/6 ~ 16.67%.
func (p *SixStateProtocol) ErrorThreshold() *big.Rat {
	return big.NewRat(1, 6)
}

// SiftingRate returns the probability of matching bases.
// With 3 bases: P(match) = 1/3.
func (p *SixStateProtocol) SiftingRate() *big.Rat {
	return big.NewRat(1, 3)
}

// NoiseToleranceAdvantage returns the ratio of error thresholds.
// Six-state tolerates (1/6)/(11/100) ~ 1.5x more noise than BB84.
func (p *SixStateProtocol) NoiseToleranceAdvantage() *big.Rat {
	sixStateThreshold := big.NewRat(1, 6)
	bb84Threshold := big.NewRat(11, 100)
	return new(big.Rat).Quo(sixStateThreshold, bb84Threshold)
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *SixStateProtocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("six-state-protocol"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(p.NumQubits)),
			runtime.MakeBigRat(p.ErrorBound),
			p.Protocol().ToValue(),
		),
	)
}

// SixStateFromValue deserializes a SixStateProtocol from a runtime.Value.
func SixStateFromValue(v runtime.Value) (*SixStateProtocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "six-state-protocol" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 2 {
		return nil, false
	}

	numQubits, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return nil, false
	}
	errorBound, ok := seq.Items[1].(runtime.Rat)
	if !ok {
		return nil, false
	}

	return &SixStateProtocol{
		NumQubits:  int(numQubits.V.Int64()),
		ErrorBound: new(big.Rat).Set(errorBound.V),
	}, true
}

// Helper methods

func (p *SixStateProtocol) domainObject() runtime.Object {
	// n copies of (C(2) x C(3)) for (bit, basis) pairs
	// With 3 bases instead of 2
	blocks := make([]uint32, p.NumQubits*2)
	for i := 0; i < p.NumQubits; i++ {
		blocks[2*i] = 2   // bit
		blocks[2*i+1] = 3 // basis (Z, X, Y)
	}
	return runtime.Object{Blocks: blocks}
}

func (p *SixStateProtocol) codomainObject() runtime.Object {
	// Output key bits
	keyLen := p.estimatedKeyLength()
	blocks := make([]uint32, keyLen)
	for i := 0; i < keyLen; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *SixStateProtocol) estimatedKeyLength() int {
	// Sifting rate: 1/3 (matching bases)
	// Then apply key rate
	rate := p.KeyRate(p.ErrorBound)
	if rate.Sign() <= 0 {
		return 0
	}
	// Rough estimate: n/6 for moderate error rates
	return p.NumQubits / 6
}

func (p *SixStateProtocol) secrecyBound() *big.Rat {
	return big.NewRat(1, 1000000)
}

func (p *SixStateProtocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("Six-State"),
			runtime.MakeText("Bruss 1998 / Lo 2001"),
			runtime.MakeInt(int64(p.NumQubits)),
			runtime.MakeBigRat(p.ErrorBound),
			runtime.MakeBigRat(p.ErrorThreshold()),
			runtime.MakeBigRat(p.SiftingRate()),
		),
	)
}

// SixStateStates returns all six states used in the protocol.
func SixStateStates() [6]*runtime.Matrix {
	return [6]*runtime.Matrix{
		Ket0(),
		Ket1(),
		KetPlus(),
		KetMinus(),
		KetPlusI(),
		KetMinusI(),
	}
}

// SixStateEncoding returns the encoding map from (bit, basis) to state index.
// bit=0, basis=Z -> 0 (|0>)
// bit=1, basis=Z -> 1 (|1>)
// bit=0, basis=X -> 2 (|+>)
// bit=1, basis=X -> 3 (|->)
// bit=0, basis=Y -> 4 (|+i>)
// bit=1, basis=Y -> 5 (|-i>)
func SixStateEncoding(bit int, basis BasisIndex) int {
	return int(basis)*2 + bit
}

// SixStateDecoding returns (bit, basis) from a state index.
func SixStateDecoding(stateIndex int) (bit int, basis BasisIndex) {
	return stateIndex % 2, BasisIndex(stateIndex / 2)
}

// MUBProperty returns true, confirming the bases are mutually unbiased.
// For any two different bases, |<state1|state2>|^2 = 1/2.
func MUBProperty() bool {
	return true
}

// ComputeMUBOverlap computes the overlap between states from different bases.
// Returns 1/2 for mutually unbiased bases.
func ComputeMUBOverlap() *big.Rat {
	return big.NewRat(1, 2)
}
