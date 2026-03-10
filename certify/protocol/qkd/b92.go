package qkd

import (
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// B92Protocol implements the Bennett 1992 two-state QKD protocol.
// Uses only two non-orthogonal states instead of BB84's four states.
//
// States: |0> (bit 0) and |+> (bit 1)
// These states have overlap <0|+> = 1/sqrt(2)
//
// Type signature: C(2)^n -> C(2)^m
// Where n is raw bits sent and m is final key length.
//
// Security: Based on impossibility of distinguishing non-orthogonal states
// Key rate: r = 1/2 (theoretical maximum, accounting for inconclusive measurements)
// Vulnerability: Susceptible to unambiguous state discrimination (USD) attacks
type B92Protocol struct {
	// NumQubits is the number of qubits to transmit.
	NumQubits int

	// ErrorBound is the maximum tolerated error rate.
	ErrorBound *big.Rat
}

// NewB92 creates a new B92 protocol with the given number of qubits.
func NewB92(numQubits int) *B92Protocol {
	return &B92Protocol{
		NumQubits:  numQubits,
		ErrorBound: big.NewRat(1, 10), // 10% error threshold
	}
}

// NewB92WithErrorBound creates a B92 protocol with a custom error bound.
func NewB92WithErrorBound(numQubits int, errorBound *big.Rat) *B92Protocol {
	return &B92Protocol{
		NumQubits:  numQubits,
		ErrorBound: errorBound,
	}
}

// Protocol returns the complete protocol specification.
func (p *B92Protocol) Protocol() *protocol.Protocol {
	return &protocol.Protocol{
		Name:        "B92",
		Description: "Bennett 1992 two-state QKD protocol using non-orthogonal states |0> and |+>",
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
				Description: "Quantum transmission: Alice encodes random bits as |0> or |+>",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionPrepare, Target: "qubit"},
					{Actor: "Alice", Type: protocol.ActionSend, Target: "Bob"},
				},
			},
			{
				Number:      2,
				Description: "Measurement: Bob performs unambiguous state discrimination",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionReceive, Target: "Alice"},
					{Actor: "Bob", Type: protocol.ActionMeasure, Target: "qubit"},
				},
			},
			{
				Number:      3,
				Description: "Announcement: Bob announces which qubits gave conclusive results",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "conclusive-positions"},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "keep-bits"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "keep-bits"},
				},
			},
			{
				Number:      4,
				Description: "Error estimation on subset of conclusive bits",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "test-bits"},
					{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "test-bits"},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "error-rate"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "error-rate"},
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
				Description: "Classical communication is authenticated",
				Type:        protocol.AssumptionAuthenticatedClassical,
			},
			{
				Name:        "Single-Photon Source",
				Description: "Each pulse contains exactly one photon (vulnerable to USD otherwise)",
				Type:        protocol.AssumptionPerfectDevices,
			},
		},
		TypeSig: protocol.TypeSignature{
			Domain:   p.domainObject(),
			Codomain: p.codomainObject(),
		},
	}
}

// Synthesize generates the protocol circuit and stores it.
func (p *B92Protocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the B92 circuit

	// Create preparation circuit
	prepCircuit := p.synthesizePrepare(store)

	// Create USD measurement circuit
	measureCircuit := p.synthesizeUSDMeasure(store)

	// Create key extraction circuit
	keyExtractCircuit := p.synthesizeKeyExtract(store)

	// Compose the full protocol
	children := make([][32]byte, 3)
	children[0] = prepCircuit
	children[1] = measureCircuit
	children[2] = keyExtractCircuit

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
func (p *B92Protocol) synthesizePrepare(store *runtime.Store) [32]byte {
	// Prepare qubit based on bit choice
	// bit=0 -> |0>
	// bit=1 -> |+>

	states := runtime.MakeSeq(
		StateToValue("ket0", Ket0()),
		StateToValue("ketPlus", KetPlus()),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2}}, // bit
		Codomain: runtime.Object{Blocks: []uint32{2}}, // qubit
		Prim:     runtime.PrimPrepare,
		Data:     states,
	}

	return store.Put(circuit)
}

// synthesizeUSDMeasure creates the unambiguous state discrimination measurement.
// USD has three outcomes: 0 (conclusively |0>), 1 (conclusively |+>), ? (inconclusive)
func (p *B92Protocol) synthesizeUSDMeasure(store *runtime.Store) [32]byte {
	// USD POVM elements:
	// E_0 = (1 - 1/sqrt(2)) * |1><1|  -- conclusively identifies |0>
	// E_1 = (1 - 1/sqrt(2)) * |-><-|  -- conclusively identifies |+>
	// E_? = I - E_0 - E_1             -- inconclusive

	// Coefficient: 1 - 1/sqrt(2) ~ 0.2929
	coeff := new(big.Rat).Sub(big.NewRat(1, 1), Sqrt2Inv)

	// E_0: identifies that state was NOT |+>, so must be |0>
	// Constructed from |1><1| (orthogonal to |0>)
	e0 := runtime.MatScale(Rho1(), coeff)

	// E_1: identifies that state was NOT |0>, so must be |+>
	// Constructed from |-><-| (orthogonal to |+>)
	e1 := runtime.MatScale(RhoMinus(), coeff)

	// E_? = I - E_0 - E_1 (inconclusive)
	id := runtime.Identity(2)
	eInconc := runtime.MatSub(runtime.MatSub(id, e0), e1)

	povmElements := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("E0-conclusive-0"),
			runtime.MatrixToValue(e0)),
		runtime.MakeTag(runtime.MakeText("E1-conclusive-1"),
			runtime.MatrixToValue(e1)),
		runtime.MakeTag(runtime.MakeText("E?-inconclusive"),
			runtime.MatrixToValue(eInconc)),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2}}, // qubit
		Codomain: runtime.Object{Blocks: []uint32{3}}, // ternary outcome: 0, 1, ?
		Prim:     runtime.PrimInstrument,
		Data:     povmElements,
	}

	return store.Put(circuit)
}

// synthesizeKeyExtract creates the key extraction circuit.
func (p *B92Protocol) synthesizeKeyExtract(store *runtime.Store) [32]byte {
	// Extract key from conclusive measurements
	// If Bob got outcome 0, Alice sent |0> (bit 0)
	// If Bob got outcome 1, Alice sent |+> (bit 1)
	// Inconclusive results are discarded

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{3}},    // Bob's ternary outcome
		Codomain: runtime.Object{Blocks: []uint32{2, 2}}, // keep_flag, bit
		Prim:     runtime.PrimBranch,
		Data: runtime.MakeTag(
			runtime.MakeText("b92-key-extract"),
			runtime.MakeSeq(
				runtime.MakeText("outcome-0 -> (keep=1, bit=0)"),
				runtime.MakeText("outcome-1 -> (keep=1, bit=1)"),
				runtime.MakeText("outcome-? -> (keep=0, bit=?)"),
			),
		),
	}

	return store.Put(circuit)
}

// KeyRate returns the theoretical key rate for B92.
// In the ideal case, about 1/4 of qubits give conclusive results with correct bit values.
// Key rate: r = (1/2) * (1 - 2*h(e)) for small error rate e
func (p *B92Protocol) KeyRate(errorRate *big.Rat) *big.Rat {
	// B92 has lower key rate than BB84 due to inconclusive measurements
	// Approximately 50% of qubits are conclusive in ideal case

	// For high error rates, no key can be generated
	if errorRate.Cmp(p.ErrorBound) > 0 {
		return big.NewRat(0, 1)
	}

	// Simplified: r ~ 1/4 * (1 - 4*e) for small e
	four := big.NewRat(4, 1)
	fourE := new(big.Rat).Mul(four, errorRate)
	oneMinus := new(big.Rat).Sub(big.NewRat(1, 1), fourE)

	rate := new(big.Rat).Mul(big.NewRat(1, 4), oneMinus)
	if rate.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	return rate
}

// ErrorThreshold returns the maximum tolerable error rate.
// For B92, this is typically around 10% due to USD attacks.
func (p *B92Protocol) ErrorThreshold() *big.Rat {
	return big.NewRat(1, 10) // 10%
}

// ConclusiveRate returns the probability of a conclusive measurement.
// For B92 with |0> and |+> states: P(conclusive) = 1 - |<0|+>|^2 = 1 - 1/2 = 1/2
func (p *B92Protocol) ConclusiveRate() *big.Rat {
	return big.NewRat(1, 2)
}

// StateOverlap returns |<0|+>|^2 = 1/2.
func (p *B92Protocol) StateOverlap() *big.Rat {
	return big.NewRat(1, 2)
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *B92Protocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("b92-protocol"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(p.NumQubits)),
			runtime.MakeBigRat(p.ErrorBound),
			p.Protocol().ToValue(),
		),
	)
}

// B92FromValue deserializes a B92Protocol from a runtime.Value.
func B92FromValue(v runtime.Value) (*B92Protocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "b92-protocol" {
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

	return &B92Protocol{
		NumQubits:  int(numQubits.V.Int64()),
		ErrorBound: new(big.Rat).Set(errorBound.V),
	}, true
}

// Helper methods

func (p *B92Protocol) domainObject() runtime.Object {
	// n bits for encoding
	blocks := make([]uint32, p.NumQubits)
	for i := 0; i < p.NumQubits; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *B92Protocol) codomainObject() runtime.Object {
	// Output is approximately n/4 bits after USD filtering and sifting
	keyLen := p.estimatedKeyLength()
	blocks := make([]uint32, keyLen)
	for i := 0; i < keyLen; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *B92Protocol) estimatedKeyLength() int {
	// About 50% of measurements are conclusive
	// After error correction and privacy amplification: ~25% of original
	rate := p.KeyRate(p.ErrorBound)
	floatRate, _ := rate.Float64()
	return int(float64(p.NumQubits) * floatRate)
}

func (p *B92Protocol) secrecyBound() *big.Rat {
	return big.NewRat(1, 1000000)
}

func (p *B92Protocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("B92"),
			runtime.MakeText("Bennett 1992"),
			runtime.MakeInt(int64(p.NumQubits)),
			runtime.MakeBigRat(p.ErrorBound),
			runtime.MakeBigRat(p.ErrorThreshold()),
			runtime.MakeBigRat(p.ConclusiveRate()),
		),
	)
}

// B92States returns the two B92 states.
func B92States() [2]*runtime.Matrix {
	return [2]*runtime.Matrix{
		Ket0(),
		KetPlus(),
	}
}

// B92POVMElements returns the USD POVM elements for B92.
func B92POVMElements() [3]*runtime.Matrix {
	coeff := new(big.Rat).Sub(big.NewRat(1, 1), Sqrt2Inv)

	e0 := runtime.MatScale(Rho1(), coeff)
	e1 := runtime.MatScale(RhoMinus(), coeff)

	id := runtime.Identity(2)
	eInconc := runtime.MatSub(runtime.MatSub(id, e0), e1)

	return [3]*runtime.Matrix{e0, e1, eInconc}
}

// B92VulnerableToUSD returns true, indicating B92's vulnerability to USD attacks.
// In USD attacks, Eve performs unambiguous state discrimination and
// only forwards qubits she measured conclusively.
func B92VulnerableToUSD() bool {
	return true
}
