package qkd

import (
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// BB84Protocol implements the Bennett-Brassard 1984 QKD protocol.
// This is the first and most widely used QKD protocol.
//
// Type signature: (C(2) x C(2))^n -> C(2)^m
// Where n is raw bits sent and m is final key length.
//
// Security: Information-theoretic security against any attack
// Key rate: r = 1 - 2*h(e) where h is binary entropy
// Error threshold: e < 11% for positive key rate
type BB84Protocol struct {
	// NumQubits is the number of qubits to transmit (n).
	NumQubits int

	// ErrorBound is the maximum tolerated error rate.
	// For BB84, this must be < 11/100 for security.
	ErrorBound *big.Rat
}

// NewBB84 creates a new BB84 protocol with the given number of qubits.
// Uses the default error bound of 11/100.
func NewBB84(numQubits int) *BB84Protocol {
	return &BB84Protocol{
		NumQubits:  numQubits,
		ErrorBound: big.NewRat(11, 100),
	}
}

// NewBB84WithErrorBound creates a BB84 protocol with a custom error bound.
func NewBB84WithErrorBound(numQubits int, errorBound *big.Rat) *BB84Protocol {
	return &BB84Protocol{
		NumQubits:  numQubits,
		ErrorBound: errorBound,
	}
}

// Protocol returns the complete protocol specification.
func (p *BB84Protocol) Protocol() *protocol.Protocol {
	return &protocol.Protocol{
		Name:        "BB84",
		Description: "Bennett-Brassard 1984 quantum key distribution protocol using four states in two conjugate bases",
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
				Description: "Quantum transmission: Alice prepares random bits in random bases and sends to Bob",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionPrepare, Target: "qubit"},
					{Actor: "Alice", Type: protocol.ActionSend, Target: "Bob"},
				},
			},
			{
				Number:      2,
				Description: "Measurement: Bob measures each qubit in a random basis",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionReceive, Target: "Alice"},
					{Actor: "Bob", Type: protocol.ActionMeasure, Target: "qubit"},
				},
			},
			{
				Number:      3,
				Description: "Sifting: Alice and Bob publicly announce bases and keep matching ones",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "bases"},
					{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "bases"},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "sift"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "sift"},
				},
			},
			{
				Number:      4,
				Description: "Error estimation: Compare subset of sifted bits to estimate QBER",
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
func (p *BB84Protocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the BB84 circuit
	// Domain: n copies of (C(2) x C(2)) for (bit, basis) pairs
	// Codomain: C(2)^m for final key bits

	// Create the preparation circuit for a single qubit
	// Input: (bit, basis) -> encoded qubit state
	prepCircuit := p.synthesizePrepare(store)

	// Create the measurement circuit
	// Input: (qubit, basis) -> classical bit
	measureCircuit := p.synthesizeMeasure(store)

	// Create the sifting circuit
	siftCircuit := p.synthesizeSift(store)

	// Compose the full protocol
	// For now, we create a simple tensor of preparation circuits
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
func (p *BB84Protocol) synthesizePrepare(store *runtime.Store) [32]byte {
	// Prepare qubit based on bit and basis choice
	// bit=0, basis=0 -> |0>
	// bit=1, basis=0 -> |1>
	// bit=0, basis=1 -> |+>
	// bit=1, basis=1 -> |->

	// Store the four states as preparation data
	states := runtime.MakeSeq(
		StateToValue("ket0", Ket0()),
		StateToValue("ket1", Ket1()),
		StateToValue("ketPlus", KetPlus()),
		StateToValue("ketMinus", KetMinus()),
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
func (p *BB84Protocol) synthesizeMeasure(store *runtime.Store) [32]byte {
	// Measure qubit in chosen basis
	// Store both basis projectors
	projectors := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("z-basis"),
			runtime.MakeSeq(
				runtime.MatrixToValue(Rho0()),
				runtime.MatrixToValue(Rho1()),
			)),
		runtime.MakeTag(runtime.MakeText("x-basis"),
			runtime.MakeSeq(
				runtime.MatrixToValue(RhoPlus()),
				runtime.MatrixToValue(RhoMinus()),
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

// synthesizeSift creates the sifting circuit.
func (p *BB84Protocol) synthesizeSift(store *runtime.Store) [32]byte {
	// Sifting: compare bases and keep matching bits
	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2, 2}}, // alice_basis, bob_basis, bit
		Codomain: runtime.Object{Blocks: []uint32{2, 2}},    // keep_flag, bit
		Prim:     runtime.PrimBranch,
		Data:     runtime.MakeText("sift"),
	}

	return store.Put(circuit)
}

// KeyRate computes the asymptotic key rate for a given error rate.
// r = 1 - 2*h(e) where h(e) = -e*log2(e) - (1-e)*log2(1-e)
// Returns the key rate as an exact rational (approximation).
func (p *BB84Protocol) KeyRate(errorRate *big.Rat) *big.Rat {
	// For exact arithmetic, we use rational approximation of binary entropy
	// h(e) ~ e*log2(e) uses log2(e) which is irrational for most e
	// We approximate using Taylor expansion or lookup

	// Simple bound: r >= 1 - 2*h(e) > 0 when e < 0.11
	// For e = 0.11, h(0.11) ~ 0.5
	// For small e, h(e) ~ e*log2(1/e) ~ e * (ln(1/e)/ln(2))

	// Use rational approximation based on error rate
	// For e = p/q, we compute an approximation

	if errorRate.Cmp(big.NewRat(11, 100)) >= 0 {
		return big.NewRat(0, 1) // No key rate for e >= 11%
	}

	// Approximate: r ~ 1 - 2*(e*5 + e^2*10) for small e
	// This is a crude lower bound
	e := new(big.Rat).Set(errorRate)
	eSq := new(big.Rat).Mul(e, e)

	// 2*h(e) ~ 10*e + 20*e^2 for small e (very rough)
	term1 := new(big.Rat).Mul(big.NewRat(10, 1), e)
	term2 := new(big.Rat).Mul(big.NewRat(20, 1), eSq)
	twoH := new(big.Rat).Add(term1, term2)

	rate := new(big.Rat).Sub(big.NewRat(1, 1), twoH)
	if rate.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	return rate
}

// ErrorThreshold returns the maximum error rate for positive key rate.
// For BB84, this is 11/100 = 11%.
func (p *BB84Protocol) ErrorThreshold() *big.Rat {
	return big.NewRat(11, 100)
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *BB84Protocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("bb84-protocol"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(p.NumQubits)),
			runtime.MakeBigRat(p.ErrorBound),
			p.Protocol().ToValue(),
		),
	)
}

// BB84FromValue deserializes a BB84Protocol from a runtime.Value.
func BB84FromValue(v runtime.Value) (*BB84Protocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "bb84-protocol" {
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

	return &BB84Protocol{
		NumQubits:  int(numQubits.V.Int64()),
		ErrorBound: new(big.Rat).Set(errorBound.V),
	}, true
}

// Helper methods

func (p *BB84Protocol) domainObject() runtime.Object {
	// n copies of (C(2) x C(2)) for (bit, basis) pairs
	// Represented as blocks for each qubit slot
	blocks := make([]uint32, p.NumQubits*2)
	for i := 0; i < p.NumQubits*2; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *BB84Protocol) codomainObject() runtime.Object {
	// Output is approximately n/2 bits after sifting (matching bases ~50%)
	// Then reduced by error correction and privacy amplification
	keyLen := p.estimatedKeyLength()
	blocks := make([]uint32, keyLen)
	for i := 0; i < keyLen; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *BB84Protocol) estimatedKeyLength() int {
	// Rough estimate: key length = n * (1/2) * keyRate
	// 1/2 factor from sifting (matching bases)
	// keyRate factor from error correction and privacy amplification
	rate := p.KeyRate(p.ErrorBound)
	if rate.Sign() <= 0 {
		return 0
	}
	// Estimate: n/4 for moderate error rates
	return p.NumQubits / 4
}

func (p *BB84Protocol) secrecyBound() *big.Rat {
	// Secrecy bound from Devetak-Winter bound
	// For BB84: S(A|E) >= 1 - h(e) - h(e)
	// Information leaked to Eve is bounded
	return big.NewRat(1, 1000000) // 10^-6 security parameter
}

func (p *BB84Protocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("BB84"),
			runtime.MakeText("Bennett-Brassard 1984"),
			runtime.MakeInt(int64(p.NumQubits)),
			runtime.MakeBigRat(p.ErrorBound),
			runtime.MakeBigRat(p.ErrorThreshold()),
		),
	)
}

// BB84States returns the four BB84 states as density matrices.
// Z-basis: |0>, |1>
// X-basis: |+>, |->
func BB84States() [4]*runtime.Matrix {
	return [4]*runtime.Matrix{
		Rho0(),
		Rho1(),
		RhoPlus(),
		RhoMinus(),
	}
}

// BB84Encoding returns the encoding map from (bit, basis) to state index.
// bit=0, basis=0 -> 0 (|0>)
// bit=1, basis=0 -> 1 (|1>)
// bit=0, basis=1 -> 2 (|+>)
// bit=1, basis=1 -> 3 (|->)
func BB84Encoding(bit, basis int) int {
	return basis*2 + bit
}

// BB84Decoding returns (bit, basis) from a state index.
func BB84Decoding(stateIndex int) (bit, basis int) {
	return stateIndex % 2, stateIndex / 2
}
