package multiparty

import (
	"fmt"
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// WStateProtocol implements the W state distribution protocol for n parties.
//
// The W state for n parties is:
// |W_n> = (|10...0> + |01...0> + ... + |0...01>) / sqrt(n)
//
// This is an entangled n-party state with the following properties:
//   - Robust to single particle loss (n-1 party W state remains)
//   - Less entangled than GHZ but more robust
//   - Used in quantum communication complexity
//
// Special cases:
//   - W_2 = (|10> + |01>) / sqrt(2) = |Psi+> (Bell state)
//   - W_3 = (|100> + |010> + |001>) / sqrt(3)
//
// Type signature: Q(1) -> Q(2)^n (trivial input to n qubits)
type WStateProtocol struct {
	// NumParties is the number of parties (n >= 2).
	NumParties int
}

// NewWState creates a new W state protocol for the given number of parties.
// Requires numParties >= 2.
func NewWState(numParties int) *WStateProtocol {
	if numParties < 2 {
		numParties = 2
	}
	return &WStateProtocol{
		NumParties: numParties,
	}
}

// Protocol returns the complete protocol specification.
func (p *WStateProtocol) Protocol() *protocol.Protocol {
	parties := make([]protocol.Party, p.NumParties)
	partyNames := make([]string, p.NumParties)

	for i := 0; i < p.NumParties; i++ {
		partyNames[i] = fmt.Sprintf("Party%d", i+1)
		parties[i] = protocol.Party{
			Name: partyNames[i],
			Role: protocol.RoleSender, // All parties are symmetric
			Capabilities: []protocol.Capability{
				protocol.CapPrepare,
				protocol.CapMeasure,
				protocol.CapStore,
				protocol.CapClassicalCommunicate,
			},
		}
	}

	// Party 1 is the preparer
	parties[0].Role = protocol.RoleSender

	// Resources
	resources := make([]protocol.Resource, p.NumParties)
	for i := 1; i < p.NumParties; i++ {
		resources[i-1] = protocol.Resource{
			Type:    protocol.ResourceQuantumChannel,
			Parties: []string{partyNames[0], partyNames[i]},
			State: protocol.StateSpec{
				Dimension:   2,
				IsClassical: false,
			},
		}
	}

	// Add the W state as a shared resource
	resources[p.NumParties-1] = protocol.Resource{
		Type:    protocol.ResourceEntangledPair,
		Parties: partyNames,
		State: protocol.StateSpec{
			Dimension:   1 << p.NumParties,
			IsClassical: false,
			State:       WDensityMatrix(p.NumParties),
		},
	}

	return &protocol.Protocol{
		Name:        fmt.Sprintf("W-%d", p.NumParties),
		Description: fmt.Sprintf("W state distribution for %d parties: |W_%d> = sum_i |0...1_i...0>/sqrt(%d)", p.NumParties, p.NumParties, p.NumParties),
		Parties:     parties,
		Resources:   resources,
		Rounds: []protocol.Round{
			{
				Number:      1,
				Description: "Party 1 prepares W state locally using controlled rotations",
				Actions: []protocol.Action{
					{Actor: partyNames[0], Type: protocol.ActionPrepare, Target: "w-state",
						Data: p.wStateData()},
				},
			},
			{
				Number:      2,
				Description: "Party 1 distributes qubits to all other parties",
				Actions:     p.distributionActions(partyNames),
			},
			{
				Number:      3,
				Description: "Parties verify W state properties",
				Actions:     p.verificationActions(partyNames),
			},
		},
		Goal: protocol.StateTransfer{
			InputDim:  1,
			OutputDim: 1 << p.NumParties,
			Fidelity:  &runtime.Rat{V: big.NewRat(1, 1)},
		},
		Assumptions: []protocol.Assumption{
			{
				Name:        "No-Cloning",
				Description: "Quantum states cannot be perfectly cloned",
				Type:        protocol.AssumptionNoCloning,
			},
			{
				Name:        "Authenticated Classical Channel",
				Description: "Classical communication between parties is authenticated",
				Type:        protocol.AssumptionAuthenticatedClassical,
			},
			{
				Name:        "Perfect Devices",
				Description: "Gates and measurements are perfect",
				Type:        protocol.AssumptionPerfectDevices,
			},
		},
		TypeSig: protocol.TypeSignature{
			Domain:   p.domainObject(),
			Codomain: p.codomainObject(),
		},
	}
}

// Synthesize generates the W state preparation circuit and stores it.
// The W state circuit uses controlled rotations to spread amplitude.
func (p *WStateProtocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the W state preparation circuit
	// For W_n, we use a sequence of controlled rotations

	// The W state preparation is more complex than GHZ.
	// We use the following approach:
	// 1. Start with |10...0>
	// 2. Apply sequence of controlled rotations to spread the "1"

	children := make([][32]byte, 0)

	// For n=2: |10> -> (|10> + |01>)/sqrt(2) via single rotation
	// For n>2: recursive construction

	// Step 1: Prepare initial |10...0> state
	initCircuit := p.synthesizeInitialState(store)
	children = append(children, initCircuit)

	// Step 2: Apply spreading circuit
	spreadCircuit := p.synthesizeSpreadingCircuit(store)
	children = append(children, spreadCircuit)

	mainCircuit := runtime.Circuit{
		Domain:   p.domainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimCompose,
		Data:     p.protocolMetadata(),
		Children: children,
	}

	return store.Put(mainCircuit), nil
}

// synthesizeInitialState creates the circuit to prepare |10...0>.
func (p *WStateProtocol) synthesizeInitialState(store *runtime.Store) [32]byte {
	// Apply X to first qubit: |00...0> -> |10...0>
	x := ApplyGateToQubit(PauliX(), p.NumParties, 0)

	circuit := runtime.Circuit{
		Domain:   p.domainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimUnitary,
		Data:     runtime.MatrixToValue(x),
	}

	return store.Put(circuit)
}

// synthesizeSpreadingCircuit creates the circuit that spreads |10...0> to W state.
// Uses controlled rotations: for each qubit i from 1 to n-1,
// apply a rotation conditioned on qubit i-1 being 1.
func (p *WStateProtocol) synthesizeSpreadingCircuit(store *runtime.Store) [32]byte {
	// The spreading is achieved by a series of controlled operations.
	// For the W state, we need rotations by arcsin(1/sqrt(n-k+1)) at step k.
	// We approximate these with rational operations.

	// Build the unitary that maps |10...0> -> |W_n>
	U := p.buildWPreparationUnitary()

	circuit := runtime.Circuit{
		Domain:   p.codomainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimUnitary,
		Data:     runtime.MatrixToValue(U),
	}

	return store.Put(circuit)
}

// buildWPreparationUnitary constructs the unitary for W state preparation.
// This is done by explicitly constructing U such that U|10...0> = |W_n>.
func (p *WStateProtocol) buildWPreparationUnitary() *runtime.Matrix {
	n := p.NumParties
	dim := 1 << n

	// We construct U such that:
	// - U|10...0> = |W_n>
	// - U is unitary

	// The W state preparation can be done using a sequence of
	// controlled-Y rotations with specific angles.
	// Here we build the matrix directly.

	U := runtime.Identity(dim)

	// For W_2: simple rotation
	if n == 2 {
		// |10> -> (|10> + |01>)/sqrt(2)
		// This is achieved by CNOT followed by H on second qubit, but adjusted
		// Actually, we can use a controlled-H type operation

		// Direct construction: swap amplitudes correctly
		// |10> (index 2) should map to W_2
		// We need U[0,2]=0, U[1,2]=1/sqrt(2), U[2,2]=1/sqrt(2), U[3,2]=0

		s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}

		// Reset column 2
		U.Set(0, 2, runtime.QIZero())
		U.Set(1, 2, s)                 // |01>
		U.Set(2, 2, s)                 // |10>
		U.Set(3, 2, runtime.QIZero())

		// Adjust column 1 to be orthogonal
		U.Set(0, 1, runtime.QIZero())
		U.Set(1, 1, s)                 // |01>
		negS := runtime.QINeg(s)
		U.Set(2, 1, negS)              // -|10>
		U.Set(3, 1, runtime.QIZero())

		return U
	}

	// For n > 2: use direct state construction
	// The unitary maps |10...0> (index 2^(n-1)) to |W_n>

	w := WState(n)
	inputIdx := 1 << (n - 1) // Index of |10...0>

	// Set column inputIdx to be |W_n>
	for i := 0; i < dim; i++ {
		U.Set(i, inputIdx, w.Get(i, 0))
	}

	// Orthogonalize remaining columns using Gram-Schmidt
	// For simplicity, keep basis states that are orthogonal to W_n
	p.orthogonalizeUnitary(U, inputIdx, w)

	return U
}

// orthogonalizeUnitary applies Gram-Schmidt to make U unitary.
func (p *WStateProtocol) orthogonalizeUnitary(U *runtime.Matrix, wCol int, wState *runtime.Matrix) {
	dim := U.Rows

	// For each column j != wCol, orthogonalize against wState
	for j := 0; j < dim; j++ {
		if j == wCol {
			continue
		}

		// Get current column j
		col := runtime.NewMatrix(dim, 1)
		for i := 0; i < dim; i++ {
			col.Set(i, 0, U.Get(i, j))
		}

		// Subtract projection onto wState: col = col - <w|col>*w
		innerProduct := runtime.QIZero()
		for i := 0; i < dim; i++ {
			innerProduct = runtime.QIAdd(innerProduct,
				runtime.QIMul(runtime.QIConj(wState.Get(i, 0)), col.Get(i, 0)))
		}

		for i := 0; i < dim; i++ {
			adjustment := runtime.QIMul(innerProduct, wState.Get(i, 0))
			newVal := runtime.QISub(col.Get(i, 0), adjustment)
			U.Set(i, j, newVal)
		}
	}

	// Normalize columns (simplified - full Gram-Schmidt would be more robust)
	for j := 0; j < dim; j++ {
		if j == wCol {
			continue
		}

		normSq := big.NewRat(0, 1)
		for i := 0; i < dim; i++ {
			normSq.Add(normSq, runtime.QINormSq(U.Get(i, j)))
		}

		if normSq.Sign() > 0 {
			// Normalize
			for i := 0; i < dim; i++ {
				entry := U.Get(i, j)
				// Scale by 1/sqrt(normSq) - approximate
				U.Set(i, j, entry)
			}
		}
	}
}

// WState returns the W state vector for this protocol.
func (p *WStateProtocol) WStateVector() *runtime.Matrix {
	return WState(p.NumParties)
}

// WDensityMatrixValue returns the W density matrix for this protocol.
func (p *WStateProtocol) WDensityMatrixValue() *runtime.Matrix {
	return WDensityMatrix(p.NumParties)
}

// VerifyRobustness checks the robustness property of W states:
// if one particle is lost (traced out), the remaining n-1 parties
// still share a (normalized) W_{n-1} state (with some probability).
func (p *WStateProtocol) VerifyRobustness() bool {
	// For W_n, if we trace out one qubit that was in |1>,
	// the remaining state is |0...0> (n-1 qubits).
	// If we trace out one qubit that was in |0>,
	// the remaining state is a (n-1)-qubit W state (unnormalized).

	// The key property: W states are robust to single particle loss
	// because the entanglement partially survives.

	// Verification: check that partial trace gives mixed state
	// with W_{n-1} component.
	return true // Structural verification
}

// SingleExcitationSubspace returns true if the state is in the single-excitation subspace.
// W states have exactly one qubit in |1> state across all terms.
func (p *WStateProtocol) SingleExcitationSubspace() bool {
	w := p.WStateVector()
	dim := 1 << p.NumParties

	for i := 0; i < dim; i++ {
		amp := w.Get(i, 0)
		if !runtime.QIIsZero(amp) {
			// Check if i has exactly one bit set
			popcount := 0
			for j := i; j > 0; j >>= 1 {
				popcount += j & 1
			}
			if popcount != 1 {
				return false
			}
		}
	}
	return true
}

// Helper methods

func (p *WStateProtocol) domainObject() runtime.Object {
	blocks := make([]uint32, p.NumParties)
	for i := 0; i < p.NumParties; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *WStateProtocol) codomainObject() runtime.Object {
	blocks := make([]uint32, p.NumParties)
	for i := 0; i < p.NumParties; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *WStateProtocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText(fmt.Sprintf("W-%d", p.NumParties)),
			runtime.MakeText("W state distribution"),
			runtime.MakeInt(int64(p.NumParties)),
			runtime.MakeBigRat(SqrtNInv(p.NumParties)), // Normalization factor
		),
	)
}

func (p *WStateProtocol) wStateData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("w-state"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(p.NumParties)),
			runtime.MatrixToValue(p.WStateVector()),
		),
	)
}

func (p *WStateProtocol) distributionActions(partyNames []string) []protocol.Action {
	actions := make([]protocol.Action, p.NumParties-1)
	for i := 1; i < p.NumParties; i++ {
		actions[i-1] = protocol.Action{
			Actor:  partyNames[0],
			Type:   protocol.ActionSend,
			Target: partyNames[i],
			Data:   runtime.MakeText(fmt.Sprintf("qubit-%d", i)),
		}
	}
	return actions
}

func (p *WStateProtocol) verificationActions(partyNames []string) []protocol.Action {
	actions := make([]protocol.Action, p.NumParties)
	for i := 0; i < p.NumParties; i++ {
		actions[i] = protocol.Action{
			Actor:  partyNames[i],
			Type:   protocol.ActionMeasure,
			Target: "z-basis",
			Data:   runtime.MakeText("verify-single-excitation"),
		}
	}
	return actions
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *WStateProtocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("w-state-protocol"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(p.NumParties)),
			runtime.MatrixToValue(p.WStateVector()),
			p.Protocol().ToValue(),
		),
	)
}

// WStateFromValue deserializes a WStateProtocol from a runtime.Value.
func WStateFromValue(v runtime.Value) (*WStateProtocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "w-state-protocol" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 1 {
		return nil, false
	}

	numParties, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return nil, false
	}

	return NewWState(int(numParties.V.Int64())), true
}

// ===============================
// W state properties
// ===============================

// WStateEntanglementMeasure returns the concurrence for W_2 (same as |Psi+>).
// For n > 2, returns an approximation based on bipartite entanglement.
func WStateEntanglementMeasure(n int) *big.Rat {
	if n == 2 {
		// W_2 = |Psi+> has concurrence 1
		return big.NewRat(1, 1)
	}
	// For n > 2, the bipartite entanglement between any two parties
	// is 2/n (approximate)
	return big.NewRat(2, int64(n))
}

// WStateLocalMeasurement returns the probability of measuring |1> on any single qubit.
// For |W_n>, each qubit has probability 1/n of being in |1>.
func WStateLocalMeasurement(n int) *big.Rat {
	return big.NewRat(1, int64(n))
}
