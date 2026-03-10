package multiparty

import (
	"fmt"
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// GHZProtocol implements the GHZ state distribution protocol for n parties.
//
// The GHZ (Greenberger-Horne-Zeilinger) state for n parties is:
// |GHZ_n> = (|0...0> + |1...1>) / sqrt(2)
//
// This is a maximally entangled n-party state with the following properties:
//   - Single qubit loss destroys all entanglement
//   - Used for multi-party secret sharing, anonymous broadcasting
//   - All parties measuring in the same basis get the same outcome
//
// Preparation circuit:
//
//	     +---+
//	q0: -| H |-*-----*-----*----- ...
//	     +---+ |     |     |
//	q1: -------X-----+-----+----- ...
//	                 |     |
//	q2: -------------X-----+----- ...
//	                       |
//	q3: -------------------X----- ...
//	...
//
// Type signature: Q(1) -> Q(2)^n (trivial input to n qubits)
type GHZProtocol struct {
	// NumParties is the number of parties (n >= 2).
	NumParties int
}

// NewGHZ creates a new GHZ protocol for the given number of parties.
// Requires numParties >= 2.
func NewGHZ(numParties int) *GHZProtocol {
	if numParties < 2 {
		numParties = 2
	}
	return &GHZProtocol{
		NumParties: numParties,
	}
}

// Protocol returns the complete protocol specification.
func (p *GHZProtocol) Protocol() *protocol.Protocol {
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

	// Party 1 is the preparer (special role)
	parties[0].Role = protocol.RoleSender

	// Resources: n-1 quantum channels (from Party1 to each other party)
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

	// Add the GHZ state as a shared resource
	resources[p.NumParties-1] = protocol.Resource{
		Type:    protocol.ResourceEntangledPair,
		Parties: partyNames,
		State: protocol.StateSpec{
			Dimension:   1 << p.NumParties, // 2^n dimensional
			IsClassical: false,
			State:       GHZDensityMatrix(p.NumParties),
		},
	}

	return &protocol.Protocol{
		Name:        fmt.Sprintf("GHZ-%d", p.NumParties),
		Description: fmt.Sprintf("GHZ state distribution for %d parties: |GHZ_%d> = (|0...0> + |1...1>)/sqrt(2)", p.NumParties, p.NumParties),
		Parties:     parties,
		Resources:   resources,
		Rounds: []protocol.Round{
			{
				Number:      1,
				Description: "Party 1 prepares GHZ state locally",
				Actions: []protocol.Action{
					{Actor: partyNames[0], Type: protocol.ActionPrepare, Target: "ghz-state",
						Data: p.ghzStateData()},
				},
			},
			{
				Number:      2,
				Description: "Party 1 distributes qubits to all other parties",
				Actions:     p.distributionActions(partyNames),
			},
			{
				Number:      3,
				Description: "All parties verify entanglement by measuring in same basis",
				Actions:     p.verificationActions(partyNames),
			},
		},
		Goal: protocol.StateTransfer{
			InputDim:  1,                              // Trivial input
			OutputDim: 1 << p.NumParties,             // 2^n dimensional GHZ state
			Fidelity:  &runtime.Rat{V: big.NewRat(1, 1)}, // Perfect fidelity
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

// Synthesize generates the GHZ preparation circuit and stores it.
func (p *GHZProtocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the GHZ preparation circuit
	// H on first qubit, then cascade of CNOTs

	// Step 1: Hadamard on first qubit
	hadamardCircuit := p.synthesizeHadamard(store)

	// Step 2: Cascade of CNOTs
	cnotCircuits := make([][32]byte, p.NumParties-1)
	for i := 1; i < p.NumParties; i++ {
		cnotCircuits[i-1] = p.synthesizeCNOT(store, 0, i)
	}

	// Compose: H, then CNOT(0,1), CNOT(0,2), ..., CNOT(0,n-1)
	children := make([][32]byte, 1+len(cnotCircuits))
	children[0] = hadamardCircuit
	copy(children[1:], cnotCircuits)

	mainCircuit := runtime.Circuit{
		Domain:   p.domainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimCompose,
		Data:     p.protocolMetadata(),
		Children: children,
	}

	return store.Put(mainCircuit), nil
}

// synthesizeHadamard creates the Hadamard gate circuit on the first qubit.
func (p *GHZProtocol) synthesizeHadamard(store *runtime.Store) [32]byte {
	// H on first qubit, identity on rest
	h := ApplyGateToQubit(Hadamard(), p.NumParties, 0)

	circuit := runtime.Circuit{
		Domain:   p.codomainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimUnitary,
		Data:     runtime.MatrixToValue(h),
	}

	return store.Put(circuit)
}

// synthesizeCNOT creates a CNOT gate circuit in the n-qubit system.
func (p *GHZProtocol) synthesizeCNOT(store *runtime.Store, control, target int) [32]byte {
	cnot := CNOTExpanded(p.NumParties, control, target)

	circuit := runtime.Circuit{
		Domain:   p.codomainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimUnitary,
		Data:     runtime.MatrixToValue(cnot),
	}

	return store.Put(circuit)
}

// GHZState returns the GHZ state vector for this protocol.
func (p *GHZProtocol) GHZState() *runtime.Matrix {
	return GHZState(p.NumParties)
}

// GHZDensityMatrix returns the GHZ density matrix for this protocol.
func (p *GHZProtocol) GHZDensityMatrixValue() *runtime.Matrix {
	return GHZDensityMatrix(p.NumParties)
}

// VerifyAllSameOutcome checks that when all parties measure in the same basis,
// they always get the same outcome.
// This is the key verification property of GHZ states.
func (p *GHZProtocol) VerifyAllSameOutcome() bool {
	// For |GHZ_n> = (|0...0> + |1...1>) / sqrt(2)
	// Measuring in Z-basis: all get 0 (prob 1/2) or all get 1 (prob 1/2)
	// Measuring in X-basis: similar correlations

	// The GHZ state has perfect correlations in the computational basis
	// This is verified by checking the state structure
	ghz := p.GHZState()
	dim := 1 << p.NumParties

	// Only indices 0 (|0...0>) and dim-1 (|1...1>) should have non-zero amplitude
	for i := 0; i < dim; i++ {
		amp := ghz.Get(i, 0)
		if i == 0 || i == dim-1 {
			// Should be 1/sqrt(2)
			if runtime.QIIsZero(amp) {
				return false
			}
		} else {
			// Should be 0
			if !runtime.QIIsZero(amp) {
				return false
			}
		}
	}

	return true
}

// Helper methods

func (p *GHZProtocol) domainObject() runtime.Object {
	// Input: trivial (just start with |0...0>)
	// Represented as n qubits in |0> state
	blocks := make([]uint32, p.NumParties)
	for i := 0; i < p.NumParties; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *GHZProtocol) codomainObject() runtime.Object {
	// Output: n qubits in GHZ state
	blocks := make([]uint32, p.NumParties)
	for i := 0; i < p.NumParties; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *GHZProtocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText(fmt.Sprintf("GHZ-%d", p.NumParties)),
			runtime.MakeText("Greenberger-Horne-Zeilinger state distribution"),
			runtime.MakeInt(int64(p.NumParties)),
			runtime.MakeBigRat(Sqrt2Inv), // Normalization factor
		),
	)
}

func (p *GHZProtocol) ghzStateData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("ghz-state"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(p.NumParties)),
			runtime.MatrixToValue(p.GHZState()),
			runtime.MatrixToValue(GHZPreparationCircuit(p.NumParties)),
		),
	)
}

func (p *GHZProtocol) distributionActions(partyNames []string) []protocol.Action {
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

func (p *GHZProtocol) verificationActions(partyNames []string) []protocol.Action {
	actions := make([]protocol.Action, p.NumParties)
	for i := 0; i < p.NumParties; i++ {
		actions[i] = protocol.Action{
			Actor:  partyNames[i],
			Type:   protocol.ActionMeasure,
			Target: "z-basis",
			Data:   runtime.MakeText("verify-correlation"),
		}
	}
	return actions
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *GHZProtocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("ghz-protocol"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(p.NumParties)),
			runtime.MatrixToValue(p.GHZState()),
			p.Protocol().ToValue(),
		),
	)
}

// GHZFromValue deserializes a GHZProtocol from a runtime.Value.
func GHZFromValue(v runtime.Value) (*GHZProtocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "ghz-protocol" {
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

	return NewGHZ(int(numParties.V.Int64())), true
}

// ===============================
// GHZ state properties
// ===============================

// GHZEntanglementWitness returns the entanglement witness for GHZ states.
// W = I/2 - |GHZ><GHZ|
// If Tr(W * rho) < 0, then rho is entangled.
func GHZEntanglementWitness(n int) *runtime.Matrix {
	dim := 1 << n
	identity := runtime.Identity(dim)
	halfI := runtime.MatScale(identity, big.NewRat(1, 2))
	ghzDM := GHZDensityMatrix(n)
	return runtime.MatSub(halfI, ghzDM)
}

// GHZCorrelation computes the n-party correlation for GHZ state.
// For GHZ states, the correlation C = <Z1 * Z2 * ... * Zn> = 0
// But <X1 * X2 * ... * Xn> = 1 for even n, 0 for odd n.
func GHZCorrelation(n int) *big.Rat {
	// For GHZ state: <Z_1 Z_2 ... Z_n> = 0
	// This is because |0...0> gives +1 and |1...1> gives (-1)^n,
	// and they occur with equal probability.
	return big.NewRat(0, 1)
}
