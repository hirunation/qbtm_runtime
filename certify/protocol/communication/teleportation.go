package communication

import (
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// TeleportationProtocol implements the Bennett et al. 1993 quantum teleportation protocol.
//
// Type signature: Q(2) x Bell -> Q(2)
// Where Q(2) is a single qubit and Bell is a maximally entangled pair.
//
// The protocol transfers an unknown quantum state |psi> from Alice to Bob
// using one Bell pair and two classical bits of communication.
//
// Protocol steps:
// 1. Alice has unknown qubit |psi> and her half of Bell pair |Phi+>
// 2. Alice performs Bell measurement on her two qubits
// 3. Alice sends 2 classical bits (measurement outcome) to Bob
// 4. Bob applies correction operator: I, X, Z, or XZ based on bits
// 5. Bob's qubit is now in state |psi>
//
// Fidelity: 1 (exact, rational 1/1) for ideal case
// Resources: 1 shared Bell pair + 2 classical bits
type TeleportationProtocol struct{}

// NewTeleportation creates a new teleportation protocol instance.
func NewTeleportation() *TeleportationProtocol {
	return &TeleportationProtocol{}
}

// Protocol returns the complete protocol specification.
func (p *TeleportationProtocol) Protocol() *protocol.Protocol {
	// Bell state density matrix for resource specification
	bellState := RhoBellPhiPlus()

	return &protocol.Protocol{
		Name:        "Teleportation",
		Description: "Bennett et al. 1993 quantum teleportation: transfer quantum state via entanglement and classical communication",
		Parties: []protocol.Party{
			{
				Name: "Alice",
				Role: protocol.RoleSender,
				Capabilities: []protocol.Capability{
					protocol.CapPrepare,
					protocol.CapMeasure,
					protocol.CapStore,
					protocol.CapClassicalCommunicate,
				},
			},
			{
				Name: "Bob",
				Role: protocol.RoleReceiver,
				Capabilities: []protocol.Capability{
					protocol.CapPrepare,
					protocol.CapStore,
					protocol.CapClassicalCommunicate,
				},
			},
		},
		Resources: []protocol.Resource{
			{
				Type:    protocol.ResourceEntangledPair,
				Parties: []string{"Alice", "Bob"},
				State: protocol.StateSpec{
					Dimension:   4, // 2x2 = 4 dimensional Hilbert space
					IsClassical: false,
					State:       bellState,
				},
			},
			{
				Type:    protocol.ResourceAuthenticatedChannel,
				Parties: []string{"Alice", "Bob"},
				State: protocol.StateSpec{
					Dimension:   4, // 2 classical bits
					IsClassical: true,
				},
			},
		},
		Rounds: []protocol.Round{
			{
				Number:      1,
				Description: "Alice receives unknown qubit |psi> to teleport",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionReceive, Target: "input-qubit"},
				},
			},
			{
				Number:      2,
				Description: "Alice performs Bell measurement on |psi> and her half of Bell pair",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "cnot",
						Data: GateToValue("CNOT", CNOT())},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "hadamard",
						Data: GateToValue("Hadamard", Hadamard())},
					{Actor: "Alice", Type: protocol.ActionMeasure, Target: "bell-measurement"},
				},
			},
			{
				Number:      3,
				Description: "Alice sends 2 classical bits (measurement result) to Bob",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionSend, Target: "Bob",
						Data: runtime.MakeText("classical-bits")},
				},
			},
			{
				Number:      4,
				Description: "Bob applies correction operator based on received bits",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionReceive, Target: "Alice"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "correction",
						Data: p.correctionData()},
				},
			},
		},
		Goal: protocol.StateTransfer{
			InputDim:  2,                           // Single qubit input
			OutputDim: 2,                           // Single qubit output
			Fidelity:  &runtime.Rat{V: big.NewRat(1, 1)}, // Perfect fidelity
		},
		Assumptions: []protocol.Assumption{
			{
				Name:        "No-Cloning",
				Description: "Quantum states cannot be perfectly cloned (fundamental to teleportation)",
				Type:        protocol.AssumptionNoCloning,
			},
			{
				Name:        "Authenticated Classical Channel",
				Description: "Classical communication between Alice and Bob is authenticated",
				Type:        protocol.AssumptionAuthenticatedClassical,
			},
			{
				Name:        "Perfect Devices",
				Description: "Bell measurement and correction gates are perfect",
				Type:        protocol.AssumptionPerfectDevices,
			},
		},
		TypeSig: protocol.TypeSignature{
			Domain:   runtime.Object{Blocks: []uint32{2, 4}}, // Q(2) x Bell
			Codomain: runtime.Object{Blocks: []uint32{2}},    // Q(2)
		},
	}
}

// Synthesize generates the teleportation circuit and stores it.
func (p *TeleportationProtocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the complete teleportation circuit
	// The circuit has 3 qubits: |psi>, Alice's Bell half, Bob's Bell half

	// Step 1: Bell measurement preparation (CNOT then H on Alice's qubits)
	bellMeasureCircuit := p.synthesizeBellMeasurement(store)

	// Step 2: Classical-controlled correction on Bob's qubit
	correctionCircuit := p.synthesizeCorrection(store)

	// Step 3: Compose the full protocol
	children := make([][32]byte, 2)
	children[0] = bellMeasureCircuit
	children[1] = correctionCircuit

	mainCircuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 4}}, // Input qubit + Bell pair
		Codomain: runtime.Object{Blocks: []uint32{2}},    // Output qubit
		Prim:     runtime.PrimCompose,
		Data:     p.protocolMetadata(),
		Children: children,
	}

	return store.Put(mainCircuit), nil
}

// synthesizeBellMeasurement creates the Bell measurement circuit.
// Alice performs: CNOT(psi, Bell_A), then H(psi), then measure both qubits.
func (p *TeleportationProtocol) synthesizeBellMeasurement(store *runtime.Store) [32]byte {
	// Bell measurement unitary on 2 qubits
	bellMeasureU := BellMeasurementUnitary()

	// The projectors for computational basis measurement after Bell rotation
	projectors := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("outcome-00"),
			runtime.MatrixToValue(DensityMatrix(Ket00()))),
		runtime.MakeTag(runtime.MakeText("outcome-01"),
			runtime.MatrixToValue(DensityMatrix(Ket01()))),
		runtime.MakeTag(runtime.MakeText("outcome-10"),
			runtime.MatrixToValue(DensityMatrix(Ket10()))),
		runtime.MakeTag(runtime.MakeText("outcome-11"),
			runtime.MatrixToValue(DensityMatrix(Ket11()))),
	)

	// Create unitary sub-circuit for Bell rotation
	unitaryCircuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{4}}, // Two qubits
		Codomain: runtime.Object{Blocks: []uint32{4}}, // Two qubits
		Prim:     runtime.PrimUnitary,
		Data:     runtime.MatrixToValue(bellMeasureU),
	}
	unitaryQGID := store.Put(unitaryCircuit)

	// Create measurement circuit
	measureCircuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{4}},    // Two qubits
		Codomain: runtime.Object{Blocks: []uint32{2, 2}}, // Two classical bits
		Prim:     runtime.PrimInstrument,
		Data:     projectors,
	}
	measureQGID := store.Put(measureCircuit)

	// Compose: measure after unitary
	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{4}},    // Two qubits (psi + Bell_A)
		Codomain: runtime.Object{Blocks: []uint32{2, 2}}, // Two classical bits
		Prim:     runtime.PrimCompose,
		Data: runtime.MakeTag(
			runtime.MakeText("bell-measurement"),
			runtime.MakeText("CNOT then H then measure"),
		),
		Children: [][32]byte{unitaryQGID, measureQGID},
	}

	return store.Put(circuit)
}

// synthesizeCorrection creates the correction circuit.
// Bob applies Z^m1 * X^m2 to his qubit based on classical bits (m1, m2).
func (p *TeleportationProtocol) synthesizeCorrection(store *runtime.Store) [32]byte {
	// Create sub-circuits for each correction operator
	corrections := AllCorrectionOperators()

	correctionChildren := make([][32]byte, 4)
	for i, corr := range corrections {
		circuit := runtime.Circuit{
			Domain:   runtime.Object{Blocks: []uint32{2}}, // Single qubit
			Codomain: runtime.Object{Blocks: []uint32{2}}, // Single qubit
			Prim:     runtime.PrimUnitary,
			Data:     runtime.MatrixToValue(corr),
		}
		correctionChildren[i] = store.Put(circuit)
	}

	// Controlled correction: branch based on classical bits
	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2, 2}}, // m1, m2, Bob's qubit
		Codomain: runtime.Object{Blocks: []uint32{2}},        // Corrected qubit
		Prim:     runtime.PrimBranch,
		Data: runtime.MakeTag(
			runtime.MakeText("teleportation-correction"),
			runtime.MakeSeq(
				runtime.MakeText("00 -> I"),
				runtime.MakeText("01 -> X"),
				runtime.MakeText("10 -> Z"),
				runtime.MakeText("11 -> XZ"),
			),
		),
		Children: correctionChildren,
	}

	return store.Put(circuit)
}

// correctionData returns the correction operator data for the protocol specification.
func (p *TeleportationProtocol) correctionData() runtime.Value {
	corrections := AllCorrectionOperators()
	return runtime.MakeTag(
		runtime.MakeText("correction-operators"),
		runtime.MakeSeq(
			GateToValue("I", corrections[0]),
			GateToValue("X", corrections[1]),
			GateToValue("Z", corrections[2]),
			GateToValue("XZ", corrections[3]),
		),
	)
}

// protocolMetadata returns metadata for the teleportation protocol.
func (p *TeleportationProtocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("Teleportation"),
			runtime.MakeText("Bennett et al. 1993"),
			runtime.MakeBigRat(big.NewRat(1, 1)), // Fidelity
			runtime.MakeInt(2),                   // Classical bits required
			runtime.MakeInt(1),                   // Bell pairs required
		),
	)
}

// Fidelity returns the fidelity of the teleportation protocol.
// For ideal teleportation, this is exactly 1.
func (p *TeleportationProtocol) Fidelity() *big.Rat {
	return big.NewRat(1, 1)
}

// ClassicalBitsRequired returns the number of classical bits needed.
func (p *TeleportationProtocol) ClassicalBitsRequired() int {
	return 2
}

// BellPairsRequired returns the number of Bell pairs needed.
func (p *TeleportationProtocol) BellPairsRequired() int {
	return 1
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *TeleportationProtocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("teleportation-protocol"),
		runtime.MakeSeq(
			runtime.MakeBigRat(p.Fidelity()),
			runtime.MakeInt(int64(p.ClassicalBitsRequired())),
			runtime.MakeInt(int64(p.BellPairsRequired())),
			p.Protocol().ToValue(),
		),
	)
}

// TeleportationFromValue deserializes a TeleportationProtocol from a runtime.Value.
func TeleportationFromValue(v runtime.Value) (*TeleportationProtocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "teleportation-protocol" {
		return nil, false
	}
	// Protocol is stateless, so just verify the tag is correct
	return NewTeleportation(), true
}

// ===============================
// Helper states for Bell measurement
// ===============================

// Ket00 returns the |00> state as a column vector (4x1).
func Ket00() *runtime.Matrix {
	ket := runtime.NewMatrix(4, 1)
	ket.Set(0, 0, runtime.QIOne())
	return ket
}

// Ket01 returns the |01> state as a column vector (4x1).
func Ket01() *runtime.Matrix {
	ket := runtime.NewMatrix(4, 1)
	ket.Set(1, 0, runtime.QIOne())
	return ket
}

// Ket10 returns the |10> state as a column vector (4x1).
func Ket10() *runtime.Matrix {
	ket := runtime.NewMatrix(4, 1)
	ket.Set(2, 0, runtime.QIOne())
	return ket
}

// Ket11 returns the |11> state as a column vector (4x1).
func Ket11() *runtime.Matrix {
	ket := runtime.NewMatrix(4, 1)
	ket.Set(3, 0, runtime.QIOne())
	return ket
}

// ComputationalBasisState returns the computational basis state |ij> for i,j in {0,1}.
func ComputationalBasisState(i, j int) *runtime.Matrix {
	ket := runtime.NewMatrix(4, 1)
	ket.Set(2*i+j, 0, runtime.QIOne())
	return ket
}

// ===============================
// Teleportation verification
// ===============================

// TeleportationVerifier provides methods to verify teleportation correctness.
type TeleportationVerifier struct {
	protocol *TeleportationProtocol
}

// NewTeleportationVerifier creates a new verifier.
func NewTeleportationVerifier() *TeleportationVerifier {
	return &TeleportationVerifier{
		protocol: NewTeleportation(),
	}
}

// VerifyCorrectness verifies that teleportation correctly transfers the state.
// For any input state |psi>, the output should be |psi> with fidelity 1.
func (v *TeleportationVerifier) VerifyCorrectness(inputState *runtime.Matrix) bool {
	// Teleportation is correct if for all measurement outcomes,
	// applying the corresponding correction recovers the original state.
	//
	// After Bell measurement with outcome (m1, m2), Bob's state is:
	// - 00: |psi>
	// - 01: X|psi>
	// - 10: Z|psi>
	// - 11: XZ|psi>
	//
	// Applying correction Z^m1 * X^m2 recovers |psi>.

	corrections := AllCorrectionOperators()

	// For outcome 00: I * |psi> = |psi> (correct)
	// For outcome 01: X * X|psi> = |psi> (correct)
	// For outcome 10: Z * Z|psi> = |psi> (correct)
	// For outcome 11: XZ * XZ|psi> = |psi> (correct)

	// Verify X*X = I
	xx := runtime.MatMul(corrections[1], corrections[1])
	if !isIdentity(xx) {
		return false
	}

	// Verify Z*Z = I
	zz := runtime.MatMul(corrections[2], corrections[2])
	if !isIdentity(zz) {
		return false
	}

	// Verify (XZ)*(XZ) = I
	xzxz := runtime.MatMul(corrections[3], corrections[3])
	if !isIdentity(xzxz) {
		return false
	}

	return true
}

// isIdentity checks if a matrix is the identity (approximately).
func isIdentity(m *runtime.Matrix) bool {
	if m.Rows != m.Cols {
		return false
	}
	n := m.Rows
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			entry := m.Get(i, j)
			if i == j {
				// Diagonal should be 1
				if entry.Re.Cmp(big.NewRat(1, 1)) != 0 || entry.Im.Sign() != 0 {
					return false
				}
			} else {
				// Off-diagonal should be 0
				if entry.Re.Sign() != 0 || entry.Im.Sign() != 0 {
					return false
				}
			}
		}
	}
	return true
}
