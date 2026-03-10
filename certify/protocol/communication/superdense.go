package communication

import (
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// SuperdenseCodingProtocol implements the Bennett-Wiesner superdense coding protocol.
//
// Type signature: C(4) x Bell -> C(4)
// Where C(4) represents 2 classical bits (4 possible values) and Bell is a maximally
// entangled pair.
//
// The protocol transmits 2 classical bits by sending only 1 qubit, using
// a pre-shared Bell pair. This achieves classical capacity of 2 bits per qubit.
//
// Protocol steps:
// 1. Alice and Bob share |Phi+> = (|00> + |11>)/sqrt(2)
// 2. Alice encodes 2 classical bits (b1, b2) by applying operator to her qubit:
//    - 00 -> I (identity)
//    - 01 -> X (bit flip)
//    - 10 -> Z (phase flip)
//    - 11 -> XZ (both)
// 3. Alice sends her qubit to Bob
// 4. Bob performs Bell measurement on both qubits
// 5. Bob decodes the 2 classical bits from measurement outcome
//
// Capacity: 2 bits per qubit (exact rational 2/1)
// Resources: 1 shared Bell pair + 1 qubit transmission
type SuperdenseCodingProtocol struct{}

// NewSuperdenseCoding creates a new superdense coding protocol instance.
func NewSuperdenseCoding() *SuperdenseCodingProtocol {
	return &SuperdenseCodingProtocol{}
}

// Protocol returns the complete protocol specification.
func (p *SuperdenseCodingProtocol) Protocol() *protocol.Protocol {
	// Bell state density matrix for resource specification
	bellState := RhoBellPhiPlus()

	return &protocol.Protocol{
		Name:        "SuperdenseCoding",
		Description: "Bennett-Wiesner superdense coding: transmit 2 classical bits via 1 qubit using entanglement",
		Parties: []protocol.Party{
			{
				Name: "Alice",
				Role: protocol.RoleSender,
				Capabilities: []protocol.Capability{
					protocol.CapPrepare,
					protocol.CapStore,
					protocol.CapQuantumCommunicate,
				},
			},
			{
				Name: "Bob",
				Role: protocol.RoleReceiver,
				Capabilities: []protocol.Capability{
					protocol.CapMeasure,
					protocol.CapStore,
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
				Type:    protocol.ResourceQuantumChannel,
				Parties: []string{"Alice", "Bob"},
				State: protocol.StateSpec{
					Dimension:   2, // Single qubit channel
					IsClassical: false,
				},
			},
		},
		Rounds: []protocol.Round{
			{
				Number:      1,
				Description: "Alice receives 2 classical bits to transmit",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionReceive, Target: "classical-input",
						Data: runtime.MakeInt(4)}, // 4 possible values (00, 01, 10, 11)
				},
			},
			{
				Number:      2,
				Description: "Alice encodes bits by applying I/X/Z/XZ to her qubit",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "encode",
						Data: p.encodingData()},
				},
			},
			{
				Number:      3,
				Description: "Alice sends her encoded qubit to Bob",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionSend, Target: "Bob",
						Data: runtime.MakeText("encoded-qubit")},
				},
			},
			{
				Number:      4,
				Description: "Bob performs Bell measurement on both qubits to decode",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionReceive, Target: "Alice"},
					{Actor: "Bob", Type: protocol.ActionMeasure, Target: "bell-measurement",
						Data: p.bellMeasurementData()},
				},
			},
		},
		Goal: p.superdenseGoal(),
		Assumptions: []protocol.Assumption{
			{
				Name:        "Perfect Entanglement",
				Description: "The shared Bell pair is a perfect |Phi+> state",
				Type:        protocol.AssumptionPerfectDevices,
			},
			{
				Name:        "Noiseless Quantum Channel",
				Description: "The quantum channel from Alice to Bob is noiseless",
				Type:        protocol.AssumptionNoSideChannel,
			},
		},
		TypeSig: protocol.TypeSignature{
			Domain:   runtime.Object{Blocks: []uint32{4, 4}}, // C(4) x Bell (4 = 2^2 classical bits, 4 = dim of Bell pair)
			Codomain: runtime.Object{Blocks: []uint32{4}},    // C(4) output
		},
	}
}

// superdenseGoal returns the security goal for superdense coding.
// We model this as a key agreement with capacity 2 bits per qubit.
func (p *SuperdenseCodingProtocol) superdenseGoal() protocol.SecurityGoal {
	// Superdense coding achieves 2 classical bits per qubit transmitted
	// Model as KeyAgreement with special interpretation:
	// - KeyLength: 2 (bits transmitted per round)
	// - ErrorRate: 0 (perfect decoding)
	// - SecrecyBound: N/A (not a secret channel, just capacity boost)
	return protocol.KeyAgreement{
		KeyLength:    2, // 2 bits per qubit
		ErrorRate:    &runtime.Rat{V: big.NewRat(0, 1)}, // Perfect
		SecrecyBound: nil, // Not applicable
	}
}

// Synthesize generates the superdense coding circuit and stores it.
func (p *SuperdenseCodingProtocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the complete superdense coding circuit
	// Input: classical bits (00, 01, 10, 11) + Bell pair
	// Output: decoded classical bits

	// Step 1: Encoding circuit (Alice's operation)
	encodeCircuit := p.synthesizeEncode(store)

	// Step 2: Bell measurement circuit (Bob's operation)
	decodeCircuit := p.synthesizeDecode(store)

	// Step 3: Compose the full protocol
	children := make([][32]byte, 2)
	children[0] = encodeCircuit
	children[1] = decodeCircuit

	mainCircuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{4, 4}}, // Classical bits + Bell pair
		Codomain: runtime.Object{Blocks: []uint32{4}},    // Decoded bits
		Prim:     runtime.PrimCompose,
		Data:     p.protocolMetadata(),
		Children: children,
	}

	return store.Put(mainCircuit), nil
}

// synthesizeEncode creates the encoding circuit.
// Alice applies I/X/Z/XZ to her qubit based on 2 classical bits.
func (p *SuperdenseCodingProtocol) synthesizeEncode(store *runtime.Store) [32]byte {
	// Create sub-circuits for each encoding operator
	encodings := AllSuperdenseEncodings()

	encodingChildren := make([][32]byte, 4)
	for i, enc := range encodings {
		circuit := runtime.Circuit{
			Domain:   runtime.Object{Blocks: []uint32{2}}, // Alice's qubit
			Codomain: runtime.Object{Blocks: []uint32{2}}, // Encoded qubit
			Prim:     runtime.PrimUnitary,
			Data:     runtime.MatrixToValue(enc),
		}
		encodingChildren[i] = store.Put(circuit)
	}

	// Branch based on classical input bits
	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{4, 2}}, // Classical bits (4 values) + Alice's qubit
		Codomain: runtime.Object{Blocks: []uint32{2}},    // Encoded qubit
		Prim:     runtime.PrimBranch,
		Data: runtime.MakeTag(
			runtime.MakeText("superdense-encoding"),
			runtime.MakeSeq(
				runtime.MakeText("00 -> I|psi>"),
				runtime.MakeText("01 -> X|psi>"),
				runtime.MakeText("10 -> Z|psi>"),
				runtime.MakeText("11 -> XZ|psi>"),
			),
		),
		Children: encodingChildren,
	}

	return store.Put(circuit)
}

// synthesizeDecode creates the decoding circuit.
// Bob performs Bell measurement on both qubits.
func (p *SuperdenseCodingProtocol) synthesizeDecode(store *runtime.Store) [32]byte {
	// Bell measurement unitary (inverse of Bell preparation)
	bellMeasureU := BellMeasurementUnitary()

	// Create unitary sub-circuit
	unitaryCircuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{4}}, // Two qubits
		Codomain: runtime.Object{Blocks: []uint32{4}}, // Two qubits (rotated)
		Prim:     runtime.PrimUnitary,
		Data:     runtime.MatrixToValue(bellMeasureU),
	}
	unitaryQGID := store.Put(unitaryCircuit)

	// Computational basis projectors
	projectors := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("00"),
			runtime.MatrixToValue(DensityMatrix(Ket00()))),
		runtime.MakeTag(runtime.MakeText("01"),
			runtime.MatrixToValue(DensityMatrix(Ket01()))),
		runtime.MakeTag(runtime.MakeText("10"),
			runtime.MatrixToValue(DensityMatrix(Ket10()))),
		runtime.MakeTag(runtime.MakeText("11"),
			runtime.MatrixToValue(DensityMatrix(Ket11()))),
	)

	// Create measurement circuit
	measureCircuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{4}}, // Two qubits
		Codomain: runtime.Object{Blocks: []uint32{4}}, // Classical output (4 values)
		Prim:     runtime.PrimInstrument,
		Data:     projectors,
	}
	measureQGID := store.Put(measureCircuit)

	// Compose: measure after unitary
	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{4}}, // Bob's two qubits (received + his Bell half)
		Codomain: runtime.Object{Blocks: []uint32{4}}, // Decoded classical bits
		Prim:     runtime.PrimCompose,
		Data: runtime.MakeTag(
			runtime.MakeText("bell-measurement-decode"),
			runtime.MakeText("CNOT then H then measure"),
		),
		Children: [][32]byte{unitaryQGID, measureQGID},
	}

	return store.Put(circuit)
}

// encodingData returns the encoding operator data for the protocol specification.
func (p *SuperdenseCodingProtocol) encodingData() runtime.Value {
	encodings := AllSuperdenseEncodings()
	return runtime.MakeTag(
		runtime.MakeText("encoding-operators"),
		runtime.MakeSeq(
			GateToValue("I", encodings[0]),
			GateToValue("X", encodings[1]),
			GateToValue("Z", encodings[2]),
			GateToValue("XZ", encodings[3]),
		),
	)
}

// bellMeasurementData returns the Bell measurement data.
func (p *SuperdenseCodingProtocol) bellMeasurementData() runtime.Value {
	projectors := BellMeasurementProjectors()
	return runtime.MakeTag(
		runtime.MakeText("bell-projectors"),
		runtime.MakeSeq(
			StateToValue("Phi+", projectors[0]),
			StateToValue("Phi-", projectors[1]),
			StateToValue("Psi+", projectors[2]),
			StateToValue("Psi-", projectors[3]),
		),
	)
}

// protocolMetadata returns metadata for the superdense coding protocol.
func (p *SuperdenseCodingProtocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("SuperdenseCoding"),
			runtime.MakeText("Bennett-Wiesner 1992"),
			runtime.MakeBigRat(big.NewRat(2, 1)), // Capacity: 2 bits per qubit
			runtime.MakeInt(1),                   // Qubits transmitted
			runtime.MakeInt(1),                   // Bell pairs required
		),
	)
}

// Capacity returns the classical capacity in bits per qubit.
// For superdense coding, this is exactly 2.
func (p *SuperdenseCodingProtocol) Capacity() *big.Rat {
	return big.NewRat(2, 1)
}

// QubitsTransmitted returns the number of qubits sent.
func (p *SuperdenseCodingProtocol) QubitsTransmitted() int {
	return 1
}

// BellPairsRequired returns the number of Bell pairs needed.
func (p *SuperdenseCodingProtocol) BellPairsRequired() int {
	return 1
}

// ClassicalBitsTransmitted returns the number of classical bits transmitted.
func (p *SuperdenseCodingProtocol) ClassicalBitsTransmitted() int {
	return 2
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *SuperdenseCodingProtocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("superdense-protocol"),
		runtime.MakeSeq(
			runtime.MakeBigRat(p.Capacity()),
			runtime.MakeInt(int64(p.QubitsTransmitted())),
			runtime.MakeInt(int64(p.BellPairsRequired())),
			runtime.MakeInt(int64(p.ClassicalBitsTransmitted())),
			p.Protocol().ToValue(),
		),
	)
}

// SuperdenseCodingFromValue deserializes a SuperdenseCodingProtocol from a runtime.Value.
func SuperdenseCodingFromValue(v runtime.Value) (*SuperdenseCodingProtocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "superdense-protocol" {
		return nil, false
	}
	// Protocol is stateless, so just verify the tag is correct
	return NewSuperdenseCoding(), true
}

// ===============================
// Superdense coding verification
// ===============================

// SuperdenseVerifier provides methods to verify superdense coding correctness.
type SuperdenseVerifier struct {
	protocol *SuperdenseCodingProtocol
}

// NewSuperdenseVerifier creates a new verifier.
func NewSuperdenseVerifier() *SuperdenseVerifier {
	return &SuperdenseVerifier{
		protocol: NewSuperdenseCoding(),
	}
}

// VerifyEncodingDecoding verifies that encoding and decoding are inverses.
// For each input (b1, b2), the decoded output should equal the input.
func (v *SuperdenseVerifier) VerifyEncodingDecoding() bool {
	// The encoding-decoding process works as follows:
	// 1. Start with |Phi+> = (|00> + |11>)/sqrt(2)
	// 2. Alice applies encoding E_{b1,b2} to her qubit (first qubit)
	// 3. State becomes: (E tensor I)|Phi+> which is another Bell state
	// 4. Bob performs Bell measurement and recovers (b1, b2)
	//
	// Encoding map:
	// I|Phi+> = |Phi+>  -> outcome 00
	// X|Phi+> = |Psi+>  -> outcome 01 (need to verify mapping)
	// Z|Phi+> = |Phi->  -> outcome 10
	// XZ|Phi+> = |Psi-> -> outcome 11

	encodings := AllSuperdenseEncodings()
	phiPlus := BellPhiPlus()

	// Apply each encoding to first qubit of |Phi+>
	for i, enc := range encodings {
		// E tensor I
		encI := tensorIdentity(enc, 2)
		// Apply to |Phi+>
		encoded := runtime.MatMul(encI, phiPlus)

		// Check which Bell state results
		bellIdx := identifyBellState(encoded)
		if bellIdx != i {
			return false // Encoding-decoding mismatch
		}
	}

	return true
}

// tensorIdentity returns E tensor I where I is n x n identity.
func tensorIdentity(e *runtime.Matrix, n int) *runtime.Matrix {
	// E is 2x2, result is 2n x 2n
	result := runtime.NewMatrix(2*n, 2*n)
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			eij := e.Get(i, j)
			for k := 0; k < n; k++ {
				// (E tensor I)[i*n+k, j*n+k] = E[i,j] * I[k,k] = E[i,j]
				result.Set(i*n+k, j*n+k, eij)
			}
		}
	}
	return result
}

// identifyBellState determines which Bell state a vector represents.
// Returns 0 for |Phi+>, 1 for |Phi->, 2 for |Psi+>, 3 for |Psi->, -1 if not a Bell state.
func identifyBellState(state *runtime.Matrix) int {
	bellStates := [4]*runtime.Matrix{
		BellPhiPlus(),
		BellPhiMinus(),
		BellPsiPlus(),
		BellPsiMinus(),
	}

	for i, bell := range bellStates {
		if statesEqual(state, bell) {
			return i
		}
	}
	return -1
}

// statesEqual checks if two state vectors are equal (up to global phase).
func statesEqual(a, b *runtime.Matrix) bool {
	if a.Rows != b.Rows || a.Cols != b.Cols {
		return false
	}

	// Find first non-zero entry to determine global phase
	var phaseA, phaseB runtime.QI
	found := false
	for i := 0; i < a.Rows && !found; i++ {
		for j := 0; j < a.Cols && !found; j++ {
			ai := a.Get(i, j)
			bi := b.Get(i, j)
			if ai.Re.Sign() != 0 || ai.Im.Sign() != 0 {
				phaseA = ai
				phaseB = bi
				found = true
			}
		}
	}

	if !found {
		// Both vectors are zero
		return true
	}

	// Check if all entries have the same ratio
	for i := 0; i < a.Rows; i++ {
		for j := 0; j < a.Cols; j++ {
			ai := a.Get(i, j)
			bi := b.Get(i, j)

			// Check ai * phaseB == bi * phaseA (cross multiply to avoid division)
			lhs := runtime.QIMul(ai, phaseB)
			rhs := runtime.QIMul(bi, phaseA)

			if lhs.Re.Cmp(rhs.Re) != 0 || lhs.Im.Cmp(rhs.Im) != 0 {
				return false
			}
		}
	}

	return true
}
