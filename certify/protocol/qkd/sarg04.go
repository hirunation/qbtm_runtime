package qkd

import (
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// SARG04Protocol implements the Scarani-Acin-Ribordy-Gisin 2004 QKD protocol.
// This is a PNS-resistant variant of BB84.
//
// Key difference from BB84:
// Instead of announcing the basis used, Alice announces a pair of non-orthogonal states,
// one of which was the actual state sent.
//
// States: Same as BB84 (|0>, |1>, |+>, |->)
// Announcement: "The state was either |0> or |+>" (or other valid pairs)
// Bob must use measurement to determine which state was sent.
//
// Type signature: (C(2) x C(2))^n -> C(2)^m
//
// Security: More robust against photon-number-splitting (PNS) attacks
// Key rate: Depends on photon number distribution, lower than BB84 for single photons
// Error threshold: Similar to BB84 for single-photon sources
type SARG04Protocol struct {
	// NumQubits is the number of qubits to transmit.
	NumQubits int

	// ErrorBound is the maximum tolerated error rate.
	ErrorBound *big.Rat

	// PhotonNumberMean is the mean photon number per pulse (for weak coherent sources).
	PhotonNumberMean *big.Rat
}

// NewSARG04 creates a new SARG04 protocol with the given number of qubits.
func NewSARG04(numQubits int) *SARG04Protocol {
	return &SARG04Protocol{
		NumQubits:        numQubits,
		ErrorBound:       big.NewRat(10, 100), // 10% error bound
		PhotonNumberMean: big.NewRat(1, 10),   // mu = 0.1 typical for QKD
	}
}

// NewSARG04WithParams creates a SARG04 protocol with custom parameters.
func NewSARG04WithParams(numQubits int, errorBound, photonMean *big.Rat) *SARG04Protocol {
	return &SARG04Protocol{
		NumQubits:        numQubits,
		ErrorBound:       errorBound,
		PhotonNumberMean: photonMean,
	}
}

// Protocol returns the complete protocol specification.
func (p *SARG04Protocol) Protocol() *protocol.Protocol {
	return &protocol.Protocol{
		Name:        "SARG04",
		Description: "Scarani-Acin-Ribordy-Gisin 2004 PNS-resistant QKD protocol",
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
				Description: "Quantum transmission: Alice prepares random bits in random bases (same as BB84)",
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
				Description: "SARG04 Announcement: Alice announces non-orthogonal state pairs instead of bases",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "state-pairs"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "decode"},
				},
			},
			{
				Number:      4,
				Description: "Sifting: Bob announces which measurements were conclusive",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "conclusive-positions"},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "keep-bits"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "keep-bits"},
				},
			},
			{
				Number:      5,
				Description: "Error estimation",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "test-bits"},
					{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "test-bits"},
					{Actor: "Alice", Type: protocol.ActionCompute, Target: "qber"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "qber"},
				},
			},
			{
				Number:      6,
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
		},
		TypeSig: protocol.TypeSignature{
			Domain:   p.domainObject(),
			Codomain: p.codomainObject(),
		},
	}
}

// Synthesize generates the protocol circuit and stores it.
func (p *SARG04Protocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the SARG04 circuit

	// Create preparation circuit (same as BB84)
	prepCircuit := p.synthesizePrepare(store)

	// Create measurement circuit
	measureCircuit := p.synthesizeMeasure(store)

	// Create SARG04 announcement encoding
	announcementCircuit := p.synthesizeAnnouncement(store)

	// Create decoding circuit
	decodeCircuit := p.synthesizeDecode(store)

	// Compose the full protocol
	children := make([][32]byte, 4)
	children[0] = prepCircuit
	children[1] = measureCircuit
	children[2] = announcementCircuit
	children[3] = decodeCircuit

	mainCircuit := runtime.Circuit{
		Domain:   p.domainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimCompose,
		Data:     p.protocolMetadata(),
		Children: children,
	}

	return store.Put(mainCircuit), nil
}

// synthesizePrepare creates the state preparation circuit (same as BB84).
func (p *SARG04Protocol) synthesizePrepare(store *runtime.Store) [32]byte {
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
func (p *SARG04Protocol) synthesizeMeasure(store *runtime.Store) [32]byte {
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

// synthesizeAnnouncement creates the SARG04 state pair announcement circuit.
func (p *SARG04Protocol) synthesizeAnnouncement(store *runtime.Store) [32]byte {
	// SARG04 announcement: Alice announces one of four state pairs
	// Each pair contains two non-orthogonal states from different bases
	//
	// Pair 0: {|0>, |+>}  - announced if Alice sent |0>
	// Pair 1: {|1>, |->}  - announced if Alice sent |1>
	// Pair 2: {|+>, |1>}  - announced if Alice sent |+>
	// Pair 3: {|->, |0>}  - announced if Alice sent |->
	//
	// The actual state sent is the first element of the pair
	// Bob must determine which state was sent from his measurement

	statePairs := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("pair-0"),
			runtime.MakeSeq(
				runtime.MakeText("|0>, |+>"),
				runtime.MatrixToValue(Ket0()),
				runtime.MatrixToValue(KetPlus()),
			)),
		runtime.MakeTag(runtime.MakeText("pair-1"),
			runtime.MakeSeq(
				runtime.MakeText("|1>, |->"),
				runtime.MatrixToValue(Ket1()),
				runtime.MatrixToValue(KetMinus()),
			)),
		runtime.MakeTag(runtime.MakeText("pair-2"),
			runtime.MakeSeq(
				runtime.MakeText("|+>, |1>"),
				runtime.MatrixToValue(KetPlus()),
				runtime.MatrixToValue(Ket1()),
			)),
		runtime.MakeTag(runtime.MakeText("pair-3"),
			runtime.MakeSeq(
				runtime.MakeText("|->, |0>"),
				runtime.MatrixToValue(KetMinus()),
				runtime.MatrixToValue(Ket0()),
			)),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2}}, // bit, basis (Alice's encoding)
		Codomain: runtime.Object{Blocks: []uint32{4}},    // state pair index (4 possibilities)
		Prim:     runtime.PrimEncode,
		Data:     statePairs,
	}

	return store.Put(circuit)
}

// synthesizeDecode creates the SARG04 decoding circuit.
func (p *SARG04Protocol) synthesizeDecode(store *runtime.Store) [32]byte {
	// Bob's decoding logic:
	// Given announced pair and measurement result, determine if conclusive
	//
	// For pair {|0>, |+>}: If Bob measured in X and got |-> -> conclusively |0>
	// For pair {|1>, |->}: If Bob measured in X and got |+> -> conclusively |1>
	// For pair {|+>, |1>}: If Bob measured in Z and got |0> -> conclusively |+>
	// For pair {|->, |0>}: If Bob measured in Z and got |1> -> conclusively |->
	//
	// Other combinations are inconclusive

	decodingRules := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("rule-0"),
			runtime.MakeSeq(
				runtime.MakeText("pair {|0>,|+>}, basis X, outcome |->) -> bit 0"),
				runtime.MakeInt(0), // pair index
				runtime.MakeInt(1), // X basis
				runtime.MakeInt(1), // outcome |->
				runtime.MakeInt(0), // decoded bit
			)),
		runtime.MakeTag(runtime.MakeText("rule-1"),
			runtime.MakeSeq(
				runtime.MakeText("pair {|1>,|->}, basis X, outcome |+>) -> bit 1"),
				runtime.MakeInt(1),
				runtime.MakeInt(1),
				runtime.MakeInt(0),
				runtime.MakeInt(1),
			)),
		runtime.MakeTag(runtime.MakeText("rule-2"),
			runtime.MakeSeq(
				runtime.MakeText("pair {|+>,|1>}, basis Z, outcome |0>) -> bit 0"),
				runtime.MakeInt(2),
				runtime.MakeInt(0),
				runtime.MakeInt(0),
				runtime.MakeInt(0),
			)),
		runtime.MakeTag(runtime.MakeText("rule-3"),
			runtime.MakeSeq(
				runtime.MakeText("pair {|->,|0>}, basis Z, outcome |1>) -> bit 1"),
				runtime.MakeInt(3),
				runtime.MakeInt(0),
				runtime.MakeInt(1),
				runtime.MakeInt(1),
			)),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{4, 2, 2}}, // pair_index, bob_basis, bob_outcome
		Codomain: runtime.Object{Blocks: []uint32{2, 2}},    // conclusive_flag, decoded_bit
		Prim:     runtime.PrimBranch,
		Data:     decodingRules,
	}

	return store.Put(circuit)
}

// KeyRate computes the key rate for SARG04.
// For single-photon source: similar to BB84
// For weak coherent source: improved resistance to PNS attacks
func (p *SARG04Protocol) KeyRate(errorRate *big.Rat) *big.Rat {
	// SARG04 has lower key rate than BB84 for single photons
	// but better performance for weak coherent sources

	// Error threshold
	if errorRate.Cmp(p.ErrorBound) > 0 {
		return big.NewRat(0, 1)
	}

	// For single-photon source:
	// SARG04 conclusive rate: ~25% (vs BB84's ~50%)
	// But PNS resistance is improved

	// Simplified: r ~ 1/4 * (1 - 4*e) for small e
	e := new(big.Rat).Set(errorRate)
	fourE := new(big.Rat).Mul(big.NewRat(4, 1), e)
	oneMinus := new(big.Rat).Sub(big.NewRat(1, 1), fourE)

	rate := new(big.Rat).Mul(big.NewRat(1, 4), oneMinus)
	if rate.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	return rate
}

// ErrorThreshold returns the maximum tolerable error rate.
func (p *SARG04Protocol) ErrorThreshold() *big.Rat {
	return big.NewRat(10, 100) // 10%
}

// ConclusiveRate returns the probability of a conclusive measurement.
// For SARG04: 1/4 (vs BB84's 1/2 after sifting).
func (p *SARG04Protocol) ConclusiveRate() *big.Rat {
	return big.NewRat(1, 4)
}

// PNSResistance returns a measure of PNS attack resistance.
// SARG04 requires Eve to measure in both bases to determine Alice's state,
// making PNS attacks more detectable.
func (p *SARG04Protocol) PNSResistance() *big.Rat {
	// SARG04 provides improved resistance by factor ~2 in terms of
	// critical photon number for PNS attacks
	return big.NewRat(2, 1)
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *SARG04Protocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("sarg04-protocol"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(p.NumQubits)),
			runtime.MakeBigRat(p.ErrorBound),
			runtime.MakeBigRat(p.PhotonNumberMean),
			p.Protocol().ToValue(),
		),
	)
}

// SARG04FromValue deserializes a SARG04Protocol from a runtime.Value.
func SARG04FromValue(v runtime.Value) (*SARG04Protocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "sarg04-protocol" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
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
	photonMean, ok := seq.Items[2].(runtime.Rat)
	if !ok {
		return nil, false
	}

	return &SARG04Protocol{
		NumQubits:        int(numQubits.V.Int64()),
		ErrorBound:       new(big.Rat).Set(errorBound.V),
		PhotonNumberMean: new(big.Rat).Set(photonMean.V),
	}, true
}

// Helper methods

func (p *SARG04Protocol) domainObject() runtime.Object {
	blocks := make([]uint32, p.NumQubits*2)
	for i := 0; i < p.NumQubits*2; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *SARG04Protocol) codomainObject() runtime.Object {
	keyLen := p.estimatedKeyLength()
	blocks := make([]uint32, keyLen)
	for i := 0; i < keyLen; i++ {
		blocks[i] = 2
	}
	return runtime.Object{Blocks: blocks}
}

func (p *SARG04Protocol) estimatedKeyLength() int {
	// SARG04 has lower key rate than BB84
	// Conclusive rate is ~25%
	rate := p.KeyRate(p.ErrorBound)
	if rate.Sign() <= 0 {
		return 0
	}
	return p.NumQubits / 8
}

func (p *SARG04Protocol) secrecyBound() *big.Rat {
	return big.NewRat(1, 1000000)
}

func (p *SARG04Protocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("SARG04"),
			runtime.MakeText("Scarani-Acin-Ribordy-Gisin 2004"),
			runtime.MakeInt(int64(p.NumQubits)),
			runtime.MakeBigRat(p.ErrorBound),
			runtime.MakeBigRat(p.ErrorThreshold()),
			runtime.MakeBigRat(p.ConclusiveRate()),
			runtime.MakeBigRat(p.PhotonNumberMean),
		),
	)
}

// SARG04StatePairs returns the four state pairs used in announcements.
// Each pair contains the actual state and a non-orthogonal decoy state.
type SARG04StatePair struct {
	Index     int    // Pair index (0-3)
	ActualBit int    // The actual bit value
	State1    string // First state in pair (actual state)
	State2    string // Second state in pair (decoy, non-orthogonal)
}

// SARG04StatePairs returns all four state pairs.
func SARG04StatePairs() []SARG04StatePair {
	return []SARG04StatePair{
		{Index: 0, ActualBit: 0, State1: "|0>", State2: "|+>"},
		{Index: 1, ActualBit: 1, State1: "|1>", State2: "|->"},
		{Index: 2, ActualBit: 0, State1: "|+>", State2: "|1>"},
		{Index: 3, ActualBit: 1, State1: "|->", State2: "|0>"},
	}
}

// SARG04EncodingMap maps (bit, basis) to state pair index.
func SARG04EncodingMap(bit, basis int) int {
	// bit=0, basis=0 (|0>) -> pair 0: {|0>, |+>}
	// bit=1, basis=0 (|1>) -> pair 1: {|1>, |->}
	// bit=0, basis=1 (|+>) -> pair 2: {|+>, |1>}
	// bit=1, basis=1 (|->) -> pair 3: {|->, |0>}
	return basis*2 + bit
}

// SARG04DecodingMap determines if a measurement is conclusive and the bit value.
// Returns (conclusive, bit).
func SARG04DecodingMap(pairIndex, bobBasis, bobOutcome int) (bool, int) {
	// pair 0: Bob measures X, gets |-> -> conclusive, bit 0
	// pair 1: Bob measures X, gets |+> -> conclusive, bit 1
	// pair 2: Bob measures Z, gets |0> -> conclusive, bit 0
	// pair 3: Bob measures Z, gets |1> -> conclusive, bit 1

	switch pairIndex {
	case 0:
		if bobBasis == 1 && bobOutcome == 1 { // X basis, |->
			return true, 0
		}
	case 1:
		if bobBasis == 1 && bobOutcome == 0 { // X basis, |+>
			return true, 1
		}
	case 2:
		if bobBasis == 0 && bobOutcome == 0 { // Z basis, |0>
			return true, 0
		}
	case 3:
		if bobBasis == 0 && bobOutcome == 1 { // Z basis, |1>
			return true, 1
		}
	}
	return false, 0
}
