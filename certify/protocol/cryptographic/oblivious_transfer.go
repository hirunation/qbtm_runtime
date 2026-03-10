// Package cryptographic provides quantum cryptographic primitive implementations.
package cryptographic

import (
	"fmt"
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// ObliviousTransferProtocol implements quantum oblivious transfer (1-of-2 OT).
//
// Oblivious Transfer (OT) is a fundamental cryptographic primitive where:
// - Alice (sender) has two messages (m0, m1)
// - Bob (receiver) has a choice bit c
// - After the protocol: Bob learns m_c but not m_{1-c}
// - Alice learns nothing about c
//
// 1-of-2 OT is complete for two-party computation: any secure computation
// can be built using OT as a building block.
//
// Quantum OT provides several advantages:
// - Can achieve information-theoretic security (vs computational security)
// - Based on physical principles (no-cloning, uncertainty)
// - Composable security in universal composability framework
//
// Security parameters:
// - SenderPrivacy: Alice's privacy (Bob learns nothing about m_{1-c})
// - ReceiverPrivacy: Bob's privacy (Alice learns nothing about c)
//
// Type signature: C(2) x C(2) x C(2) -> C(2)
// (m0, m1, c) -> m_c
type ObliviousTransferProtocol struct {
	// SenderPrivacy is the security against cheating Bob.
	// Bob should not learn m_{1-c}. Range: [0, 1]
	SenderPrivacy *big.Rat

	// ReceiverPrivacy is the security against cheating Alice.
	// Alice should not learn the choice bit c. Range: [0, 1]
	ReceiverPrivacy *big.Rat
}

// NewObliviousTransfer creates a new OT protocol with specified security parameters.
func NewObliviousTransfer(senderPrivacy, receiverPrivacy *big.Rat) (*ObliviousTransferProtocol, error) {
	zero := big.NewRat(0, 1)
	one := big.NewRat(1, 1)

	if senderPrivacy.Cmp(zero) < 0 || senderPrivacy.Cmp(one) > 0 {
		return nil, fmt.Errorf("sender privacy must be in [0, 1], got %v", senderPrivacy.RatString())
	}
	if receiverPrivacy.Cmp(zero) < 0 || receiverPrivacy.Cmp(one) > 0 {
		return nil, fmt.Errorf("receiver privacy must be in [0, 1], got %v", receiverPrivacy.RatString())
	}

	return &ObliviousTransferProtocol{
		SenderPrivacy:   new(big.Rat).Set(senderPrivacy),
		ReceiverPrivacy: new(big.Rat).Set(receiverPrivacy),
	}, nil
}

// NewObliviousTransferIdeal creates an ideal OT with perfect security for both parties.
func NewObliviousTransferIdeal() *ObliviousTransferProtocol {
	one := big.NewRat(1, 1)
	return &ObliviousTransferProtocol{
		SenderPrivacy:   new(big.Rat).Set(one),
		ReceiverPrivacy: new(big.Rat).Set(one),
	}
}

// NewObliviousTransferBalanced creates a balanced OT with equal sender/receiver privacy.
func NewObliviousTransferBalanced(privacy *big.Rat) *ObliviousTransferProtocol {
	return &ObliviousTransferProtocol{
		SenderPrivacy:   new(big.Rat).Set(privacy),
		ReceiverPrivacy: new(big.Rat).Set(privacy),
	}
}

// NewObliviousTransferFromBitCommitment creates OT using bit commitment as building block.
// If bit commitment has (binding, hiding), the resulting OT has:
// - SenderPrivacy = hiding (Bob can't distinguish m0, m1 states)
// - ReceiverPrivacy = binding (Alice can't learn c)
func NewObliviousTransferFromBitCommitment(bc *BitCommitmentProtocol) *ObliviousTransferProtocol {
	return &ObliviousTransferProtocol{
		SenderPrivacy:   new(big.Rat).Set(bc.Hiding),
		ReceiverPrivacy: new(big.Rat).Set(bc.Binding),
	}
}

// Protocol returns the complete protocol specification.
func (p *ObliviousTransferProtocol) Protocol() *protocol.Protocol {
	return &protocol.Protocol{
		Name:        "Quantum1of2OT",
		Description: "Quantum 1-of-2 oblivious transfer with composable security",
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
					protocol.CapStore,
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
		Rounds: p.protocolRounds(),
		Goal: protocol.ObliviousTransfer{
			SenderPrivacy:   &runtime.Rat{V: new(big.Rat).Set(p.SenderPrivacy)},
			ReceiverPrivacy: &runtime.Rat{V: new(big.Rat).Set(p.ReceiverPrivacy)},
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

// protocolRounds returns the rounds for quantum OT protocol.
func (p *ObliviousTransferProtocol) protocolRounds() []protocol.Round {
	return []protocol.Round{
		{
			Number:      1,
			Description: "Alice prepares random qubits in random bases",
			Actions: []protocol.Action{
				{Actor: "Alice", Type: protocol.ActionPrepare, Target: "random-states",
					Data: p.alicePrepareData()},
			},
		},
		{
			Number:      2,
			Description: "Alice sends qubits to Bob",
			Actions: []protocol.Action{
				{Actor: "Alice", Type: protocol.ActionSend, Target: "Bob",
					Data: runtime.MakeText("quantum-states")},
			},
		},
		{
			Number:      3,
			Description: "Bob measures in basis determined by choice bit c",
			Actions: []protocol.Action{
				{Actor: "Bob", Type: protocol.ActionReceive, Target: "Alice"},
				{Actor: "Bob", Type: protocol.ActionMeasure, Target: "choice-basis",
					Data: p.bobMeasureData()},
			},
		},
		{
			Number:      4,
			Description: "Bob announces which qubits he received correctly",
			Actions: []protocol.Action{
				{Actor: "Bob", Type: protocol.ActionAnnounce, Target: "received-positions",
					Data: runtime.MakeText("subset-indices")},
			},
		},
		{
			Number:      5,
			Description: "Alice announces bases for all qubits",
			Actions: []protocol.Action{
				{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "all-bases",
					Data: runtime.MakeText("preparation-bases")},
			},
		},
		{
			Number:      6,
			Description: "Bob partitions positions by matching/non-matching basis",
			Actions: []protocol.Action{
				{Actor: "Bob", Type: protocol.ActionCompute, Target: "partition",
					Data: p.bobPartitionData()},
			},
		},
		{
			Number:      7,
			Description: "Alice sends m0 XOR (bits where Bob used basis 0), m1 XOR (bits where Bob used basis 1)",
			Actions: []protocol.Action{
				{Actor: "Alice", Type: protocol.ActionCompute, Target: "encode-messages",
					Data: p.aliceEncodeData()},
				{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "encoded-messages",
					Data: runtime.MakeText("m0-xor, m1-xor")},
			},
		},
		{
			Number:      8,
			Description: "Bob decodes m_c using his measurement results",
			Actions: []protocol.Action{
				{Actor: "Bob", Type: protocol.ActionCompute, Target: "decode",
					Data: p.bobDecodeData()},
			},
		},
	}
}

// Synthesize generates the OT circuit and stores it.
func (p *ObliviousTransferProtocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the OT circuit
	// Domain: C(2) x C(2) x C(2) for (m0, m1, c)
	// Codomain: C(2) for m_c

	// Create the encoding circuit (Alice prepares states based on messages)
	encodeCircuit := p.synthesizeEncode(store)

	// Create the transfer circuit (quantum transmission)
	transferCircuit := p.synthesizeTransfer(store)

	// Create the decoding circuit (Bob extracts m_c)
	decodeCircuit := p.synthesizeDecode(store)

	// Compose
	children := [][32]byte{encodeCircuit, transferCircuit, decodeCircuit}

	mainCircuit := runtime.Circuit{
		Domain:   p.domainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimCompose,
		Data:     p.protocolMetadata(),
		Children: children,
	}

	return store.Put(mainCircuit), nil
}

// synthesizeEncode creates Alice's encoding circuit.
func (p *ObliviousTransferProtocol) synthesizeEncode(store *runtime.Store) [32]byte {
	// Alice encodes messages into quantum states
	// For each bit position, prepare state based on (m0_i, m1_i, basis_i)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2}}, // m0, m1
		Codomain: runtime.Object{Blocks: []uint32{2, 2}}, // encoded states + basis info
		Prim:     runtime.PrimPrepare,
		Data: runtime.MakeTag(
			runtime.MakeText("ot-encode"),
			runtime.MakeSeq(
				runtime.MakeText("Encode messages into BB84-style states"),
				runtime.MakeText("m0 determines Z-basis encoding"),
				runtime.MakeText("m1 determines X-basis encoding"),
			),
		),
	}

	return store.Put(circuit)
}

// synthesizeTransfer creates the quantum transfer circuit.
func (p *ObliviousTransferProtocol) synthesizeTransfer(store *runtime.Store) [32]byte {
	// Quantum channel from Alice to Bob
	// Bob measures based on choice bit

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2, 2}}, // states, basis-info, choice-bit
		Codomain: runtime.Object{Blocks: []uint32{2, 2}},    // measurement results, which-message
		Prim:     runtime.PrimInstrument,
		Data: runtime.MakeTag(
			runtime.MakeText("ot-transfer"),
			runtime.MakeSeq(
				runtime.MakeText("Bob measures in basis determined by choice c"),
				runtime.MakeText("c=0: measure in Z-basis (gets bits correlated with m0)"),
				runtime.MakeText("c=1: measure in X-basis (gets bits correlated with m1)"),
			),
		),
	}

	return store.Put(circuit)
}

// synthesizeDecode creates Bob's decoding circuit.
func (p *ObliviousTransferProtocol) synthesizeDecode(store *runtime.Store) [32]byte {
	// Bob extracts m_c from his measurement results and Alice's announcement
	// Use PrimBranch for classical computation (XOR decoding)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2}}, // measurement results, encoded messages
		Codomain: runtime.Object{Blocks: []uint32{2}},    // decoded m_c
		Prim:     runtime.PrimBranch,
		Data: runtime.MakeTag(
			runtime.MakeText("ot-decode"),
			runtime.MakeSeq(
				runtime.MakeText("XOR measurement results with appropriate encoded message"),
				runtime.MakeText("Bob gets m_c, learns nothing about m_{1-c}"),
			),
		),
	}

	return store.Put(circuit)
}

// SenderPrivacyLeakage returns how much Bob learns about m_{1-c}.
// This equals 1 - SenderPrivacy.
func (p *ObliviousTransferProtocol) SenderPrivacyLeakage() *big.Rat {
	one := big.NewRat(1, 1)
	return new(big.Rat).Sub(one, p.SenderPrivacy)
}

// ReceiverPrivacyLeakage returns how much Alice learns about c.
// This equals 1 - ReceiverPrivacy.
func (p *ObliviousTransferProtocol) ReceiverPrivacyLeakage() *big.Rat {
	one := big.NewRat(1, 1)
	return new(big.Rat).Sub(one, p.ReceiverPrivacy)
}

// IsIdeal checks if this OT has perfect security for both parties.
func (p *ObliviousTransferProtocol) IsIdeal() bool {
	one := big.NewRat(1, 1)
	return p.SenderPrivacy.Cmp(one) == 0 && p.ReceiverPrivacy.Cmp(one) == 0
}

// IsComposable returns true if this OT is composably secure.
// Composable security means the OT can be safely composed with other protocols.
func (p *ObliviousTransferProtocol) IsComposable() bool {
	// For composable security, both privacies should be sufficiently high
	threshold := big.NewRat(1, 2)
	return p.SenderPrivacy.Cmp(threshold) >= 0 && p.ReceiverPrivacy.Cmp(threshold) >= 0
}

// SecurityLevel returns the minimum of sender and receiver privacy.
func (p *ObliviousTransferProtocol) SecurityLevel() *big.Rat {
	if p.SenderPrivacy.Cmp(p.ReceiverPrivacy) < 0 {
		return new(big.Rat).Set(p.SenderPrivacy)
	}
	return new(big.Rat).Set(p.ReceiverPrivacy)
}

// Helper methods

func (p *ObliviousTransferProtocol) domainObject() runtime.Object {
	// Input: (m0, m1, c) - two messages and choice bit
	return runtime.Object{Blocks: []uint32{2, 2, 2}}
}

func (p *ObliviousTransferProtocol) codomainObject() runtime.Object {
	// Output: m_c - the chosen message
	return runtime.Object{Blocks: []uint32{2}}
}

func (p *ObliviousTransferProtocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("Quantum1of2OT"),
			runtime.MakeText("1-of-2 Oblivious Transfer"),
			runtime.MakeBigRat(p.SenderPrivacy),
			runtime.MakeBigRat(p.ReceiverPrivacy),
			runtime.MakeBool(p.IsIdeal()),
			runtime.MakeBool(p.IsComposable()),
		),
	)
}

func (p *ObliviousTransferProtocol) alicePrepareData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("ot-alice-prepare"),
		runtime.MakeSeq(
			runtime.MakeText("Prepare n random qubits in random Z or X basis"),
			runtime.MakeText("Z-basis states encode information related to m0"),
			runtime.MakeText("X-basis states encode information related to m1"),
		),
	)
}

func (p *ObliviousTransferProtocol) bobMeasureData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("ot-bob-measure"),
		runtime.MakeSeq(
			runtime.MakeText("Bob measures all qubits"),
			runtime.MakeText("Uses Z-basis if c=0 (to get m0)"),
			runtime.MakeText("Uses X-basis if c=1 (to get m1)"),
		),
	)
}

func (p *ObliviousTransferProtocol) bobPartitionData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("ot-bob-partition"),
		runtime.MakeSeq(
			runtime.MakeText("Partition positions into I0 (matching Z) and I1 (matching X)"),
			runtime.MakeText("Positions in I_c give Bob correct bits for m_c"),
		),
	)
}

func (p *ObliviousTransferProtocol) aliceEncodeData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("ot-alice-encode"),
		runtime.MakeSeq(
			runtime.MakeText("Alice computes x0 = m0 XOR (bits in I0)"),
			runtime.MakeText("Alice computes x1 = m1 XOR (bits in I1)"),
			runtime.MakeText("Alice sends (x0, x1) to Bob"),
		),
	)
}

func (p *ObliviousTransferProtocol) bobDecodeData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("ot-bob-decode"),
		runtime.MakeSeq(
			runtime.MakeText("Bob computes m_c = x_c XOR (his bits in I_c)"),
			runtime.MakeText("Bob cannot compute m_{1-c} (wrong basis measurement)"),
		),
	)
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *ObliviousTransferProtocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("oblivious-transfer-protocol"),
		runtime.MakeSeq(
			runtime.MakeBigRat(p.SenderPrivacy),
			runtime.MakeBigRat(p.ReceiverPrivacy),
			p.Protocol().ToValue(),
		),
	)
}

// ObliviousTransferFromValue deserializes an ObliviousTransferProtocol from a runtime.Value.
func ObliviousTransferFromValue(v runtime.Value) (*ObliviousTransferProtocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "oblivious-transfer-protocol" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 2 {
		return nil, false
	}

	senderPrivacy, ok := seq.Items[0].(runtime.Rat)
	if !ok {
		return nil, false
	}
	receiverPrivacy, ok := seq.Items[1].(runtime.Rat)
	if !ok {
		return nil, false
	}

	return &ObliviousTransferProtocol{
		SenderPrivacy:   new(big.Rat).Set(senderPrivacy.V),
		ReceiverPrivacy: new(big.Rat).Set(receiverPrivacy.V),
	}, true
}

// ===============================
// OT Extensions and Variants
// ===============================

// RabinOT represents Rabin's original OT variant where Bob receives
// the message with probability 1/2 and Alice doesn't know if he received it.
type RabinOT struct {
	TransmissionProbability *big.Rat // Probability Bob receives the message
}

// NewRabinOT creates a Rabin OT with transmission probability 1/2.
func NewRabinOT() *RabinOT {
	return &RabinOT{
		TransmissionProbability: big.NewRat(1, 2),
	}
}

// ChosenOneOT represents chosen 1-of-n OT where Bob can choose one of n messages.
type ChosenOneOT struct {
	NumMessages     int      // n - number of messages Alice has
	SenderPrivacy   *big.Rat // Bob learns nothing about other messages
	ReceiverPrivacy *big.Rat // Alice learns nothing about Bob's choice
}

// NewChosenOneOT creates a 1-of-n OT protocol.
func NewChosenOneOT(n int, senderPrivacy, receiverPrivacy *big.Rat) *ChosenOneOT {
	if n < 2 {
		n = 2
	}
	return &ChosenOneOT{
		NumMessages:     n,
		SenderPrivacy:   new(big.Rat).Set(senderPrivacy),
		ReceiverPrivacy: new(big.Rat).Set(receiverPrivacy),
	}
}

// ===============================
// OT Completeness
// ===============================

// OTCompletenessDescription describes OT's role as a complete primitive.
func OTCompletenessDescription() string {
	return `Oblivious Transfer Completeness:

OT is a complete primitive for secure two-party computation:
- Any secure computation can be built using OT as a building block
- Kilian (1988): OT implies any secure computation
- OT is equivalent to:
  - 1-of-2 bit OT
  - String OT (transfer of strings instead of bits)
  - Committed OT
  - Rabin OT (probabilistic variant)

Quantum OT advantages:
- Information-theoretic security (no computational assumptions)
- Composable security (UC-secure)
- Based on physical principles (no-cloning, uncertainty)

OT from Bit Commitment:
- If we have secure bit commitment, we can build OT
- Alice commits to random bits
- Bob requests unveiling based on choice
- Security inherited from bit commitment`
}
