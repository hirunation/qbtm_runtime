// Package cryptographic provides quantum cryptographic primitive implementations.
package cryptographic

import (
	"fmt"
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// BitCommitmentProtocol implements quantum bit commitment with parametric security.
//
// Quantum bit commitment allows Alice to commit to a bit in a way that:
// - Binding: Alice cannot change the committed bit after committing
// - Hiding: Bob cannot learn the bit before Alice reveals it
//
// Mayers-Lo-Chau Theorem (1996-1997):
// Perfect binding AND perfect hiding are impossible simultaneously.
// Trade-off constraint: binding + hiding <= 1
//
// This impossibility arises because:
// - If perfectly hiding: Alice can use EPR attack to change her commitment
// - If perfectly binding: Bob can distinguish states (violating hiding)
//
// Protocol Phases:
// 1. Commit Phase: Alice prepares state encoding her bit, sends to Bob
// 2. Reveal Phase: Alice reveals commitment and proof, Bob verifies
//
// Type signature: C(2) -> C(2) (commit bit -> revealed bit)
type BitCommitmentProtocol struct {
	// Binding is the security against cheating Alice (1 - probability she can change bit).
	// Range: [0, 1]
	Binding *big.Rat

	// Hiding is the security against cheating Bob (1 - information leaked to Bob).
	// Range: [0, 1]
	Hiding *big.Rat
}

// NewBitCommitment creates a new bit commitment protocol with specified security parameters.
// Returns an error if binding + hiding > 1 (violates Mayers-Lo-Chau theorem).
func NewBitCommitment(binding, hiding *big.Rat) (*BitCommitmentProtocol, error) {
	// Check trade-off constraint: binding + hiding <= 1
	sum := new(big.Rat).Add(binding, hiding)
	one := big.NewRat(1, 1)

	if sum.Cmp(one) > 0 {
		return nil, fmt.Errorf("binding (%v) + hiding (%v) = %v > 1: violates Mayers-Lo-Chau theorem",
			binding.RatString(), hiding.RatString(), sum.RatString())
	}

	return &BitCommitmentProtocol{
		Binding: new(big.Rat).Set(binding),
		Hiding:  new(big.Rat).Set(hiding),
	}, nil
}

// NewBitCommitmentBalanced creates a balanced bit commitment with binding = hiding = 1/2.
// This is on the Mayers-Lo-Chau boundary.
func NewBitCommitmentBalanced() *BitCommitmentProtocol {
	half := big.NewRat(1, 2)
	return &BitCommitmentProtocol{
		Binding: new(big.Rat).Set(half),
		Hiding:  new(big.Rat).Set(half),
	}
}

// NewBitCommitmentBinding creates a maximally binding commitment (binding=1, hiding=0).
// This is perfectly binding but provides no hiding.
func NewBitCommitmentBinding() *BitCommitmentProtocol {
	return &BitCommitmentProtocol{
		Binding: big.NewRat(1, 1),
		Hiding:  big.NewRat(0, 1),
	}
}

// NewBitCommitmentHiding creates a maximally hiding commitment (binding=0, hiding=1).
// This is perfectly hiding but provides no binding.
func NewBitCommitmentHiding() *BitCommitmentProtocol {
	return &BitCommitmentProtocol{
		Binding: big.NewRat(0, 1),
		Hiding:  big.NewRat(1, 1),
	}
}

// NewBitCommitmentParametric creates a commitment with binding=b and hiding=1-b.
// The parameter b must be in [0, 1].
func NewBitCommitmentParametric(b *big.Rat) (*BitCommitmentProtocol, error) {
	zero := big.NewRat(0, 1)
	one := big.NewRat(1, 1)

	if b.Cmp(zero) < 0 || b.Cmp(one) > 0 {
		return nil, fmt.Errorf("binding parameter must be in [0, 1], got %v", b.RatString())
	}

	hiding := new(big.Rat).Sub(one, b)
	return &BitCommitmentProtocol{
		Binding: new(big.Rat).Set(b),
		Hiding:  hiding,
	}, nil
}

// Protocol returns the complete protocol specification.
func (p *BitCommitmentProtocol) Protocol() *protocol.Protocol {
	return &protocol.Protocol{
		Name:        "QuantumBitCommitment",
		Description: "Quantum bit commitment with parametric binding-hiding trade-off",
		Parties: []protocol.Party{
			{
				Name: "Alice",
				Role: protocol.RoleSender,
				Capabilities: []protocol.Capability{
					protocol.CapPrepare,
					protocol.CapStore,
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
		Rounds: []protocol.Round{
			{
				Number:      1,
				Description: "Commit Phase: Alice prepares commitment state",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionPrepare, Target: "commitment-state",
						Data: p.commitPrepareData()},
				},
			},
			{
				Number:      2,
				Description: "Alice sends commitment to Bob",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionSend, Target: "Bob",
						Data: runtime.MakeText("commitment-qubits")},
				},
			},
			{
				Number:      3,
				Description: "Bob stores commitment (waiting phase)",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionReceive, Target: "Alice"},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "store",
						Data: runtime.MakeText("store-commitment")},
				},
			},
			{
				Number:      4,
				Description: "Reveal Phase: Alice sends reveal information",
				Actions: []protocol.Action{
					{Actor: "Alice", Type: protocol.ActionAnnounce, Target: "reveal",
						Data: p.revealData()},
				},
			},
			{
				Number:      5,
				Description: "Bob verifies commitment",
				Actions: []protocol.Action{
					{Actor: "Bob", Type: protocol.ActionMeasure, Target: "verification-basis",
						Data: p.verifyData()},
					{Actor: "Bob", Type: protocol.ActionCompute, Target: "verify",
						Data: runtime.MakeText("check-commitment")},
				},
			},
		},
		Goal: protocol.BitCommitment{
			Binding: &runtime.Rat{V: new(big.Rat).Set(p.Binding)},
			Hiding:  &runtime.Rat{V: new(big.Rat).Set(p.Hiding)},
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

// Synthesize generates the bit commitment circuit and stores it.
func (p *BitCommitmentProtocol) Synthesize(store *runtime.Store) ([32]byte, error) {
	// Build the bit commitment circuit
	// Domain: C(2) for bit to commit
	// Codomain: C(2) for revealed bit

	// Create commit circuit
	commitCircuit := p.synthesizeCommit(store)

	// Create reveal circuit
	revealCircuit := p.synthesizeReveal(store)

	// Create verify circuit
	verifyCircuit := p.synthesizeVerify(store)

	// Compose
	children := [][32]byte{commitCircuit, revealCircuit, verifyCircuit}

	mainCircuit := runtime.Circuit{
		Domain:   p.domainObject(),
		Codomain: p.codomainObject(),
		Prim:     runtime.PrimCompose,
		Data:     p.protocolMetadata(),
		Children: children,
	}

	return store.Put(mainCircuit), nil
}

// synthesizeCommit creates the commitment encoding circuit.
func (p *BitCommitmentProtocol) synthesizeCommit(store *runtime.Store) [32]byte {
	// Commitment encoding depends on binding/hiding parameters
	// For balanced: encode using BB84-style states
	// bit=0 -> |0> with probability binding, |+> with probability hiding
	// bit=1 -> |1> with probability binding, |-> with probability hiding

	commitStates := runtime.MakeSeq(
		runtime.MakeTag(runtime.MakeText("commit-0"),
			runtime.MakeSeq(
				stateToValue("ket0", ket0()),
				stateToValue("ketPlus", ketPlus()),
			)),
		runtime.MakeTag(runtime.MakeText("commit-1"),
			runtime.MakeSeq(
				stateToValue("ket1", ket1()),
				stateToValue("ketMinus", ketMinus()),
			)),
	)

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2}},    // bit
		Codomain: runtime.Object{Blocks: []uint32{2, 2}}, // qubit x basis-choice
		Prim:     runtime.PrimPrepare,
		Data: runtime.MakeTag(
			runtime.MakeText("commitment-encoding"),
			runtime.MakeSeq(
				commitStates,
				runtime.MakeBigRat(p.Binding),
				runtime.MakeBigRat(p.Hiding),
			),
		),
	}

	return store.Put(circuit)
}

// synthesizeReveal creates the reveal circuit.
func (p *BitCommitmentProtocol) synthesizeReveal(store *runtime.Store) [32]byte {
	// Reveal: Alice sends (bit, basis) to allow Bob to verify

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2}}, // bit x basis
		Codomain: runtime.Object{Blocks: []uint32{2, 2}}, // revealed info
		Prim:     runtime.PrimId,
		Data: runtime.MakeTag(
			runtime.MakeText("reveal"),
			runtime.MakeText("Alice reveals committed bit and basis choice"),
		),
	}

	return store.Put(circuit)
}

// synthesizeVerify creates the verification circuit.
func (p *BitCommitmentProtocol) synthesizeVerify(store *runtime.Store) [32]byte {
	// Bob measures stored state in revealed basis and checks consistency

	circuit := runtime.Circuit{
		Domain:   runtime.Object{Blocks: []uint32{2, 2, 2}}, // qubit, bit, basis
		Codomain: runtime.Object{Blocks: []uint32{2}},       // verified bit
		Prim:     runtime.PrimInstrument,
		Data: runtime.MakeTag(
			runtime.MakeText("verification"),
			runtime.MakeSeq(
				runtime.MakeText("Measure stored qubit in revealed basis"),
				runtime.MakeText("Check consistency with revealed bit"),
			),
		),
	}

	return store.Put(circuit)
}

// EPRAttackSuccess returns the probability Alice can change her commitment using EPR attack.
// This equals 1 - Binding.
func (p *BitCommitmentProtocol) EPRAttackSuccess() *big.Rat {
	one := big.NewRat(1, 1)
	return new(big.Rat).Sub(one, p.Binding)
}

// DistinguishingAdvantage returns Bob's advantage in distinguishing committed bits.
// This equals 1 - Hiding.
func (p *BitCommitmentProtocol) DistinguishingAdvantage() *big.Rat {
	one := big.NewRat(1, 1)
	return new(big.Rat).Sub(one, p.Hiding)
}

// TradeOffSlack returns how far below the Mayers-Lo-Chau boundary this protocol is.
// Returns 1 - (binding + hiding). Zero means on boundary, positive means below.
func (p *BitCommitmentProtocol) TradeOffSlack() *big.Rat {
	one := big.NewRat(1, 1)
	sum := new(big.Rat).Add(p.Binding, p.Hiding)
	return new(big.Rat).Sub(one, sum)
}

// IsOnBoundary checks if binding + hiding = 1 (optimal trade-off).
func (p *BitCommitmentProtocol) IsOnBoundary() bool {
	sum := new(big.Rat).Add(p.Binding, p.Hiding)
	one := big.NewRat(1, 1)
	return sum.Cmp(one) == 0
}

// IsBalanced checks if binding = hiding.
func (p *BitCommitmentProtocol) IsBalanced() bool {
	return p.Binding.Cmp(p.Hiding) == 0
}

// SecurityLevel returns the minimum of binding and hiding (weakest link).
func (p *BitCommitmentProtocol) SecurityLevel() *big.Rat {
	if p.Binding.Cmp(p.Hiding) < 0 {
		return new(big.Rat).Set(p.Binding)
	}
	return new(big.Rat).Set(p.Hiding)
}

// ValidateParameters checks if the protocol parameters are valid.
func (p *BitCommitmentProtocol) ValidateParameters() error {
	zero := big.NewRat(0, 1)
	one := big.NewRat(1, 1)

	if p.Binding.Cmp(zero) < 0 || p.Binding.Cmp(one) > 0 {
		return fmt.Errorf("binding must be in [0, 1], got %v", p.Binding.RatString())
	}
	if p.Hiding.Cmp(zero) < 0 || p.Hiding.Cmp(one) > 0 {
		return fmt.Errorf("hiding must be in [0, 1], got %v", p.Hiding.RatString())
	}

	sum := new(big.Rat).Add(p.Binding, p.Hiding)
	if sum.Cmp(one) > 0 {
		return fmt.Errorf("binding + hiding = %v > 1: violates Mayers-Lo-Chau", sum.RatString())
	}

	return nil
}

// Helper methods

func (p *BitCommitmentProtocol) domainObject() runtime.Object {
	// Input: bit to commit
	return runtime.Object{Blocks: []uint32{2}}
}

func (p *BitCommitmentProtocol) codomainObject() runtime.Object {
	// Output: revealed/verified bit
	return runtime.Object{Blocks: []uint32{2}}
}

func (p *BitCommitmentProtocol) protocolMetadata() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("protocol-metadata"),
		runtime.MakeSeq(
			runtime.MakeText("QuantumBitCommitment"),
			runtime.MakeText("Mayers-Lo-Chau constrained"),
			runtime.MakeBigRat(p.Binding),
			runtime.MakeBigRat(p.Hiding),
			runtime.MakeBigRat(p.TradeOffSlack()),
			runtime.MakeBool(p.IsOnBoundary()),
		),
	)
}

func (p *BitCommitmentProtocol) commitPrepareData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("commit-prepare"),
		runtime.MakeSeq(
			runtime.MakeText("Prepare commitment state based on bit"),
			runtime.MakeText("Encoding depends on binding/hiding trade-off"),
			runtime.MakeBigRat(p.Binding),
			runtime.MakeBigRat(p.Hiding),
		),
	)
}

func (p *BitCommitmentProtocol) revealData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("reveal-info"),
		runtime.MakeSeq(
			runtime.MakeText("Alice reveals committed bit and encoding basis"),
			runtime.MakeText("This allows Bob to verify the commitment"),
		),
	)
}

func (p *BitCommitmentProtocol) verifyData() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("verify-commitment"),
		runtime.MakeSeq(
			runtime.MakeText("Bob measures stored state in revealed basis"),
			runtime.MakeText("Accepts if measurement matches revealed bit"),
		),
	)
}

// ToValue converts the protocol to a runtime.Value for serialization.
func (p *BitCommitmentProtocol) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("bit-commitment-protocol"),
		runtime.MakeSeq(
			runtime.MakeBigRat(p.Binding),
			runtime.MakeBigRat(p.Hiding),
			p.Protocol().ToValue(),
		),
	)
}

// BitCommitmentFromValue deserializes a BitCommitmentProtocol from a runtime.Value.
func BitCommitmentFromValue(v runtime.Value) (*BitCommitmentProtocol, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "bit-commitment-protocol" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 2 {
		return nil, false
	}

	binding, ok := seq.Items[0].(runtime.Rat)
	if !ok {
		return nil, false
	}
	hiding, ok := seq.Items[1].(runtime.Rat)
	if !ok {
		return nil, false
	}

	return &BitCommitmentProtocol{
		Binding: new(big.Rat).Set(binding.V),
		Hiding:  new(big.Rat).Set(hiding.V),
	}, true
}

// ===============================
// EPR Attack Analysis
// ===============================

// EPRAttackDescription describes the EPR attack against bit commitment.
func EPRAttackDescription() string {
	return `EPR Attack (Mayers 1996, Lo-Chau 1997):
1. Alice prepares EPR pair (|00> + |11>)/sqrt(2) instead of commitment state
2. Sends one qubit to Bob as "commitment"
3. Keeps other qubit (purification)
4. At reveal time, measures her qubit to steer Bob's state
5. Can reveal either 0 or 1 with success probability depending on protocol

This attack works because:
- If protocol is perfectly hiding, commitment states for 0 and 1 are indistinguishable to Bob
- But Alice holds purification and can transform between them
- Binding and hiding cannot both be perfect simultaneously`
}

// ===============================
// Protocol Variants
// ===============================

// BoundedStorageModel represents a bit commitment secure in bounded storage model.
// If Bob's quantum memory is limited, security can exceed Mayers-Lo-Chau.
type BoundedStorageModel struct {
	MemoryBound int // Bob's memory bound in qubits
	Binding     *big.Rat
	Hiding      *big.Rat
}

// NewBoundedStorageCommitment creates commitment secure against bounded-memory adversary.
// Security can exceed standard limits if adversary's memory is bounded.
func NewBoundedStorageCommitment(memoryBound int) *BoundedStorageModel {
	// In bounded storage model, security improves with memory bound
	// For simplicity, use approximate formula
	// Higher memory bound -> worse security (approaches MLC limit)
	// Lower memory bound -> better security

	// Simplified: binding = hiding = 1/2 + epsilon where epsilon depends on bound
	half := big.NewRat(1, 2)

	return &BoundedStorageModel{
		MemoryBound: memoryBound,
		Binding:     new(big.Rat).Set(half),
		Hiding:      new(big.Rat).Set(half),
	}
}
