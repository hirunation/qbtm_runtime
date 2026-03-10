// Package protocol provides quantum protocol specification types.
package protocol

import (
	"qbtm/runtime"
)

// Protocol represents a complete protocol specification.
type Protocol struct {
	Name        string
	Description string
	Parties     []Party
	Resources   []Resource
	Rounds      []Round
	Goal        SecurityGoal
	Assumptions []Assumption
	TypeSig     TypeSignature
}

// Party represents a participant in a protocol.
type Party struct {
	Name         string
	Role         Role
	Capabilities []Capability
}

// Role represents a party's role in a protocol.
type Role int

const (
	RoleSender Role = iota
	RoleReceiver
	RoleAdversary
	RoleArbiter
)

// String returns the string representation of a Role.
func (r Role) String() string {
	switch r {
	case RoleSender:
		return "sender"
	case RoleReceiver:
		return "receiver"
	case RoleAdversary:
		return "adversary"
	case RoleArbiter:
		return "arbiter"
	default:
		return "unknown"
	}
}

// Capability represents what a party can do.
type Capability int

const (
	CapPrepare Capability = iota
	CapMeasure
	CapStore
	CapClassicalCommunicate
	CapQuantumCommunicate
)

// String returns the string representation of a Capability.
func (c Capability) String() string {
	switch c {
	case CapPrepare:
		return "prepare"
	case CapMeasure:
		return "measure"
	case CapStore:
		return "store"
	case CapClassicalCommunicate:
		return "classical-communicate"
	case CapQuantumCommunicate:
		return "quantum-communicate"
	default:
		return "unknown"
	}
}

// Resource represents a quantum or classical resource.
type Resource struct {
	Type    ResourceType
	Parties []string
	State   StateSpec
}

// ResourceType identifies the type of resource.
type ResourceType int

const (
	ResourceClassicalChannel ResourceType = iota
	ResourceQuantumChannel
	ResourceEntangledPair
	ResourceSharedRandomness
	ResourceAuthenticatedChannel
)

// String returns the string representation of a ResourceType.
func (r ResourceType) String() string {
	switch r {
	case ResourceClassicalChannel:
		return "classical-channel"
	case ResourceQuantumChannel:
		return "quantum-channel"
	case ResourceEntangledPair:
		return "entangled-pair"
	case ResourceSharedRandomness:
		return "shared-randomness"
	case ResourceAuthenticatedChannel:
		return "authenticated-channel"
	default:
		return "unknown"
	}
}

// StateSpec specifies a quantum or classical state.
type StateSpec struct {
	Dimension   int
	IsClassical bool
	State       *runtime.Matrix
}

// Round represents a single round of protocol execution.
type Round struct {
	Number      int
	Actions     []Action
	Description string
}

// Action represents a protocol action.
type Action struct {
	Actor  string
	Type   ActionType
	Target string
	Data   runtime.Value
}

// ActionType identifies the type of action.
type ActionType int

const (
	ActionPrepare ActionType = iota
	ActionMeasure
	ActionSend
	ActionReceive
	ActionCompute
	ActionAnnounce
)

// String returns the string representation of an ActionType.
func (a ActionType) String() string {
	switch a {
	case ActionPrepare:
		return "prepare"
	case ActionMeasure:
		return "measure"
	case ActionSend:
		return "send"
	case ActionReceive:
		return "receive"
	case ActionCompute:
		return "compute"
	case ActionAnnounce:
		return "announce"
	default:
		return "unknown"
	}
}

// SecurityGoal represents the security objective of a protocol.
type SecurityGoal interface {
	goalTag()
	Name() string
	ToValue() runtime.Value
}

// KeyAgreement represents a key agreement goal.
type KeyAgreement struct {
	KeyLength    int
	ErrorRate    *runtime.Rat
	SecrecyBound *runtime.Rat
}

func (KeyAgreement) goalTag() {}
func (k KeyAgreement) Name() string { return "key-agreement" }
func (k KeyAgreement) ToValue() runtime.Value {
	var errorRateVal runtime.Value = runtime.MakeNil()
	if k.ErrorRate != nil {
		errorRateVal = *k.ErrorRate
	}
	var secrecyVal runtime.Value = runtime.MakeNil()
	if k.SecrecyBound != nil {
		secrecyVal = *k.SecrecyBound
	}
	return runtime.MakeTag(
		runtime.MakeText("key-agreement"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(k.KeyLength)),
			errorRateVal,
			secrecyVal,
		),
	)
}

// StateTransfer represents a state transfer goal.
type StateTransfer struct {
	InputDim  int
	OutputDim int
	Fidelity  *runtime.Rat
}

func (StateTransfer) goalTag() {}
func (s StateTransfer) Name() string { return "state-transfer" }
func (s StateTransfer) ToValue() runtime.Value {
	var fidelityVal runtime.Value = runtime.MakeNil()
	if s.Fidelity != nil {
		fidelityVal = *s.Fidelity
	}
	return runtime.MakeTag(
		runtime.MakeText("state-transfer"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(s.InputDim)),
			runtime.MakeInt(int64(s.OutputDim)),
			fidelityVal,
		),
	)
}

// SecretSharing represents a secret sharing goal.
type SecretSharing struct {
	Threshold int
	Total     int
}

func (SecretSharing) goalTag() {}
func (s SecretSharing) Name() string { return "secret-sharing" }
func (s SecretSharing) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("secret-sharing"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(s.Threshold)),
			runtime.MakeInt(int64(s.Total)),
		),
	)
}

// BitCommitment represents a bit commitment goal.
type BitCommitment struct {
	Binding *runtime.Rat
	Hiding  *runtime.Rat
}

func (BitCommitment) goalTag() {}
func (b BitCommitment) Name() string { return "bit-commitment" }
func (b BitCommitment) ToValue() runtime.Value {
	var bindingVal runtime.Value = runtime.MakeNil()
	if b.Binding != nil {
		bindingVal = *b.Binding
	}
	var hidingVal runtime.Value = runtime.MakeNil()
	if b.Hiding != nil {
		hidingVal = *b.Hiding
	}
	return runtime.MakeTag(
		runtime.MakeText("bit-commitment"),
		runtime.MakeSeq(bindingVal, hidingVal),
	)
}

// CoinFlip represents a coin flipping goal.
// Kitaev bound: Cheating bias >= 1/sqrt(2) - 1/2 for any quantum protocol.
type CoinFlip struct {
	Bias *runtime.Rat // Cheating bias (Kitaev bound: >= 1/sqrt(2) - 1/2)
}

func (CoinFlip) goalTag() {}
func (c CoinFlip) Name() string { return "coin-flip" }
func (c CoinFlip) ToValue() runtime.Value {
	var biasVal runtime.Value = runtime.MakeNil()
	if c.Bias != nil {
		biasVal = *c.Bias
	}
	return runtime.MakeTag(
		runtime.MakeText("coin-flip"),
		runtime.MakeSeq(biasVal),
	)
}

// ObliviousTransfer represents an oblivious transfer goal.
type ObliviousTransfer struct {
	SenderPrivacy   *runtime.Rat
	ReceiverPrivacy *runtime.Rat
}

func (ObliviousTransfer) goalTag() {}
func (o ObliviousTransfer) Name() string { return "oblivious-transfer" }
func (o ObliviousTransfer) ToValue() runtime.Value {
	var senderPrivacyVal runtime.Value = runtime.MakeNil()
	if o.SenderPrivacy != nil {
		senderPrivacyVal = *o.SenderPrivacy
	}
	var receiverPrivacyVal runtime.Value = runtime.MakeNil()
	if o.ReceiverPrivacy != nil {
		receiverPrivacyVal = *o.ReceiverPrivacy
	}
	return runtime.MakeTag(
		runtime.MakeText("oblivious-transfer"),
		runtime.MakeSeq(senderPrivacyVal, receiverPrivacyVal),
	)
}

// Assumption represents a security assumption.
type Assumption struct {
	Name        string
	Description string
	Type        AssumptionType
}

// AssumptionType categorizes assumptions.
type AssumptionType int

const (
	AssumptionNoCloning AssumptionType = iota
	AssumptionAuthenticatedClassical
	AssumptionNoSideChannel
	AssumptionPerfectDevices
	AssumptionIIDAttacks
)

// String returns the string representation of an AssumptionType.
func (a AssumptionType) String() string {
	switch a {
	case AssumptionNoCloning:
		return "no-cloning"
	case AssumptionAuthenticatedClassical:
		return "authenticated-classical"
	case AssumptionNoSideChannel:
		return "no-side-channel"
	case AssumptionPerfectDevices:
		return "perfect-devices"
	case AssumptionIIDAttacks:
		return "iid-attacks"
	default:
		return "unknown"
	}
}

// TypeSignature represents the quantum type of a protocol.
type TypeSignature struct {
	Domain   runtime.Object
	Codomain runtime.Object
}

// ProtocolSynthesizer provides an interface for synthesizing protocol circuits.
type ProtocolSynthesizer interface {
	// Synthesize generates the protocol circuit and stores it in the given store.
	// Returns the QGID of the synthesized circuit.
	Synthesize(store *runtime.Store) ([32]byte, error)

	// Protocol returns the protocol specification being synthesized.
	Protocol() *Protocol
}

// ToValue converts a Protocol to a runtime.Value.
func (p *Protocol) ToValue() runtime.Value {
	if p == nil {
		return runtime.MakeNil()
	}

	parties := make([]runtime.Value, len(p.Parties))
	for i, party := range p.Parties {
		parties[i] = partyToValue(party)
	}

	resources := make([]runtime.Value, len(p.Resources))
	for i, res := range p.Resources {
		resources[i] = resourceToValue(res)
	}

	rounds := make([]runtime.Value, len(p.Rounds))
	for i, round := range p.Rounds {
		rounds[i] = roundToValue(round)
	}

	assumptions := make([]runtime.Value, len(p.Assumptions))
	for i, a := range p.Assumptions {
		assumptions[i] = assumptionToValue(a)
	}

	var goalVal runtime.Value = runtime.MakeNil()
	if p.Goal != nil {
		goalVal = p.Goal.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("protocol"),
		runtime.MakeSeq(
			runtime.MakeText(p.Name),
			runtime.MakeText(p.Description),
			runtime.MakeSeq(parties...),
			runtime.MakeSeq(resources...),
			runtime.MakeSeq(rounds...),
			goalVal,
			runtime.MakeSeq(assumptions...),
			runtime.ObjectToValue(p.TypeSig.Domain),
			runtime.ObjectToValue(p.TypeSig.Codomain),
		),
	)
}

func partyToValue(p Party) runtime.Value {
	caps := make([]runtime.Value, len(p.Capabilities))
	for i, c := range p.Capabilities {
		caps[i] = runtime.MakeInt(int64(c))
	}
	return runtime.MakeTag(
		runtime.MakeText("party"),
		runtime.MakeSeq(
			runtime.MakeText(p.Name),
			runtime.MakeInt(int64(p.Role)),
			runtime.MakeSeq(caps...),
		),
	)
}

func resourceToValue(r Resource) runtime.Value {
	partiesVal := make([]runtime.Value, len(r.Parties))
	for i, p := range r.Parties {
		partiesVal[i] = runtime.MakeText(p)
	}
	var stateVal runtime.Value = runtime.MakeNil()
	if r.State.State != nil {
		stateVal = runtime.MatrixToValue(r.State.State)
	}
	return runtime.MakeTag(
		runtime.MakeText("resource"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(r.Type)),
			runtime.MakeSeq(partiesVal...),
			runtime.MakeInt(int64(r.State.Dimension)),
			runtime.MakeBool(r.State.IsClassical),
			stateVal,
		),
	)
}

func roundToValue(r Round) runtime.Value {
	actions := make([]runtime.Value, len(r.Actions))
	for i, a := range r.Actions {
		actions[i] = actionToValue(a)
	}
	return runtime.MakeTag(
		runtime.MakeText("round"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(r.Number)),
			runtime.MakeText(r.Description),
			runtime.MakeSeq(actions...),
		),
	)
}

func actionToValue(a Action) runtime.Value {
	var dataVal runtime.Value = runtime.MakeNil()
	if a.Data != nil {
		dataVal = a.Data
	}
	return runtime.MakeTag(
		runtime.MakeText("action"),
		runtime.MakeSeq(
			runtime.MakeText(a.Actor),
			runtime.MakeInt(int64(a.Type)),
			runtime.MakeText(a.Target),
			dataVal,
		),
	)
}

func assumptionToValue(a Assumption) runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("assumption"),
		runtime.MakeSeq(
			runtime.MakeText(a.Name),
			runtime.MakeText(a.Description),
			runtime.MakeInt(int64(a.Type)),
		),
	)
}

// ProtocolFromValue deserializes a Protocol from a runtime.Value.
func ProtocolFromValue(v runtime.Value) (*Protocol, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "protocol" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 9 {
		return nil, false
	}

	name, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	desc, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return nil, false
	}

	partiesSeq, ok := seq.Items[2].(runtime.Seq)
	if !ok {
		return nil, false
	}
	parties := make([]Party, len(partiesSeq.Items))
	for i, item := range partiesSeq.Items {
		p, ok := PartyFromValue(item)
		if !ok {
			return nil, false
		}
		parties[i] = p
	}

	resourcesSeq, ok := seq.Items[3].(runtime.Seq)
	if !ok {
		return nil, false
	}
	resources := make([]Resource, len(resourcesSeq.Items))
	for i, item := range resourcesSeq.Items {
		r, ok := ResourceFromValue(item)
		if !ok {
			return nil, false
		}
		resources[i] = r
	}

	roundsSeq, ok := seq.Items[4].(runtime.Seq)
	if !ok {
		return nil, false
	}
	rounds := make([]Round, len(roundsSeq.Items))
	for i, item := range roundsSeq.Items {
		r, ok := roundFromValue(item)
		if !ok {
			return nil, false
		}
		rounds[i] = r
	}

	goal, ok := SecurityGoalFromValue(seq.Items[5])
	if !ok {
		return nil, false
	}

	assumptionsSeq, ok := seq.Items[6].(runtime.Seq)
	if !ok {
		return nil, false
	}
	assumptions := make([]Assumption, len(assumptionsSeq.Items))
	for i, item := range assumptionsSeq.Items {
		a, ok := assumptionFromValue(item)
		if !ok {
			return nil, false
		}
		assumptions[i] = a
	}

	domain, ok := runtime.ObjectFromValue(seq.Items[7])
	if !ok {
		return nil, false
	}
	codomain, ok := runtime.ObjectFromValue(seq.Items[8])
	if !ok {
		return nil, false
	}

	return &Protocol{
		Name:        name.V,
		Description: desc.V,
		Parties:     parties,
		Resources:   resources,
		Rounds:      rounds,
		Goal:        goal,
		Assumptions: assumptions,
		TypeSig: TypeSignature{
			Domain:   domain,
			Codomain: codomain,
		},
	}, true
}

// PartyFromValue deserializes a Party from a runtime.Value.
func PartyFromValue(v runtime.Value) (Party, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return Party{}, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "party" {
		return Party{}, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
		return Party{}, false
	}

	name, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return Party{}, false
	}
	role, ok := seq.Items[1].(runtime.Int)
	if !ok {
		return Party{}, false
	}
	capsSeq, ok := seq.Items[2].(runtime.Seq)
	if !ok {
		return Party{}, false
	}

	caps := make([]Capability, len(capsSeq.Items))
	for i, item := range capsSeq.Items {
		c, ok := item.(runtime.Int)
		if !ok {
			return Party{}, false
		}
		caps[i] = Capability(c.V.Int64())
	}

	return Party{
		Name:         name.V,
		Role:         Role(role.V.Int64()),
		Capabilities: caps,
	}, true
}

// ResourceFromValue deserializes a Resource from a runtime.Value.
func ResourceFromValue(v runtime.Value) (Resource, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return Resource{}, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "resource" {
		return Resource{}, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 5 {
		return Resource{}, false
	}

	resType, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return Resource{}, false
	}

	partiesSeq, ok := seq.Items[1].(runtime.Seq)
	if !ok {
		return Resource{}, false
	}
	parties := make([]string, len(partiesSeq.Items))
	for i, item := range partiesSeq.Items {
		p, ok := item.(runtime.Text)
		if !ok {
			return Resource{}, false
		}
		parties[i] = p.V
	}

	dimension, ok := seq.Items[2].(runtime.Int)
	if !ok {
		return Resource{}, false
	}

	isClassical, ok := seq.Items[3].(runtime.Bool)
	if !ok {
		return Resource{}, false
	}

	var state *runtime.Matrix
	if _, isNil := seq.Items[4].(runtime.Nil); !isNil {
		state, ok = runtime.MatrixFromValue(seq.Items[4])
		if !ok {
			return Resource{}, false
		}
	}

	return Resource{
		Type:    ResourceType(resType.V.Int64()),
		Parties: parties,
		State: StateSpec{
			Dimension:   int(dimension.V.Int64()),
			IsClassical: isClassical.V,
			State:       state,
		},
	}, true
}

func roundFromValue(v runtime.Value) (Round, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return Round{}, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "round" {
		return Round{}, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
		return Round{}, false
	}

	num, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return Round{}, false
	}
	desc, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return Round{}, false
	}
	actionsSeq, ok := seq.Items[2].(runtime.Seq)
	if !ok {
		return Round{}, false
	}

	actions := make([]Action, len(actionsSeq.Items))
	for i, item := range actionsSeq.Items {
		a, ok := actionFromValue(item)
		if !ok {
			return Round{}, false
		}
		actions[i] = a
	}

	return Round{
		Number:      int(num.V.Int64()),
		Description: desc.V,
		Actions:     actions,
	}, true
}

func actionFromValue(v runtime.Value) (Action, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return Action{}, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "action" {
		return Action{}, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 4 {
		return Action{}, false
	}

	actor, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return Action{}, false
	}
	actionType, ok := seq.Items[1].(runtime.Int)
	if !ok {
		return Action{}, false
	}
	target, ok := seq.Items[2].(runtime.Text)
	if !ok {
		return Action{}, false
	}

	var data runtime.Value = runtime.MakeNil()
	if _, isNil := seq.Items[3].(runtime.Nil); !isNil {
		data = seq.Items[3]
	}

	return Action{
		Actor:  actor.V,
		Type:   ActionType(actionType.V.Int64()),
		Target: target.V,
		Data:   data,
	}, true
}

func assumptionFromValue(v runtime.Value) (Assumption, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return Assumption{}, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "assumption" {
		return Assumption{}, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
		return Assumption{}, false
	}

	name, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return Assumption{}, false
	}
	desc, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return Assumption{}, false
	}
	aType, ok := seq.Items[2].(runtime.Int)
	if !ok {
		return Assumption{}, false
	}

	return Assumption{
		Name:        name.V,
		Description: desc.V,
		Type:        AssumptionType(aType.V.Int64()),
	}, true
}

// SecurityGoalFromValue deserializes a SecurityGoal from a runtime.Value.
func SecurityGoalFromValue(v runtime.Value) (SecurityGoal, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok {
		return nil, false
	}

	switch label.V {
	case "key-agreement":
		return keyAgreementFromValue(tag.Payload)
	case "state-transfer":
		return stateTransferFromValue(tag.Payload)
	case "secret-sharing":
		return secretSharingFromValue(tag.Payload)
	case "bit-commitment":
		return bitCommitmentFromValue(tag.Payload)
	case "coin-flip":
		return coinFlipFromValue(tag.Payload)
	case "oblivious-transfer":
		return obliviousTransferFromValue(tag.Payload)
	default:
		return nil, false
	}
}

func keyAgreementFromValue(v runtime.Value) (SecurityGoal, bool) {
	seq, ok := v.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
		return nil, false
	}

	keyLen, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return nil, false
	}

	var errorRate *runtime.Rat
	if rat, ok := seq.Items[1].(runtime.Rat); ok {
		errorRate = &rat
	}

	var secrecyBound *runtime.Rat
	if rat, ok := seq.Items[2].(runtime.Rat); ok {
		secrecyBound = &rat
	}

	return KeyAgreement{
		KeyLength:    int(keyLen.V.Int64()),
		ErrorRate:    errorRate,
		SecrecyBound: secrecyBound,
	}, true
}

func stateTransferFromValue(v runtime.Value) (SecurityGoal, bool) {
	seq, ok := v.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
		return nil, false
	}

	inputDim, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return nil, false
	}

	outputDim, ok := seq.Items[1].(runtime.Int)
	if !ok {
		return nil, false
	}

	var fidelity *runtime.Rat
	if rat, ok := seq.Items[2].(runtime.Rat); ok {
		fidelity = &rat
	}

	return StateTransfer{
		InputDim:  int(inputDim.V.Int64()),
		OutputDim: int(outputDim.V.Int64()),
		Fidelity:  fidelity,
	}, true
}

func secretSharingFromValue(v runtime.Value) (SecurityGoal, bool) {
	seq, ok := v.(runtime.Seq)
	if !ok || len(seq.Items) < 2 {
		return nil, false
	}

	threshold, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return nil, false
	}

	total, ok := seq.Items[1].(runtime.Int)
	if !ok {
		return nil, false
	}

	return SecretSharing{
		Threshold: int(threshold.V.Int64()),
		Total:     int(total.V.Int64()),
	}, true
}

func bitCommitmentFromValue(v runtime.Value) (SecurityGoal, bool) {
	seq, ok := v.(runtime.Seq)
	if !ok || len(seq.Items) < 2 {
		return nil, false
	}

	var binding *runtime.Rat
	if rat, ok := seq.Items[0].(runtime.Rat); ok {
		binding = &rat
	}

	var hiding *runtime.Rat
	if rat, ok := seq.Items[1].(runtime.Rat); ok {
		hiding = &rat
	}

	return BitCommitment{
		Binding: binding,
		Hiding:  hiding,
	}, true
}

func coinFlipFromValue(v runtime.Value) (SecurityGoal, bool) {
	seq, ok := v.(runtime.Seq)
	if !ok || len(seq.Items) < 1 {
		return nil, false
	}

	var bias *runtime.Rat
	if rat, ok := seq.Items[0].(runtime.Rat); ok {
		bias = &rat
	}

	return CoinFlip{
		Bias: bias,
	}, true
}

func obliviousTransferFromValue(v runtime.Value) (SecurityGoal, bool) {
	seq, ok := v.(runtime.Seq)
	if !ok || len(seq.Items) < 2 {
		return nil, false
	}

	var senderPrivacy *runtime.Rat
	if rat, ok := seq.Items[0].(runtime.Rat); ok {
		senderPrivacy = &rat
	}

	var receiverPrivacy *runtime.Rat
	if rat, ok := seq.Items[1].(runtime.Rat); ok {
		receiverPrivacy = &rat
	}

	return ObliviousTransfer{
		SenderPrivacy:   senderPrivacy,
		ReceiverPrivacy: receiverPrivacy,
	}, true
}
