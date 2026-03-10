// witness.go provides witness types for certificates.
//
// Witnesses are computational artifacts that prove claims:
// - Choi matrices for correctness
// - Security bounds as exact rationals
// - Composition proofs
package certificate

import (
	"math/big"

	"qbtm/runtime"
)

// WitnessType identifies the type of witness.
type WitnessType int

const (
	WitnessChoiMatrix WitnessType = iota
	WitnessSecurityBound
	WitnessKeyRate
	WitnessNoiseTolerance
	WitnessCompositionProof
	WitnessEntropyBound
	WitnessAttackAnalysis
	WitnessChoiEquality
	WitnessInformationBound
)

// String returns a human-readable name for the witness type.
func (t WitnessType) String() string {
	switch t {
	case WitnessChoiMatrix:
		return "choi-matrix"
	case WitnessSecurityBound:
		return "security-bound"
	case WitnessKeyRate:
		return "key-rate"
	case WitnessNoiseTolerance:
		return "noise-tolerance"
	case WitnessCompositionProof:
		return "composition-proof"
	case WitnessEntropyBound:
		return "entropy-bound"
	case WitnessAttackAnalysis:
		return "attack-analysis"
	case WitnessChoiEquality:
		return "choi-equality"
	case WitnessInformationBound:
		return "information-bound"
	default:
		return "unknown"
	}
}

// Witness represents a computational proof artifact.
type Witness struct {
	Type        WitnessType
	Description string
	Data        runtime.Value
	Assumptions []string
}

// NewChoiWitness creates a witness from a Choi matrix.
func NewChoiWitness(matrix *runtime.Matrix, desc string) *Witness {
	var matrixVal runtime.Value = runtime.MakeNil()
	if matrix != nil {
		matrixVal = runtime.MatrixToValue(matrix)
	}
	return &Witness{
		Type:        WitnessChoiMatrix,
		Description: desc,
		Data:        matrixVal,
	}
}

// NewSecurityWitness creates a security bound witness.
func NewSecurityWitness(keyRate, epsilon *big.Rat) *Witness {
	return &Witness{
		Type:        WitnessSecurityBound,
		Description: "Security bound under coherent attacks",
		Data: runtime.MakeSeq(
			runtime.MakeBigRat(keyRate),
			runtime.MakeBigRat(epsilon),
		),
	}
}

// NewKeyRateWitness creates a key rate witness.
func NewKeyRateWitness(rate *big.Rat, attackModel string) *Witness {
	return &Witness{
		Type:        WitnessKeyRate,
		Description: "Asymptotic key rate",
		Data: runtime.MakeSeq(
			runtime.MakeBigRat(rate),
			runtime.MakeText(attackModel),
		),
	}
}

// NewNoiseWitness creates a noise tolerance witness.
func NewNoiseWitness(threshold *big.Rat, noiseModel string) *Witness {
	return &Witness{
		Type:        WitnessNoiseTolerance,
		Description: "Noise tolerance threshold",
		Data: runtime.MakeSeq(
			runtime.MakeBigRat(threshold),
			runtime.MakeText(noiseModel),
		),
	}
}

// NewCompositionWitness creates a composition proof witness.
func NewCompositionWitness(protocols []string, compositionType string) *Witness {
	protoVals := make([]runtime.Value, len(protocols))
	for i, p := range protocols {
		protoVals[i] = runtime.MakeText(p)
	}
	return &Witness{
		Type:        WitnessCompositionProof,
		Description: "Protocol composition proof",
		Data: runtime.MakeSeq(
			runtime.MakeSeq(protoVals...),
			runtime.MakeText(compositionType),
		),
	}
}

// AddAssumption adds an assumption to the witness.
func (w *Witness) AddAssumption(assumption string) {
	w.Assumptions = append(w.Assumptions, assumption)
}

// Verify verifies the witness based on its type.
func (w *Witness) Verify() bool {
	if w == nil {
		return false
	}

	// Basic validation based on witness type
	switch w.Type {
	case WitnessSecurityBound:
		// Security bounds should have positive key rate
		if seq, ok := w.Data.(runtime.Seq); ok && len(seq.Items) >= 2 {
			if keyRate, ok := seq.Items[0].(runtime.Rat); ok {
				if keyRate.V.Sign() < 0 {
					return false
				}
			}
		}
	case WitnessKeyRate:
		// Key rate should be non-negative
		if seq, ok := w.Data.(runtime.Seq); ok && len(seq.Items) >= 1 {
			if rate, ok := seq.Items[0].(runtime.Rat); ok {
				if rate.V.Sign() < 0 {
					return false
				}
			}
		}
	case WitnessNoiseTolerance:
		// Threshold should be positive
		if seq, ok := w.Data.(runtime.Seq); ok && len(seq.Items) >= 1 {
			if threshold, ok := seq.Items[0].(runtime.Rat); ok {
				if threshold.V.Sign() <= 0 {
					return false
				}
			}
		}
	}

	return true
}

// ToValue converts a Witness to a runtime.Value.
func (w *Witness) ToValue() runtime.Value {
	assumptions := make([]runtime.Value, len(w.Assumptions))
	for i, a := range w.Assumptions {
		assumptions[i] = runtime.MakeText(a)
	}

	return runtime.MakeTag(
		runtime.MakeText("witness"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(w.Type)),
			runtime.MakeText(w.Description),
			w.Data,
			runtime.MakeSeq(assumptions...),
		),
	)
}

// WitnessFromValue deserializes a Witness from a runtime.Value.
func WitnessFromValue(v runtime.Value) (*Witness, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "witness" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 4 {
		return nil, false
	}

	// Parse type
	typeInt, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return nil, false
	}

	// Parse description
	desc, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return nil, false
	}

	// Data is item 2 (any Value type)
	data := seq.Items[2]

	// Parse assumptions
	assumptionsSeq, ok := seq.Items[3].(runtime.Seq)
	if !ok {
		return nil, false
	}
	assumptions := make([]string, 0, len(assumptionsSeq.Items))
	for _, item := range assumptionsSeq.Items {
		if text, ok := item.(runtime.Text); ok {
			assumptions = append(assumptions, text.V)
		}
	}

	return &Witness{
		Type:        WitnessType(typeInt.V.Int64()),
		Description: desc.V,
		Data:        data,
		Assumptions: assumptions,
	}, true
}

// ChoiEqualityWitness proves (or disproves) that two channels are identical.
type ChoiEqualityWitness struct {
	ChannelA    [32]byte        // QGID of channel A
	ChannelB    [32]byte        // QGID of channel B
	ChoiMatrixA *runtime.Matrix // Choi matrix of A
	ChoiMatrixB *runtime.Matrix // Choi matrix of B
	Equal       bool            // True if channels are identical
	DifferAt    int             // Index of first differing entry (if not equal)
}

// Verify re-verifies the equality claim in the witness.
func (w *ChoiEqualityWitness) Verify() bool {
	if w == nil {
		return false
	}
	if w.ChoiMatrixA == nil || w.ChoiMatrixB == nil {
		return false
	}
	if w.Equal {
		return runtime.MatrixEqual(w.ChoiMatrixA, w.ChoiMatrixB)
	}
	// Verify the difference at specified index
	if w.DifferAt < 0 || w.DifferAt >= len(w.ChoiMatrixA.Data) || w.DifferAt >= len(w.ChoiMatrixB.Data) {
		return false
	}
	return !runtime.QIEqual(w.ChoiMatrixA.Data[w.DifferAt], w.ChoiMatrixB.Data[w.DifferAt])
}

// ToValue converts a ChoiEqualityWitness to a runtime.Value.
func (w *ChoiEqualityWitness) ToValue() runtime.Value {
	if w == nil {
		return runtime.MakeNil()
	}
	var matrixAVal, matrixBVal runtime.Value = runtime.MakeNil(), runtime.MakeNil()
	if w.ChoiMatrixA != nil {
		matrixAVal = runtime.MatrixToValue(w.ChoiMatrixA)
	}
	if w.ChoiMatrixB != nil {
		matrixBVal = runtime.MatrixToValue(w.ChoiMatrixB)
	}
	return runtime.MakeTag(
		runtime.MakeText("choi-equality-witness"),
		runtime.MakeSeq(
			runtime.MakeBytes(w.ChannelA[:]),
			runtime.MakeBytes(w.ChannelB[:]),
			matrixAVal,
			matrixBVal,
			runtime.MakeBool(w.Equal),
			runtime.MakeInt(int64(w.DifferAt)),
		),
	)
}

// ChoiEqualityWitnessFromValue deserializes a ChoiEqualityWitness from a runtime.Value.
func ChoiEqualityWitnessFromValue(v runtime.Value) (*ChoiEqualityWitness, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "choi-equality-witness" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 6 {
		return nil, false
	}

	w := &ChoiEqualityWitness{}

	// Parse channel A QGID
	if bytes, ok := seq.Items[0].(runtime.Bytes); ok && len(bytes.V) == 32 {
		copy(w.ChannelA[:], bytes.V)
	}

	// Parse channel B QGID
	if bytes, ok := seq.Items[1].(runtime.Bytes); ok && len(bytes.V) == 32 {
		copy(w.ChannelB[:], bytes.V)
	}

	// Parse Choi matrices
	if _, isNil := seq.Items[2].(runtime.Nil); !isNil {
		w.ChoiMatrixA, _ = runtime.MatrixFromValue(seq.Items[2])
	}
	if _, isNil := seq.Items[3].(runtime.Nil); !isNil {
		w.ChoiMatrixB, _ = runtime.MatrixFromValue(seq.Items[3])
	}

	// Parse Equal flag
	if b, ok := seq.Items[4].(runtime.Bool); ok {
		w.Equal = b.V
	}

	// Parse DifferAt index
	if i, ok := seq.Items[5].(runtime.Int); ok {
		w.DifferAt = int(i.V.Int64())
	}

	return w, true
}

// InformationBoundWitness proves I(X:E) <= bound for a protocol.
type InformationBoundWitness struct {
	Protocol         string   // Protocol name
	AttackModel      string   // Attack model (individual, collective, coherent)
	InfoBound        *big.Rat // Upper bound on mutual information I(X:E)
	DisturbanceLower *big.Rat // Lower bound on disturbance induced
	Derivation       string   // Proof derivation steps
}

// Verify verifies the information bound witness.
func (w *InformationBoundWitness) Verify() bool {
	if w == nil {
		return false
	}
	// Info bound must be non-negative
	if w.InfoBound != nil && w.InfoBound.Sign() < 0 {
		return false
	}
	// Disturbance must be non-negative
	if w.DisturbanceLower != nil && w.DisturbanceLower.Sign() < 0 {
		return false
	}
	return true
}

// ToValue converts an InformationBoundWitness to a runtime.Value.
func (w *InformationBoundWitness) ToValue() runtime.Value {
	if w == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeTag(
		runtime.MakeText("information-bound-witness"),
		runtime.MakeSeq(
			runtime.MakeText(w.Protocol),
			runtime.MakeText(w.AttackModel),
			ratOrNil(w.InfoBound),
			ratOrNil(w.DisturbanceLower),
			runtime.MakeText(w.Derivation),
		),
	)
}

// InformationBoundWitnessFromValue deserializes an InformationBoundWitness from a runtime.Value.
func InformationBoundWitnessFromValue(v runtime.Value) (*InformationBoundWitness, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "information-bound-witness" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 5 {
		return nil, false
	}

	protocol, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	attackModel, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return nil, false
	}
	derivation, ok := seq.Items[4].(runtime.Text)
	if !ok {
		return nil, false
	}

	return &InformationBoundWitness{
		Protocol:         protocol.V,
		AttackModel:      attackModel.V,
		InfoBound:        ratFromValue(seq.Items[2]),
		DisturbanceLower: ratFromValue(seq.Items[3]),
		Derivation:       derivation.V,
	}, true
}

// AttackWitness proves specific attack characteristics.
type AttackWitness struct {
	AttackName     string   // Name of the attack
	InfoGained     *big.Rat // Information gained by attacker
	Disturbance    *big.Rat // Disturbance induced by attack
	Detectable     bool     // Whether the attack is detectable
	Countermeasure string   // Recommended countermeasure
}

// Verify verifies the attack witness.
func (w *AttackWitness) Verify() bool {
	if w == nil {
		return false
	}
	// Info gained must be non-negative
	if w.InfoGained != nil && w.InfoGained.Sign() < 0 {
		return false
	}
	// Disturbance must be non-negative
	if w.Disturbance != nil && w.Disturbance.Sign() < 0 {
		return false
	}
	return true
}

// ToValue converts an AttackWitness to a runtime.Value.
func (w *AttackWitness) ToValue() runtime.Value {
	if w == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeTag(
		runtime.MakeText("attack-witness"),
		runtime.MakeSeq(
			runtime.MakeText(w.AttackName),
			ratOrNil(w.InfoGained),
			ratOrNil(w.Disturbance),
			runtime.MakeBool(w.Detectable),
			runtime.MakeText(w.Countermeasure),
		),
	)
}

// AttackWitnessFromValue deserializes an AttackWitness from a runtime.Value.
func AttackWitnessFromValue(v runtime.Value) (*AttackWitness, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "attack-witness" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 5 {
		return nil, false
	}

	name, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	detectable, ok := seq.Items[3].(runtime.Bool)
	if !ok {
		return nil, false
	}
	countermeasure, ok := seq.Items[4].(runtime.Text)
	if !ok {
		return nil, false
	}

	return &AttackWitness{
		AttackName:     name.V,
		InfoGained:     ratFromValue(seq.Items[1]),
		Disturbance:    ratFromValue(seq.Items[2]),
		Detectable:     detectable.V,
		Countermeasure: countermeasure.V,
	}, true
}

// KeyRateWitness proves achievable key rate.
type KeyRateWitness struct {
	Protocol    string   // Protocol name
	ErrorRate   *big.Rat // Error rate (QBER)
	KeyRate     *big.Rat // Achievable key rate
	Formula     string   // Key rate formula (e.g., "1-2h(e)")
	AttackModel string   // Attack model assumed
}

// Verify verifies the key rate witness.
func (w *KeyRateWitness) Verify() bool {
	if w == nil {
		return false
	}
	// Key rate should be in [0, 1]
	if w.KeyRate != nil {
		if w.KeyRate.Sign() < 0 {
			return false
		}
		if w.KeyRate.Cmp(big.NewRat(1, 1)) > 0 {
			return false
		}
	}
	// Error rate should be in [0, 1]
	if w.ErrorRate != nil {
		if w.ErrorRate.Sign() < 0 {
			return false
		}
		if w.ErrorRate.Cmp(big.NewRat(1, 1)) > 0 {
			return false
		}
	}
	return true
}

// ToValue converts a KeyRateWitness to a runtime.Value.
func (w *KeyRateWitness) ToValue() runtime.Value {
	if w == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeTag(
		runtime.MakeText("key-rate-witness"),
		runtime.MakeSeq(
			runtime.MakeText(w.Protocol),
			ratOrNil(w.ErrorRate),
			ratOrNil(w.KeyRate),
			runtime.MakeText(w.Formula),
			runtime.MakeText(w.AttackModel),
		),
	)
}

// KeyRateWitnessFromValue deserializes a KeyRateWitness from a runtime.Value.
func KeyRateWitnessFromValue(v runtime.Value) (*KeyRateWitness, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "key-rate-witness" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 5 {
		return nil, false
	}

	protocol, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	formula, ok := seq.Items[3].(runtime.Text)
	if !ok {
		return nil, false
	}
	attackModel, ok := seq.Items[4].(runtime.Text)
	if !ok {
		return nil, false
	}

	return &KeyRateWitness{
		Protocol:    protocol.V,
		ErrorRate:   ratFromValue(seq.Items[1]),
		KeyRate:     ratFromValue(seq.Items[2]),
		Formula:     formula.V,
		AttackModel: attackModel.V,
	}, true
}

// EntropyWitness with symbolic entropy representation.
type EntropyWitness struct {
	Symbolic string   // Symbolic entropy expression (e.g., "h(e)")
	Lower    *big.Rat // Lower bound
	Upper    *big.Rat // Upper bound
}

// Verify verifies the entropy witness.
func (w *EntropyWitness) Verify() bool {
	if w == nil {
		return false
	}
	// Entropy bounds must be non-negative
	if w.Lower != nil && w.Lower.Sign() < 0 {
		return false
	}
	if w.Upper != nil && w.Upper.Sign() < 0 {
		return false
	}
	// Lower must be <= Upper
	if w.Lower != nil && w.Upper != nil {
		if w.Lower.Cmp(w.Upper) > 0 {
			return false
		}
	}
	return true
}

// ToValue converts an EntropyWitness to a runtime.Value.
func (w *EntropyWitness) ToValue() runtime.Value {
	if w == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeTag(
		runtime.MakeText("entropy-witness"),
		runtime.MakeSeq(
			runtime.MakeText(w.Symbolic),
			ratOrNil(w.Lower),
			ratOrNil(w.Upper),
		),
	)
}

// EntropyWitnessFromValue deserializes an EntropyWitness from a runtime.Value.
func EntropyWitnessFromValue(v runtime.Value) (*EntropyWitness, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "entropy-witness" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
		return nil, false
	}

	symbolic, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}

	return &EntropyWitness{
		Symbolic: symbolic.V,
		Lower:    ratFromValue(seq.Items[1]),
		Upper:    ratFromValue(seq.Items[2]),
	}, true
}

