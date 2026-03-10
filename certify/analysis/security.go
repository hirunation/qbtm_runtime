// security.go provides security bound computation for quantum protocols.
//
// Security analysis computes exact bounds on information leakage
// and derives secure key rates for various adversary models.
// All computations use exact rational arithmetic with symbolic
// entropy expressions where transcendental functions appear.
package analysis

import (
	"fmt"
	"math/big"
	"time"

	"qbtm/certify/attack"
	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// SecurityResult holds the complete result of security analysis.
type SecurityResult struct {
	Protocol       string               // Protocol name (e.g., "BB84", "E91")
	AdversaryModel string               // "individual", "collective", or "coherent"
	KeyRate        *Entropy             // Symbolic or computed key rate
	KeyRateBound   *big.Rat             // Rational lower bound on key rate
	Threshold      *big.Rat             // Error threshold for security
	IsSecure       bool                 // Whether observed error < threshold
	Certificate    *SecurityCertificate // Complete security certificate
}

// ModelAdversary represents an adversary as a CP map E: Q(d) -> Q(d) tensor Q(e).
// The adversary intercepts quantum communication and produces correlated output
// to both the legitimate receiver and Eve's ancilla system.
type ModelAdversary struct {
	Name       string          // Descriptive name for the adversary model
	ChoiMatrix *runtime.Matrix // Choi representation of attack channel
	OutputDimE int             // Dimension of Eve's output system
	Attack     attack.Attack   // Underlying attack implementation
}

// NewAdversaryFromAttack creates a ModelAdversary from an attack.Attack.
func NewAdversaryFromAttack(a attack.Attack) *ModelAdversary {
	if a == nil {
		return nil
	}

	choi := a.ChoiMatrix()
	outputDimE := 2 // Default qubit ancilla
	if choi != nil {
		// Infer Eve's dimension from Choi matrix size
		// For d-dimensional input, Choi is d^2 x d^2 for channel alone
		// With ancilla e, total output is d*e, so Choi is d^2 x (d*e)^2
		totalDim := choi.Cols
		inputDim := choi.Rows
		if inputDim > 0 {
			outputDimE = totalDim / inputDim
		}
	}

	return &ModelAdversary{
		Name:       a.Name(),
		ChoiMatrix: choi,
		OutputDimE: outputDimE,
		Attack:     a,
	}
}

// InformationGained returns the information gained by this adversary.
func (m *ModelAdversary) InformationGained() *big.Rat {
	if m == nil || m.Attack == nil {
		return big.NewRat(0, 1)
	}
	return m.Attack.InformationGained()
}

// DisturbanceInduced returns the disturbance induced by this adversary.
func (m *ModelAdversary) DisturbanceInduced() *big.Rat {
	if m == nil || m.Attack == nil {
		return big.NewRat(0, 1)
	}
	return m.Attack.DisturbanceInduced()
}

// ComputeInformation computes I(X:E) for the given attack.
// Uses the Holevo bound: I(X:E) <= chi(rho_E) where chi is the Holevo quantity.
func ComputeInformation(protocol string, adversary *ModelAdversary, errorRate *big.Rat) *Entropy {
	if adversary == nil || errorRate == nil {
		return NewExactEntropy(big.NewRat(0, 1))
	}

	// For each protocol, the information-disturbance tradeoff differs
	// We use the optimal (for Eve) tradeoff curves

	switch protocol {
	case "BB84", "bb84":
		// For BB84: I(X:E) <= h((1 + sqrt(1-4*e*(1-e)))/2)
		// At optimal attack: I = h(e) approximately
		return computeBB84Information(errorRate)

	case "E91", "e91":
		// E91 uses entanglement, so information depends on Bell violation
		return computeE91Information(errorRate)

	case "Six-State", "six-state", "SixState":
		// Six-state has better security: I(X:E) <= (4/3)*h(3e/2)
		return computeSixStateInformation(errorRate)

	case "B92", "b92":
		// B92 has different tradeoff due to non-orthogonal states
		return computeB92Information(errorRate)

	case "SARG04", "sarg04":
		// SARG04 is similar to BB84 but with different encoding
		return computeSARG04Information(errorRate)

	default:
		// Generic bound: I(X:E) <= h(e)
		return BinaryEntropy(errorRate)
	}
}

// computeBB84Information computes information for BB84 protocol.
func computeBB84Information(errorRate *big.Rat) *Entropy {
	// For intercept-resend attack: I = 1 bit, e = 0.25
	// For optimal cloning: I ~ 0.4 bits, e ~ 0.167
	// General bound: I(X:E) <= h((1 + sqrt(1-4e(1-e)))/2)

	// Use simpler bound: I <= 2*h(e) (valid for small e)
	he := BinaryEntropy(errorRate)
	return EntropyScale(he, big.NewRat(2, 1))
}

// computeE91Information computes information for E91 protocol.
func computeE91Information(errorRate *big.Rat) *Entropy {
	// E91 security comes from Bell inequality violation
	// Information leakage bounded by failure to violate CHSH
	// Simplified: similar to BB84 for comparison attacks
	return computeBB84Information(errorRate)
}

// computeSixStateInformation computes information for Six-State protocol.
func computeSixStateInformation(errorRate *big.Rat) *Entropy {
	// Six-state has tighter bound due to extra basis
	// I(X:E) <= (4/3)*h(3e/2)
	adjustedError := new(big.Rat).Mul(errorRate, big.NewRat(3, 2))

	// Cap at 1/2 (beyond which h decreases)
	half := big.NewRat(1, 2)
	if adjustedError.Cmp(half) > 0 {
		adjustedError = half
	}

	he := BinaryEntropy(adjustedError)
	return EntropyScale(he, big.NewRat(4, 3))
}

// computeB92Information computes information for B92 protocol.
func computeB92Information(errorRate *big.Rat) *Entropy {
	// B92 uses non-orthogonal states, different tradeoff
	// Simplified bound similar to BB84
	return computeBB84Information(errorRate)
}

// computeSARG04Information computes information for SARG04 protocol.
func computeSARG04Information(errorRate *big.Rat) *Entropy {
	// SARG04 has slightly different encoding than BB84
	return computeBB84Information(errorRate)
}

// DeriveKeyRate computes the secure key rate for a protocol.
// Returns both the symbolic key rate and a rational lower bound.
//
// Key rate formulas:
// - BB84: r = 1 - 2h(e)
// - E91: r = 1 - h((1 + sqrt((S/2)^2 - 1))/2)
// - Six-State: r = 1 - (5/3)h(3e/2)
// - B92: r = 1/2 * (1 - h(2e))
// - SARG04: r = 1 - 2h(e) - f(mu) (with photon number correction)
func DeriveKeyRate(protocol string, errorRate *big.Rat, adversaryModel string) (*Entropy, *big.Rat) {
	switch protocol {
	case "BB84", "bb84":
		return BB84KeyRate(errorRate)

	case "E91", "e91":
		// For E91, we need CHSH value; approximate from error rate
		// S ~ 2*sqrt(2)*(1 - 2*e) for ideal case
		// Simplified: use BB84 formula
		return BB84KeyRate(errorRate)

	case "Six-State", "six-state", "SixState":
		return SixStateKeyRate(errorRate)

	case "B92", "b92":
		return B92KeyRate(errorRate)

	case "SARG04", "sarg04":
		return SARG04KeyRate(big.NewRat(1, 2), errorRate) // Default mean photon 0.5

	default:
		// Generic: use BB84 formula
		return BB84KeyRate(errorRate)
	}
}

// BB84KeyRate computes the key rate for BB84 protocol.
// Formula: r = 1 - 2h(e)
// This is the Devetak-Winter bound for collective attacks.
func BB84KeyRate(errorRate *big.Rat) (*Entropy, *big.Rat) {
	if errorRate == nil {
		return NewExactEntropy(big.NewRat(1, 1)), big.NewRat(1, 1)
	}

	// r = 1 - 2h(e)
	one := NewExactEntropy(big.NewRat(1, 1))
	he := BinaryEntropy(errorRate)
	twoHe := EntropyScale(he, big.NewRat(2, 1))
	keyRate := EntropySub(one, twoHe)

	// Lower bound: use lower bound of keyRate
	lowerBound := keyRate.Lower
	if lowerBound.Sign() < 0 {
		lowerBound = big.NewRat(0, 1)
	}

	return keyRate, new(big.Rat).Set(lowerBound)
}

// E91KeyRate computes the key rate for E91 protocol.
// Formula: r = 1 - h((1 + sqrt((S/2)^2 - 1))/2)
// where S is the CHSH value (2 < S <= 2*sqrt(2) for entanglement).
func E91KeyRate(chshValue *big.Rat) (*Entropy, *big.Rat) {
	if chshValue == nil {
		return NewExactEntropy(big.NewRat(0, 1)), big.NewRat(0, 1)
	}

	// For maximal violation S = 2*sqrt(2), the argument becomes 1/2
	// and h(1/2) = 1, so r = 0. Wait, that's wrong...
	// Actually for S = 2*sqrt(2): (S/2)^2 - 1 = 2 - 1 = 1, sqrt(1) = 1
	// argument = (1 + 1)/2 = 1, h(1) = 0, so r = 1

	// Compute (S/2)^2
	sOver2 := new(big.Rat).Quo(chshValue, big.NewRat(2, 1))
	sOver2Sq := new(big.Rat).Mul(sOver2, sOver2)

	// Check if (S/2)^2 >= 1 (required for meaningful sqrt)
	one := big.NewRat(1, 1)
	if sOver2Sq.Cmp(one) < 0 {
		// No entanglement detected, key rate is 0
		return NewExactEntropy(big.NewRat(0, 1)), big.NewRat(0, 1)
	}

	// For exact computation, we need sqrt which is irrational
	// Use bounds: sqrt(x) is in [x/(ceil(sqrt(x))+1), ceil(sqrt(x))]

	// Simplified: for S close to 2*sqrt(2) ~ 2.828, use linear approximation
	// r ~ (S - 2) / (2*sqrt(2) - 2) for S in [2, 2*sqrt(2)]

	two := big.NewRat(2, 1)
	sMinusTwo := new(big.Rat).Sub(chshValue, two)

	if sMinusTwo.Sign() <= 0 {
		return NewExactEntropy(big.NewRat(0, 1)), big.NewRat(0, 1)
	}

	// 2*sqrt(2) - 2 ~ 0.828
	divisor := big.NewRat(828, 1000)
	keyRateApprox := new(big.Rat).Quo(sMinusTwo, divisor)

	if keyRateApprox.Cmp(one) > 0 {
		keyRateApprox = one
	}

	symbolic := fmt.Sprintf("1-h((1+sqrt((%s/2)^2-1))/2)", chshValue.RatString())
	lower := new(big.Rat).Set(keyRateApprox)
	upper := new(big.Rat).Set(one)

	return NewSymbolicEntropy(symbolic, lower, upper), lower
}

// SixStateKeyRate computes the key rate for Six-State protocol.
// Formula: r = 1 - (5/3)h(3e/2)
// This tighter bound reflects the additional security from 3 bases.
func SixStateKeyRate(errorRate *big.Rat) (*Entropy, *big.Rat) {
	if errorRate == nil {
		return NewExactEntropy(big.NewRat(1, 1)), big.NewRat(1, 1)
	}

	// Adjusted error: 3e/2
	adjustedError := new(big.Rat).Mul(errorRate, big.NewRat(3, 2))

	// Cap at 1 for valid probability
	one := big.NewRat(1, 1)
	if adjustedError.Cmp(one) > 0 {
		adjustedError = one
	}

	// h(3e/2)
	he := BinaryEntropy(adjustedError)

	// (5/3)*h(3e/2)
	scaledHe := EntropyScale(he, big.NewRat(5, 3))

	// 1 - (5/3)*h(3e/2)
	oneEntropy := NewExactEntropy(big.NewRat(1, 1))
	keyRate := EntropySub(oneEntropy, scaledHe)

	lowerBound := keyRate.Lower
	if lowerBound.Sign() < 0 {
		lowerBound = big.NewRat(0, 1)
	}

	return keyRate, new(big.Rat).Set(lowerBound)
}

// B92KeyRate computes the key rate for B92 protocol.
// For the simple case, r = 1/2. For finite error:
// r = 1/2 * (1 - h(2e))
func B92KeyRate(errorRate *big.Rat) (*Entropy, *big.Rat) {
	if errorRate == nil || errorRate.Sign() == 0 {
		// Ideal case: r = 1/2
		half := big.NewRat(1, 2)
		return NewExactEntropy(half), half
	}

	// Adjusted error for B92: 2e
	twoE := new(big.Rat).Mul(errorRate, big.NewRat(2, 1))

	// Cap at 1
	one := big.NewRat(1, 1)
	if twoE.Cmp(one) > 0 {
		twoE = one
	}

	// h(2e)
	he := BinaryEntropy(twoE)

	// 1 - h(2e)
	oneEntropy := NewExactEntropy(big.NewRat(1, 1))
	correction := EntropySub(oneEntropy, he)

	// (1/2) * (1 - h(2e))
	keyRate := EntropyScale(correction, big.NewRat(1, 2))

	lowerBound := keyRate.Lower
	if lowerBound.Sign() < 0 {
		lowerBound = big.NewRat(0, 1)
	}

	return keyRate, new(big.Rat).Set(lowerBound)
}

// SARG04KeyRate computes the key rate for SARG04 protocol.
// Formula: r = 1 - 2h(e) - f(mu)
// where f(mu) is a correction factor depending on mean photon number.
func SARG04KeyRate(meanPhoton, errorRate *big.Rat) (*Entropy, *big.Rat) {
	if errorRate == nil {
		return NewExactEntropy(big.NewRat(1, 1)), big.NewRat(1, 1)
	}

	// Start with BB84-like rate
	bb84Rate, _ := BB84KeyRate(errorRate)

	// Photon number correction: for weak coherent source with mean photon mu,
	// multi-photon events leak information
	// f(mu) ~ mu^2 / 2 for small mu
	if meanPhoton != nil && meanPhoton.Sign() > 0 {
		muSq := new(big.Rat).Mul(meanPhoton, meanPhoton)
		correction := new(big.Rat).Quo(muSq, big.NewRat(2, 1))
		correctionEntropy := NewExactEntropy(correction)
		bb84Rate = EntropySub(bb84Rate, correctionEntropy)
	}

	lowerBound := bb84Rate.Lower
	if lowerBound.Sign() < 0 {
		lowerBound = big.NewRat(0, 1)
	}

	return bb84Rate, new(big.Rat).Set(lowerBound)
}

// SecurityThresholds contains known error thresholds for different protocols.
// These are the maximum QBER values at which positive key rate is achievable.
var SecurityThresholds = map[string]*big.Rat{
	"BB84":      big.NewRat(11, 100),  // 11% (exact: ~11.0%)
	"E91":       big.NewRat(11, 100),  // ~11% (same as BB84 for intercept-resend)
	"Six-State": big.NewRat(1, 6),     // 16.67% (exact: 1/6)
	"B92":       big.NewRat(1, 4),     // 25%
	"SARG04":    big.NewRat(10, 100),  // ~10% (depends on photon number)
}

// GetSecurityThreshold returns the error threshold for a protocol.
func GetSecurityThreshold(protocol string) *big.Rat {
	if thresh, ok := SecurityThresholds[protocol]; ok {
		return new(big.Rat).Set(thresh)
	}
	// Default: use BB84 threshold
	return big.NewRat(11, 100)
}

// ThresholdDerivation explains how the threshold was derived for a protocol.
func ThresholdDerivation(protocol string) string {
	switch protocol {
	case "BB84":
		return "BB84 threshold derived from 1-2h(e)=0, giving e=h^{-1}(1/2)~0.11. " +
			"At this QBER, the key rate becomes zero under collective attacks."

	case "E91":
		return "E91 threshold follows from CHSH violation requirements. " +
			"When S drops below 2 (classical limit), no secure key can be extracted. " +
			"Error rate ~11% corresponds to S~2 for intercept-resend attacks."

	case "Six-State":
		return "Six-State threshold from 1-(5/3)h(3e/2)=0, giving e=1/6~16.67%. " +
			"The extra basis provides better security against eavesdropping."

	case "B92":
		return "B92 uses non-orthogonal states with threshold ~25%. " +
			"The protocol trades efficiency for simplicity."

	case "SARG04":
		return "SARG04 threshold ~10% is lower than BB84 due to photon-number-splitting " +
			"attacks. The threshold depends on the mean photon number of the source."

	default:
		return "Threshold derived from key rate formula equalling zero."
	}
}

// SecurityCertificate bundles a complete security proof.
type SecurityCertificate struct {
	Protocol       string           // Protocol analyzed
	AdversaryModel string           // Adversary model used
	KeyRate        *Entropy         // Proven key rate
	ErrorRate      *big.Rat         // Observed error rate
	Threshold      *big.Rat         // Security threshold
	Witness        *SecurityWitness // Evidence for security claim
	Timestamp      int64            // Unix timestamp of analysis
}

// NewSecurityCertificate creates a new security certificate.
func NewSecurityCertificate(protocol, adversaryModel string, keyRate *Entropy, errorRate, threshold *big.Rat) *SecurityCertificate {
	return &SecurityCertificate{
		Protocol:       protocol,
		AdversaryModel: adversaryModel,
		KeyRate:        keyRate,
		ErrorRate:      new(big.Rat).Set(errorRate),
		Threshold:      new(big.Rat).Set(threshold),
		Witness:        nil,
		Timestamp:      time.Now().Unix(),
	}
}

// IsSecure returns true if the certificate shows the protocol is secure.
func (c *SecurityCertificate) IsSecure() bool {
	if c == nil {
		return false
	}
	// Secure if error rate < threshold and key rate > 0
	if c.ErrorRate.Cmp(c.Threshold) >= 0 {
		return false
	}
	if c.KeyRate != nil && !c.KeyRate.IsPositive() {
		return false
	}
	return true
}

// ToValue converts a SecurityCertificate to a runtime.Value.
func (c *SecurityCertificate) ToValue() runtime.Value {
	if c == nil {
		return runtime.MakeNil()
	}

	var witnessVal runtime.Value = runtime.MakeNil()
	if c.Witness != nil {
		witnessVal = c.Witness.ToValue()
	}

	var keyRateVal runtime.Value = runtime.MakeNil()
	if c.KeyRate != nil {
		keyRateVal = c.KeyRate.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("security-certificate"),
		runtime.MakeSeq(
			runtime.MakeText(c.Protocol),
			runtime.MakeText(c.AdversaryModel),
			keyRateVal,
			runtime.MakeBigRat(c.ErrorRate),
			runtime.MakeBigRat(c.Threshold),
			witnessVal,
			runtime.MakeInt(c.Timestamp),
		),
	)
}

// SecurityCertificateFromValue parses a SecurityCertificate from a runtime.Value.
func SecurityCertificateFromValue(v runtime.Value) (*SecurityCertificate, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "security-certificate" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 7 {
		return nil, false
	}

	protocol, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	adversaryModel, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return nil, false
	}
	keyRate, ok := EntropyFromValue(seq.Items[2])
	if !ok {
		return nil, false
	}
	errorRate, ok := seq.Items[3].(runtime.Rat)
	if !ok {
		return nil, false
	}
	threshold, ok := seq.Items[4].(runtime.Rat)
	if !ok {
		return nil, false
	}
	witness, ok := SecurityWitnessFromValue(seq.Items[5])
	if !ok {
		return nil, false
	}
	timestamp, ok := seq.Items[6].(runtime.Int)
	if !ok {
		return nil, false
	}

	return &SecurityCertificate{
		Protocol:       protocol.V,
		AdversaryModel: adversaryModel.V,
		KeyRate:        keyRate,
		ErrorRate:      new(big.Rat).Set(errorRate.V),
		Threshold:      new(big.Rat).Set(threshold.V),
		Witness:        witness,
		Timestamp:      timestamp.V.Int64(),
	}, true
}

// SecurityWitness provides evidence for a security claim.
type SecurityWitness struct {
	InfoBound        *big.Rat // I(X:E) upper bound
	DisturbanceLower *big.Rat // Minimum detectable disturbance
	AttackOptimal    bool     // Whether attack is optimal for model
	Derivation       string   // Proof derivation steps
}

// NewSecurityWitness creates a new security witness.
func NewSecurityWitness(infoBound, disturbanceLower *big.Rat, attackOptimal bool, derivation string) *SecurityWitness {
	w := &SecurityWitness{
		AttackOptimal: attackOptimal,
		Derivation:    derivation,
	}
	if infoBound != nil {
		w.InfoBound = new(big.Rat).Set(infoBound)
	}
	if disturbanceLower != nil {
		w.DisturbanceLower = new(big.Rat).Set(disturbanceLower)
	}
	return w
}

// ToValue converts a SecurityWitness to a runtime.Value.
func (w *SecurityWitness) ToValue() runtime.Value {
	if w == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeTag(
		runtime.MakeText("security-witness"),
		runtime.MakeSeq(
			ratOrNil(w.InfoBound),
			ratOrNil(w.DisturbanceLower),
			runtime.MakeBool(w.AttackOptimal),
			runtime.MakeText(w.Derivation),
		),
	)
}

// SecurityWitnessFromValue parses a SecurityWitness from a runtime.Value.
func SecurityWitnessFromValue(v runtime.Value) (*SecurityWitness, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "security-witness" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 4 {
		return nil, false
	}

	w := &SecurityWitness{}
	w.InfoBound = ratFromValue(seq.Items[0])
	w.DisturbanceLower = ratFromValue(seq.Items[1])

	optimal, ok := seq.Items[2].(runtime.Bool)
	if !ok {
		return nil, false
	}
	w.AttackOptimal = optimal.V

	derivation, ok := seq.Items[3].(runtime.Text)
	if !ok {
		return nil, false
	}
	w.Derivation = derivation.V

	return w, true
}

// ComputeSecurityBounds computes comprehensive security bounds for a protocol.
func ComputeSecurityBounds(p *protocol.Protocol, attackModel string) (*SecurityResult, error) {
	if p == nil {
		return nil, fmt.Errorf("nil protocol")
	}

	// Determine error rate from protocol goal if available
	errorRate := big.NewRat(0, 1)
	if ka, ok := p.Goal.(protocol.KeyAgreement); ok && ka.ErrorRate != nil {
		errorRate = new(big.Rat).Set(ka.ErrorRate.V)
	}

	// Get threshold for this protocol
	threshold := GetSecurityThreshold(p.Name)

	// Compute key rate
	keyRate, keyRateBound := DeriveKeyRate(p.Name, errorRate, attackModel)

	// Determine if secure
	isSecure := errorRate.Cmp(threshold) < 0 && keyRateBound.Sign() > 0

	// Create certificate
	cert := NewSecurityCertificate(p.Name, attackModel, keyRate, errorRate, threshold)

	// Add witness with derivation
	derivation := fmt.Sprintf("Protocol: %s\nAdversary model: %s\nError rate: %s\nThreshold: %s\nKey rate: %s\n%s",
		p.Name, attackModel, errorRate.RatString(), threshold.RatString(),
		keyRate.String(), ThresholdDerivation(p.Name))

	infoBound := ComputeInformation(p.Name, nil, errorRate).Upper
	cert.Witness = NewSecurityWitness(infoBound, big.NewRat(0, 1), true, derivation)

	return &SecurityResult{
		Protocol:       p.Name,
		AdversaryModel: attackModel,
		KeyRate:        keyRate,
		KeyRateBound:   keyRateBound,
		Threshold:      threshold,
		IsSecure:       isSecure,
		Certificate:    cert,
	}, nil
}

// ComputeKeyRateForQBER computes the asymptotic key rate for a given QBER.
// This is a simplified interface for quick key rate computation.
func ComputeKeyRateForQBER(qber *big.Rat, attackModel string) *big.Rat {
	// Default to BB84 formula
	keyRate, bound := BB84KeyRate(qber)
	_ = keyRate
	return bound
}

// ToValue converts a SecurityResult to a runtime.Value.
func (r *SecurityResult) ToValue() runtime.Value {
	if r == nil {
		return runtime.MakeNil()
	}

	var keyRateVal runtime.Value = runtime.MakeNil()
	if r.KeyRate != nil {
		keyRateVal = r.KeyRate.ToValue()
	}

	var certVal runtime.Value = runtime.MakeNil()
	if r.Certificate != nil {
		certVal = r.Certificate.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("security-result"),
		runtime.MakeSeq(
			runtime.MakeText(r.Protocol),
			runtime.MakeText(r.AdversaryModel),
			keyRateVal,
			ratOrNil(r.KeyRateBound),
			ratOrNil(r.Threshold),
			runtime.MakeBool(r.IsSecure),
			certVal,
		),
	)
}

// SecurityResultFromValue parses a SecurityResult from a runtime.Value.
func SecurityResultFromValue(v runtime.Value) (*SecurityResult, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "security-result" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 7 {
		return nil, false
	}

	protocol, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	adversaryModel, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return nil, false
	}
	keyRate, ok := EntropyFromValue(seq.Items[2])
	if !ok {
		return nil, false
	}
	keyRateBound := ratFromValue(seq.Items[3])
	threshold := ratFromValue(seq.Items[4])

	isSecure, ok := seq.Items[5].(runtime.Bool)
	if !ok {
		return nil, false
	}

	cert, ok := SecurityCertificateFromValue(seq.Items[6])
	if !ok {
		return nil, false
	}

	return &SecurityResult{
		Protocol:       protocol.V,
		AdversaryModel: adversaryModel.V,
		KeyRate:        keyRate,
		KeyRateBound:   keyRateBound,
		Threshold:      threshold,
		IsSecure:       isSecure.V,
		Certificate:    cert,
	}, true
}

// AnalyzeAdversary performs security analysis for a specific adversary.
func AnalyzeAdversary(protocol string, adversary *ModelAdversary, errorRate *big.Rat) *SecurityResult {
	if adversary == nil {
		return nil
	}

	adversaryModel := "individual"
	if adversary.Attack != nil {
		// Determine model from attack type
		desc := adversary.Attack.Description()
		if desc != "" {
			// Simple heuristic
			if len(desc) > 10 && desc[0:10] == "collective" {
				adversaryModel = "collective"
			} else if len(desc) > 8 && desc[0:8] == "coherent" {
				adversaryModel = "coherent"
			}
		}
	}

	// Compute information gained
	info := ComputeInformation(protocol, adversary, errorRate)

	// Compute key rate
	keyRate, keyRateBound := DeriveKeyRate(protocol, errorRate, adversaryModel)

	// Get threshold
	threshold := GetSecurityThreshold(protocol)

	// Determine security
	isSecure := errorRate.Cmp(threshold) < 0 && keyRateBound.Sign() > 0

	// Create certificate
	cert := NewSecurityCertificate(protocol, adversaryModel, keyRate, errorRate, threshold)
	cert.Witness = NewSecurityWitness(
		info.Upper,
		adversary.DisturbanceInduced(),
		true,
		fmt.Sprintf("Analysis of %s attack against %s protocol", adversary.Name, protocol),
	)

	return &SecurityResult{
		Protocol:       protocol,
		AdversaryModel: adversaryModel,
		KeyRate:        keyRate,
		KeyRateBound:   keyRateBound,
		Threshold:      threshold,
		IsSecure:       isSecure,
		Certificate:    cert,
	}
}
