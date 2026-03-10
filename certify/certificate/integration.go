// integration.go provides helper functions to create certificates from analysis results.
//
// This file bridges the analysis package types with certificate types,
// providing convenient constructors for Evidence from various analysis results.
package certificate

import (
	"math/big"
	"time"

	"qbtm/runtime"
)

// CreateFromCorrectnessResult creates Evidence from a correctness analysis result.
// The result parameter should have fields: Correct (bool), Fidelity (*big.Rat),
// ChoiMatrix (*runtime.Matrix), IdealChannel (*runtime.Matrix).
func CreateFromCorrectnessResult(correct bool, fidelity *big.Rat, choiMatrix, idealChannel *runtime.Matrix) *Evidence {
	// Determine status
	status := StatusFailed
	if correct {
		status = StatusVerified
	}

	// Create claim
	claim := NewCorrectnessClaim("", fidelity)

	// Create witness
	witness := &Witness{
		Type:        WitnessChoiEquality,
		Description: "Choi matrix equality witness",
		Data:        runtime.MakeNil(),
	}

	if choiMatrix != nil && idealChannel != nil {
		// Create ChoiEqualityWitness data
		witness.Data = runtime.MakeSeq(
			runtime.MatrixToValue(choiMatrix),
			runtime.MatrixToValue(idealChannel),
			runtime.MakeBool(correct),
		)
	}

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}
}

// CreateFromSecurityResult creates Evidence from a security analysis result.
// Parameters match SecurityResult fields from the analysis package.
func CreateFromSecurityResult(protocol string, adversaryModel string, keyRateBound *big.Rat, threshold *big.Rat, isSecure bool) *Evidence {
	// Determine status
	status := StatusFailed
	if isSecure {
		status = StatusVerified
	} else if keyRateBound != nil && keyRateBound.Sign() > 0 {
		status = StatusConditional
	}

	// Create claim based on key rate
	var claim *Claim
	if keyRateBound != nil {
		claim = NewKeyAgreementClaim(protocol, keyRateBound, threshold)
	} else {
		claim = NewSecrecyClaim(protocol, big.NewRat(0, 1), adversaryModel)
	}

	// Create security witness
	witness := NewSecurityWitness(keyRateBound, big.NewRat(0, 1))
	witness.Description = "Security bound under " + adversaryModel + " attacks"

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}
}

// CreateFromNoiseResult creates Evidence from a noise tolerance analysis result.
// Parameters match NoiseToleranceResult fields from the analysis package.
func CreateFromNoiseResult(protocol string, errorRate *big.Rat, threshold *big.Rat, isSecure bool, margin *big.Rat, noiseModel string) *Evidence {
	// Determine status
	status := StatusFailed
	if isSecure {
		status = StatusVerified
	} else if margin != nil && margin.Sign() >= 0 {
		status = StatusConditional
	}

	// Create claim
	claim := NewNoiseToleranceClaim(protocol, threshold, noiseModel)

	// Create witness
	witness := NewNoiseWitness(threshold, noiseModel)
	witness.AddAssumption("Error rate: " + errorRate.RatString())
	if margin != nil {
		witness.AddAssumption("Margin: " + margin.RatString())
	}

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}
}

// CreateFromKeyRateResult creates Evidence from a key rate computation.
func CreateFromKeyRateResult(protocol string, errorRate *big.Rat, keyRate *big.Rat, formula string, attackModel string) *Evidence {
	// Determine status
	status := StatusFailed
	if keyRate != nil && keyRate.Sign() > 0 {
		status = StatusVerified
	}

	// Create claim
	claim := NewKeyAgreementClaim(protocol, keyRate, errorRate)

	// Create key rate witness
	witness := &Witness{
		Type:        WitnessKeyRate,
		Description: "Key rate derivation: " + formula,
		Data: runtime.MakeSeq(
			runtime.MakeBigRat(keyRate),
			runtime.MakeText(attackModel),
		),
	}
	witness.AddAssumption("Formula: " + formula)
	witness.AddAssumption("Attack model: " + attackModel)

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}
}

// CreateFromAttackAnalysis creates Evidence from attack analysis.
func CreateFromAttackAnalysis(protocol string, attackName string, infoGained *big.Rat, disturbance *big.Rat, detectable bool) *Evidence {
	// Determine status - secure if disturbance is detectable
	status := StatusFailed
	if detectable && disturbance.Sign() > 0 {
		status = StatusVerified
	} else if disturbance.Sign() > 0 {
		status = StatusConditional
	}

	// Create attack resistance claim
	claim := NewAttackResistanceClaim(protocol, attackName, detectable)

	// Create attack witness
	attackWitness := &AttackWitness{
		AttackName:     attackName,
		InfoGained:     infoGained,
		Disturbance:    disturbance,
		Detectable:     detectable,
		Countermeasure: "Error rate monitoring",
	}

	witness := &Witness{
		Type:        WitnessAttackAnalysis,
		Description: "Attack analysis for " + attackName,
		Data:        attackWitness.ToValue(),
	}

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}
}

// CreateFromChoiEquality creates Evidence from Choi matrix equality comparison.
func CreateFromChoiEquality(channelA, channelB *runtime.Matrix, equal bool, differAt int) *Evidence {
	status := StatusFailed
	if equal {
		status = StatusVerified
	}

	// Create correctness claim
	fidelity := big.NewRat(0, 1)
	if equal {
		fidelity = big.NewRat(1, 1)
	}
	claim := NewCorrectnessClaim("", fidelity)

	// Create Choi equality witness
	choiWitness := &ChoiEqualityWitness{
		ChoiMatrixA: channelA,
		ChoiMatrixB: channelB,
		Equal:       equal,
		DifferAt:    differAt,
	}

	witness := &Witness{
		Type:        WitnessChoiEquality,
		Description: "Choi matrix equality verification",
		Data:        choiWitness.ToValue(),
	}

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}
}

// CreateFromEntropyBounds creates Evidence from entropy bound computation.
func CreateFromEntropyBounds(protocol string, symbolic string, lower, upper *big.Rat) *Evidence {
	status := StatusVerified

	// Create secrecy claim (entropy relates to secrecy)
	claim := NewSecrecyClaim(protocol, upper, "entropy-bound")

	// Create entropy witness
	entropyWitness := &EntropyWitness{
		Symbolic: symbolic,
		Lower:    lower,
		Upper:    upper,
	}

	witness := &Witness{
		Type:        WitnessEntropyBound,
		Description: "Entropy bound: " + symbolic,
		Data:        entropyWitness.ToValue(),
	}

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}
}

// CreateFromInformationBound creates Evidence from information leakage bound.
func CreateFromInformationBound(protocol string, attackModel string, infoBound *big.Rat, disturbanceLower *big.Rat, derivation string) *Evidence {
	// Secure if information bound is small (< 1 bit)
	status := StatusFailed
	if infoBound != nil && infoBound.Cmp(big.NewRat(1, 1)) < 0 {
		status = StatusVerified
	}

	// Create secrecy claim
	claim := NewSecrecyClaim(protocol, infoBound, attackModel)

	// Create information bound witness
	infoBoundWitness := &InformationBoundWitness{
		Protocol:         protocol,
		AttackModel:      attackModel,
		InfoBound:        infoBound,
		DisturbanceLower: disturbanceLower,
		Derivation:       derivation,
	}

	witness := &Witness{
		Type:        WitnessInformationBound,
		Description: "Information leakage bound: I(X:E) <= " + infoBound.RatString(),
		Data:        infoBoundWitness.ToValue(),
	}

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}
}

// CreateBitCommitmentEvidence creates Evidence for bit commitment protocol.
func CreateBitCommitmentEvidence(protocol string, binding, hiding *big.Rat) *Bundle {
	bundle := NewBundle(protocol)

	// Add binding evidence
	bindingClaim := NewBindingClaim(protocol, binding)
	bindingWitness := &Witness{
		Type:        WitnessSecurityBound,
		Description: "Binding property bound",
		Data:        runtime.MakeBigRat(binding),
	}
	bindingStatus := StatusFailed
	if binding != nil && binding.Cmp(big.NewRat(1, 2)) > 0 {
		bindingStatus = StatusVerified
	}
	bundle.AddEvidence(&Evidence{
		Status:    bindingStatus,
		Claim:     bindingClaim,
		Witness:   bindingWitness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	})

	// Add hiding evidence
	hidingClaim := NewHidingClaim(protocol, hiding)
	hidingWitness := &Witness{
		Type:        WitnessSecurityBound,
		Description: "Hiding property bound",
		Data:        runtime.MakeBigRat(hiding),
	}
	hidingStatus := StatusFailed
	if hiding != nil && hiding.Cmp(big.NewRat(1, 2)) > 0 {
		hidingStatus = StatusVerified
	}
	bundle.AddEvidence(&Evidence{
		Status:    hidingStatus,
		Claim:     hidingClaim,
		Witness:   hidingWitness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	})

	return bundle
}

// CreateCoinFlipEvidence creates Evidence for coin flipping protocol.
func CreateCoinFlipEvidence(protocol string, bias *big.Rat) *Evidence {
	claim := NewBiasClaim(protocol, bias)

	witness := &Witness{
		Type:        WitnessSecurityBound,
		Description: "Coin flip bias bound",
		Data:        runtime.MakeBigRat(bias),
	}

	// Kitaev bound: bias >= 1/sqrt(2) - 1/2 ~ 0.207
	// Any protocol with smaller bias is optimal
	status := StatusVerified
	if bias != nil {
		kitaevBound := big.NewRat(207, 1000) // Approximate Kitaev bound
		if bias.Cmp(kitaevBound) < 0 {
			status = StatusConditional // Better than Kitaev bound - suspicious
		}
	}

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: time.Now().Unix(),
		Version:   "1.0.0",
	}
}
