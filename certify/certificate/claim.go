// claim.go provides claim types for certificates.
//
// Claims are security assertions that can be verified and certified:
// - Correctness: Protocol achieves its stated goal
// - Security: Protocol is secure against specified attacks
// - Composition: Protocol composes securely with others
package certificate

import (
	"math/big"

	"qbtm/runtime"
)

// ClaimType identifies the type of security claim.
type ClaimType int

const (
	ClaimCorrectness ClaimType = iota
	ClaimSecrecy
	ClaimAuthenticity
	ClaimKeyAgreement
	ClaimStateTransfer
	ClaimComposability
	ClaimNoiseTolerance
	ClaimAttackResistance
	ClaimBinding  // For bit commitment
	ClaimHiding   // For bit commitment
	ClaimBias     // For coin flipping
)

// String returns a human-readable name for the claim type.
func (t ClaimType) String() string {
	switch t {
	case ClaimCorrectness:
		return "correctness"
	case ClaimSecrecy:
		return "secrecy"
	case ClaimAuthenticity:
		return "authenticity"
	case ClaimKeyAgreement:
		return "key-agreement"
	case ClaimStateTransfer:
		return "state-transfer"
	case ClaimComposability:
		return "composability"
	case ClaimNoiseTolerance:
		return "noise-tolerance"
	case ClaimAttackResistance:
		return "attack-resistance"
	case ClaimBinding:
		return "binding"
	case ClaimHiding:
		return "hiding"
	case ClaimBias:
		return "bias"
	default:
		return "unknown"
	}
}

// Claim represents a security assertion about a protocol.
type Claim struct {
	Type         ClaimType
	Protocol     string
	Description  string
	Parameters   map[string]*big.Rat
	Dependencies []string // Other claims this depends on
}

// NewCorrectnessClaim creates a correctness claim.
func NewCorrectnessClaim(protocol string, fidelity *big.Rat) *Claim {
	return &Claim{
		Type:        ClaimCorrectness,
		Protocol:    protocol,
		Description: "Protocol is correct (achieves ideal functionality)",
		Parameters: map[string]*big.Rat{
			"fidelity": fidelity,
		},
	}
}

// NewSecrecyClaim creates a secrecy claim.
func NewSecrecyClaim(protocol string, epsilon *big.Rat, attackModel string) *Claim {
	return &Claim{
		Type:        ClaimSecrecy,
		Protocol:    protocol,
		Description: "Protocol is epsilon-secret against " + attackModel,
		Parameters: map[string]*big.Rat{
			"epsilon": epsilon,
		},
	}
}

// NewKeyAgreementClaim creates a key agreement claim.
func NewKeyAgreementClaim(protocol string, keyRate, errorThreshold *big.Rat) *Claim {
	return &Claim{
		Type:        ClaimKeyAgreement,
		Protocol:    protocol,
		Description: "Protocol achieves secure key agreement",
		Parameters: map[string]*big.Rat{
			"key-rate":        keyRate,
			"error-threshold": errorThreshold,
		},
	}
}

// NewComposabilityClaim creates a composability claim.
func NewComposabilityClaim(protocol string, securityLoss *big.Rat) *Claim {
	return &Claim{
		Type:        ClaimComposability,
		Protocol:    protocol,
		Description: "Protocol is universally composable",
		Parameters: map[string]*big.Rat{
			"security-loss": securityLoss,
		},
	}
}

// NewNoiseToleranceClaim creates a noise tolerance claim.
func NewNoiseToleranceClaim(protocol string, threshold *big.Rat, noiseModel string) *Claim {
	return &Claim{
		Type:        ClaimNoiseTolerance,
		Protocol:    protocol,
		Description: "Protocol tolerates " + noiseModel + " noise",
		Parameters: map[string]*big.Rat{
			"threshold": threshold,
		},
	}
}

// NewStateTransferClaim creates a state transfer claim.
func NewStateTransferClaim(protocol string, fidelity *big.Rat) *Claim {
	return &Claim{
		Type:        ClaimStateTransfer,
		Protocol:    protocol,
		Description: "Protocol achieves quantum state transfer",
		Parameters: map[string]*big.Rat{
			"fidelity": fidelity,
		},
	}
}

// NewAttackResistanceClaim creates an attack resistance claim.
func NewAttackResistanceClaim(protocol string, attack string, secure bool) *Claim {
	secureVal := big.NewRat(0, 1)
	if secure {
		secureVal = big.NewRat(1, 1)
	}
	return &Claim{
		Type:        ClaimAttackResistance,
		Protocol:    protocol,
		Description: "Protocol is resistant to " + attack + " attack",
		Parameters: map[string]*big.Rat{
			"secure": secureVal,
		},
	}
}

// NewBindingClaim creates a binding claim for bit commitment.
func NewBindingClaim(protocol string, binding *big.Rat) *Claim {
	return &Claim{
		Type:        ClaimBinding,
		Protocol:    protocol,
		Description: "Protocol achieves binding property",
		Parameters: map[string]*big.Rat{
			"binding": binding,
		},
	}
}

// NewHidingClaim creates a hiding claim for bit commitment.
func NewHidingClaim(protocol string, hiding *big.Rat) *Claim {
	return &Claim{
		Type:        ClaimHiding,
		Protocol:    protocol,
		Description: "Protocol achieves hiding property",
		Parameters: map[string]*big.Rat{
			"hiding": hiding,
		},
	}
}

// NewBiasClaim creates a bias claim for coin flipping.
func NewBiasClaim(protocol string, bias *big.Rat) *Claim {
	return &Claim{
		Type:        ClaimBias,
		Protocol:    protocol,
		Description: "Protocol achieves bounded bias coin flipping",
		Parameters: map[string]*big.Rat{
			"bias": bias,
		},
	}
}

// AddDependency adds a claim dependency.
func (c *Claim) AddDependency(dep string) {
	c.Dependencies = append(c.Dependencies, dep)
}

// CanVerify returns true if the claim has all required parameters for verification.
func (c *Claim) CanVerify() bool {
	if c == nil || c.Parameters == nil {
		return false
	}

	// Check required parameters based on claim type
	switch c.Type {
	case ClaimCorrectness:
		_, hasFidelity := c.Parameters["fidelity"]
		return hasFidelity
	case ClaimSecrecy:
		_, hasEpsilon := c.Parameters["epsilon"]
		return hasEpsilon
	case ClaimKeyAgreement:
		_, hasKeyRate := c.Parameters["key-rate"]
		_, hasErrorThreshold := c.Parameters["error-threshold"]
		return hasKeyRate && hasErrorThreshold
	case ClaimStateTransfer:
		_, hasFidelity := c.Parameters["fidelity"]
		return hasFidelity
	case ClaimComposability:
		_, hasSecurityLoss := c.Parameters["security-loss"]
		return hasSecurityLoss
	case ClaimNoiseTolerance:
		_, hasThreshold := c.Parameters["threshold"]
		return hasThreshold
	case ClaimAttackResistance:
		_, hasSecure := c.Parameters["secure"]
		return hasSecure
	case ClaimBinding:
		_, hasBinding := c.Parameters["binding"]
		return hasBinding
	case ClaimHiding:
		_, hasHiding := c.Parameters["hiding"]
		return hasHiding
	case ClaimBias:
		_, hasBias := c.Parameters["bias"]
		return hasBias
	default:
		return len(c.Parameters) > 0
	}
}

// Verify verifies the claim against the provided witness.
func (c *Claim) Verify(witness *Witness) bool {
	if c == nil || !c.CanVerify() {
		return false
	}

	// If no witness provided, we can only check parameter validity
	if witness == nil {
		return c.verifyParameters()
	}

	// Verify witness type matches claim type
	switch c.Type {
	case ClaimCorrectness:
		if witness.Type != WitnessChoiMatrix && witness.Type != WitnessChoiEquality {
			return false
		}
		// Check fidelity is 1 for perfect correctness
		if fidelity, ok := c.Parameters["fidelity"]; ok {
			if fidelity.Cmp(big.NewRat(1, 1)) == 0 {
				// Perfect fidelity requires exact equality in witness
				return witness.Verify()
			}
		}
	case ClaimSecrecy, ClaimKeyAgreement:
		if witness.Type != WitnessSecurityBound && witness.Type != WitnessKeyRate {
			return false
		}
	case ClaimNoiseTolerance:
		if witness.Type != WitnessNoiseTolerance {
			return false
		}
	case ClaimComposability:
		if witness.Type != WitnessCompositionProof {
			return false
		}
	}

	return witness.Verify()
}

// verifyParameters checks that all parameters are valid.
func (c *Claim) verifyParameters() bool {
	for key, val := range c.Parameters {
		if val == nil {
			return false
		}
		// Check bounds based on parameter type
		switch key {
		case "fidelity", "epsilon", "key-rate", "threshold", "binding", "hiding", "bias", "security-loss":
			// These should be in [0, 1]
			if val.Sign() < 0 || val.Cmp(big.NewRat(1, 1)) > 0 {
				return false
			}
		case "error-threshold":
			// Error threshold should be positive
			if val.Sign() <= 0 {
				return false
			}
		}
	}
	return true
}

// ToValue converts a Claim to a runtime.Value.
func (c *Claim) ToValue() runtime.Value {
	params := make([]runtime.Value, 0, len(c.Parameters)*2)
	for k, v := range c.Parameters {
		params = append(params, runtime.MakeText(k), runtime.MakeBigRat(v))
	}

	deps := make([]runtime.Value, len(c.Dependencies))
	for i, d := range c.Dependencies {
		deps[i] = runtime.MakeText(d)
	}

	return runtime.MakeTag(
		runtime.MakeText("claim"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(c.Type)),
			runtime.MakeText(c.Protocol),
			runtime.MakeText(c.Description),
			runtime.MakeSeq(params...),
			runtime.MakeSeq(deps...),
		),
	)
}

// ClaimFromValue deserializes a Claim from a runtime.Value.
func ClaimFromValue(v runtime.Value) (*Claim, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "claim" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 5 {
		return nil, false
	}

	// Parse type
	typeInt, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return nil, false
	}

	// Parse protocol
	protocol, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return nil, false
	}

	// Parse description
	description, ok := seq.Items[2].(runtime.Text)
	if !ok {
		return nil, false
	}

	// Parse parameters
	paramsSeq, ok := seq.Items[3].(runtime.Seq)
	if !ok {
		return nil, false
	}
	parameters := make(map[string]*big.Rat)
	for i := 0; i+1 < len(paramsSeq.Items); i += 2 {
		key, ok := paramsSeq.Items[i].(runtime.Text)
		if !ok {
			continue
		}
		val, ok := paramsSeq.Items[i+1].(runtime.Rat)
		if !ok {
			continue
		}
		parameters[key.V] = new(big.Rat).Set(val.V)
	}

	// Parse dependencies
	depsSeq, ok := seq.Items[4].(runtime.Seq)
	if !ok {
		return nil, false
	}
	dependencies := make([]string, 0, len(depsSeq.Items))
	for _, item := range depsSeq.Items {
		if text, ok := item.(runtime.Text); ok {
			dependencies = append(dependencies, text.V)
		}
	}

	return &Claim{
		Type:         ClaimType(typeInt.V.Int64()),
		Protocol:     protocol.V,
		Description:  description.V,
		Parameters:   parameters,
		Dependencies: dependencies,
	}, true
}
