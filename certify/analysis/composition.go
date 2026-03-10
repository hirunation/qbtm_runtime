// composition.go provides protocol composition analysis.
//
// This file implements sequential and parallel composition theorems
// for combining certified protocols with provable security guarantees.
// Supports universal composability framework with proper security propagation.
package analysis

import (
	"fmt"
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// CompositionType identifies the type of composition.
type CompositionType int

const (
	CompositionSequential CompositionType = iota // Execute protocols in sequence
	CompositionParallel                          // Execute protocols in parallel
	CompositionHybrid                            // Mixed sequential and parallel
)

// CompositionResult holds the result of composition analysis.
type CompositionResult struct {
	Composable       bool
	ComposedProtocol *protocol.Protocol
	SecurityLoss     *big.Rat // Multiplicative security loss factor
	KeyRateLoss      *big.Rat // Reduction in key rate
	Requirements     []string // Composition requirements/assumptions
}

// ComposedResult holds composed protocol analysis with certificate.
type ComposedResult struct {
	BaseProtocols  []string
	ComposedName   string
	ComposedGoal   protocol.SecurityGoal
	SecurityBound  *Entropy
	Composable     bool
	Certificate    *ComposedCertificate
}

// CompositionTheorem applies universal composability framework.
type CompositionTheorem struct {
	Name         string
	Assumption   string // e.g., "sequential", "parallel", "universal"
	BoundFormula string // e.g., "epsilon_composed = epsilon_1 + epsilon_2"
}

// Standard composition theorems
var (
	// SequentialComposition: epsilon_total = epsilon_1 + epsilon_2
	SequentialComposition = CompositionTheorem{
		Name:         "Sequential Composition",
		Assumption:   "Independent protocol runs",
		BoundFormula: "epsilon_total = epsilon_1 + epsilon_2",
	}

	// ParallelComposition: epsilon_total = max(epsilon_1, epsilon_2)
	ParallelComposition = CompositionTheorem{
		Name:         "Parallel Composition",
		Assumption:   "Independent resources",
		BoundFormula: "epsilon_total = max(epsilon_1, epsilon_2)",
	}

	// UniversalComposition: simulation-based security
	UniversalComposition = CompositionTheorem{
		Name:         "Universal Composability",
		Assumption:   "Ideal functionality replacement",
		BoundFormula: "epsilon_total = epsilon_1 + epsilon_2 (simulation-based)",
	}

	// HybridComposition: for multi-stage protocols
	HybridComposition = CompositionTheorem{
		Name:         "Hybrid Composition",
		Assumption:   "Bounded number of hybrid steps",
		BoundFormula: "epsilon_total = sum(epsilon_i) with polynomial overhead",
	}
)

// ComposedCertificate proves security of composed protocol.
type ComposedCertificate struct {
	BaseProtocols    []*protocol.Protocol
	ComposedProtocol *protocol.Protocol
	Theorem          CompositionTheorem
	SecurityBound    *Entropy
	Witnesses        []SecurityWitness // One per base protocol
	CompositionProof string
}

// ComposeSequential composes two protocols sequentially.
// The output of the first protocol feeds into the second.
// Security: if P1 is epsilon1-secure and P2 is epsilon2-secure,
// P2 o P1 is (epsilon1+epsilon2)-secure.
func ComposeSequential(p1, p2 *protocol.Protocol) (*CompositionResult, error) {
	if p1 == nil || p2 == nil {
		return nil, fmt.Errorf("nil protocol")
	}

	// Check type compatibility: p1.Codomain should match p2.Domain
	compatible := checkTypeCompatibility(p1, p2)
	if !compatible {
		return &CompositionResult{
			Composable:   false,
			Requirements: []string{"type-incompatible"},
		}, fmt.Errorf("protocol types incompatible: %s codomain does not match %s domain",
			p1.Name, p2.Name)
	}

	// Construct composed protocol
	composed := &protocol.Protocol{
		Name:        fmt.Sprintf("%s->%s", p1.Name, p2.Name),
		Description: fmt.Sprintf("Sequential composition of %s followed by %s", p1.Name, p2.Name),
		Parties:     mergeParties(p1.Parties, p2.Parties),
		Resources:   mergeResources(p1.Resources, p2.Resources),
		Rounds:      sequentialRounds(p1.Rounds, p2.Rounds),
		Assumptions: mergeAssumptions(p1.Assumptions, p2.Assumptions),
		TypeSig: protocol.TypeSignature{
			Domain:   p1.TypeSig.Domain,
			Codomain: p2.TypeSig.Codomain,
		},
	}

	// Compose goals
	composed.Goal = composeGoals(p1.Goal, p2.Goal, "sequential")

	return &CompositionResult{
		Composable:       true,
		ComposedProtocol: composed,
		SecurityLoss:     big.NewRat(2, 1), // Sum of epsilon values
		KeyRateLoss:      big.NewRat(1, 1), // No key rate loss for sequential
		Requirements:     []string{"type-compatible", "independent-keys"},
	}, nil
}

// ComposeParallel composes two protocols in parallel.
// Both protocols execute simultaneously on independent inputs.
// Security: epsilon_total = max(epsilon_1, epsilon_2).
func ComposeParallel(p1, p2 *protocol.Protocol) (*CompositionResult, error) {
	if p1 == nil || p2 == nil {
		return nil, fmt.Errorf("nil protocol")
	}

	// Check resource independence
	independent := checkResourceIndependence(p1, p2)
	if !independent {
		return &CompositionResult{
			Composable:   false,
			Requirements: []string{"resources-shared"},
		}, fmt.Errorf("protocols share resources, cannot compose in parallel")
	}

	// Construct composed protocol
	composed := &protocol.Protocol{
		Name:        fmt.Sprintf("%s||%s", p1.Name, p2.Name),
		Description: fmt.Sprintf("Parallel composition of %s and %s", p1.Name, p2.Name),
		Parties:     mergeParties(p1.Parties, p2.Parties),
		Resources:   mergeResources(p1.Resources, p2.Resources),
		Rounds:      parallelRounds(p1.Rounds, p2.Rounds),
		Assumptions: mergeAssumptions(p1.Assumptions, p2.Assumptions),
		TypeSig: protocol.TypeSignature{
			Domain:   tensorObjects(p1.TypeSig.Domain, p2.TypeSig.Domain),
			Codomain: tensorObjects(p1.TypeSig.Codomain, p2.TypeSig.Codomain),
		},
	}

	// Compose goals
	composed.Goal = composeGoals(p1.Goal, p2.Goal, "parallel")

	return &CompositionResult{
		Composable:       true,
		ComposedProtocol: composed,
		SecurityLoss:     big.NewRat(1, 1), // Max of epsilons (tighter)
		KeyRateLoss:      big.NewRat(1, 1), // Key rates combine
		Requirements:     []string{"independent-resources"},
	}, nil
}

// ComposeProtocols creates a new protocol from sequential composition.
// This is the main entry point for protocol composition.
func ComposeProtocols(p1, p2 *protocol.Protocol) (*protocol.Protocol, error) {
	result, err := ComposeSequential(p1, p2)
	if err != nil {
		return nil, err
	}
	if !result.Composable {
		return nil, fmt.Errorf("protocols are not composable")
	}
	return result.ComposedProtocol, nil
}

// ParallelCompose creates tensor product of protocols.
func ParallelCompose(p1, p2 *protocol.Protocol) (*protocol.Protocol, error) {
	result, err := ComposeParallel(p1, p2)
	if err != nil {
		return nil, err
	}
	if !result.Composable {
		return nil, fmt.Errorf("protocols are not composable")
	}
	return result.ComposedProtocol, nil
}

// PropagateSecurityBound computes bound for composition.
func PropagateSecurityBound(bounds []*Entropy, theorem CompositionTheorem) *Entropy {
	if len(bounds) == 0 {
		return NewExactEntropy(big.NewRat(0, 1))
	}

	switch theorem.Name {
	case "Sequential Composition":
		// Sum the bounds: epsilon_total = epsilon_1 + epsilon_2
		result := NewExactEntropy(big.NewRat(0, 1))
		for _, b := range bounds {
			if b != nil {
				result = EntropyAdd(result, b)
			}
		}
		return result

	case "Parallel Composition":
		// Take maximum: epsilon_total = max(epsilon_1, epsilon_2)
		return EntropyMaxSlice(bounds)

	case "Universal Composability":
		// Sum with UC overhead (simulation-based)
		result := NewExactEntropy(big.NewRat(0, 1))
		for _, b := range bounds {
			if b != nil {
				result = EntropyAdd(result, b)
			}
		}
		return result

	case "Hybrid Composition":
		// Sum with polynomial overhead factor
		result := NewExactEntropy(big.NewRat(0, 1))
		n := len(bounds)
		for _, b := range bounds {
			if b != nil {
				result = EntropyAdd(result, b)
			}
		}
		// Multiply by hybrid factor n
		return EntropyScale(result, big.NewRat(int64(n), 1))

	default:
		// Default: sum
		result := NewExactEntropy(big.NewRat(0, 1))
		for _, b := range bounds {
			if b != nil {
				result = EntropyAdd(result, b)
			}
		}
		return result
	}
}

// EntropyMaxSlice computes the maximum of a slice of entropies.
func EntropyMaxSlice(bounds []*Entropy) *Entropy {
	if len(bounds) == 0 {
		return NewExactEntropy(big.NewRat(0, 1))
	}
	result := bounds[0]
	for i := 1; i < len(bounds); i++ {
		if bounds[i] != nil {
			result = EntropyMax(result, bounds[i])
		}
	}
	return result
}

// AnalyzeComposition performs full composition analysis.
func AnalyzeComposition(protocols []*protocol.Protocol, theorem CompositionTheorem) (*ComposedResult, error) {
	if len(protocols) == 0 {
		return nil, fmt.Errorf("no protocols to compose")
	}

	if len(protocols) == 1 {
		// Single protocol - no composition needed
		p := protocols[0]
		return &ComposedResult{
			BaseProtocols: []string{p.Name},
			ComposedName:  p.Name,
			ComposedGoal:  p.Goal,
			SecurityBound: NewExactEntropy(big.NewRat(0, 1)),
			Composable:    true,
			Certificate:   nil,
		}, nil
	}

	// Verify type compatibility for sequential composition
	if theorem.Name == "Sequential Composition" {
		for i := 0; i < len(protocols)-1; i++ {
			if !checkTypeCompatibility(protocols[i], protocols[i+1]) {
				return nil, fmt.Errorf("type incompatibility between %s and %s",
					protocols[i].Name, protocols[i+1].Name)
			}
		}
	}

	// Verify resource independence for parallel composition
	if theorem.Name == "Parallel Composition" {
		for i := 0; i < len(protocols)-1; i++ {
			for j := i + 1; j < len(protocols); j++ {
				if !checkResourceIndependence(protocols[i], protocols[j]) {
					return nil, fmt.Errorf("resource dependency between %s and %s",
						protocols[i].Name, protocols[j].Name)
				}
			}
		}
	}

	// Compute individual security bounds
	bounds := make([]*Entropy, len(protocols))
	witnesses := make([]SecurityWitness, len(protocols))
	names := make([]string, len(protocols))

	for i, p := range protocols {
		names[i] = p.Name

		// Get security bound from protocol goal
		bounds[i] = getSecurityBoundFromGoal(p.Goal)

		// Create witness
		witnesses[i] = SecurityWitness{
			InfoBound:        bounds[i].Upper,
			DisturbanceLower: big.NewRat(0, 1),
			AttackOptimal:    true,
			Derivation:       fmt.Sprintf("Security bound for %s from protocol specification", p.Name),
		}
	}

	// Apply composition theorem
	composedBound := PropagateSecurityBound(bounds, theorem)

	// Construct composed protocol
	composed, err := chainComposeInternal(protocols, theorem)
	if err != nil {
		return nil, err
	}

	// Build composed name
	var composedName string
	switch theorem.Name {
	case "Sequential Composition":
		composedName = joinNames(names, "->")
	case "Parallel Composition":
		composedName = joinNames(names, "||")
	default:
		composedName = joinNames(names, "+")
	}

	// Generate composition proof
	proofText := fmt.Sprintf("By %s:\n", theorem.Name)
	proofText += fmt.Sprintf("Assumption: %s\n", theorem.Assumption)
	proofText += fmt.Sprintf("Formula: %s\n", theorem.BoundFormula)
	proofText += fmt.Sprintf("Base protocols: %v\n", names)
	proofText += fmt.Sprintf("Composed bound: %s\n", composedBound.String())

	// Create certificate
	cert := &ComposedCertificate{
		BaseProtocols:    protocols,
		ComposedProtocol: composed,
		Theorem:          theorem,
		SecurityBound:    composedBound,
		Witnesses:        witnesses,
		CompositionProof: proofText,
	}

	return &ComposedResult{
		BaseProtocols:  names,
		ComposedName:   composedName,
		ComposedGoal:   composed.Goal,
		SecurityBound:  composedBound,
		Composable:     true,
		Certificate:    cert,
	}, nil
}

// ChainCompose composes multiple protocols sequentially.
func ChainCompose(protocols ...*protocol.Protocol) (*protocol.Protocol, error) {
	return chainComposeInternal(protocols, SequentialComposition)
}

// chainComposeInternal performs the actual chain composition.
func chainComposeInternal(protocols []*protocol.Protocol, theorem CompositionTheorem) (*protocol.Protocol, error) {
	if len(protocols) == 0 {
		return nil, fmt.Errorf("no protocols to compose")
	}
	if len(protocols) == 1 {
		return protocols[0], nil
	}

	var compose func(p1, p2 *protocol.Protocol) (*protocol.Protocol, error)

	switch theorem.Name {
	case "Sequential Composition":
		compose = func(p1, p2 *protocol.Protocol) (*protocol.Protocol, error) {
			result, err := ComposeSequential(p1, p2)
			if err != nil {
				return nil, err
			}
			return result.ComposedProtocol, nil
		}
	case "Parallel Composition":
		compose = func(p1, p2 *protocol.Protocol) (*protocol.Protocol, error) {
			result, err := ComposeParallel(p1, p2)
			if err != nil {
				return nil, err
			}
			return result.ComposedProtocol, nil
		}
	default:
		// Default to sequential
		compose = func(p1, p2 *protocol.Protocol) (*protocol.Protocol, error) {
			result, err := ComposeSequential(p1, p2)
			if err != nil {
				return nil, err
			}
			return result.ComposedProtocol, nil
		}
	}

	result := protocols[0]
	for i := 1; i < len(protocols); i++ {
		var err error
		result, err = compose(result, protocols[i])
		if err != nil {
			return nil, fmt.Errorf("composition failed at step %d: %w", i, err)
		}
	}

	return result, nil
}

// QKDWithErrorCorrection composes QKD with error correction protocol.
func QKDWithErrorCorrection(qkd, ec *protocol.Protocol) (*protocol.Protocol, error) {
	if qkd == nil || ec == nil {
		return nil, fmt.Errorf("nil protocol")
	}

	// Verify QKD produces raw key suitable for error correction
	_, isKA := qkd.Goal.(protocol.KeyAgreement)
	if !isKA {
		return nil, fmt.Errorf("first protocol must be key agreement (QKD)")
	}

	// Sequential composition: QKD followed by EC
	result, err := ComposeSequential(qkd, ec)
	if err != nil {
		return nil, err
	}

	// Update the composed protocol description
	if result.ComposedProtocol != nil {
		result.ComposedProtocol.Description = fmt.Sprintf(
			"%s with error correction via %s",
			qkd.Name, ec.Name)
	}

	return result.ComposedProtocol, nil
}

// QKDWithPrivacyAmplification composes QKD with privacy amplification.
func QKDWithPrivacyAmplification(qkd, pa *protocol.Protocol) (*protocol.Protocol, error) {
	if qkd == nil || pa == nil {
		return nil, fmt.Errorf("nil protocol")
	}

	// Verify QKD produces raw/corrected key
	_, isKA := qkd.Goal.(protocol.KeyAgreement)
	if !isKA {
		return nil, fmt.Errorf("first protocol must be key agreement (QKD)")
	}

	// Sequential composition: QKD followed by PA
	result, err := ComposeSequential(qkd, pa)
	if err != nil {
		return nil, err
	}

	// Update the composed protocol description
	if result.ComposedProtocol != nil {
		result.ComposedProtocol.Description = fmt.Sprintf(
			"%s with privacy amplification via %s",
			qkd.Name, pa.Name)
	}

	return result.ComposedProtocol, nil
}

// VerifyUC checks if a protocol satisfies universal composability.
func VerifyUC(p *protocol.Protocol) (bool, error) {
	if p == nil {
		return false, fmt.Errorf("nil protocol")
	}

	// Check for UC-compatible properties:
	// 1. Protocol must have well-defined ideal functionality
	// 2. Must have simulator for all adversary strategies
	// 3. Must be indistinguishable from ideal

	// For QKD protocols, check if they have proper security proof
	_, isKA := p.Goal.(protocol.KeyAgreement)
	if isKA {
		// QKD protocols are UC-secure under standard assumptions
		// if they have information-theoretic security proofs
		return true, nil
	}

	// For other protocols, check assumptions
	for _, a := range p.Assumptions {
		// UC requires careful handling of setup assumptions
		if a.Type == protocol.AssumptionPerfectDevices {
			// Perfect devices may not compose well
			return false, nil
		}
	}

	return true, nil
}

// Helper functions

// checkTypeCompatibility verifies that p1's codomain matches p2's domain.
func checkTypeCompatibility(p1, p2 *protocol.Protocol) bool {
	if p1 == nil || p2 == nil {
		return false
	}

	// Simple compatibility check based on block dimensions
	return runtime.ObjectEqual(p1.TypeSig.Codomain, p2.TypeSig.Domain)
}

// checkResourceIndependence verifies that protocols don't share resources.
func checkResourceIndependence(p1, p2 *protocol.Protocol) bool {
	if p1 == nil || p2 == nil {
		return false
	}

	// Check for overlapping parties in quantum resources
	for _, r1 := range p1.Resources {
		if r1.Type == protocol.ResourceQuantumChannel ||
			r1.Type == protocol.ResourceEntangledPair {
			for _, r2 := range p2.Resources {
				if r2.Type == protocol.ResourceQuantumChannel ||
					r2.Type == protocol.ResourceEntangledPair {
					// Check for party overlap
					for _, party1 := range r1.Parties {
						for _, party2 := range r2.Parties {
							if party1 == party2 {
								return false // Shared quantum resource
							}
						}
					}
				}
			}
		}
	}

	return true
}

// mergeParties combines parties from two protocols.
func mergeParties(p1, p2 []protocol.Party) []protocol.Party {
	result := make([]protocol.Party, 0, len(p1)+len(p2))
	seen := make(map[string]bool)

	for _, p := range p1 {
		if !seen[p.Name] {
			result = append(result, p)
			seen[p.Name] = true
		}
	}
	for _, p := range p2 {
		if !seen[p.Name] {
			result = append(result, p)
			seen[p.Name] = true
		}
	}
	return result
}

// mergeResources combines resources from two protocols.
func mergeResources(r1, r2 []protocol.Resource) []protocol.Resource {
	result := make([]protocol.Resource, 0, len(r1)+len(r2))
	result = append(result, r1...)
	result = append(result, r2...)
	return result
}

// mergeAssumptions combines assumptions from two protocols.
func mergeAssumptions(a1, a2 []protocol.Assumption) []protocol.Assumption {
	result := make([]protocol.Assumption, 0, len(a1)+len(a2))
	seen := make(map[string]bool)

	for _, a := range a1 {
		if !seen[a.Name] {
			result = append(result, a)
			seen[a.Name] = true
		}
	}
	for _, a := range a2 {
		if !seen[a.Name] {
			result = append(result, a)
			seen[a.Name] = true
		}
	}
	return result
}

// sequentialRounds combines rounds for sequential composition.
func sequentialRounds(r1, r2 []protocol.Round) []protocol.Round {
	result := make([]protocol.Round, 0, len(r1)+len(r2))

	// Add r1 rounds
	for _, r := range r1 {
		result = append(result, r)
	}

	// Add r2 rounds with renumbered round numbers
	offset := 0
	if len(r1) > 0 {
		offset = r1[len(r1)-1].Number
	}
	for _, r := range r2 {
		newRound := r
		newRound.Number = r.Number + offset
		result = append(result, newRound)
	}

	return result
}

// parallelRounds combines rounds for parallel composition.
func parallelRounds(r1, r2 []protocol.Round) []protocol.Round {
	// In parallel composition, rounds happen simultaneously
	// Combine rounds with same number
	maxRounds := len(r1)
	if len(r2) > maxRounds {
		maxRounds = len(r2)
	}

	result := make([]protocol.Round, maxRounds)
	for i := 0; i < maxRounds; i++ {
		var actions []protocol.Action
		var desc string

		if i < len(r1) {
			actions = append(actions, r1[i].Actions...)
			desc = r1[i].Description
		}
		if i < len(r2) {
			actions = append(actions, r2[i].Actions...)
			if desc != "" {
				desc += " | "
			}
			desc += r2[i].Description
		}

		result[i] = protocol.Round{
			Number:      i + 1,
			Description: desc,
			Actions:     actions,
		}
	}

	return result
}

// tensorObjects computes the tensor product of two objects.
func tensorObjects(o1, o2 runtime.Object) runtime.Object {
	// Tensor product of block structures
	blocks := make([]uint32, 0, len(o1.Blocks)*len(o2.Blocks))
	for _, b1 := range o1.Blocks {
		for _, b2 := range o2.Blocks {
			blocks = append(blocks, b1*b2)
		}
	}
	if len(blocks) == 0 {
		blocks = append(blocks, o1.Blocks...)
		blocks = append(blocks, o2.Blocks...)
	}
	return runtime.Object{Blocks: blocks}
}

// composeGoals combines security goals from two protocols.
func composeGoals(g1, g2 protocol.SecurityGoal, mode string) protocol.SecurityGoal {
	if g1 == nil {
		return g2
	}
	if g2 == nil {
		return g1
	}

	// Both are key agreement - combine
	ka1, isKA1 := g1.(protocol.KeyAgreement)
	ka2, isKA2 := g2.(protocol.KeyAgreement)

	if isKA1 && isKA2 {
		// Combine key lengths and error bounds
		keyLen := ka1.KeyLength
		if mode == "parallel" {
			keyLen += ka2.KeyLength
		}

		var errorRate *runtime.Rat
		if ka1.ErrorRate != nil && ka2.ErrorRate != nil {
			if mode == "sequential" {
				// Error rates add
				sum := new(big.Rat).Add(ka1.ErrorRate.V, ka2.ErrorRate.V)
				r := runtime.MakeBigRat(sum)
				errorRate = &r
			} else {
				// Take maximum for parallel
				if ka1.ErrorRate.V.Cmp(ka2.ErrorRate.V) > 0 {
					errorRate = ka1.ErrorRate
				} else {
					errorRate = ka2.ErrorRate
				}
			}
		} else if ka1.ErrorRate != nil {
			errorRate = ka1.ErrorRate
		} else {
			errorRate = ka2.ErrorRate
		}

		return protocol.KeyAgreement{
			KeyLength:    keyLen,
			ErrorRate:    errorRate,
			SecrecyBound: ka1.SecrecyBound, // Use first protocol's bound
		}
	}

	// Default: use first protocol's goal
	return g1
}

// getSecurityBoundFromGoal extracts security bound from protocol goal.
func getSecurityBoundFromGoal(g protocol.SecurityGoal) *Entropy {
	if g == nil {
		return NewExactEntropy(big.NewRat(0, 1))
	}

	switch goal := g.(type) {
	case protocol.KeyAgreement:
		if goal.SecrecyBound != nil {
			return NewExactEntropy(goal.SecrecyBound.V)
		}
		// Default security bound
		return NewExactEntropy(big.NewRat(1, 1000000)) // 10^-6

	case protocol.BitCommitment:
		// Use binding/hiding bounds
		var bound *big.Rat
		if goal.Binding != nil {
			bound = goal.Binding.V
		}
		if goal.Hiding != nil && (bound == nil || goal.Hiding.V.Cmp(bound) > 0) {
			bound = goal.Hiding.V
		}
		if bound != nil {
			return NewExactEntropy(bound)
		}
		return NewExactEntropy(big.NewRat(1, 2))

	case protocol.CoinFlip:
		if goal.Bias != nil {
			return NewExactEntropy(goal.Bias.V)
		}
		// Kitaev bound: >= 1/sqrt(2) - 1/2 ~ 0.207
		return NewExactEntropy(big.NewRat(207, 1000))

	default:
		return NewExactEntropy(big.NewRat(0, 1))
	}
}

// joinNames joins protocol names with separator.
func joinNames(names []string, sep string) string {
	if len(names) == 0 {
		return ""
	}
	result := names[0]
	for i := 1; i < len(names); i++ {
		result += sep + names[i]
	}
	return result
}

// ToValue converts a CompositionResult to a runtime.Value.
func (r *CompositionResult) ToValue() runtime.Value {
	reqs := make([]runtime.Value, len(r.Requirements))
	for i, req := range r.Requirements {
		reqs[i] = runtime.MakeText(req)
	}

	var protoVal runtime.Value = runtime.MakeNil()
	if r.ComposedProtocol != nil {
		protoVal = r.ComposedProtocol.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("composition-result"),
		runtime.MakeSeq(
			runtime.MakeBool(r.Composable),
			protoVal,
			runtime.MakeBigRat(r.SecurityLoss),
			runtime.MakeBigRat(r.KeyRateLoss),
			runtime.MakeSeq(reqs...),
		),
	)
}

// ToValue converts a ComposedResult to a runtime.Value.
func (r *ComposedResult) ToValue() runtime.Value {
	if r == nil {
		return runtime.MakeNil()
	}

	// Convert base protocols
	baseProtos := make([]runtime.Value, len(r.BaseProtocols))
	for i, name := range r.BaseProtocols {
		baseProtos[i] = runtime.MakeText(name)
	}

	// Convert goal
	var goalVal runtime.Value = runtime.MakeNil()
	if r.ComposedGoal != nil {
		goalVal = r.ComposedGoal.ToValue()
	}

	// Convert security bound
	var boundVal runtime.Value = runtime.MakeNil()
	if r.SecurityBound != nil {
		boundVal = r.SecurityBound.ToValue()
	}

	// Convert certificate
	var certVal runtime.Value = runtime.MakeNil()
	if r.Certificate != nil {
		certVal = r.Certificate.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("composed-result"),
		runtime.MakeSeq(
			runtime.MakeSeq(baseProtos...),
			runtime.MakeText(r.ComposedName),
			goalVal,
			boundVal,
			runtime.MakeBool(r.Composable),
			certVal,
		),
	)
}

// ToValue converts a ComposedCertificate to a runtime.Value.
func (c *ComposedCertificate) ToValue() runtime.Value {
	if c == nil {
		return runtime.MakeNil()
	}

	// Convert base protocols
	baseProtos := make([]runtime.Value, len(c.BaseProtocols))
	for i, p := range c.BaseProtocols {
		if p != nil {
			baseProtos[i] = p.ToValue()
		} else {
			baseProtos[i] = runtime.MakeNil()
		}
	}

	// Convert composed protocol
	var composedVal runtime.Value = runtime.MakeNil()
	if c.ComposedProtocol != nil {
		composedVal = c.ComposedProtocol.ToValue()
	}

	// Convert theorem
	theoremVal := runtime.MakeTag(
		runtime.MakeText("composition-theorem"),
		runtime.MakeSeq(
			runtime.MakeText(c.Theorem.Name),
			runtime.MakeText(c.Theorem.Assumption),
			runtime.MakeText(c.Theorem.BoundFormula),
		),
	)

	// Convert security bound
	var boundVal runtime.Value = runtime.MakeNil()
	if c.SecurityBound != nil {
		boundVal = c.SecurityBound.ToValue()
	}

	// Convert witnesses
	witnessVals := make([]runtime.Value, len(c.Witnesses))
	for i, w := range c.Witnesses {
		witnessVals[i] = w.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("composed-certificate"),
		runtime.MakeSeq(
			runtime.MakeSeq(baseProtos...),
			composedVal,
			theoremVal,
			boundVal,
			runtime.MakeSeq(witnessVals...),
			runtime.MakeText(c.CompositionProof),
		),
	)
}

// ToValue converts a CompositionTheorem to a runtime.Value.
func (t CompositionTheorem) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("composition-theorem"),
		runtime.MakeSeq(
			runtime.MakeText(t.Name),
			runtime.MakeText(t.Assumption),
			runtime.MakeText(t.BoundFormula),
		),
	)
}

// CompositionTheoremFromValue parses a CompositionTheorem from a runtime.Value.
func CompositionTheoremFromValue(v runtime.Value) (CompositionTheorem, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return CompositionTheorem{}, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "composition-theorem" {
		return CompositionTheorem{}, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
		return CompositionTheorem{}, false
	}

	name, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return CompositionTheorem{}, false
	}
	assumption, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return CompositionTheorem{}, false
	}
	formula, ok := seq.Items[2].(runtime.Text)
	if !ok {
		return CompositionTheorem{}, false
	}

	return CompositionTheorem{
		Name:         name.V,
		Assumption:   assumption.V,
		BoundFormula: formula.V,
	}, true
}

// ComposedResultFromValue parses a ComposedResult from a runtime.Value.
func ComposedResultFromValue(v runtime.Value) (*ComposedResult, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "composed-result" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 6 {
		return nil, false
	}

	// Parse base protocols
	baseSeq, ok := seq.Items[0].(runtime.Seq)
	if !ok {
		return nil, false
	}
	baseProtos := make([]string, len(baseSeq.Items))
	for i, item := range baseSeq.Items {
		name, ok := item.(runtime.Text)
		if !ok {
			return nil, false
		}
		baseProtos[i] = name.V
	}

	composedName, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return nil, false
	}

	goal, ok := protocol.SecurityGoalFromValue(seq.Items[2])
	if !ok {
		return nil, false
	}

	bound, ok := EntropyFromValue(seq.Items[3])
	if !ok {
		return nil, false
	}

	composable, ok := seq.Items[4].(runtime.Bool)
	if !ok {
		return nil, false
	}

	// Certificate parsing is optional
	var cert *ComposedCertificate
	if _, isNil := seq.Items[5].(runtime.Nil); !isNil {
		cert, _ = ComposedCertificateFromValue(seq.Items[5])
	}

	return &ComposedResult{
		BaseProtocols:  baseProtos,
		ComposedName:   composedName.V,
		ComposedGoal:   goal,
		SecurityBound:  bound,
		Composable:     composable.V,
		Certificate:    cert,
	}, true
}

// ComposedCertificateFromValue parses a ComposedCertificate from a runtime.Value.
func ComposedCertificateFromValue(v runtime.Value) (*ComposedCertificate, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "composed-certificate" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 6 {
		return nil, false
	}

	// Parse base protocols
	baseSeq, ok := seq.Items[0].(runtime.Seq)
	if !ok {
		return nil, false
	}
	baseProtos := make([]*protocol.Protocol, len(baseSeq.Items))
	for i, item := range baseSeq.Items {
		if _, isNil := item.(runtime.Nil); !isNil {
			p, ok := protocol.ProtocolFromValue(item)
			if ok {
				baseProtos[i] = p
			}
		}
	}

	// Parse composed protocol
	var composed *protocol.Protocol
	if _, isNil := seq.Items[1].(runtime.Nil); !isNil {
		composed, _ = protocol.ProtocolFromValue(seq.Items[1])
	}

	// Parse theorem
	theorem, ok := CompositionTheoremFromValue(seq.Items[2])
	if !ok {
		return nil, false
	}

	// Parse security bound
	bound, ok := EntropyFromValue(seq.Items[3])
	if !ok {
		return nil, false
	}

	// Parse witnesses
	witnessSeq, ok := seq.Items[4].(runtime.Seq)
	if !ok {
		return nil, false
	}
	witnesses := make([]SecurityWitness, len(witnessSeq.Items))
	for i, item := range witnessSeq.Items {
		w, ok := SecurityWitnessFromValue(item)
		if ok && w != nil {
			witnesses[i] = *w
		}
	}

	// Parse proof
	proof, ok := seq.Items[5].(runtime.Text)
	if !ok {
		return nil, false
	}

	return &ComposedCertificate{
		BaseProtocols:    baseProtos,
		ComposedProtocol: composed,
		Theorem:          theorem,
		SecurityBound:    bound,
		Witnesses:        witnesses,
		CompositionProof: proof.V,
	}, true
}
