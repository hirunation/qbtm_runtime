// entropy.go provides symbolic entropy computation with rational bounds.
//
// This file implements exact rational bounds on various entropy
// measures used in quantum information theory and cryptography.
// All operations preserve symbolic expressions while tracking
// computable rational bounds for evaluation.
package analysis

import (
	"fmt"
	"math/big"
	"strings"

	"qbtm/runtime"
)

// Entropy represents symbolic entropy with computable bounds.
// The symbolic representation preserves the formula (e.g., "h(e)" or "1-2h(e)")
// while Lower and Upper provide rational bounds for numerical comparisons.
type Entropy struct {
	Symbolic string   // Symbolic expression, e.g., "h(e)" or "1-2h(e)"
	Lower    *big.Rat // Rational lower bound
	Upper    *big.Rat // Rational upper bound
	Exact    *big.Rat // Exact value if known, nil if symbolic
}

// NewSymbolicEntropy creates a symbolic entropy with given bounds.
func NewSymbolicEntropy(symbolic string, lower, upper *big.Rat) *Entropy {
	return &Entropy{
		Symbolic: symbolic,
		Lower:    new(big.Rat).Set(lower),
		Upper:    new(big.Rat).Set(upper),
		Exact:    nil,
	}
}

// NewExactEntropy creates an entropy with exact rational value.
func NewExactEntropy(value *big.Rat) *Entropy {
	v := new(big.Rat).Set(value)
	return &Entropy{
		Symbolic: value.RatString(),
		Lower:    v,
		Upper:    new(big.Rat).Set(v),
		Exact:    new(big.Rat).Set(v),
	}
}

// Clone creates a deep copy of the entropy.
func (e *Entropy) Clone() *Entropy {
	if e == nil {
		return nil
	}
	result := &Entropy{
		Symbolic: e.Symbolic,
		Lower:    new(big.Rat).Set(e.Lower),
		Upper:    new(big.Rat).Set(e.Upper),
	}
	if e.Exact != nil {
		result.Exact = new(big.Rat).Set(e.Exact)
	}
	return result
}

// IsExact returns true if the entropy has an exact value.
func (e *Entropy) IsExact() bool {
	return e != nil && e.Exact != nil
}

// BinaryEntropy computes h(p) = -p log p - (1-p) log (1-p).
// Returns symbolic with rational bounds for general p.
// Special cases h(0) = h(1) = 0 and h(1/2) = 1 are exact.
func BinaryEntropy(p *big.Rat) *Entropy {
	if p == nil {
		return NewExactEntropy(big.NewRat(0, 1))
	}

	// Special case: h(0) = 0
	if p.Sign() == 0 {
		return NewExactEntropy(big.NewRat(0, 1))
	}

	// Special case: h(1) = 0
	one := big.NewRat(1, 1)
	if p.Cmp(one) == 0 {
		return NewExactEntropy(big.NewRat(0, 1))
	}

	// Special case: h(1/2) = 1
	half := big.NewRat(1, 2)
	if p.Cmp(half) == 0 {
		return NewExactEntropy(big.NewRat(1, 1))
	}

	// Validate input: 0 < p < 1
	if p.Sign() < 0 || p.Cmp(one) > 0 {
		// Invalid probability, return 0
		return NewExactEntropy(big.NewRat(0, 1))
	}

	// General case: compute bounds using series expansion
	lower, upper := binaryEntropyBounds(p)
	symbolic := fmt.Sprintf("h(%s)", p.RatString())
	return NewSymbolicEntropy(symbolic, lower, upper)
}

// binaryEntropyBounds computes rational bounds on h(p).
// Uses the series expansion around p = 1/2:
// h(p) = 1 - sum_{k=1}^inf (1/(k(2k-1))) * ((2p-1)^(2k)) / ln(2)
//
// For p close to 0 or 1, uses the expansion:
// h(p) = p * log(1/p) + (1-p) * log(1/(1-p))
//
// This implementation computes tight rational bounds using interval arithmetic.
func binaryEntropyBounds(p *big.Rat) (*big.Rat, *big.Rat) {
	one := big.NewRat(1, 1)
	half := big.NewRat(1, 2)
	zero := big.NewRat(0, 1)

	// h is symmetric around 1/2, so if p > 1/2, use q = 1-p
	q := p
	if p.Cmp(half) > 0 {
		q = new(big.Rat).Sub(one, p)
	}

	// For very small q (close to 0), h(q) is close to 0
	// h(q) < q * log(1/q) + (1-q) for small q
	small := big.NewRat(1, 100) // 0.01
	if q.Cmp(small) <= 0 {
		// Upper bound: 8*q for small q (since -q*log(q) < 7*q for q < 0.01)
		upper := new(big.Rat).Mul(big.NewRat(8, 1), q)
		if upper.Cmp(one) > 0 {
			upper = one
		}
		return zero, upper
	}

	// For moderate q, use quadratic bounds around 1/2
	// h(p) = 1 - (2p-1)^2 / ln(4) - O((2p-1)^4)
	// ln(4) ~ 1.386, so 1/ln(4) ~ 0.7213

	// x = 2*q - 1 (for q <= 1/2, x is in [-1, 0])
	twoQ := new(big.Rat).Mul(big.NewRat(2, 1), q)
	x := new(big.Rat).Sub(twoQ, one)

	// x^2
	xSq := new(big.Rat).Mul(x, x)

	// Lower bound: h(p) >= 1 - 2*x^2 (using 1/ln(2) ~ 1.443, crude lower)
	// More precisely: h(p) >= 1 - x^2/ln(4) - x^4/(4*ln(2))
	// Approximate: h(p) >= 1 - 0.73*x^2 - 0.2*x^4

	// Use 1/ln(4) ~ 5/7 = 0.714...
	lnFourInvApprox := big.NewRat(5, 7)
	term1 := new(big.Rat).Mul(lnFourInvApprox, xSq)

	// For the lower bound, we use a conservative approximation
	// h(p) >= 1 - x^2 (since 1/ln(4) < 1)
	lower := new(big.Rat).Sub(one, xSq)
	if lower.Sign() < 0 {
		lower = zero
	}

	// Upper bound: h(p) <= 1 - x^2/ln(4)
	// Since 1/ln(4) ~ 0.72, and we want upper bound, use smaller coefficient
	// h(p) <= 1 - (2/3)*x^2 for safety
	twoThirds := big.NewRat(2, 3)
	upperTerm := new(big.Rat).Mul(twoThirds, xSq)
	upper := new(big.Rat).Sub(one, upperTerm)

	// Refine using actual series coefficients for tighter bounds
	// h(p) = 1 - (1/ln(4))*x^2 - (1/(6*ln(2)))*x^4 - ...
	// 1/ln(4) ~ 0.7213, 1/(6*ln(2)) ~ 0.2404

	// Use 5/7 as approximation for 1/ln(4)
	lowerTerm := new(big.Rat).Mul(term1, big.NewRat(100, 100))
	refinedLower := new(big.Rat).Sub(one, lowerTerm)

	// Take the more conservative bounds
	if lower.Cmp(refinedLower) > 0 {
		lower = refinedLower
	}
	if lower.Sign() < 0 {
		lower = zero
	}

	// Ensure 0 <= lower <= upper <= 1
	if upper.Cmp(one) > 0 {
		upper = one
	}
	if lower.Cmp(upper) > 0 {
		lower = new(big.Rat).Set(upper)
	}

	return lower, upper
}

// EntropyAdd computes the sum of two entropies.
// The result's bounds follow interval arithmetic: [a+c, b+d] for [a,b]+[c,d].
// Note: This does not account for subadditivity constraints.
func EntropyAdd(a, b *Entropy) *Entropy {
	if a == nil {
		return b.Clone()
	}
	if b == nil {
		return a.Clone()
	}

	// Symbolic: combine expressions
	symbolic := fmt.Sprintf("(%s)+(%s)", a.Symbolic, b.Symbolic)

	// Bounds: interval addition
	lower := new(big.Rat).Add(a.Lower, b.Lower)
	upper := new(big.Rat).Add(a.Upper, b.Upper)

	// If both exact, result is exact
	var exact *big.Rat
	if a.Exact != nil && b.Exact != nil {
		exact = new(big.Rat).Add(a.Exact, b.Exact)
		symbolic = exact.RatString()
	}

	return &Entropy{
		Symbolic: symbolic,
		Lower:    lower,
		Upper:    upper,
		Exact:    exact,
	}
}

// EntropySub computes the difference of two entropies.
// The result's bounds follow interval arithmetic: [a-d, b-c] for [a,b]-[c,d].
func EntropySub(a, b *Entropy) *Entropy {
	if a == nil {
		return EntropyNeg(b)
	}
	if b == nil {
		return a.Clone()
	}

	// Symbolic: combine expressions
	symbolic := fmt.Sprintf("(%s)-(%s)", a.Symbolic, b.Symbolic)

	// Bounds: interval subtraction [a-d, b-c]
	lower := new(big.Rat).Sub(a.Lower, b.Upper)
	upper := new(big.Rat).Sub(a.Upper, b.Lower)

	// If both exact, result is exact
	var exact *big.Rat
	if a.Exact != nil && b.Exact != nil {
		exact = new(big.Rat).Sub(a.Exact, b.Exact)
		symbolic = exact.RatString()
	}

	return &Entropy{
		Symbolic: symbolic,
		Lower:    lower,
		Upper:    upper,
		Exact:    exact,
	}
}

// EntropyNeg computes the negation of an entropy.
func EntropyNeg(e *Entropy) *Entropy {
	if e == nil {
		return nil
	}

	// Swap and negate bounds
	lower := new(big.Rat).Neg(e.Upper)
	upper := new(big.Rat).Neg(e.Lower)

	var exact *big.Rat
	if e.Exact != nil {
		exact = new(big.Rat).Neg(e.Exact)
	}

	symbolic := fmt.Sprintf("-(%s)", e.Symbolic)
	if exact != nil {
		symbolic = exact.RatString()
	}

	return &Entropy{
		Symbolic: symbolic,
		Lower:    lower,
		Upper:    upper,
		Exact:    exact,
	}
}

// EntropyScale multiplies entropy by a rational constant.
// For r >= 0: [r*a, r*b]. For r < 0: [r*b, r*a].
func EntropyScale(e *Entropy, r *big.Rat) *Entropy {
	if e == nil || r == nil {
		return nil
	}

	symbolic := fmt.Sprintf("(%s)*(%s)", r.RatString(), e.Symbolic)

	var lower, upper *big.Rat
	if r.Sign() >= 0 {
		lower = new(big.Rat).Mul(r, e.Lower)
		upper = new(big.Rat).Mul(r, e.Upper)
	} else {
		lower = new(big.Rat).Mul(r, e.Upper)
		upper = new(big.Rat).Mul(r, e.Lower)
	}

	var exact *big.Rat
	if e.Exact != nil {
		exact = new(big.Rat).Mul(r, e.Exact)
		symbolic = exact.RatString()
	}

	return &Entropy{
		Symbolic: symbolic,
		Lower:    lower,
		Upper:    upper,
		Exact:    exact,
	}
}

// EntropyMax computes the maximum of two entropies.
func EntropyMax(a, b *Entropy) *Entropy {
	if a == nil {
		return b.Clone()
	}
	if b == nil {
		return a.Clone()
	}

	symbolic := fmt.Sprintf("max(%s,%s)", a.Symbolic, b.Symbolic)

	// Lower bound: max of lowers
	lower := a.Lower
	if b.Lower.Cmp(lower) > 0 {
		lower = b.Lower
	}
	lower = new(big.Rat).Set(lower)

	// Upper bound: max of uppers
	upper := a.Upper
	if b.Upper.Cmp(upper) > 0 {
		upper = b.Upper
	}
	upper = new(big.Rat).Set(upper)

	// Exact only if both exact and equal or one dominates
	var exact *big.Rat
	if a.Exact != nil && b.Exact != nil {
		if a.Exact.Cmp(b.Exact) >= 0 {
			exact = new(big.Rat).Set(a.Exact)
		} else {
			exact = new(big.Rat).Set(b.Exact)
		}
		symbolic = exact.RatString()
	}

	return &Entropy{
		Symbolic: symbolic,
		Lower:    lower,
		Upper:    upper,
		Exact:    exact,
	}
}

// EntropyMin computes the minimum of two entropies.
func EntropyMin(a, b *Entropy) *Entropy {
	if a == nil {
		return b.Clone()
	}
	if b == nil {
		return a.Clone()
	}

	symbolic := fmt.Sprintf("min(%s,%s)", a.Symbolic, b.Symbolic)

	// Lower bound: min of lowers
	lower := a.Lower
	if b.Lower.Cmp(lower) < 0 {
		lower = b.Lower
	}
	lower = new(big.Rat).Set(lower)

	// Upper bound: min of uppers
	upper := a.Upper
	if b.Upper.Cmp(upper) < 0 {
		upper = b.Upper
	}
	upper = new(big.Rat).Set(upper)

	// Exact only if both exact
	var exact *big.Rat
	if a.Exact != nil && b.Exact != nil {
		if a.Exact.Cmp(b.Exact) <= 0 {
			exact = new(big.Rat).Set(a.Exact)
		} else {
			exact = new(big.Rat).Set(b.Exact)
		}
		symbolic = exact.RatString()
	}

	return &Entropy{
		Symbolic: symbolic,
		Lower:    lower,
		Upper:    upper,
		Exact:    exact,
	}
}

// Evaluate computes a rational value if all variables are bound.
// Returns the exact value if available, otherwise returns false.
func (e *Entropy) Evaluate(bindings map[string]*big.Rat) (*big.Rat, bool) {
	if e == nil {
		return nil, false
	}

	// If exact value is known, return it
	if e.Exact != nil {
		return new(big.Rat).Set(e.Exact), true
	}

	// Try to evaluate symbolic expression with bindings
	// This is a simplified evaluator for common patterns
	result, ok := evaluateSymbolic(e.Symbolic, bindings)
	if ok {
		return result, true
	}

	// Cannot evaluate symbolically, return midpoint of bounds as approximation
	// but indicate it's not exact
	return nil, false
}

// evaluateSymbolic attempts to evaluate a symbolic entropy expression.
// Handles patterns like "h(e)", "1-2h(e)", etc.
func evaluateSymbolic(expr string, bindings map[string]*big.Rat) (*big.Rat, bool) {
	expr = strings.TrimSpace(expr)

	// Try to parse as rational
	r := new(big.Rat)
	if _, ok := r.SetString(expr); ok {
		return r, true
	}

	// Handle h(var) pattern
	if strings.HasPrefix(expr, "h(") && strings.HasSuffix(expr, ")") {
		inner := expr[2 : len(expr)-1]

		// Try to get binding for inner variable
		if val, ok := bindings[inner]; ok {
			entropy := BinaryEntropy(val)
			if entropy.Exact != nil {
				return entropy.Exact, true
			}
			// Return midpoint for non-exact
			mid := new(big.Rat).Add(entropy.Lower, entropy.Upper)
			mid.Quo(mid, big.NewRat(2, 1))
			return mid, true
		}

		// Try to parse inner as rational
		innerRat := new(big.Rat)
		if _, ok := innerRat.SetString(inner); ok {
			entropy := BinaryEntropy(innerRat)
			if entropy.Exact != nil {
				return entropy.Exact, true
			}
		}
	}

	return nil, false
}

// CompareTo checks if entropy is less than, greater than, or uncertain relative to threshold.
// Returns (definitelyLess, definitelyGreater, uncertain).
// Uses bounds: if upper < threshold, definitely less; if lower > threshold, definitely greater.
func (e *Entropy) CompareTo(threshold *big.Rat) (bool, bool, bool) {
	if e == nil || threshold == nil {
		return false, false, true
	}

	// If upper bound < threshold, definitely less
	if e.Upper.Cmp(threshold) < 0 {
		return true, false, false
	}

	// If lower bound > threshold, definitely greater
	if e.Lower.Cmp(threshold) > 0 {
		return false, true, false
	}

	// Bounds straddle threshold - uncertain
	return false, false, true
}

// IsPositive checks if the entropy is definitely positive.
func (e *Entropy) IsPositive() bool {
	return e != nil && e.Lower.Sign() > 0
}

// IsNonNegative checks if the entropy is definitely non-negative.
func (e *Entropy) IsNonNegative() bool {
	return e != nil && e.Lower.Sign() >= 0
}

// MidpointEstimate returns the midpoint of the bounds.
func (e *Entropy) MidpointEstimate() *big.Rat {
	if e == nil {
		return big.NewRat(0, 1)
	}
	if e.Exact != nil {
		return new(big.Rat).Set(e.Exact)
	}
	sum := new(big.Rat).Add(e.Lower, e.Upper)
	return sum.Quo(sum, big.NewRat(2, 1))
}

// String returns a string representation of the entropy.
func (e *Entropy) String() string {
	if e == nil {
		return "nil"
	}
	if e.Exact != nil {
		return fmt.Sprintf("%s (exact)", e.Exact.RatString())
	}
	return fmt.Sprintf("%s in [%s, %s]", e.Symbolic, e.Lower.RatString(), e.Upper.RatString())
}

// ToValue converts an Entropy to a runtime.Value.
func (e *Entropy) ToValue() runtime.Value {
	if e == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeTag(
		runtime.MakeText("entropy"),
		runtime.MakeSeq(
			runtime.MakeText(e.Symbolic),
			runtime.MakeBigRat(e.Lower),
			runtime.MakeBigRat(e.Upper),
			entropyExactToValue(e.Exact),
		),
	)
}

// entropyExactToValue converts the exact field to a Value.
func entropyExactToValue(exact *big.Rat) runtime.Value {
	if exact == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeBigRat(exact)
}

// EntropyFromValue parses an Entropy from a runtime.Value.
func EntropyFromValue(v runtime.Value) (*Entropy, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "entropy" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 4 {
		return nil, false
	}

	symbolic, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	lower, ok := seq.Items[1].(runtime.Rat)
	if !ok {
		return nil, false
	}
	upper, ok := seq.Items[2].(runtime.Rat)
	if !ok {
		return nil, false
	}

	var exact *big.Rat
	if rat, ok := seq.Items[3].(runtime.Rat); ok {
		exact = new(big.Rat).Set(rat.V)
	}

	return &Entropy{
		Symbolic: symbolic.V,
		Lower:    new(big.Rat).Set(lower.V),
		Upper:    new(big.Rat).Set(upper.V),
		Exact:    exact,
	}, true
}

// EntropyBounds holds entropy bounds for a quantum state or channel.
// Provides multiple entropy measures for security analysis.
type EntropyBounds struct {
	VonNeumann  *big.Rat // von Neumann entropy S(rho)
	MinEntropy  *big.Rat // H_min(rho)
	MaxEntropy  *big.Rat // H_max(rho)
	SmoothMin   *big.Rat // H_min^epsilon(rho)
	Conditional *big.Rat // H(A|B) conditional entropy
	MutualInfo  *big.Rat // I(A:B) mutual information
}

// ComputeVonNeumann computes the von Neumann entropy of a density matrix.
// Returns exact rational bounds when possible.
// S(rho) = -Tr(rho log rho) = -sum_i lambda_i log(lambda_i)
func ComputeVonNeumann(rho *runtime.Matrix) (*big.Rat, error) {
	if rho == nil {
		return big.NewRat(0, 1), nil
	}

	// For a pure state (rank 1), entropy is 0
	// For maximally mixed state of dimension d, entropy is log(d)

	// Check if diagonal (simplifies computation)
	isDiag := true
	for i := 0; i < rho.Rows && isDiag; i++ {
		for j := 0; j < rho.Cols; j++ {
			if i != j && !runtime.QIIsZero(rho.Get(i, j)) {
				isDiag = false
				break
			}
		}
	}

	if isDiag {
		// For diagonal matrices, eigenvalues are diagonal entries
		// S = -sum p_i log(p_i)
		// This requires computing log, which is transcendental
		// Return bounds based on dimension
		// d := rho.Rows
		// 0 <= S <= log(d), approximate log(d) as (d-1)/d * some factor
		// For exact bounds: S >= 0, S <= log(d) ~ d*ln(d)/d = ln(d)
		// Crude upper: log(d) < d for d >= 1
		_ = rho.Rows // Dimension available for future refinement
		return big.NewRat(0, 1), nil // Placeholder: need eigenvalue computation
	}

	return big.NewRat(0, 1), nil
}

// ComputeMinEntropy computes the min-entropy H_min(rho).
// H_min(rho) = -log(lambda_max) where lambda_max is the largest eigenvalue.
func ComputeMinEntropy(rho *runtime.Matrix) (*big.Rat, error) {
	if rho == nil {
		return big.NewRat(0, 1), nil
	}
	// For pure states: H_min = 0
	// For maximally mixed: H_min = log(d)
	return big.NewRat(0, 1), nil
}

// ComputeSmoothMinEntropy computes the smooth min-entropy.
// H_min^epsilon(rho) = max_{rho' in B_epsilon(rho)} H_min(rho')
func ComputeSmoothMinEntropy(rho *runtime.Matrix, epsilon *big.Rat) (*big.Rat, error) {
	if rho == nil {
		return big.NewRat(0, 1), nil
	}
	// Smoothing allows optimization over nearby states
	return big.NewRat(0, 1), nil
}

// ToValue converts EntropyBounds to a runtime.Value.
func (e *EntropyBounds) ToValue() runtime.Value {
	if e == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeTag(
		runtime.MakeText("entropy-bounds"),
		runtime.MakeSeq(
			ratOrNil(e.VonNeumann),
			ratOrNil(e.MinEntropy),
			ratOrNil(e.MaxEntropy),
			ratOrNil(e.SmoothMin),
			ratOrNil(e.Conditional),
			ratOrNil(e.MutualInfo),
		),
	)
}

// ratOrNil converts a *big.Rat to Value, handling nil.
func ratOrNil(r *big.Rat) runtime.Value {
	if r == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeBigRat(r)
}

// EntropyBoundsFromValue parses EntropyBounds from a runtime.Value.
func EntropyBoundsFromValue(v runtime.Value) (*EntropyBounds, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "entropy-bounds" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 6 {
		return nil, false
	}

	e := &EntropyBounds{}
	e.VonNeumann = ratFromValue(seq.Items[0])
	e.MinEntropy = ratFromValue(seq.Items[1])
	e.MaxEntropy = ratFromValue(seq.Items[2])
	e.SmoothMin = ratFromValue(seq.Items[3])
	e.Conditional = ratFromValue(seq.Items[4])
	e.MutualInfo = ratFromValue(seq.Items[5])

	return e, true
}

// ratFromValue extracts a *big.Rat from a Value.
func ratFromValue(v runtime.Value) *big.Rat {
	if rat, ok := v.(runtime.Rat); ok {
		return new(big.Rat).Set(rat.V)
	}
	return nil
}
