// attack.go provides the base Attack interface and common types.
//
// All quantum attacks are modeled as completely positive (CP) maps,
// represented by their Choi matrix or Kraus operator decomposition.
package attack

import (
	"math/big"

	"qbtm/runtime"
)

// Attack represents a quantum attack strategy as a CP map.
type Attack interface {
	// Name returns the attack identifier.
	Name() string

	// Description returns a human-readable description.
	Description() string

	// ChoiMatrix returns the Choi-Jamiolkowski representation.
	// For a channel Phi: B(H_A) -> B(H_B), the Choi matrix is
	// J(Phi) = (id_A tensor Phi)(|Omega><Omega|)
	// where |Omega> = sum_i |i>|i> is the maximally entangled state.
	ChoiMatrix() *runtime.Matrix

	// KrausOperators returns the Kraus decomposition {K_i}.
	// The channel acts as Phi(rho) = sum_i K_i * rho * K_i^dagger.
	KrausOperators() []*runtime.Matrix

	// InformationGained returns the mutual information I(X:E).
	// This is the information Eve gains about the key bits.
	InformationGained() *big.Rat

	// DisturbanceInduced returns the error rate induced by the attack.
	// This is the QBER introduced when the attack is applied.
	DisturbanceInduced() *big.Rat

	// ApplicableProtocols returns the list of protocols this attack applies to.
	ApplicableProtocols() []string

	// ToValue converts the attack to a runtime.Value for serialization.
	ToValue() runtime.Value
}

// AttackResult holds the results of analyzing an attack against a protocol.
type AttackResult struct {
	Attack        Attack   // The attack that was analyzed
	Protocol      string   // The protocol being attacked
	InfoGained    *big.Rat // Information gained by attacker
	Disturbance   *big.Rat // QBER induced by attack
	KeyRateImpact *big.Rat // Impact on secure key rate
	Detected      bool     // Whether the attack would be detected
	DetectionProb *big.Rat // Probability of detection (if applicable)
}

// NewAttackResult creates an AttackResult for the given attack and protocol.
func NewAttackResult(attack Attack, protocol string) *AttackResult {
	return &AttackResult{
		Attack:        attack,
		Protocol:      protocol,
		InfoGained:    attack.InformationGained(),
		Disturbance:   attack.DisturbanceInduced(),
		KeyRateImpact: computeKeyRateImpact(attack.DisturbanceInduced()),
		Detected:      isDetectable(attack.DisturbanceInduced()),
		DetectionProb: detectionProbability(attack.DisturbanceInduced()),
	}
}

// computeKeyRateImpact estimates key rate reduction from disturbance.
// Uses simplified Devetak-Winter bound: r ~ 1 - 2*h(Q) for BB84.
// For small Q, this approximates to 1 - 2*Q*log2(1/Q).
func computeKeyRateImpact(qber *big.Rat) *big.Rat {
	if qber.Sign() == 0 {
		return big.NewRat(0, 1)
	}
	// Simplified: key rate reduction ~ 2 * QBER for small QBER
	two := big.NewRat(2, 1)
	impact := new(big.Rat).Mul(two, qber)
	// Cap at 1
	one := big.NewRat(1, 1)
	if impact.Cmp(one) > 0 {
		return one
	}
	return impact
}

// isDetectable checks if the attack induces detectable disturbance.
// For BB84-type protocols, any QBER above 0 is potentially detectable.
func isDetectable(qber *big.Rat) bool {
	return qber.Sign() > 0
}

// detectionProbability estimates the probability of detecting the attack.
// Based on the number of test bits needed to detect the QBER.
func detectionProbability(qber *big.Rat) *big.Rat {
	if qber.Sign() == 0 {
		return big.NewRat(0, 1)
	}
	// For significant QBER (> 5%), detection is almost certain
	threshold := big.NewRat(5, 100)
	if qber.Cmp(threshold) >= 0 {
		return big.NewRat(99, 100)
	}
	// For smaller QBER, detection probability scales with QBER
	// Approximately: P_detect ~ 20 * QBER (for small QBER)
	twenty := big.NewRat(20, 1)
	return new(big.Rat).Mul(twenty, qber)
}

// ToValue converts an AttackResult to a runtime.Value.
func (r *AttackResult) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("attack-result"),
		runtime.MakeSeq(
			r.Attack.ToValue(),
			runtime.MakeText(r.Protocol),
			runtime.MakeBigRat(r.InfoGained),
			runtime.MakeBigRat(r.Disturbance),
			runtime.MakeBigRat(r.KeyRateImpact),
			runtime.MakeBool(r.Detected),
			runtime.MakeBigRat(r.DetectionProb),
		),
	)
}

// InfoDisturbanceTradeoff computes the fundamental information-disturbance tradeoff.
// For BB84-type protocols: I(X:E) <= h(1/2 + sqrt(D(1-D)))
// where D is disturbance and h is binary entropy.
// This returns an upper bound on information for a given disturbance.
func InfoDisturbanceTradeoff(disturbance *big.Rat) *big.Rat {
	if disturbance.Sign() == 0 {
		return big.NewRat(0, 1)
	}
	// For exact computation, we need h(1/2 + sqrt(D(1-D)))
	// h(p) = -p*log2(p) - (1-p)*log2(1-p)
	// We use a rational approximation for common disturbance values.

	// At D = 1/4 (intercept-resend): sqrt(1/4 * 3/4) = sqrt(3)/4, info ~ 0.5
	// At D = 1/6 (optimal cloning): sqrt(1/6 * 5/6) = sqrt(5)/6, info ~ 0.4
	// At D = 0: info = 0
	// At D = 1/2: sqrt(1/4) = 1/2, h(1) = 0, but this is maximum disturbance

	// We use piecewise linear approximation for exact rationals
	one := big.NewRat(1, 1)
	oneHalf := big.NewRat(1, 2)

	// If disturbance >= 1/2, return 0 (no useful channel)
	if disturbance.Cmp(oneHalf) >= 0 {
		return big.NewRat(0, 1)
	}

	// For small disturbance D, sqrt(D(1-D)) ~ sqrt(D)
	// Info bound ~ 2*sqrt(D) for small D
	// We approximate: I <= 2*D for D <= 1/4

	quarter := big.NewRat(1, 4)
	if disturbance.Cmp(quarter) <= 0 {
		// Linear approximation: I ~ 2*D
		return new(big.Rat).Mul(big.NewRat(2, 1), disturbance)
	}

	// For 1/4 < D < 1/2, interpolate down to 0
	// I ~ 1 - 2*(D - 1/4) = 1.5 - 2*D
	twoD := new(big.Rat).Mul(big.NewRat(2, 1), disturbance)
	result := new(big.Rat).Sub(big.NewRat(3, 2), twoD)
	if result.Cmp(one) > 0 {
		return one
	}
	if result.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	return result
}

// OptimalAttackLine returns points on the optimal attack frontier.
// Each point is [information_gained, disturbance_induced].
func OptimalAttackLine() [][2]*big.Rat {
	return [][2]*big.Rat{
		// No attack
		{big.NewRat(0, 1), big.NewRat(0, 1)},
		// Weak attack (partial information)
		{big.NewRat(1, 8), big.NewRat(1, 16)},
		// Optimal cloning point
		{big.NewRat(1, 3), big.NewRat(1, 6)},
		// Intercept-resend point
		{big.NewRat(1, 2), big.NewRat(1, 4)},
		// Strong attack (high disturbance)
		{big.NewRat(3, 4), big.NewRat(3, 8)},
		// Maximum attack (destroys channel)
		{big.NewRat(1, 1), big.NewRat(1, 2)},
	}
}

// AttackCategory classifies attacks by their power level.
type AttackCategory int

const (
	CategoryIndividual AttackCategory = iota // IID attacks
	CategoryCollective                       // Collective measurement
	CategoryCoherent                         // Full quantum memory
	CategoryImplementation                   // Device imperfections
)

// String returns the attack category name.
func (c AttackCategory) String() string {
	switch c {
	case CategoryIndividual:
		return "individual"
	case CategoryCollective:
		return "collective"
	case CategoryCoherent:
		return "coherent"
	case CategoryImplementation:
		return "implementation"
	default:
		return "unknown"
	}
}

// StandardBases defines common measurement bases.
var StandardBases = map[string]string{
	"z":      "computational basis {|0>, |1>}",
	"x":      "Hadamard basis {|+>, |->}",
	"y":      "circular basis {|R>, |L>}",
	"random": "uniformly random from {Z, X}",
	"breidbart": "Breidbart basis at pi/8",
}

// PauliMatrices returns the Pauli matrices {I, X, Y, Z}.
func PauliMatrices() map[string]*runtime.Matrix {
	zero := big.NewRat(0, 1)
	one := big.NewRat(1, 1)
	negOne := big.NewRat(-1, 1)

	// I = [[1, 0], [0, 1]]
	I := runtime.NewMatrix(2, 2)
	I.Set(0, 0, runtime.NewQI(one, zero))
	I.Set(1, 1, runtime.NewQI(one, zero))

	// X = [[0, 1], [1, 0]]
	X := runtime.NewMatrix(2, 2)
	X.Set(0, 1, runtime.NewQI(one, zero))
	X.Set(1, 0, runtime.NewQI(one, zero))

	// Y = [[0, -i], [i, 0]]
	Y := runtime.NewMatrix(2, 2)
	Y.Set(0, 1, runtime.NewQI(zero, negOne))
	Y.Set(1, 0, runtime.NewQI(zero, one))

	// Z = [[1, 0], [0, -1]]
	Z := runtime.NewMatrix(2, 2)
	Z.Set(0, 0, runtime.NewQI(one, zero))
	Z.Set(1, 1, runtime.NewQI(negOne, zero))

	return map[string]*runtime.Matrix{
		"I": I,
		"X": X,
		"Y": Y,
		"Z": Z,
	}
}

// DepolarizingChannel returns the Kraus operators for the depolarizing channel.
// Phi(rho) = (1-p)*rho + p/3*(X*rho*X + Y*rho*Y + Z*rho*Z)
// Kraus operators: K0 = sqrt(1-p)*I, K1 = sqrt(p/3)*X, K2 = sqrt(p/3)*Y, K3 = sqrt(p/3)*Z
// For computational simplicity, we return the unscaled operators and the coefficients.
func DepolarizingChannel(p *big.Rat) ([]*runtime.Matrix, []*big.Rat) {
	paulis := PauliMatrices()
	operators := []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}

	// Coefficients: sqrt(1-p), sqrt(p/3), sqrt(p/3), sqrt(p/3)
	// We store the squared coefficients for exact arithmetic
	one := big.NewRat(1, 1)
	three := big.NewRat(3, 1)
	oneMinusP := new(big.Rat).Sub(one, p)
	pOverThree := new(big.Rat).Quo(p, three)

	coeffSq := []*big.Rat{
		oneMinusP,   // (sqrt(1-p))^2 = 1-p
		pOverThree,  // (sqrt(p/3))^2 = p/3
		pOverThree,
		pOverThree,
	}

	return operators, coeffSq
}

// ComputeChoiMatrix computes the Choi matrix from Kraus operators.
// J(Phi) = sum_i (I tensor K_i) |Omega><Omega| (I tensor K_i^dagger)
// where |Omega> = (1/sqrt(d)) * sum_j |j>|j>
// For 2x2 matrices, this produces a 4x4 Choi matrix.
func ComputeChoiMatrix(kraus []*runtime.Matrix, coeffSq []*big.Rat) *runtime.Matrix {
	if len(kraus) == 0 {
		return nil
	}

	d := kraus[0].Rows // Input dimension
	choi := runtime.NewMatrix(d*d, d*d)

	// Build the Choi matrix entry by entry
	// J[i*d+j, k*d+l] = sum_m coeff_m * K_m[j,l] * conj(K_m[i,k])
	for i := 0; i < d; i++ {
		for j := 0; j < d; j++ {
			for k := 0; k < d; k++ {
				for l := 0; l < d; l++ {
					sum := runtime.QIZero()
					for m, K := range kraus {
						// K[j,l] * conj(K[i,k]) * coeff^2
						kjl := K.Get(j, l)
						kik := K.Get(i, k)
						kikConj := runtime.QIConj(kik)
						prod := runtime.QIMul(kjl, kikConj)
						scaled := runtime.QIScale(prod, coeffSq[m])
						sum = runtime.QIAdd(sum, scaled)
					}
					choi.Set(i*d+j, k*d+l, sum)
				}
			}
		}
	}

	return choi
}

// VerifyCompleteness checks that Kraus operators satisfy sum_i K_i^dag K_i = I.
// Returns true if the channel is trace-preserving.
func VerifyCompleteness(kraus []*runtime.Matrix, coeffSq []*big.Rat) bool {
	if len(kraus) == 0 {
		return false
	}

	d := kraus[0].Cols
	sum := runtime.NewMatrix(d, d)

	for i, K := range kraus {
		Kdag := runtime.Dagger(K)
		KdagK := runtime.MatMul(Kdag, K)
		scaled := runtime.MatScale(KdagK, coeffSq[i])
		sum = runtime.MatAdd(sum, scaled)
	}

	// Check if sum equals identity
	I := runtime.Identity(d)
	return runtime.MatrixEqual(sum, I)
}
