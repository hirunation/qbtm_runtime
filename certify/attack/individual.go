// individual.go provides individual attack implementations.
//
// Individual attacks are applied independently to each quantum signal.
// They represent the simplest class of eavesdropping strategies where
// Eve performs the same operation on each qubit and measures immediately.
package attack

import (
	"math/big"

	"qbtm/runtime"
)

// InterceptResendAttack represents the intercept-resend attack.
// Eve intercepts each qubit, measures in a chosen basis, and resends
// a freshly prepared state based on the measurement outcome.
//
// For random basis choice:
// - Information gained: 1/2 (50% chance of correct basis)
// - Disturbance induced: 1/4 (25% QBER from wrong basis cases)
//
// The attack channel is equivalent to a depolarizing channel with p=1/4.
type InterceptResendAttack struct {
	measurementBasis string   // "random", "z", "x", "breidbart"
	infoGained       *big.Rat // Cached information gain
	disturbance      *big.Rat // Cached disturbance
}

// NewInterceptResend creates an intercept-resend attack with random basis.
func NewInterceptResend() *InterceptResendAttack {
	return &InterceptResendAttack{
		measurementBasis: "random",
		infoGained:       big.NewRat(1, 2),
		disturbance:      big.NewRat(1, 4),
	}
}

// NewInterceptResendWithBasis creates an intercept-resend attack with specified basis.
func NewInterceptResendWithBasis(basis string) *InterceptResendAttack {
	a := &InterceptResendAttack{
		measurementBasis: basis,
	}

	switch basis {
	case "z", "x":
		// Fixed basis: correct half the time, wrong half the time
		// When wrong, 50% error on those qubits
		a.infoGained = big.NewRat(1, 2)
		a.disturbance = big.NewRat(1, 4)
	case "breidbart":
		// Breidbart basis at optimal angle (pi/8)
		// Maximizes information for minimum disturbance
		// Info ~ 0.585, Disturbance ~ 0.146
		a.infoGained = big.NewRat(3, 5)    // Approximation: 0.6
		a.disturbance = big.NewRat(3, 20)  // Approximation: 0.15
	default: // "random"
		a.infoGained = big.NewRat(1, 2)
		a.disturbance = big.NewRat(1, 4)
	}

	return a
}

// Name returns the attack name.
func (a *InterceptResendAttack) Name() string {
	return "intercept-resend"
}

// Description returns a human-readable description.
func (a *InterceptResendAttack) Description() string {
	return "Measure each qubit in " + a.measurementBasis + " basis and resend based on outcome"
}

// MeasurementBasis returns the basis used for measurement.
func (a *InterceptResendAttack) MeasurementBasis() string {
	return a.measurementBasis
}

// ChoiMatrix returns the Choi matrix of the intercept-resend channel.
// For random basis, this is equivalent to a depolarizing channel:
// Phi(rho) = (1-p)rho + p/3(XrhoX + YrhoY + ZrhoZ) with p = 1/4
func (a *InterceptResendAttack) ChoiMatrix() *runtime.Matrix {
	p := a.disturbance // p = 1/4 for random basis
	kraus, coeffSq := DepolarizingChannel(p)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
// K0 = sqrt(1-p) * I
// K1 = sqrt(p/3) * X
// K2 = sqrt(p/3) * Y
// K3 = sqrt(p/3) * Z
// where p = disturbance (1/4 for random basis)
func (a *InterceptResendAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}
}

// KrausCoefficients returns the squared coefficients for Kraus operators.
func (a *InterceptResendAttack) KrausCoefficients() []*big.Rat {
	p := a.disturbance
	one := big.NewRat(1, 1)
	three := big.NewRat(3, 1)
	oneMinusP := new(big.Rat).Sub(one, p)
	pOverThree := new(big.Rat).Quo(p, three)

	return []*big.Rat{oneMinusP, pOverThree, pOverThree, pOverThree}
}

// InformationGained returns the mutual information I(X:E).
func (a *InterceptResendAttack) InformationGained() *big.Rat {
	return new(big.Rat).Set(a.infoGained)
}

// DisturbanceInduced returns the QBER induced by the attack.
func (a *InterceptResendAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.disturbance)
}

// ApplicableProtocols returns protocols this attack applies to.
func (a *InterceptResendAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "Six-State", "SARG04", "B92"}
}

// ToValue converts the attack to a runtime.Value.
func (a *InterceptResendAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("intercept-resend-attack"),
		runtime.MakeSeq(
			runtime.MakeText(a.measurementBasis),
			runtime.MakeBigRat(a.infoGained),
			runtime.MakeBigRat(a.disturbance),
			runtime.MatrixToValue(a.ChoiMatrix()),
		),
	)
}

// OptimalCloningAttack represents the optimal quantum cloning attack.
// Eve applies the optimal 1->2 universal cloning machine, keeping one copy.
//
// For the Buzek-Hillery optimal cloner:
// - Fidelity of each clone: 5/6
// - Information gained: ~2/3 (derived from clone fidelity)
// - Disturbance induced: 1/6 (error rate from imperfect clone to Bob)
type OptimalCloningAttack struct {
	numClones   int      // Number of output clones (usually 2)
	fidelity    *big.Rat // Fidelity of each clone
	disturbance *big.Rat // QBER induced
}

// NewOptimalCloning creates an optimal 1->2 cloning attack.
func NewOptimalCloning() *OptimalCloningAttack {
	return &OptimalCloningAttack{
		numClones:   2,
		fidelity:    big.NewRat(5, 6),
		disturbance: big.NewRat(1, 6),
	}
}

// NewOptimalCloningN creates an optimal 1->N cloning attack.
// Fidelity of each clone: (N+1)/(2N) for symmetric cloning.
func NewOptimalCloningN(n int) *OptimalCloningAttack {
	if n < 2 {
		n = 2
	}
	// Fidelity = (N+1)/(2N)
	fidelity := big.NewRat(int64(n+1), int64(2*n))
	// Disturbance = 1 - fidelity = (N-1)/(2N)
	disturbance := big.NewRat(int64(n-1), int64(2*n))

	return &OptimalCloningAttack{
		numClones:   n,
		fidelity:    fidelity,
		disturbance: disturbance,
	}
}

// Name returns the attack name.
func (a *OptimalCloningAttack) Name() string {
	return "optimal-cloning"
}

// Description returns a human-readable description.
func (a *OptimalCloningAttack) Description() string {
	return "Universal optimal quantum cloning attack"
}

// NumClones returns the number of output clones.
func (a *OptimalCloningAttack) NumClones() int {
	return a.numClones
}

// CloneFidelity returns the fidelity of each clone.
func (a *OptimalCloningAttack) CloneFidelity() *big.Rat {
	return new(big.Rat).Set(a.fidelity)
}

// ChoiMatrix returns the Choi matrix of the cloning channel (to Bob).
// The channel to Bob is approximately a depolarizing channel.
func (a *OptimalCloningAttack) ChoiMatrix() *runtime.Matrix {
	// The effective channel to Bob is depolarizing with p = disturbance
	kraus, coeffSq := DepolarizingChannel(a.disturbance)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition for Bob's channel.
func (a *OptimalCloningAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}
}

// InformationGained returns the mutual information I(X:E).
// For optimal cloning with fidelity F, Eve's information is approximately
// I ~ h(F) where h is binary entropy. For F=5/6, this gives ~2/3.
func (a *OptimalCloningAttack) InformationGained() *big.Rat {
	// Approximation based on clone fidelity
	// For N=2 (F=5/6): I ~ 2/3
	// General: I ~ 2*(1 - F) + F*log(F) approximation
	return big.NewRat(2, 3)
}

// DisturbanceInduced returns the QBER induced by the attack.
func (a *OptimalCloningAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.disturbance)
}

// ApplicableProtocols returns protocols this attack applies to.
func (a *OptimalCloningAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "Six-State", "SARG04", "B92"}
}

// ToValue converts the attack to a runtime.Value.
func (a *OptimalCloningAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("optimal-cloning-attack"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(a.numClones)),
			runtime.MakeBigRat(a.fidelity),
			runtime.MakeBigRat(a.disturbance),
			runtime.MatrixToValue(a.ChoiMatrix()),
		),
	)
}

// USDAttack represents the Unambiguous State Discrimination attack.
// Eve performs a USD measurement to distinguish non-orthogonal states.
// This attack is particularly relevant for B92 and SARG04 protocols.
//
// For states with overlap |<psi0|psi1>|^2 = eta:
// - Success probability: 1 - sqrt(eta)
// - Inconclusive probability: sqrt(eta)
// - No disturbance when conclusive (perfect information)
// - Must handle inconclusive results (resend random or block)
type USDAttack struct {
	stateOverlap   *big.Rat // |<psi0|psi1>|^2
	successProb    *big.Rat // Probability of conclusive outcome
	inconclusive   *big.Rat // Probability of inconclusive outcome
	resendStrategy string   // "random", "block", "optimal"
}

// NewUSD creates a USD attack for states with given overlap.
// overlap is |<psi0|psi1>|^2.
func NewUSD(overlap *big.Rat) *USDAttack {
	// Success probability = 1 - sqrt(overlap)
	// We use rational approximation for sqrt
	successProb := computeUSDSuccess(overlap)
	inconclusive := new(big.Rat).Sub(big.NewRat(1, 1), successProb)

	return &USDAttack{
		stateOverlap:   overlap,
		successProb:    successProb,
		inconclusive:   inconclusive,
		resendStrategy: "random",
	}
}

// NewUSDB92 creates a USD attack optimized for B92 protocol.
// B92 uses |0> and |+>, with overlap |<0|+>|^2 = 1/2.
func NewUSDB92() *USDAttack {
	return NewUSD(big.NewRat(1, 2))
}

// NewUSDSARG04 creates a USD attack for SARG04 protocol.
// SARG04 uses state pairs with overlap depending on encoding.
func NewUSDSARG04() *USDAttack {
	// SARG04 typical overlap: cos^2(pi/8) ~ 0.854
	// We use the rational approximation 7/8
	return NewUSD(big.NewRat(7, 8))
}

// computeUSDSuccess computes success probability for USD.
// P_success = 1 - sqrt(overlap)
// Uses rational approximations for common values.
func computeUSDSuccess(overlap *big.Rat) *big.Rat {
	// For exact computation of sqrt of rationals, we use approximations
	// Common cases:
	// overlap = 1/2: sqrt(1/2) ~ 0.707, success ~ 0.293 ~ 3/10
	// overlap = 1/4: sqrt(1/4) = 1/2, success = 1/2
	// overlap = 3/4: sqrt(3/4) ~ 0.866, success ~ 0.134 ~ 1/7
	// overlap = 7/8: sqrt(7/8) ~ 0.935, success ~ 0.065 ~ 1/15

	one := big.NewRat(1, 1)
	half := big.NewRat(1, 2)
	quarter := big.NewRat(1, 4)
	threeQuarters := big.NewRat(3, 4)
	sevenEighths := big.NewRat(7, 8)

	// Handle exact cases
	if overlap.Cmp(quarter) == 0 {
		return big.NewRat(1, 2)
	}

	// Use approximations for other cases
	if overlap.Cmp(half) == 0 {
		return big.NewRat(3, 10) // sqrt(1/2) ~ 0.707, success ~ 0.293
	}
	if overlap.Cmp(threeQuarters) == 0 {
		return big.NewRat(1, 7) // sqrt(3/4) ~ 0.866, success ~ 0.134
	}
	if overlap.Cmp(sevenEighths) == 0 {
		return big.NewRat(1, 15) // sqrt(7/8) ~ 0.935, success ~ 0.065
	}

	// General approximation: success ~ 1 - sqrt(overlap) ~ (1-overlap)/2 for overlap near 1
	oneMinusOverlap := new(big.Rat).Sub(one, overlap)
	return new(big.Rat).Quo(oneMinusOverlap, big.NewRat(2, 1))
}

// Name returns the attack name.
func (a *USDAttack) Name() string {
	return "usd"
}

// Description returns a human-readable description.
func (a *USDAttack) Description() string {
	return "Unambiguous state discrimination attack on non-orthogonal states"
}

// StateOverlap returns the overlap between the two states.
func (a *USDAttack) StateOverlap() *big.Rat {
	return new(big.Rat).Set(a.stateOverlap)
}

// SuccessProbability returns the probability of conclusive USD outcome.
func (a *USDAttack) SuccessProbability() *big.Rat {
	return new(big.Rat).Set(a.successProb)
}

// InconclusiveRate returns the probability of inconclusive outcome.
func (a *USDAttack) InconclusiveRate() *big.Rat {
	return new(big.Rat).Set(a.inconclusive)
}

// ChoiMatrix returns the Choi matrix of the USD channel.
// USD is a probabilistic channel with three outcomes: |0>, |1>, inconclusive.
func (a *USDAttack) ChoiMatrix() *runtime.Matrix {
	// USD POVM has three elements. The channel is more complex than depolarizing.
	// For simplicity, we model the effective channel to Bob.
	// When conclusive: perfect state, no disturbance
	// When inconclusive: random resend, 50% error on that basis

	// Effective disturbance = inconclusive_rate * 1/2 = sqrt(overlap) * 1/2
	// We compute a depolarizing approximation
	two := big.NewRat(2, 1)
	effectiveP := new(big.Rat).Quo(a.inconclusive, two)
	kraus, coeffSq := DepolarizingChannel(effectiveP)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *USDAttack) KrausOperators() []*runtime.Matrix {
	// Simplified: treat as effective depolarizing channel
	paulis := PauliMatrices()
	return []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}
}

// InformationGained returns the mutual information I(X:E).
// Eve gets full information when USD succeeds.
// I = success_probability * 1 = success_probability
func (a *USDAttack) InformationGained() *big.Rat {
	return new(big.Rat).Set(a.successProb)
}

// DisturbanceInduced returns the QBER induced by the attack.
// Disturbance comes from inconclusive results being handled.
// With random resend: disturbance = inconclusive * 1/2
func (a *USDAttack) DisturbanceInduced() *big.Rat {
	two := big.NewRat(2, 1)
	return new(big.Rat).Quo(a.inconclusive, two)
}

// ApplicableProtocols returns protocols this attack applies to.
// USD is most effective against non-orthogonal state protocols.
func (a *USDAttack) ApplicableProtocols() []string {
	return []string{"B92", "SARG04"}
}

// ToValue converts the attack to a runtime.Value.
func (a *USDAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("usd-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.stateOverlap),
			runtime.MakeBigRat(a.successProb),
			runtime.MakeBigRat(a.inconclusive),
			runtime.MakeText(a.resendStrategy),
			runtime.MatrixToValue(a.ChoiMatrix()),
		),
	)
}

// PhaseCovariantCloningAttack implements phase-covariant cloning.
// Optimal for equatorial states (BB84 without Z basis).
type PhaseCovariantCloningAttack struct {
	fidelity    *big.Rat
	disturbance *big.Rat
}

// NewPhaseCovariantCloning creates a phase-covariant cloning attack.
// Optimal fidelity for equatorial states: (1 + 1/sqrt(2))/2 ~ 0.854
// We use rational approximation 6/7.
func NewPhaseCovariantCloning() *PhaseCovariantCloningAttack {
	return &PhaseCovariantCloningAttack{
		fidelity:    big.NewRat(6, 7),
		disturbance: big.NewRat(1, 7),
	}
}

// Name returns the attack name.
func (a *PhaseCovariantCloningAttack) Name() string {
	return "phase-covariant-cloning"
}

// Description returns a human-readable description.
func (a *PhaseCovariantCloningAttack) Description() string {
	return "Phase-covariant cloning optimal for equatorial states"
}

// CloneFidelity returns the fidelity of each clone.
func (a *PhaseCovariantCloningAttack) CloneFidelity() *big.Rat {
	return new(big.Rat).Set(a.fidelity)
}

// ChoiMatrix returns the Choi matrix.
func (a *PhaseCovariantCloningAttack) ChoiMatrix() *runtime.Matrix {
	kraus, coeffSq := DepolarizingChannel(a.disturbance)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *PhaseCovariantCloningAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{paulis["I"], paulis["X"], paulis["Y"], paulis["Z"]}
}

// InformationGained returns the mutual information I(X:E).
func (a *PhaseCovariantCloningAttack) InformationGained() *big.Rat {
	return big.NewRat(5, 7) // Higher info than universal cloning
}

// DisturbanceInduced returns the QBER induced.
func (a *PhaseCovariantCloningAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.disturbance)
}

// ApplicableProtocols returns applicable protocols.
func (a *PhaseCovariantCloningAttack) ApplicableProtocols() []string {
	return []string{"BB84", "B92"} // Protocols with equatorial states
}

// ToValue converts to runtime.Value.
func (a *PhaseCovariantCloningAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("phase-covariant-cloning-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.fidelity),
			runtime.MakeBigRat(a.disturbance),
		),
	)
}

// BeamSplittingAttack represents the beam-splitting attack.
// Eve splits off a portion of each pulse (relevant for weak coherent sources).
type BeamSplittingAttack struct {
	splitRatio  *big.Rat // Fraction split to Eve
	disturbance *big.Rat // Induced error rate
}

// NewBeamSplitting creates a beam-splitting attack with given split ratio.
func NewBeamSplitting(splitRatio *big.Rat) *BeamSplittingAttack {
	// Disturbance is zero if Eve only takes vacuum/single photons
	// For weak coherent pulses, this depends on mean photon number
	return &BeamSplittingAttack{
		splitRatio:  splitRatio,
		disturbance: big.NewRat(0, 1), // Ideally zero disturbance
	}
}

// Name returns the attack name.
func (a *BeamSplittingAttack) Name() string {
	return "beam-splitting"
}

// Description returns a human-readable description.
func (a *BeamSplittingAttack) Description() string {
	return "Beam-splitting attack for weak coherent pulse sources"
}

// SplitRatio returns the fraction of signal split to Eve.
func (a *BeamSplittingAttack) SplitRatio() *big.Rat {
	return new(big.Rat).Set(a.splitRatio)
}

// ChoiMatrix returns the Choi matrix (identity channel to Bob).
func (a *BeamSplittingAttack) ChoiMatrix() *runtime.Matrix {
	// Ideally, beam splitting doesn't disturb the transmitted state
	// The channel to Bob is approximately identity
	return ComputeChoiMatrix([]*runtime.Matrix{runtime.Identity(2)}, []*big.Rat{big.NewRat(1, 1)})
}

// KrausOperators returns the Kraus decomposition.
func (a *BeamSplittingAttack) KrausOperators() []*runtime.Matrix {
	return []*runtime.Matrix{runtime.Identity(2)}
}

// InformationGained returns the mutual information I(X:E).
// Depends on split ratio and mean photon number.
func (a *BeamSplittingAttack) InformationGained() *big.Rat {
	// For single photons: Eve gets info with prob = splitRatio
	// This is a simplified model
	return new(big.Rat).Set(a.splitRatio)
}

// DisturbanceInduced returns the QBER induced.
func (a *BeamSplittingAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.disturbance)
}

// ApplicableProtocols returns applicable protocols.
func (a *BeamSplittingAttack) ApplicableProtocols() []string {
	return []string{"BB84", "B92", "SARG04"} // Weak coherent pulse implementations
}

// ToValue converts to runtime.Value.
func (a *BeamSplittingAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("beam-splitting-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.splitRatio),
			runtime.MakeBigRat(a.disturbance),
		),
	)
}

// IndividualAttackFromValue parses an individual attack from a runtime.Value.
func IndividualAttackFromValue(v runtime.Value) (Attack, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}

	label, ok := tag.Label.(runtime.Text)
	if !ok {
		return nil, false
	}

	switch label.V {
	case "intercept-resend-attack":
		seq, ok := tag.Payload.(runtime.Seq)
		if !ok || len(seq.Items) < 2 {
			return nil, false
		}
		basis, ok := seq.Items[0].(runtime.Text)
		if !ok {
			return nil, false
		}
		return NewInterceptResendWithBasis(basis.V), true

	case "optimal-cloning-attack":
		seq, ok := tag.Payload.(runtime.Seq)
		if !ok || len(seq.Items) < 1 {
			return nil, false
		}
		numClones, ok := seq.Items[0].(runtime.Int)
		if !ok {
			return nil, false
		}
		return NewOptimalCloningN(int(numClones.V.Int64())), true

	case "usd-attack":
		seq, ok := tag.Payload.(runtime.Seq)
		if !ok || len(seq.Items) < 1 {
			return nil, false
		}
		overlap, ok := seq.Items[0].(runtime.Rat)
		if !ok {
			return nil, false
		}
		return NewUSD(overlap.V), true

	default:
		return nil, false
	}
}

// AllIndividualAttacks returns all standard individual attacks.
func AllIndividualAttacks() []Attack {
	return []Attack{
		NewInterceptResend(),
		NewInterceptResendWithBasis("breidbart"),
		NewOptimalCloning(),
		NewOptimalCloningN(3),
		NewUSDB92(),
		NewUSDSARG04(),
		NewPhaseCovariantCloning(),
		NewBeamSplitting(big.NewRat(1, 10)),
	}
}
