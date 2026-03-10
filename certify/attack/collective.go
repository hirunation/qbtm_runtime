// collective.go provides collective attack implementations.
//
// Collective attacks allow the adversary to perform a joint measurement
// on all intercepted quantum signals, but must use the same interaction
// for each signal. This is bounded by the Holevo quantity.
package attack

import (
	"math/big"

	"qbtm/runtime"
)

// CollectiveMeasurementAttack represents the general collective measurement attack.
// Eve stores all intercepted qubits in quantum memory and performs an optimal
// collective measurement after the protocol completes.
//
// The information Eve can extract is bounded by the Holevo quantity chi(rho_E).
type CollectiveMeasurementAttack struct {
	memorySize    int      // Number of qubits Eve can store
	measurement   string   // "optimal", "individual", "sequential"
	holevoBound   *big.Rat // Upper bound on accessible information
	inducedError  *big.Rat // QBER induced by the attack
	interaction   string   // Interaction type: "cloning", "cnot", "swap"
}

// NewCollectiveMeasurement creates a collective measurement attack.
func NewCollectiveMeasurement(n int) *CollectiveMeasurementAttack {
	return &CollectiveMeasurementAttack{
		memorySize:   n,
		measurement:  "optimal",
		holevoBound:  big.NewRat(1, 1), // Bounded by 1 bit per qubit
		inducedError: big.NewRat(11, 100), // ~11% QBER at optimal attack
		interaction:  "optimal",
	}
}

// NewCollectiveMeasurementWithParams creates a collective attack with specific parameters.
func NewCollectiveMeasurementWithParams(n int, measurement, interaction string, qber *big.Rat) *CollectiveMeasurementAttack {
	a := &CollectiveMeasurementAttack{
		memorySize:   n,
		measurement:  measurement,
		inducedError: qber,
		interaction:  interaction,
	}
	a.holevoBound = a.computeHolevoBound()
	return a
}

// computeHolevoBound computes the Holevo bound based on QBER.
// chi(rho_E) = S(rho_E) - sum_x p(x) S(rho_E|x)
// For BB84 with QBER Q, this is approximately h(1/2 + sqrt(Q(1-Q))) - h(Q)
func (a *CollectiveMeasurementAttack) computeHolevoBound() *big.Rat {
	// Use the information-disturbance tradeoff
	return InfoDisturbanceTradeoff(a.inducedError)
}

// Name returns the attack name.
func (a *CollectiveMeasurementAttack) Name() string {
	return "collective-measurement"
}

// Description returns a human-readable description.
func (a *CollectiveMeasurementAttack) Description() string {
	return "Collective measurement attack with quantum memory"
}

// MemorySize returns the number of qubits Eve can store.
func (a *CollectiveMeasurementAttack) MemorySize() int {
	return a.memorySize
}

// MeasurementStrategy returns the measurement strategy used.
func (a *CollectiveMeasurementAttack) MeasurementStrategy() string {
	return a.measurement
}

// HolevoBound returns the Holevo bound on accessible information.
func (a *CollectiveMeasurementAttack) HolevoBound() *big.Rat {
	return new(big.Rat).Set(a.holevoBound)
}

// ChoiMatrix returns the Choi matrix of the collective attack channel.
// For the n-qubit collective attack, this would be a (2^n x 2^n) matrix.
// We return the single-qubit marginal channel.
func (a *CollectiveMeasurementAttack) ChoiMatrix() *runtime.Matrix {
	// The effective single-qubit channel is approximately depolarizing
	kraus, coeffSq := DepolarizingChannel(a.inducedError)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition of the marginal channel.
func (a *CollectiveMeasurementAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}
}

// InformationGained returns the mutual information I(X:E).
// Bounded by Holevo quantity.
func (a *CollectiveMeasurementAttack) InformationGained() *big.Rat {
	return new(big.Rat).Set(a.holevoBound)
}

// DisturbanceInduced returns the QBER induced by the attack.
func (a *CollectiveMeasurementAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.inducedError)
}

// ApplicableProtocols returns protocols this attack applies to.
func (a *CollectiveMeasurementAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "Six-State", "SARG04", "B92"}
}

// ToValue converts the attack to a runtime.Value.
func (a *CollectiveMeasurementAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("collective-measurement-attack"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(a.memorySize)),
			runtime.MakeText(a.measurement),
			runtime.MakeBigRat(a.holevoBound),
			runtime.MakeBigRat(a.inducedError),
			runtime.MakeText(a.interaction),
		),
	)
}

// AsymmetricCloningAttack implements the asymmetric cloning collective attack.
// Eve uses an asymmetric cloner to trade off between her fidelity and Bob's fidelity.
//
// For an asymmetric 1->2 cloner with shrinking factor s:
// - Bob's fidelity: F_B = (1 + s)/2
// - Eve's fidelity: F_E = (2 - s^2)/(2 + s^2)
// where s in [0, 1] controls the trade-off.
type AsymmetricCloningAttack struct {
	shrinkingFactor *big.Rat // Trade-off parameter s in [0, 1]
	bobFidelity     *big.Rat // Fidelity of Bob's copy
	eveFidelity     *big.Rat // Fidelity of Eve's copy
	disturbance     *big.Rat // QBER induced (1 - F_B)
}

// NewAsymmetricCloning creates an asymmetric cloning attack with given shrinking factor.
// s=1 gives symmetric cloning (F_B = F_E = 5/6)
// s=0 gives trivial attack (F_B = 1, F_E = 1/2)
func NewAsymmetricCloning(shrinkingFactor *big.Rat) *AsymmetricCloningAttack {
	// Compute fidelities
	// F_B = (1 + s)/2
	// F_E = (2 - s^2)/(2 + s^2)

	one := big.NewRat(1, 1)
	two := big.NewRat(2, 1)

	// Bob's fidelity
	onePlusS := new(big.Rat).Add(one, shrinkingFactor)
	bobFidelity := new(big.Rat).Quo(onePlusS, two)

	// Eve's fidelity: (2 - s^2)/(2 + s^2)
	sSquared := new(big.Rat).Mul(shrinkingFactor, shrinkingFactor)
	numerator := new(big.Rat).Sub(two, sSquared)
	denominator := new(big.Rat).Add(two, sSquared)
	eveFidelity := new(big.Rat).Quo(numerator, denominator)

	// Disturbance = 1 - F_B
	disturbance := new(big.Rat).Sub(one, bobFidelity)

	return &AsymmetricCloningAttack{
		shrinkingFactor: shrinkingFactor,
		bobFidelity:     bobFidelity,
		eveFidelity:     eveFidelity,
		disturbance:     disturbance,
	}
}

// NewAsymmetricCloningOptimal creates an asymmetric cloning attack at optimal trade-off.
// Uses s = sqrt(2) - 1 ~ 0.414, which gives maximum Eve information for tolerable QBER.
func NewAsymmetricCloningOptimal() *AsymmetricCloningAttack {
	// sqrt(2) - 1 ~ 0.414 ~ 2/5
	return NewAsymmetricCloning(big.NewRat(2, 5))
}

// NewAsymmetricCloningSymmetric creates symmetric cloning (s=1).
func NewAsymmetricCloningSymmetric() *AsymmetricCloningAttack {
	return NewAsymmetricCloning(big.NewRat(1, 1))
}

// Name returns the attack name.
func (a *AsymmetricCloningAttack) Name() string {
	return "asymmetric-cloning"
}

// Description returns a human-readable description.
func (a *AsymmetricCloningAttack) Description() string {
	return "Asymmetric cloning attack with collective measurement"
}

// ShrinkingFactor returns the trade-off parameter.
func (a *AsymmetricCloningAttack) ShrinkingFactor() *big.Rat {
	return new(big.Rat).Set(a.shrinkingFactor)
}

// BobsFidelity returns the fidelity of Bob's copy.
func (a *AsymmetricCloningAttack) BobsFidelity() *big.Rat {
	return new(big.Rat).Set(a.bobFidelity)
}

// EvesFidelity returns the fidelity of Eve's copy.
func (a *AsymmetricCloningAttack) EvesFidelity() *big.Rat {
	return new(big.Rat).Set(a.eveFidelity)
}

// ChoiMatrix returns the Choi matrix of the channel to Bob.
func (a *AsymmetricCloningAttack) ChoiMatrix() *runtime.Matrix {
	kraus, coeffSq := DepolarizingChannel(a.disturbance)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *AsymmetricCloningAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}
}

// InformationGained returns the mutual information I(X:E).
// Related to Eve's fidelity: I ~ h(F_E) for fidelity F_E.
func (a *AsymmetricCloningAttack) InformationGained() *big.Rat {
	// Approximation: info scales with Eve's fidelity
	// For F_E near 1/2, info is small; for F_E near 1, info is large
	// We use: I ~ 2*(F_E - 1/2)
	half := big.NewRat(1, 2)
	excess := new(big.Rat).Sub(a.eveFidelity, half)
	return new(big.Rat).Mul(big.NewRat(2, 1), excess)
}

// DisturbanceInduced returns the QBER induced by the attack.
func (a *AsymmetricCloningAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.disturbance)
}

// ApplicableProtocols returns protocols this attack applies to.
func (a *AsymmetricCloningAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "Six-State", "SARG04", "B92"}
}

// ToValue converts the attack to a runtime.Value.
func (a *AsymmetricCloningAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("asymmetric-cloning-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.shrinkingFactor),
			runtime.MakeBigRat(a.bobFidelity),
			runtime.MakeBigRat(a.eveFidelity),
			runtime.MakeBigRat(a.disturbance),
		),
	)
}

// DevetakWinterAttack implements the optimal collective attack based on
// the Devetak-Winter bound.
//
// For BB84:
// r = 1 - h(Q) - h(Q) = 1 - 2h(Q)
// where Q is the QBER and h is binary entropy.
// Security threshold: Q_max ~ 11%
type DevetakWinterAttack struct {
	qber              *big.Rat // Quantum bit error rate
	securityThreshold *big.Rat // Maximum tolerable QBER
	keyRate           *big.Rat // Achievable key rate
}

// NewDevetakWinter creates a Devetak-Winter optimal collective attack.
func NewDevetakWinter(qber *big.Rat) *DevetakWinterAttack {
	a := &DevetakWinterAttack{
		qber:              qber,
		securityThreshold: big.NewRat(11, 100), // ~11% for BB84
	}
	a.keyRate = a.computeKeyRate()
	return a
}

// NewDevetakWinterBB84 creates the attack at the BB84 threshold.
func NewDevetakWinterBB84() *DevetakWinterAttack {
	return NewDevetakWinter(big.NewRat(11, 100))
}

// NewDevetakWinterSixState creates the attack at the Six-State threshold.
func NewDevetakWinterSixState() *DevetakWinterAttack {
	a := &DevetakWinterAttack{
		qber:              big.NewRat(126, 1000), // ~12.6%
		securityThreshold: big.NewRat(126, 1000),
	}
	a.keyRate = a.computeKeyRate()
	return a
}

// computeKeyRate computes the achievable key rate.
// r = 1 - 2*h(Q) using rational approximation for binary entropy.
func (a *DevetakWinterAttack) computeKeyRate() *big.Rat {
	// Binary entropy h(p) approximation for small p:
	// h(p) ~ -p*log2(p) - (1-p)*log2(1-p)
	// For p near 0.11: h(0.11) ~ 0.5
	// For p near 0: h(p) ~ 0
	// For p = 0.5: h(0.5) = 1

	one := big.NewRat(1, 1)

	// Simplified: h(Q) ~ 4*Q for Q < 0.15
	// Then r = 1 - 2*h(Q) ~ 1 - 8*Q
	threshold := big.NewRat(15, 100)
	if a.qber.Cmp(threshold) < 0 {
		eight := big.NewRat(8, 1)
		reduction := new(big.Rat).Mul(eight, a.qber)
		rate := new(big.Rat).Sub(one, reduction)
		if rate.Sign() < 0 {
			return big.NewRat(0, 1)
		}
		return rate
	}

	// For larger QBER, key rate approaches 0
	return big.NewRat(0, 1)
}

// Name returns the attack name.
func (a *DevetakWinterAttack) Name() string {
	return "devetak-winter"
}

// Description returns a human-readable description.
func (a *DevetakWinterAttack) Description() string {
	return "Optimal collective attack via Devetak-Winter bound"
}

// SecurityThreshold returns the maximum tolerable QBER for security.
func (a *DevetakWinterAttack) SecurityThreshold() *big.Rat {
	return new(big.Rat).Set(a.securityThreshold)
}

// KeyRate returns the achievable secure key rate.
func (a *DevetakWinterAttack) KeyRate() *big.Rat {
	return new(big.Rat).Set(a.keyRate)
}

// ChoiMatrix returns the Choi matrix of the attack channel.
func (a *DevetakWinterAttack) ChoiMatrix() *runtime.Matrix {
	kraus, coeffSq := DepolarizingChannel(a.qber)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *DevetakWinterAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{paulis["I"], paulis["X"], paulis["Y"], paulis["Z"]}
}

// InformationGained returns the information Eve can gain.
func (a *DevetakWinterAttack) InformationGained() *big.Rat {
	// Eve's information at the security threshold is maximal
	return InfoDisturbanceTradeoff(a.qber)
}

// DisturbanceInduced returns the QBER induced.
func (a *DevetakWinterAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.qber)
}

// ApplicableProtocols returns applicable protocols.
func (a *DevetakWinterAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "Six-State"}
}

// ToValue converts to runtime.Value.
func (a *DevetakWinterAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("devetak-winter-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.qber),
			runtime.MakeBigRat(a.securityThreshold),
			runtime.MakeBigRat(a.keyRate),
		),
	)
}

// EntanglementBasedAttack implements collective attacks using entanglement.
// Eve prepares an entangled state with each qubit she passes to Bob.
type EntanglementBasedAttack struct {
	entanglementStrength *big.Rat // 0 = no entanglement, 1 = maximal
	disturbance          *big.Rat // QBER induced
}

// NewEntanglementBased creates an entanglement-based collective attack.
func NewEntanglementBased(strength *big.Rat) *EntanglementBasedAttack {
	// Disturbance scales with entanglement strength
	// For maximal entanglement (strength=1), disturbance ~ 1/2
	// For no entanglement (strength=0), disturbance = 0
	half := big.NewRat(1, 2)
	disturbance := new(big.Rat).Mul(half, strength)

	return &EntanglementBasedAttack{
		entanglementStrength: strength,
		disturbance:          disturbance,
	}
}

// NewEntanglementBasedOptimal creates the attack at optimal strength.
func NewEntanglementBasedOptimal() *EntanglementBasedAttack {
	// Optimal around 22% entanglement for BB84 threshold
	return NewEntanglementBased(big.NewRat(22, 100))
}

// Name returns the attack name.
func (a *EntanglementBasedAttack) Name() string {
	return "entanglement-based"
}

// Description returns a human-readable description.
func (a *EntanglementBasedAttack) Description() string {
	return "Collective attack using entanglement with probes"
}

// EntanglementStrength returns the entanglement parameter.
func (a *EntanglementBasedAttack) EntanglementStrength() *big.Rat {
	return new(big.Rat).Set(a.entanglementStrength)
}

// ChoiMatrix returns the Choi matrix.
func (a *EntanglementBasedAttack) ChoiMatrix() *runtime.Matrix {
	kraus, coeffSq := DepolarizingChannel(a.disturbance)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *EntanglementBasedAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{paulis["I"], paulis["X"], paulis["Y"], paulis["Z"]}
}

// InformationGained returns the information Eve gains.
func (a *EntanglementBasedAttack) InformationGained() *big.Rat {
	return InfoDisturbanceTradeoff(a.disturbance)
}

// DisturbanceInduced returns the QBER induced.
func (a *EntanglementBasedAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.disturbance)
}

// ApplicableProtocols returns applicable protocols.
func (a *EntanglementBasedAttack) ApplicableProtocols() []string {
	return []string{"BB84", "Six-State"}
}

// ToValue converts to runtime.Value.
func (a *EntanglementBasedAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("entanglement-based-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.entanglementStrength),
			runtime.MakeBigRat(a.disturbance),
		),
	)
}

// SequentialAttack implements a sequential measurement strategy.
// Eve performs individual measurements but optimizes over all accumulated outcomes.
type SequentialAttack struct {
	windowSize  int      // Number of qubits in sliding window
	disturbance *big.Rat // QBER induced
}

// NewSequentialAttack creates a sequential collective attack.
func NewSequentialAttack(windowSize int) *SequentialAttack {
	// Sequential attacks are intermediate between individual and full collective
	// Disturbance is similar to individual attacks
	return &SequentialAttack{
		windowSize:  windowSize,
		disturbance: big.NewRat(1, 4), // Similar to intercept-resend
	}
}

// Name returns the attack name.
func (a *SequentialAttack) Name() string {
	return "sequential"
}

// Description returns a human-readable description.
func (a *SequentialAttack) Description() string {
	return "Sequential measurement attack with sliding window optimization"
}

// WindowSize returns the sliding window size.
func (a *SequentialAttack) WindowSize() int {
	return a.windowSize
}

// ChoiMatrix returns the Choi matrix.
func (a *SequentialAttack) ChoiMatrix() *runtime.Matrix {
	kraus, coeffSq := DepolarizingChannel(a.disturbance)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *SequentialAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{paulis["I"], paulis["X"], paulis["Y"], paulis["Z"]}
}

// InformationGained returns the information Eve gains.
func (a *SequentialAttack) InformationGained() *big.Rat {
	// Sequential attacks gain slightly more than pure individual
	return big.NewRat(3, 5)
}

// DisturbanceInduced returns the QBER induced.
func (a *SequentialAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.disturbance)
}

// ApplicableProtocols returns applicable protocols.
func (a *SequentialAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "Six-State"}
}

// ToValue converts to runtime.Value.
func (a *SequentialAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("sequential-attack"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(a.windowSize)),
			runtime.MakeBigRat(a.disturbance),
		),
	)
}

// CollectiveAttackFromValue parses a collective attack from a runtime.Value.
func CollectiveAttackFromValue(v runtime.Value) (Attack, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}

	label, ok := tag.Label.(runtime.Text)
	if !ok {
		return nil, false
	}

	switch label.V {
	case "collective-measurement-attack":
		seq, ok := tag.Payload.(runtime.Seq)
		if !ok || len(seq.Items) < 1 {
			return nil, false
		}
		memSize, ok := seq.Items[0].(runtime.Int)
		if !ok {
			return nil, false
		}
		return NewCollectiveMeasurement(int(memSize.V.Int64())), true

	case "asymmetric-cloning-attack":
		seq, ok := tag.Payload.(runtime.Seq)
		if !ok || len(seq.Items) < 1 {
			return nil, false
		}
		shrinking, ok := seq.Items[0].(runtime.Rat)
		if !ok {
			return nil, false
		}
		return NewAsymmetricCloning(shrinking.V), true

	case "devetak-winter-attack":
		seq, ok := tag.Payload.(runtime.Seq)
		if !ok || len(seq.Items) < 1 {
			return nil, false
		}
		qber, ok := seq.Items[0].(runtime.Rat)
		if !ok {
			return nil, false
		}
		return NewDevetakWinter(qber.V), true

	default:
		return nil, false
	}
}

// AllCollectiveAttacks returns all standard collective attacks.
func AllCollectiveAttacks() []Attack {
	return []Attack{
		NewCollectiveMeasurement(100),
		NewAsymmetricCloningOptimal(),
		NewAsymmetricCloningSymmetric(),
		NewDevetakWinterBB84(),
		NewDevetakWinterSixState(),
		NewEntanglementBasedOptimal(),
		NewSequentialAttack(10),
	}
}

// SecurityThresholds returns the security thresholds for various protocols.
func SecurityThresholds() map[string]*big.Rat {
	return map[string]*big.Rat{
		"BB84":      big.NewRat(11, 100),   // ~11%
		"Six-State": big.NewRat(126, 1000), // ~12.6%
		"B92":       big.NewRat(146, 1000), // ~14.6%
		"SARG04":    big.NewRat(109, 1000), // ~10.9%
		"E91":       big.NewRat(11, 100),   // ~11% (equivalent to BB84)
	}
}

// IsSecure checks if the given QBER is below the security threshold for a protocol.
func IsSecure(protocol string, qber *big.Rat) bool {
	thresholds := SecurityThresholds()
	threshold, ok := thresholds[protocol]
	if !ok {
		return false
	}
	return qber.Cmp(threshold) < 0
}
