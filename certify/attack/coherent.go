// coherent.go provides coherent attack implementations.
//
// Coherent attacks are the most general class of attacks where
// the adversary can apply arbitrary quantum operations and maintain
// quantum memory across the entire protocol execution.
//
// Security against coherent attacks provides unconditional security.
package attack

import (
	"math/big"

	"qbtm/runtime"
)

// GeneralCoherentAttack represents the most general coherent attack.
// Eve can apply arbitrary quantum operations and store qubits for
// collective processing at any time.
//
// Security bounds use smooth min-entropy (Renner framework) or
// relative entropy of entanglement.
type GeneralCoherentAttack struct {
	memoryQubits      int             // Quantum memory size (0 = unlimited)
	securityThreshold *big.Rat        // Maximum tolerable QBER
	securityParameter *big.Rat        // Epsilon security parameter
	keyRateBound      func(*big.Rat) *big.Rat
}

// NewGeneralCoherent creates a general coherent attack with unlimited memory.
func NewGeneralCoherent() *GeneralCoherentAttack {
	return &GeneralCoherentAttack{
		memoryQubits:      0, // Unlimited
		securityThreshold: big.NewRat(11, 100), // ~11% for BB84
		securityParameter: big.NewRat(1, 1000000), // 10^-6
		keyRateBound:      coherentKeyRateBound,
	}
}

// NewMemoryBoundedCoherent creates a coherent attack with bounded quantum memory.
func NewMemoryBoundedCoherent(memoryQubits int) *GeneralCoherentAttack {
	// With bounded memory, higher QBER can be tolerated
	// Threshold increases roughly as log(memory)
	threshold := big.NewRat(11, 100)
	if memoryQubits > 0 && memoryQubits < 100 {
		// Boost threshold for small memory
		threshold = big.NewRat(15, 100)
	}

	return &GeneralCoherentAttack{
		memoryQubits:      memoryQubits,
		securityThreshold: threshold,
		securityParameter: big.NewRat(1, 1000000),
		keyRateBound:      coherentKeyRateBound,
	}
}

// coherentKeyRateBound computes the key rate bound for coherent attacks.
// Uses the Devetak-Winter formula with smooth min-entropy corrections.
// r = H_min(X|E) - H(X|Y) >= 1 - h(Q) - h(Q_x) for BB84
func coherentKeyRateBound(qber *big.Rat) *big.Rat {
	one := big.NewRat(1, 1)

	// For QBER >= threshold, no secure key
	threshold := big.NewRat(11, 100)
	if qber.Cmp(threshold) >= 0 {
		return big.NewRat(0, 1)
	}

	// Simplified bound: r ~ 1 - 2*h(Q)
	// For small Q: h(Q) ~ -Q*log(Q) ~ 4*Q for Q < 0.15
	// So r ~ 1 - 8*Q
	eight := big.NewRat(8, 1)
	reduction := new(big.Rat).Mul(eight, qber)
	rate := new(big.Rat).Sub(one, reduction)

	if rate.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	return rate
}

// Name returns the attack name.
func (a *GeneralCoherentAttack) Name() string {
	if a.memoryQubits > 0 {
		return "memory-bounded-coherent"
	}
	return "general-coherent"
}

// Description returns a human-readable description.
func (a *GeneralCoherentAttack) Description() string {
	if a.memoryQubits > 0 {
		return "Coherent attack with bounded quantum memory"
	}
	return "Most general attack with unbounded quantum memory"
}

// MemoryQubits returns the quantum memory bound (0 = unlimited).
func (a *GeneralCoherentAttack) MemoryQubits() int {
	return a.memoryQubits
}

// SecurityThreshold returns the maximum tolerable QBER.
func (a *GeneralCoherentAttack) SecurityThreshold() *big.Rat {
	return new(big.Rat).Set(a.securityThreshold)
}

// SecurityParameter returns the epsilon security parameter.
func (a *GeneralCoherentAttack) SecurityParameter() *big.Rat {
	return new(big.Rat).Set(a.securityParameter)
}

// KeyRateBound returns the secure key rate for given QBER.
func (a *GeneralCoherentAttack) KeyRateBound(qber *big.Rat) *big.Rat {
	return a.keyRateBound(qber)
}

// ChoiMatrix returns the Choi matrix of the attack channel.
// For coherent attacks, we return the worst-case channel at threshold.
func (a *GeneralCoherentAttack) ChoiMatrix() *runtime.Matrix {
	kraus, coeffSq := DepolarizingChannel(a.securityThreshold)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *GeneralCoherentAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{paulis["I"], paulis["X"], paulis["Y"], paulis["Z"]}
}

// InformationGained returns the maximum information Eve can gain.
// For coherent attacks at threshold, Eve learns everything about the key.
func (a *GeneralCoherentAttack) InformationGained() *big.Rat {
	return big.NewRat(1, 1)
}

// DisturbanceInduced returns the QBER at security threshold.
func (a *GeneralCoherentAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.securityThreshold)
}

// ApplicableProtocols returns protocols this attack applies to.
func (a *GeneralCoherentAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "Six-State", "SARG04", "B92"}
}

// ToValue converts the attack to a runtime.Value.
func (a *GeneralCoherentAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("coherent-attack"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(a.memoryQubits)),
			runtime.MakeBigRat(a.securityThreshold),
			runtime.MakeBigRat(a.securityParameter),
		),
	)
}

// RennerSecurityAttack implements security analysis using Renner's framework.
// Uses smooth min-entropy for finite-key analysis.
type RennerSecurityAttack struct {
	numSignals        int64    // Total number of signals exchanged
	securityParameter *big.Rat // Epsilon security
	qber              *big.Rat // Observed QBER
	finiteKeyRate     *big.Rat // Achievable rate with finite effects
}

// NewRennerSecurity creates a security analysis using Renner's framework.
func NewRennerSecurity(numSignals int64, qber *big.Rat) *RennerSecurityAttack {
	a := &RennerSecurityAttack{
		numSignals:        numSignals,
		securityParameter: big.NewRat(1, 1000000000), // 10^-9
		qber:              qber,
	}
	a.finiteKeyRate = a.computeFiniteKeyRate()
	return a
}

// computeFiniteKeyRate computes the key rate with finite-size effects.
// r_finite = r_asymptotic - O(sqrt(log(1/eps)/n))
func (a *RennerSecurityAttack) computeFiniteKeyRate() *big.Rat {
	// Asymptotic rate
	asymptotic := coherentKeyRateBound(a.qber)
	if asymptotic.Sign() <= 0 {
		return big.NewRat(0, 1)
	}

	// Finite-size correction: approximately 7/sqrt(n) for typical parameters
	// We use a rational approximation
	if a.numSignals < 1000 {
		return big.NewRat(0, 1) // Too few signals
	}

	// Correction ~ 7/sqrt(n)
	// For n=10000: correction ~ 0.07
	// For n=1000000: correction ~ 0.007
	// We approximate: correction ~ 700/n for n > 10000
	correction := big.NewRat(700, a.numSignals)

	rate := new(big.Rat).Sub(asymptotic, correction)
	if rate.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	return rate
}

// Name returns the attack name.
func (a *RennerSecurityAttack) Name() string {
	return "renner-security"
}

// Description returns a human-readable description.
func (a *RennerSecurityAttack) Description() string {
	return "Finite-key security analysis via smooth min-entropy"
}

// NumSignals returns the number of signals exchanged.
func (a *RennerSecurityAttack) NumSignals() int64 {
	return a.numSignals
}

// FiniteKeyRate returns the achievable finite key rate.
func (a *RennerSecurityAttack) FiniteKeyRate() *big.Rat {
	return new(big.Rat).Set(a.finiteKeyRate)
}

// ChoiMatrix returns the Choi matrix at the observed QBER.
func (a *RennerSecurityAttack) ChoiMatrix() *runtime.Matrix {
	kraus, coeffSq := DepolarizingChannel(a.qber)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *RennerSecurityAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{paulis["I"], paulis["X"], paulis["Y"], paulis["Z"]}
}

// InformationGained returns the information bound.
func (a *RennerSecurityAttack) InformationGained() *big.Rat {
	return InfoDisturbanceTradeoff(a.qber)
}

// DisturbanceInduced returns the observed QBER.
func (a *RennerSecurityAttack) DisturbanceInduced() *big.Rat {
	return new(big.Rat).Set(a.qber)
}

// ApplicableProtocols returns applicable protocols.
func (a *RennerSecurityAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "Six-State"}
}

// ToValue converts to runtime.Value.
func (a *RennerSecurityAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("renner-security-attack"),
		runtime.MakeSeq(
			runtime.MakeInt(a.numSignals),
			runtime.MakeBigRat(a.securityParameter),
			runtime.MakeBigRat(a.qber),
			runtime.MakeBigRat(a.finiteKeyRate),
		),
	)
}

// ComposableSecurityAttack provides composable security guarantees.
// Security is measured by the trace distance from ideal functionality.
type ComposableSecurityAttack struct {
	correctnessError *big.Rat // Probability of protocol correctness failure
	secrecyError     *big.Rat // Trace distance from ideal secrecy
	totalEpsilon     *big.Rat // Combined security parameter
}

// NewComposableSecurity creates a composable security analysis.
func NewComposableSecurity(correctness, secrecy *big.Rat) *ComposableSecurityAttack {
	total := new(big.Rat).Add(correctness, secrecy)
	return &ComposableSecurityAttack{
		correctnessError: correctness,
		secrecyError:     secrecy,
		totalEpsilon:     total,
	}
}

// NewComposableSecurityDefault creates analysis with standard parameters.
func NewComposableSecurityDefault() *ComposableSecurityAttack {
	return NewComposableSecurity(
		big.NewRat(1, 1000000000), // 10^-9 correctness
		big.NewRat(1, 1000000000), // 10^-9 secrecy
	)
}

// Name returns the attack name.
func (a *ComposableSecurityAttack) Name() string {
	return "composable-security"
}

// Description returns a human-readable description.
func (a *ComposableSecurityAttack) Description() string {
	return "Composable security analysis with trace distance bound"
}

// CorrectnessError returns the correctness error bound.
func (a *ComposableSecurityAttack) CorrectnessError() *big.Rat {
	return new(big.Rat).Set(a.correctnessError)
}

// SecrecyError returns the secrecy error bound.
func (a *ComposableSecurityAttack) SecrecyError() *big.Rat {
	return new(big.Rat).Set(a.secrecyError)
}

// TotalEpsilon returns the combined security parameter.
func (a *ComposableSecurityAttack) TotalEpsilon() *big.Rat {
	return new(big.Rat).Set(a.totalEpsilon)
}

// ChoiMatrix returns the Choi matrix (worst-case channel).
func (a *ComposableSecurityAttack) ChoiMatrix() *runtime.Matrix {
	// At worst case, QBER is at threshold
	threshold := big.NewRat(11, 100)
	kraus, coeffSq := DepolarizingChannel(threshold)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *ComposableSecurityAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{paulis["I"], paulis["X"], paulis["Y"], paulis["Z"]}
}

// InformationGained returns the maximum information gain at threshold.
func (a *ComposableSecurityAttack) InformationGained() *big.Rat {
	return big.NewRat(1, 1)
}

// DisturbanceInduced returns the threshold QBER.
func (a *ComposableSecurityAttack) DisturbanceInduced() *big.Rat {
	return big.NewRat(11, 100)
}

// ApplicableProtocols returns applicable protocols.
func (a *ComposableSecurityAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "Six-State", "SARG04"}
}

// ToValue converts to runtime.Value.
func (a *ComposableSecurityAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("composable-security-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.correctnessError),
			runtime.MakeBigRat(a.secrecyError),
			runtime.MakeBigRat(a.totalEpsilon),
		),
	)
}

// DeviceIndependentAttack represents device-independent security.
// No assumptions about internal workings of devices.
type DeviceIndependentAttack struct {
	chshViolation *big.Rat // CHSH inequality violation (max 2*sqrt(2))
	localBound    *big.Rat // Classical local bound (2)
	quantumBound  *big.Rat // Quantum Tsirelson bound (2*sqrt(2))
}

// NewDeviceIndependent creates a device-independent security analysis.
func NewDeviceIndependent(chshViolation *big.Rat) *DeviceIndependentAttack {
	return &DeviceIndependentAttack{
		chshViolation: chshViolation,
		localBound:    big.NewRat(2, 1),
		quantumBound:  big.NewRat(283, 100), // ~2.83 approximation for 2*sqrt(2)
	}
}

// NewDeviceIndependentMaximal creates analysis at maximal violation.
func NewDeviceIndependentMaximal() *DeviceIndependentAttack {
	return NewDeviceIndependent(big.NewRat(283, 100))
}

// Name returns the attack name.
func (a *DeviceIndependentAttack) Name() string {
	return "device-independent"
}

// Description returns a human-readable description.
func (a *DeviceIndependentAttack) Description() string {
	return "Device-independent security via Bell inequality violation"
}

// CHSHViolation returns the observed CHSH violation.
func (a *DeviceIndependentAttack) CHSHViolation() *big.Rat {
	return new(big.Rat).Set(a.chshViolation)
}

// IsQuantum checks if the violation exceeds the classical bound.
func (a *DeviceIndependentAttack) IsQuantum() bool {
	return a.chshViolation.Cmp(a.localBound) > 0
}

// ChoiMatrix returns the Choi matrix (depolarizing at some effective noise).
func (a *DeviceIndependentAttack) ChoiMatrix() *runtime.Matrix {
	// Effective noise depends on CHSH violation
	// S = 2*sqrt(2)*(1-p) for depolarizing noise p
	// p = 1 - S/(2*sqrt(2)) = 1 - S/2.83
	one := big.NewRat(1, 1)
	quantum := big.NewRat(283, 100)
	ratio := new(big.Rat).Quo(a.chshViolation, quantum)
	noise := new(big.Rat).Sub(one, ratio)
	if noise.Sign() < 0 {
		noise = big.NewRat(0, 1)
	}
	kraus, coeffSq := DepolarizingChannel(noise)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *DeviceIndependentAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{paulis["I"], paulis["X"], paulis["Y"], paulis["Z"]}
}

// InformationGained returns the information Eve can gain.
// Related to CHSH violation via Tsirelson's bound.
func (a *DeviceIndependentAttack) InformationGained() *big.Rat {
	// If CHSH >= 2*sqrt(2), Eve gets no information
	// If CHSH = 2 (classical), Eve can know everything
	if a.chshViolation.Cmp(a.quantumBound) >= 0 {
		return big.NewRat(0, 1)
	}
	if a.chshViolation.Cmp(a.localBound) <= 0 {
		return big.NewRat(1, 1)
	}
	// Interpolate
	num := new(big.Rat).Sub(a.quantumBound, a.chshViolation)
	denom := new(big.Rat).Sub(a.quantumBound, a.localBound)
	return new(big.Rat).Quo(num, denom)
}

// DisturbanceInduced returns effective disturbance from imperfect violation.
func (a *DeviceIndependentAttack) DisturbanceInduced() *big.Rat {
	// At maximal violation, no disturbance
	// At classical bound, maximum disturbance (1/2)
	info := a.InformationGained()
	return new(big.Rat).Quo(info, big.NewRat(2, 1))
}

// ApplicableProtocols returns applicable protocols.
func (a *DeviceIndependentAttack) ApplicableProtocols() []string {
	return []string{"E91", "DIQKD"}
}

// ToValue converts to runtime.Value.
func (a *DeviceIndependentAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("device-independent-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.chshViolation),
			runtime.MakeBigRat(a.localBound),
			runtime.MakeBigRat(a.quantumBound),
		),
	)
}

// CoherentAttackFromValue parses a coherent attack from a runtime.Value.
func CoherentAttackFromValue(v runtime.Value) (Attack, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}

	label, ok := tag.Label.(runtime.Text)
	if !ok {
		return nil, false
	}

	switch label.V {
	case "coherent-attack":
		seq, ok := tag.Payload.(runtime.Seq)
		if !ok || len(seq.Items) < 1 {
			return nil, false
		}
		memQubits, ok := seq.Items[0].(runtime.Int)
		if !ok {
			return nil, false
		}
		if memQubits.V.Int64() > 0 {
			return NewMemoryBoundedCoherent(int(memQubits.V.Int64())), true
		}
		return NewGeneralCoherent(), true

	case "renner-security-attack":
		seq, ok := tag.Payload.(runtime.Seq)
		if !ok || len(seq.Items) < 3 {
			return nil, false
		}
		numSignals, ok := seq.Items[0].(runtime.Int)
		if !ok {
			return nil, false
		}
		qber, ok := seq.Items[2].(runtime.Rat)
		if !ok {
			return nil, false
		}
		return NewRennerSecurity(numSignals.V.Int64(), qber.V), true

	case "device-independent-attack":
		seq, ok := tag.Payload.(runtime.Seq)
		if !ok || len(seq.Items) < 1 {
			return nil, false
		}
		chsh, ok := seq.Items[0].(runtime.Rat)
		if !ok {
			return nil, false
		}
		return NewDeviceIndependent(chsh.V), true

	default:
		return nil, false
	}
}

// AllCoherentAttacks returns all standard coherent attacks.
func AllCoherentAttacks() []Attack {
	return []Attack{
		NewGeneralCoherent(),
		NewMemoryBoundedCoherent(100),
		NewMemoryBoundedCoherent(10),
		NewRennerSecurity(100000, big.NewRat(5, 100)),
		NewComposableSecurityDefault(),
		NewDeviceIndependentMaximal(),
	}
}

// AllAttacks returns all standard attacks across all categories.
func AllAttacks() []Attack {
	attacks := make([]Attack, 0)
	attacks = append(attacks, AllIndividualAttacks()...)
	attacks = append(attacks, AllCollectiveAttacks()...)
	attacks = append(attacks, AllCoherentAttacks()...)
	return attacks
}

// AttacksForProtocol returns attacks applicable to a specific protocol.
func AttacksForProtocol(protocol string) []Attack {
	all := AllAttacks()
	result := make([]Attack, 0)
	for _, attack := range all {
		for _, p := range attack.ApplicableProtocols() {
			if p == protocol {
				result = append(result, attack)
				break
			}
		}
	}
	return result
}
