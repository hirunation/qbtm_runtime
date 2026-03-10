// implementation.go provides implementation attack models.
//
// Implementation attacks exploit imperfections in real-world
// quantum devices rather than attacking the protocol itself.
// These attacks target practical vulnerabilities in sources,
// detectors, and other components of QKD systems.
package attack

import (
	"math/big"

	"qbtm/runtime"
)

// DeviceType identifies the targeted device component.
type DeviceType int

const (
	DeviceSource DeviceType = iota
	DeviceDetector
	DeviceChannel
	DeviceRNG
	DeviceClassical
	DeviceModulator
)

// String returns the device type name.
func (d DeviceType) String() string {
	switch d {
	case DeviceSource:
		return "source"
	case DeviceDetector:
		return "detector"
	case DeviceChannel:
		return "channel"
	case DeviceRNG:
		return "rng"
	case DeviceClassical:
		return "classical"
	case DeviceModulator:
		return "modulator"
	default:
		return "unknown"
	}
}

// Severity indicates the attack severity.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the severity level name.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// =============================================================================
// PNS Attack (Photon Number Splitting)
// =============================================================================

// PNSAttack represents the photon number splitting attack.
// This attack exploits multi-photon emissions in weak coherent pulse (WCP) sources.
//
// For a WCP source with mean photon number mu:
// - P(n) = e^(-mu) * mu^n / n! (Poisson distribution)
// - P(n>=2) = 1 - e^(-mu) * (1 + mu) (multi-photon probability)
//
// Eve blocks single-photon pulses (causing loss), splits multi-photon pulses,
// keeps one photon and forwards the rest. She waits for basis announcement
// to measure her stored photons in the correct basis.
//
// Key insight: Eve gains full information on multi-photon pulses with zero
// disturbance on those pulses. The attack is undetectable without decoy states.
type PNSAttack struct {
	MeanPhotonNumber *big.Rat // mu: mean photon number per pulse
	MultiPhotonProb  *big.Rat // P(n>=2): probability of multi-photon emission
	ChannelLoss      *big.Rat // eta: channel transmission (0 to 1)
	targetDevice     DeviceType
	severity         Severity
}

// NewPNS creates a PNS attack for a source with given mean photon number.
// Typical WCP sources use mu ~ 0.1 to 0.5.
func NewPNS(meanPhoton *big.Rat) *PNSAttack {
	// Compute P(n>=2) = 1 - (1 + mu) * e^(-mu)
	// For rational approximation:
	// mu = 0.1: P(n>=2) ~ 0.0047 ~ 1/213
	// mu = 0.2: P(n>=2) ~ 0.0175 ~ 1/57
	// mu = 0.5: P(n>=2) ~ 0.0902 ~ 1/11
	multiPhotonProb := computeMultiPhotonProb(meanPhoton)

	return &PNSAttack{
		MeanPhotonNumber: new(big.Rat).Set(meanPhoton),
		MultiPhotonProb:  multiPhotonProb,
		ChannelLoss:      big.NewRat(1, 10), // Default 10% transmission (10 dB loss)
		targetDevice:     DeviceSource,
		severity:         SeverityHigh,
	}
}

// NewPNSWithLoss creates a PNS attack with specified channel loss.
func NewPNSWithLoss(meanPhoton, channelLoss *big.Rat) *PNSAttack {
	a := NewPNS(meanPhoton)
	a.ChannelLoss = new(big.Rat).Set(channelLoss)
	return a
}

// computeMultiPhotonProb computes P(n>=2) for Poisson distribution.
// P(n>=2) = 1 - P(0) - P(1) = 1 - e^(-mu) - mu*e^(-mu) = 1 - (1+mu)*e^(-mu)
// We use rational approximations for common mu values.
func computeMultiPhotonProb(mu *big.Rat) *big.Rat {
	// Common approximations:
	// For small mu: P(n>=2) ~ mu^2/2 (first term of Taylor expansion)
	one := big.NewRat(1, 1)
	two := big.NewRat(2, 1)

	// mu^2 / 2 is a good approximation for small mu
	muSq := new(big.Rat).Mul(mu, mu)
	approx := new(big.Rat).Quo(muSq, two)

	// Cap at reasonable maximum
	if approx.Cmp(one) > 0 {
		return one
	}
	return approx
}

// Name returns the attack name.
func (a *PNSAttack) Name() string {
	return "pns"
}

// Description returns a human-readable description.
func (a *PNSAttack) Description() string {
	return "Photon number splitting attack on multi-photon pulses from weak coherent sources"
}

// TargetDevice returns the targeted device component.
func (a *PNSAttack) TargetDevice() DeviceType {
	return a.targetDevice
}

// Severity returns the attack severity.
func (a *PNSAttack) Severity() Severity {
	return a.severity
}

// ChoiMatrix returns the Choi matrix of the PNS channel.
// For single-photon pulses: identity channel (Eve blocks, no info)
// For multi-photon pulses: identity channel (Eve splits, gets info but no disturbance)
// Overall: the channel to Bob is effectively identity (or loss)
func (a *PNSAttack) ChoiMatrix() *runtime.Matrix {
	// PNS doesn't disturb the quantum state - it's an identity channel to Bob
	// (Eve just removes some photons from multi-photon pulses)
	kraus := []*runtime.Matrix{runtime.Identity(2)}
	coeffSq := []*big.Rat{big.NewRat(1, 1)}
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
// PNS is effectively an identity channel for transmitted states.
func (a *PNSAttack) KrausOperators() []*runtime.Matrix {
	return []*runtime.Matrix{runtime.Identity(2)}
}

// InformationGained returns the mutual information I(X:E).
// Eve gains full information on multi-photon pulses.
// I(X:E) = P(n>=2) * 1 = P(n>=2)
// With channel loss, Eve can hide the attack better.
func (a *PNSAttack) InformationGained() *big.Rat {
	// Eve's information = fraction of multi-photon pulses
	// In realistic scenarios with loss, Eve can hide single-photon blocking
	// by matching expected detection rate
	return new(big.Rat).Set(a.MultiPhotonProb)
}

// DisturbanceInduced returns the QBER induced by the attack.
// PNS induces ZERO disturbance - this is its key danger.
// Eve perfectly copies multi-photon pulses without introducing errors.
func (a *PNSAttack) DisturbanceInduced() *big.Rat {
	return big.NewRat(0, 1) // Zero disturbance - undetectable!
}

// SecureKeyFraction returns the fraction of key from single-photon pulses.
// This is the fraction of the key that is secure against PNS.
// Secure fraction = P(n=1) / (P(n=1) + P(n>=2)) when accounting for loss
func (a *PNSAttack) SecureKeyFraction() *big.Rat {
	// P(n=1) ~ mu * e^(-mu) ~ mu for small mu
	// Secure fraction ~ P(n=1) / (P(n=1) + P(n>=2))
	pSingle := new(big.Rat).Set(a.MeanPhotonNumber) // approximation: P(1) ~ mu

	total := new(big.Rat).Add(pSingle, a.MultiPhotonProb)
	if total.Sign() == 0 {
		return big.NewRat(0, 1)
	}

	return new(big.Rat).Quo(pSingle, total)
}

// ApplicableProtocols returns protocols this attack applies to.
// PNS applies to any protocol using weak coherent pulse sources.
func (a *PNSAttack) ApplicableProtocols() []string {
	return []string{"BB84", "B92", "SARG04", "Six-State"} // WCP implementations
}

// ToValue converts the attack to a runtime.Value.
func (a *PNSAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("pns-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.MeanPhotonNumber),
			runtime.MakeBigRat(a.MultiPhotonProb),
			runtime.MakeBigRat(a.ChannelLoss),
			runtime.MakeBigRat(a.InformationGained()),
			runtime.MakeBigRat(a.DisturbanceInduced()),
			runtime.MakeBigRat(a.SecureKeyFraction()),
		),
	)
}

// =============================================================================
// Detector Blinding Attack
// =============================================================================

// DetectorBlindingAttack represents the detector blinding attack.
// This attack exploits the behavior of single-photon detectors (SPDs) when
// illuminated with bright light, forcing them into linear (classical) mode.
//
// Attack mechanism:
// 1. Eve sends continuous bright light to blind Bob's SPDs
// 2. Detectors exit Geiger mode, no longer respond to single photons
// 3. Eve performs intercept-resend but sends bright trigger pulses
// 4. Only the detector matching Eve's measurement result clicks
// 5. Eve gains full information with zero detectable QBER
//
// This attack was demonstrated on commercial QKD systems (2010-2011).
type DetectorBlindingAttack struct {
	BlindingPower     *big.Rat // Power needed to blind detector (mW)
	ControlEfficiency *big.Rat // How well Eve can control which detector clicks (0 to 1)
	TriggerPower      *big.Rat // Power of trigger pulses
	targetDevice      DeviceType
	severity          Severity
}

// NewDetectorBlinding creates a detector blinding attack.
func NewDetectorBlinding() *DetectorBlindingAttack {
	return &DetectorBlindingAttack{
		BlindingPower:     big.NewRat(1, 1),   // ~1 mW typical
		ControlEfficiency: big.NewRat(99, 100), // 99% control
		TriggerPower:      big.NewRat(1, 100), // 10 uW triggers
		targetDevice:      DeviceDetector,
		severity:          SeverityCritical,
	}
}

// NewDetectorBlindingWithEfficiency creates an attack with specified control efficiency.
func NewDetectorBlindingWithEfficiency(efficiency *big.Rat) *DetectorBlindingAttack {
	a := NewDetectorBlinding()
	a.ControlEfficiency = new(big.Rat).Set(efficiency)
	return a
}

// Name returns the attack name.
func (a *DetectorBlindingAttack) Name() string {
	return "detector-blinding"
}

// Description returns a human-readable description.
func (a *DetectorBlindingAttack) Description() string {
	return "Blind single-photon detectors with bright light to control detection outcomes"
}

// TargetDevice returns the targeted device component.
func (a *DetectorBlindingAttack) TargetDevice() DeviceType {
	return a.targetDevice
}

// Severity returns the attack severity.
func (a *DetectorBlindingAttack) Severity() Severity {
	return a.severity
}

// ChoiMatrix returns the Choi matrix of the blinding channel.
// With perfect control, Eve performs intercept-resend but creates no errors.
// The effective channel is close to identity when control is high.
func (a *DetectorBlindingAttack) ChoiMatrix() *runtime.Matrix {
	// When Eve has perfect control, the channel appears as identity to Bob
	// Any imperfections create a depolarizing component
	one := big.NewRat(1, 1)
	imperfection := new(big.Rat).Sub(one, a.ControlEfficiency)

	// Small depolarizing noise from imperfect control
	kraus, coeffSq := DepolarizingChannel(imperfection)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *DetectorBlindingAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}
}

// InformationGained returns the mutual information I(X:E).
// With high control efficiency, Eve gains nearly full information.
func (a *DetectorBlindingAttack) InformationGained() *big.Rat {
	// Eve's info = control efficiency (she knows what Bob detected)
	return new(big.Rat).Set(a.ControlEfficiency)
}

// DisturbanceInduced returns the QBER induced by the attack.
// With perfect control, QBER can be zero.
// Imperfect control introduces errors proportional to (1 - efficiency).
func (a *DetectorBlindingAttack) DisturbanceInduced() *big.Rat {
	// QBER = (1 - control_efficiency) / 2
	// Factor of 1/2 because errors are random when control fails
	one := big.NewRat(1, 1)
	two := big.NewRat(2, 1)
	imperfection := new(big.Rat).Sub(one, a.ControlEfficiency)
	return new(big.Rat).Quo(imperfection, two)
}

// ApplicableProtocols returns protocols this attack applies to.
// Detector blinding applies to any protocol using vulnerable SPDs.
func (a *DetectorBlindingAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "B92", "SARG04", "Six-State", "COW", "DPS"}
}

// ToValue converts the attack to a runtime.Value.
func (a *DetectorBlindingAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("detector-blinding-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.BlindingPower),
			runtime.MakeBigRat(a.ControlEfficiency),
			runtime.MakeBigRat(a.TriggerPower),
			runtime.MakeBigRat(a.InformationGained()),
			runtime.MakeBigRat(a.DisturbanceInduced()),
		),
	)
}

// =============================================================================
// Time-Shift Attack
// =============================================================================

// TimeShiftAttack represents the time-shift attack.
// This attack exploits timing-dependent efficiency differences between detectors.
//
// Attack mechanism:
// 1. Real detectors have efficiency that varies with photon arrival time
// 2. Different detectors may have different timing profiles
// 3. Eve shifts photon arrival times to bias which detector fires
// 4. Eve measures in random basis, shifts timing based on result
// 5. When bases match, correct detector fires; when bases differ, any result is OK
//
// Information gain depends on the efficiency mismatch between detectors.
type TimeShiftAttack struct {
	EfficiencyMismatch *big.Rat // Ratio of detector efficiencies at shifted times
	TimingResolution   *big.Rat // Timing jitter/resolution in ns
	MaxTimeShift       *big.Rat // Maximum time shift Eve can apply in ns
	targetDevice       DeviceType
	severity           Severity
}

// NewTimeShift creates a time-shift attack with specified efficiency mismatch.
// mismatch = eta_max / eta_min at the timing points Eve exploits.
func NewTimeShift(mismatch *big.Rat) *TimeShiftAttack {
	return &TimeShiftAttack{
		EfficiencyMismatch: new(big.Rat).Set(mismatch),
		TimingResolution:   big.NewRat(1, 10),  // 100 ps typical
		MaxTimeShift:       big.NewRat(1, 1),   // 1 ns typical
		targetDevice:       DeviceDetector,
		severity:           SeverityMedium,
	}
}

// NewTimeShiftDefault creates a time-shift attack with typical parameters.
func NewTimeShiftDefault() *TimeShiftAttack {
	// Typical mismatch: 2:1 efficiency ratio
	return NewTimeShift(big.NewRat(2, 1))
}

// Name returns the attack name.
func (a *TimeShiftAttack) Name() string {
	return "time-shift"
}

// Description returns a human-readable description.
func (a *TimeShiftAttack) Description() string {
	return "Exploit timing-dependent detector efficiency differences to bias detection outcomes"
}

// TargetDevice returns the targeted device component.
func (a *TimeShiftAttack) TargetDevice() DeviceType {
	return a.targetDevice
}

// Severity returns the attack severity.
func (a *TimeShiftAttack) Severity() Severity {
	return a.severity
}

// ChoiMatrix returns the Choi matrix.
func (a *TimeShiftAttack) ChoiMatrix() *runtime.Matrix {
	// The channel is approximately depolarizing with parameter related to mismatch
	p := a.DisturbanceInduced()
	kraus, coeffSq := DepolarizingChannel(p)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *TimeShiftAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}
}

// InformationGained returns the mutual information I(X:E).
// Information scales with efficiency mismatch.
// I ~ (eta_max - eta_min) / (eta_max + eta_min) = (mismatch - 1) / (mismatch + 1)
func (a *TimeShiftAttack) InformationGained() *big.Rat {
	// For mismatch ratio r = eta_max/eta_min
	// Bias = (r - 1) / (r + 1)
	// Eve's information ~ bias (simplified)
	one := big.NewRat(1, 1)
	numerator := new(big.Rat).Sub(a.EfficiencyMismatch, one)
	denominator := new(big.Rat).Add(a.EfficiencyMismatch, one)

	if denominator.Sign() == 0 {
		return big.NewRat(0, 1)
	}

	bias := new(big.Rat).Quo(numerator, denominator)

	// Info gained is approximately half the bias (averaged over bases)
	two := big.NewRat(2, 1)
	return new(big.Rat).Quo(bias, two)
}

// DisturbanceInduced returns the QBER induced by the attack.
// Disturbance comes from basis mismatch cases where timing shift causes wrong result.
func (a *TimeShiftAttack) DisturbanceInduced() *big.Rat {
	// When Eve guesses wrong basis, timing shift may cause wrong detector to fire
	// QBER ~ (1/2) * (1 - 1/mismatch) for wrong basis cases
	// Averaged: QBER ~ (1/4) * (1 - 1/mismatch)
	one := big.NewRat(1, 1)
	four := big.NewRat(4, 1)

	invMismatch, ok := new(big.Rat).SetString("1")
	if !ok || a.EfficiencyMismatch.Sign() == 0 {
		return big.NewRat(0, 1)
	}
	invMismatch = new(big.Rat).Quo(one, a.EfficiencyMismatch)

	diff := new(big.Rat).Sub(one, invMismatch)
	return new(big.Rat).Quo(diff, four)
}

// ApplicableProtocols returns protocols this attack applies to.
func (a *TimeShiftAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "B92", "SARG04", "Six-State"}
}

// ToValue converts the attack to a runtime.Value.
func (a *TimeShiftAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("time-shift-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.EfficiencyMismatch),
			runtime.MakeBigRat(a.TimingResolution),
			runtime.MakeBigRat(a.MaxTimeShift),
			runtime.MakeBigRat(a.InformationGained()),
			runtime.MakeBigRat(a.DisturbanceInduced()),
		),
	)
}

// =============================================================================
// Trojan Horse Attack
// =============================================================================

// TrojanHorseAttack represents the Trojan horse attack.
// This attack probes internal device states by injecting bright light.
//
// Attack mechanism:
// 1. Eve sends bright probe pulses into Alice's device (e.g., through fiber)
// 2. Light reflects from internal components (phase modulators, beam splitters)
// 3. Reflected light carries information about modulator settings
// 4. Eve measures the reflected light to learn Alice's encoding
//
// This attack can reveal basis/bit choices without disturbing quantum signals.
type TrojanHorseAttack struct {
	ProbePower      *big.Rat // Power of injected probe light (mW)
	Reflectivity    *big.Rat // Device reflectivity (fraction reflected back)
	ModulatorLeak   *big.Rat // Information leakage per reflection
	ProbeWavelength *big.Rat // Wavelength of probe (nm), may differ from signal
	targetDevice    DeviceType
	severity        Severity
}

// NewTrojanHorse creates a Trojan horse attack with default parameters.
func NewTrojanHorse() *TrojanHorseAttack {
	return &TrojanHorseAttack{
		ProbePower:      big.NewRat(1, 1),     // 1 mW probe
		Reflectivity:    big.NewRat(1, 1000),  // 0.1% reflection (with isolator)
		ModulatorLeak:   big.NewRat(1, 10),    // 10% info per reflection
		ProbeWavelength: big.NewRat(1550, 1),  // 1550 nm
		targetDevice:    DeviceModulator,
		severity:        SeverityHigh,
	}
}

// NewTrojanHorseWithReflectivity creates an attack with specified reflectivity.
// Higher reflectivity = more information, but also easier to detect.
func NewTrojanHorseWithReflectivity(reflectivity *big.Rat) *TrojanHorseAttack {
	a := NewTrojanHorse()
	a.Reflectivity = new(big.Rat).Set(reflectivity)
	return a
}

// Name returns the attack name.
func (a *TrojanHorseAttack) Name() string {
	return "trojan-horse"
}

// Description returns a human-readable description.
func (a *TrojanHorseAttack) Description() string {
	return "Inject bright light to probe internal device states via back-reflections"
}

// TargetDevice returns the targeted device component.
func (a *TrojanHorseAttack) TargetDevice() DeviceType {
	return a.targetDevice
}

// Severity returns the attack severity.
func (a *TrojanHorseAttack) Severity() Severity {
	return a.severity
}

// ChoiMatrix returns the Choi matrix.
// Trojan horse doesn't affect the quantum channel - it's a side channel attack.
func (a *TrojanHorseAttack) ChoiMatrix() *runtime.Matrix {
	// The quantum channel itself is unaffected - identity
	kraus := []*runtime.Matrix{runtime.Identity(2)}
	coeffSq := []*big.Rat{big.NewRat(1, 1)}
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *TrojanHorseAttack) KrausOperators() []*runtime.Matrix {
	return []*runtime.Matrix{runtime.Identity(2)}
}

// InformationGained returns the mutual information I(X:E).
// Information depends on reflectivity and modulator characteristics.
// I = reflectivity * modulator_leak * probe_effectiveness
func (a *TrojanHorseAttack) InformationGained() *big.Rat {
	// Simplified: information scales with reflectivity * modulator leakage
	// Real attacks need sufficient photon count and SNR
	info := new(big.Rat).Mul(a.Reflectivity, a.ModulatorLeak)

	// Scale by probe power (diminishing returns)
	// For simplicity, assume 1 mW gives full effectiveness
	one := big.NewRat(1, 1)
	if info.Cmp(one) > 0 {
		return one
	}
	return info
}

// DisturbanceInduced returns the QBER induced by the attack.
// Trojan horse attack induces ZERO disturbance on the quantum channel.
// It's a purely passive side-channel attack.
func (a *TrojanHorseAttack) DisturbanceInduced() *big.Rat {
	return big.NewRat(0, 1) // No disturbance - side channel attack
}

// ApplicableProtocols returns protocols this attack applies to.
// Affects any protocol where Alice has accessible optical components.
func (a *TrojanHorseAttack) ApplicableProtocols() []string {
	return []string{"BB84", "B92", "SARG04", "Six-State", "COW", "DPS"}
}

// ToValue converts the attack to a runtime.Value.
func (a *TrojanHorseAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("trojan-horse-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.ProbePower),
			runtime.MakeBigRat(a.Reflectivity),
			runtime.MakeBigRat(a.ModulatorLeak),
			runtime.MakeBigRat(a.ProbeWavelength),
			runtime.MakeBigRat(a.InformationGained()),
			runtime.MakeBigRat(a.DisturbanceInduced()),
		),
	)
}

// =============================================================================
// Wavelength Attack
// =============================================================================

// WavelengthAttack represents the wavelength-dependent efficiency attack.
// This attack exploits the fact that detector and optical component efficiency
// varies with wavelength.
//
// Attack mechanism:
// 1. Eve intercepts and measures quantum signals
// 2. Eve resends at a different wavelength where detector efficiencies differ
// 3. The wavelength shift biases which detector fires
// 4. Eve can gain partial information with reduced disturbance
type WavelengthAttack struct {
	WavelengthShift     *big.Rat // Shift from design wavelength (nm)
	EfficiencyRatio     *big.Rat // Ratio of efficiencies at shifted wavelength
	DesignWavelength    *big.Rat // Original design wavelength (nm)
	targetDevice        DeviceType
	severity            Severity
}

// NewWavelengthAttack creates a wavelength attack with specified shift.
func NewWavelengthAttack(shift *big.Rat) *WavelengthAttack {
	// Efficiency ratio depends on shift magnitude
	// Typical: 1 nm shift might give 5% efficiency difference
	ratio := computeWavelengthEfficiencyRatio(shift)

	return &WavelengthAttack{
		WavelengthShift:  new(big.Rat).Set(shift),
		EfficiencyRatio:  ratio,
		DesignWavelength: big.NewRat(1550, 1), // 1550 nm standard
		targetDevice:     DeviceDetector,
		severity:         SeverityMedium,
	}
}

// NewWavelengthAttackDefault creates a wavelength attack with typical parameters.
func NewWavelengthAttackDefault() *WavelengthAttack {
	return NewWavelengthAttack(big.NewRat(5, 1)) // 5 nm shift
}

// computeWavelengthEfficiencyRatio estimates efficiency ratio from wavelength shift.
func computeWavelengthEfficiencyRatio(shift *big.Rat) *big.Rat {
	// Simplified model: ratio ~ 1 + k * |shift|
	// where k ~ 0.02 per nm for typical InGaAs detectors
	k := big.NewRat(2, 100) // 2% per nm
	one := big.NewRat(1, 1)

	// |shift| * k
	absShift := new(big.Rat).Abs(shift)
	delta := new(big.Rat).Mul(absShift, k)

	return new(big.Rat).Add(one, delta)
}

// Name returns the attack name.
func (a *WavelengthAttack) Name() string {
	return "wavelength"
}

// Description returns a human-readable description.
func (a *WavelengthAttack) Description() string {
	return "Exploit wavelength-dependent detector efficiency to bias detection outcomes"
}

// TargetDevice returns the targeted device component.
func (a *WavelengthAttack) TargetDevice() DeviceType {
	return a.targetDevice
}

// Severity returns the attack severity.
func (a *WavelengthAttack) Severity() Severity {
	return a.severity
}

// ChoiMatrix returns the Choi matrix.
func (a *WavelengthAttack) ChoiMatrix() *runtime.Matrix {
	p := a.DisturbanceInduced()
	kraus, coeffSq := DepolarizingChannel(p)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *WavelengthAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}
}

// InformationGained returns the mutual information I(X:E).
// Similar to time-shift, information scales with efficiency ratio.
func (a *WavelengthAttack) InformationGained() *big.Rat {
	one := big.NewRat(1, 1)
	numerator := new(big.Rat).Sub(a.EfficiencyRatio, one)
	denominator := new(big.Rat).Add(a.EfficiencyRatio, one)

	if denominator.Sign() == 0 {
		return big.NewRat(0, 1)
	}

	bias := new(big.Rat).Quo(numerator, denominator)
	two := big.NewRat(2, 1)
	return new(big.Rat).Quo(bias, two)
}

// DisturbanceInduced returns the QBER induced by the attack.
func (a *WavelengthAttack) DisturbanceInduced() *big.Rat {
	one := big.NewRat(1, 1)
	four := big.NewRat(4, 1)

	if a.EfficiencyRatio.Sign() == 0 {
		return big.NewRat(0, 1)
	}

	invRatio := new(big.Rat).Quo(one, a.EfficiencyRatio)
	diff := new(big.Rat).Sub(one, invRatio)
	return new(big.Rat).Quo(diff, four)
}

// ApplicableProtocols returns protocols this attack applies to.
func (a *WavelengthAttack) ApplicableProtocols() []string {
	return []string{"BB84", "B92", "SARG04", "Six-State"}
}

// ToValue converts the attack to a runtime.Value.
func (a *WavelengthAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("wavelength-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.WavelengthShift),
			runtime.MakeBigRat(a.EfficiencyRatio),
			runtime.MakeBigRat(a.DesignWavelength),
			runtime.MakeBigRat(a.InformationGained()),
			runtime.MakeBigRat(a.DisturbanceInduced()),
		),
	)
}

// =============================================================================
// After-Gate Attack
// =============================================================================

// AfterGateAttack represents the after-gate attack.
// This attack exploits afterpulses in APD (avalanche photodiode) detectors.
//
// Attack mechanism:
// 1. Eve intercepts and measures quantum signals
// 2. Eve resends pulses timed to arrive during the detector dead time
// 3. These pulses may trigger afterpulses that correlate with Eve's measurement
// 4. The afterpulse probability depends on the detection history
//
// This attack exploits the fact that APD detectors have memory effects.
type AfterGateAttack struct {
	GateDelay           *big.Rat // Timing offset relative to gate (ns)
	AfterpulseProbability *big.Rat // Probability of afterpulse given previous detection
	DeadTime            *big.Rat // Detector dead time (ns)
	targetDevice        DeviceType
	severity            Severity
}

// NewAfterGateAttack creates an after-gate attack with specified delay.
func NewAfterGateAttack(delay *big.Rat) *AfterGateAttack {
	// Afterpulse probability depends on timing
	// Typical: 1-5% afterpulse probability
	afterpulseProb := big.NewRat(2, 100) // 2% typical

	return &AfterGateAttack{
		GateDelay:           new(big.Rat).Set(delay),
		AfterpulseProbability: afterpulseProb,
		DeadTime:            big.NewRat(10, 1), // 10 ns typical
		targetDevice:        DeviceDetector,
		severity:            SeverityLow,
	}
}

// NewAfterGateAttackDefault creates an after-gate attack with typical parameters.
func NewAfterGateAttackDefault() *AfterGateAttack {
	return NewAfterGateAttack(big.NewRat(5, 1)) // 5 ns delay
}

// Name returns the attack name.
func (a *AfterGateAttack) Name() string {
	return "after-gate"
}

// Description returns a human-readable description.
func (a *AfterGateAttack) Description() string {
	return "Exploit APD afterpulses by timing attacks relative to detector gates"
}

// TargetDevice returns the targeted device component.
func (a *AfterGateAttack) TargetDevice() DeviceType {
	return a.targetDevice
}

// Severity returns the attack severity.
func (a *AfterGateAttack) Severity() Severity {
	return a.severity
}

// ChoiMatrix returns the Choi matrix.
func (a *AfterGateAttack) ChoiMatrix() *runtime.Matrix {
	p := a.DisturbanceInduced()
	kraus, coeffSq := DepolarizingChannel(p)
	return ComputeChoiMatrix(kraus, coeffSq)
}

// KrausOperators returns the Kraus decomposition.
func (a *AfterGateAttack) KrausOperators() []*runtime.Matrix {
	paulis := PauliMatrices()
	return []*runtime.Matrix{
		paulis["I"],
		paulis["X"],
		paulis["Y"],
		paulis["Z"],
	}
}

// InformationGained returns the mutual information I(X:E).
// Limited by afterpulse probability and timing precision.
func (a *AfterGateAttack) InformationGained() *big.Rat {
	// Eve's info is limited by the afterpulse correlation
	// Simplified: info ~ afterpulse_prob / 2
	two := big.NewRat(2, 1)
	return new(big.Rat).Quo(a.AfterpulseProbability, two)
}

// DisturbanceInduced returns the QBER induced by the attack.
func (a *AfterGateAttack) DisturbanceInduced() *big.Rat {
	// After-gate attack typically has limited QBER impact
	// QBER contribution ~ afterpulse_prob / 4
	four := big.NewRat(4, 1)
	return new(big.Rat).Quo(a.AfterpulseProbability, four)
}

// ApplicableProtocols returns protocols this attack applies to.
func (a *AfterGateAttack) ApplicableProtocols() []string {
	return []string{"BB84", "E91", "SARG04", "Six-State"}
}

// ToValue converts the attack to a runtime.Value.
func (a *AfterGateAttack) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("after-gate-attack"),
		runtime.MakeSeq(
			runtime.MakeBigRat(a.GateDelay),
			runtime.MakeBigRat(a.AfterpulseProbability),
			runtime.MakeBigRat(a.DeadTime),
			runtime.MakeBigRat(a.InformationGained()),
			runtime.MakeBigRat(a.DisturbanceInduced()),
		),
	)
}

// =============================================================================
// Countermeasures
// =============================================================================

// Countermeasure represents a defense against implementation attacks.
type Countermeasure struct {
	Name        string    // Countermeasure identifier
	Description string    // Human-readable description
	Attacks     []string  // Attack names this countermeasure defends against
	Overhead    *big.Rat  // Performance/key rate cost (0 = no cost, 1 = prohibitive)
	Effectiveness *big.Rat // How effective (0 = none, 1 = complete defense)
}

// Countermeasures defines standard countermeasures for implementation attacks.
var Countermeasures = []Countermeasure{
	{
		Name:        "decoy-state",
		Description: "Random intensity decoy pulses to detect PNS attacks",
		Attacks:     []string{"pns"},
		Overhead:    big.NewRat(1, 10),  // 10% key rate reduction
		Effectiveness: big.NewRat(99, 100), // 99% effective
	},
	{
		Name:        "mdi-qkd",
		Description: "Measurement-device-independent QKD eliminates all detector attacks",
		Attacks:     []string{"detector-blinding", "time-shift", "wavelength", "after-gate"},
		Overhead:    big.NewRat(1, 2),   // 50% key rate reduction
		Effectiveness: big.NewRat(1, 1), // 100% effective against detector attacks
	},
	{
		Name:        "optical-isolator",
		Description: "Optical isolators prevent back-propagation into devices",
		Attacks:     []string{"trojan-horse"},
		Overhead:    big.NewRat(1, 100), // 1% loss from isolator
		Effectiveness: big.NewRat(99, 100), // 99% effective (limited by isolator quality)
	},
	{
		Name:        "detector-monitoring",
		Description: "Monitor detector current/temperature to detect blinding",
		Attacks:     []string{"detector-blinding"},
		Overhead:    big.NewRat(1, 100), // 1% overhead for monitoring
		Effectiveness: big.NewRat(95, 100), // 95% effective
	},
	{
		Name:        "tight-timing-window",
		Description: "Narrow timing acceptance window reduces time-shift vulnerability",
		Attacks:     []string{"time-shift"},
		Overhead:    big.NewRat(5, 100), // 5% detection rate reduction
		Effectiveness: big.NewRat(90, 100), // 90% effective
	},
	{
		Name:        "wavelength-filter",
		Description: "Narrow bandpass filter at design wavelength",
		Attacks:     []string{"wavelength", "trojan-horse"},
		Overhead:    big.NewRat(2, 100), // 2% loss
		Effectiveness: big.NewRat(95, 100), // 95% effective
	},
	{
		Name:        "efficiency-matching",
		Description: "Match detector efficiencies to eliminate side-channel attacks",
		Attacks:     []string{"time-shift", "wavelength"},
		Overhead:    big.NewRat(0, 1),   // No runtime overhead
		Effectiveness: big.NewRat(85, 100), // 85% effective (limited by matching precision)
	},
	{
		Name:        "device-independent-qkd",
		Description: "Full device-independent QKD with Bell test verification",
		Attacks:     []string{"pns", "detector-blinding", "time-shift", "trojan-horse", "wavelength", "after-gate"},
		Overhead:    big.NewRat(9, 10),  // 90% key rate reduction
		Effectiveness: big.NewRat(1, 1), // 100% effective (all attacks)
	},
}

// CountermeasureForAttack returns countermeasures effective against the given attack.
func CountermeasureForAttack(attackName string) []Countermeasure {
	var result []Countermeasure
	for _, cm := range Countermeasures {
		for _, a := range cm.Attacks {
			if a == attackName {
				result = append(result, cm)
				break
			}
		}
	}
	return result
}

// ToValue converts a Countermeasure to a runtime.Value.
func (c *Countermeasure) ToValue() runtime.Value {
	attackItems := make([]runtime.Value, len(c.Attacks))
	for i, a := range c.Attacks {
		attackItems[i] = runtime.MakeText(a)
	}

	return runtime.MakeTag(
		runtime.MakeText("countermeasure"),
		runtime.MakeSeq(
			runtime.MakeText(c.Name),
			runtime.MakeText(c.Description),
			runtime.MakeSeq(attackItems...),
			runtime.MakeBigRat(c.Overhead),
			runtime.MakeBigRat(c.Effectiveness),
		),
	)
}

// =============================================================================
// Implementation Attack Registry
// =============================================================================

// AllImplementationAttacks returns all standard implementation attacks.
func AllImplementationAttacks() []Attack {
	return []Attack{
		NewPNS(big.NewRat(1, 10)),           // mu = 0.1
		NewPNS(big.NewRat(1, 2)),            // mu = 0.5
		NewDetectorBlinding(),
		NewTimeShiftDefault(),
		NewTrojanHorse(),
		NewWavelengthAttackDefault(),
		NewAfterGateAttackDefault(),
	}
}

// ImplementationAttackFromValue parses an implementation attack from a runtime.Value.
func ImplementationAttackFromValue(v runtime.Value) (Attack, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}

	label, ok := tag.Label.(runtime.Text)
	if !ok {
		return nil, false
	}

	seq, ok := tag.Payload.(runtime.Seq)
	if !ok {
		return nil, false
	}

	switch label.V {
	case "pns-attack":
		if len(seq.Items) < 1 {
			return nil, false
		}
		mu, ok := seq.Items[0].(runtime.Rat)
		if !ok {
			return nil, false
		}
		return NewPNS(mu.V), true

	case "detector-blinding-attack":
		return NewDetectorBlinding(), true

	case "time-shift-attack":
		if len(seq.Items) < 1 {
			return nil, false
		}
		mismatch, ok := seq.Items[0].(runtime.Rat)
		if !ok {
			return nil, false
		}
		return NewTimeShift(mismatch.V), true

	case "trojan-horse-attack":
		return NewTrojanHorse(), true

	case "wavelength-attack":
		if len(seq.Items) < 1 {
			return nil, false
		}
		shift, ok := seq.Items[0].(runtime.Rat)
		if !ok {
			return nil, false
		}
		return NewWavelengthAttack(shift.V), true

	case "after-gate-attack":
		if len(seq.Items) < 1 {
			return nil, false
		}
		delay, ok := seq.Items[0].(runtime.Rat)
		if !ok {
			return nil, false
		}
		return NewAfterGateAttack(delay.V), true

	default:
		return nil, false
	}
}

// AnalyzeImplementationVulnerabilities analyzes a protocol's vulnerability
// to implementation attacks and suggests countermeasures.
func AnalyzeImplementationVulnerabilities(protocol string) []ImplementationVulnerability {
	attacks := AllImplementationAttacks()
	var vulnerabilities []ImplementationVulnerability

	for _, attack := range attacks {
		applicable := false
		for _, p := range attack.ApplicableProtocols() {
			if p == protocol {
				applicable = true
				break
			}
		}

		if applicable {
			countermeasures := CountermeasureForAttack(attack.Name())
			vuln := ImplementationVulnerability{
				Attack:          attack,
				Protocol:        protocol,
				InfoLeakage:     attack.InformationGained(),
				Disturbance:     attack.DisturbanceInduced(),
				Countermeasures: countermeasures,
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

// ImplementationVulnerability represents a protocol's vulnerability to an attack.
type ImplementationVulnerability struct {
	Attack          Attack
	Protocol        string
	InfoLeakage     *big.Rat
	Disturbance     *big.Rat
	Countermeasures []Countermeasure
}

// ToValue converts an ImplementationVulnerability to a runtime.Value.
func (v *ImplementationVulnerability) ToValue() runtime.Value {
	cmItems := make([]runtime.Value, len(v.Countermeasures))
	for i, cm := range v.Countermeasures {
		cmItems[i] = cm.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("implementation-vulnerability"),
		runtime.MakeSeq(
			v.Attack.ToValue(),
			runtime.MakeText(v.Protocol),
			runtime.MakeBigRat(v.InfoLeakage),
			runtime.MakeBigRat(v.Disturbance),
			runtime.MakeSeq(cmItems...),
		),
	)
}

// SecurityAnalysis performs comprehensive security analysis against implementation attacks.
type SecurityAnalysis struct {
	Protocol            string
	Vulnerabilities     []ImplementationVulnerability
	WorstCaseInfoLeak   *big.Rat
	TotalDisturbance    *big.Rat
	RecommendedDefenses []Countermeasure
}

// AnalyzeSecurity performs security analysis for a protocol.
func AnalyzeSecurity(protocol string) *SecurityAnalysis {
	vulns := AnalyzeImplementationVulnerabilities(protocol)

	worstInfo := big.NewRat(0, 1)
	totalDist := big.NewRat(0, 1)
	defenseSet := make(map[string]Countermeasure)

	for _, v := range vulns {
		if v.InfoLeakage.Cmp(worstInfo) > 0 {
			worstInfo = v.InfoLeakage
		}
		totalDist = new(big.Rat).Add(totalDist, v.Disturbance)

		for _, cm := range v.Countermeasures {
			if _, exists := defenseSet[cm.Name]; !exists {
				defenseSet[cm.Name] = cm
			}
		}
	}

	// Cap total disturbance at 1
	one := big.NewRat(1, 1)
	if totalDist.Cmp(one) > 0 {
		totalDist = one
	}

	// Sort defenses by effectiveness
	var defenses []Countermeasure
	for _, cm := range defenseSet {
		defenses = append(defenses, cm)
	}

	return &SecurityAnalysis{
		Protocol:            protocol,
		Vulnerabilities:     vulns,
		WorstCaseInfoLeak:   worstInfo,
		TotalDisturbance:    totalDist,
		RecommendedDefenses: defenses,
	}
}

// ToValue converts a SecurityAnalysis to a runtime.Value.
func (a *SecurityAnalysis) ToValue() runtime.Value {
	vulnItems := make([]runtime.Value, len(a.Vulnerabilities))
	for i, v := range a.Vulnerabilities {
		vulnItems[i] = v.ToValue()
	}

	defenseItems := make([]runtime.Value, len(a.RecommendedDefenses))
	for i, d := range a.RecommendedDefenses {
		defenseItems[i] = d.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("security-analysis"),
		runtime.MakeSeq(
			runtime.MakeText(a.Protocol),
			runtime.MakeSeq(vulnItems...),
			runtime.MakeBigRat(a.WorstCaseInfoLeak),
			runtime.MakeBigRat(a.TotalDisturbance),
			runtime.MakeSeq(defenseItems...),
		),
	)
}
