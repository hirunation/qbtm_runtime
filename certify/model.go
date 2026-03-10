// model.go constructs certifiable models from protocol specifications.
//
// This file provides the model construction pipeline that transforms
// protocol specifications into verifiable quantum models with exact
// rational representations.
package certify

import (
	"fmt"
	"math/big"

	"qbtm/certify/analysis"
	"qbtm/certify/certificate"
	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// Model represents a certifiable quantum protocol model.
type Model struct {
	Protocol *protocol.Protocol

	// Internal representation for analysis
	choiMatrix   *runtime.Matrix
	idealChannel *runtime.Matrix
	synthesizer  protocol.ProtocolSynthesizer
	circuitQGID  [32]byte
	store        *runtime.Store

	// Analysis results
	CorrectnessResult *analysis.CorrectnessResult
	SecurityResult    *analysis.SecurityResult
	NoiseResult       *analysis.NoiseToleranceResult

	// Certificate
	Certificate *certificate.FullAnalysisBundle
}

// NewModel creates a new certifiable model from a protocol specification.
func NewModel(p *protocol.Protocol) *Model {
	return &Model{
		Protocol: p,
		store:    runtime.NewStore(),
	}
}

// NewModelFromSynthesizer creates a model from a protocol synthesizer.
func NewModelFromSynthesizer(synth protocol.ProtocolSynthesizer) *Model {
	if synth == nil {
		return nil
	}
	return &Model{
		Protocol:    synth.Protocol(),
		synthesizer: synth,
		store:       runtime.NewStore(),
	}
}

// BuildModel constructs a complete certifiable model from a protocol name.
// This is the main entry point for model construction.
//
// The function performs the following steps:
// 1. Looks up the protocol specification by name
// 2. Creates a synthesizer for the protocol
// 3. Synthesizes the quantum circuit
// 4. Computes the Choi matrix representation
// 5. Computes the ideal channel for correctness verification
// 6. Optionally runs security and noise analysis
//
// Options can specify:
// - ErrorRate: assumed quantum bit error rate
// - AdversaryModel: "individual", "collective", or "coherent"
// - IncludeAnalysis: whether to run full analysis
func BuildModel(protocolName string, options *BuildOptions) (*Model, error) {
	if options == nil {
		options = DefaultBuildOptions()
	}

	// Get protocol synthesizer
	synth, err := certificate.GetProtocol(protocolName)
	if err != nil {
		return nil, fmt.Errorf("failed to get protocol %s: %w", protocolName, err)
	}

	model := &Model{
		Protocol:    synth.Protocol(),
		synthesizer: synth,
		store:       runtime.NewStore(),
	}

	// Synthesize the circuit
	if options.SynthesizeCircuit {
		qgid, synthErr := synth.Synthesize(model.store)
		if synthErr != nil {
			return nil, fmt.Errorf("failed to synthesize circuit: %w", synthErr)
		}
		model.circuitQGID = qgid

		// Compute Choi matrix
		if options.ComputeChoi {
			choi, choiErr := analysis.ComputeChannel(qgid, model.store)
			if choiErr != nil {
				// Non-fatal: we can still build the model
				model.choiMatrix = nil
			} else {
				model.choiMatrix = choi
			}
		}
	}

	// Compute ideal channel for correctness verification
	if options.ComputeIdeal && model.Protocol != nil && model.Protocol.Goal != nil {
		idealChoi, idealErr := analysis.ComputeIdealChannel(model.Protocol.Goal)
		if idealErr == nil {
			model.idealChannel = idealChoi
		}
	}

	// Run correctness verification
	if options.VerifyCorrectness && model.Protocol != nil {
		result, verifyErr := analysis.VerifyCorrectness(model.Protocol, model.store)
		if verifyErr == nil {
			model.CorrectnessResult = result
		}
	}

	// Run security analysis
	if options.AnalyzeSecurity && model.Protocol != nil {
		secResult, secErr := analysis.ComputeSecurityBounds(model.Protocol, options.AdversaryModel)
		if secErr == nil {
			model.SecurityResult = secResult
		}
	}

	// Run noise tolerance analysis
	if options.AnalyzeNoise && model.Protocol != nil && options.NoiseModel != nil {
		noiseResult, noiseErr := analysis.AnalyzeNoiseTolerance(model.Protocol, options.NoiseModel)
		if noiseErr == nil {
			model.NoiseResult = &analysis.NoiseToleranceResult{
				Protocol:  model.Protocol.Name,
				ErrorRate: options.ErrorRate,
				Threshold: analysis.GetSecurityThreshold(model.Protocol.Name),
				IsSecure:  noiseResult.Tolerant,
				Margin:    new(big.Rat).Sub(noiseResult.MaxNoise, options.ErrorRate),
			}
		}
	}

	// Generate full certificate bundle if requested
	if options.GenerateCertificate {
		analysisOpts := &certificate.AnalysisOptions{
			ErrorRate:       options.ErrorRate,
			AdversaryModels: []string{options.AdversaryModel},
			NoiseModels:     options.NoiseModels,
			IncludeAttacks:  options.IncludeAttacks,
			IncludeCircuit:  options.SynthesizeCircuit,
			Verbose:         options.Verbose,
		}
		bundle, bundleErr := certificate.GenerateFullAnalysis(protocolName, analysisOpts)
		if bundleErr == nil {
			model.Certificate = bundle
		}
	}

	return model, nil
}

// BuildOptions configures model building.
type BuildOptions struct {
	// Circuit synthesis
	SynthesizeCircuit bool // Whether to synthesize the quantum circuit

	// Choi matrix computation
	ComputeChoi  bool // Whether to compute the Choi matrix
	ComputeIdeal bool // Whether to compute the ideal channel

	// Analysis options
	VerifyCorrectness bool     // Whether to verify correctness
	AnalyzeSecurity   bool     // Whether to analyze security
	AnalyzeNoise      bool     // Whether to analyze noise tolerance
	IncludeAttacks    bool     // Whether to include attack analysis
	Verbose           bool     // Whether to include detailed derivations

	// Parameters
	ErrorRate      *big.Rat            // Assumed QBER
	AdversaryModel string              // "individual", "collective", "coherent"
	NoiseModel     *analysis.NoiseModel // Noise model for tolerance analysis
	NoiseModels    []string            // List of noise models to analyze

	// Certificate generation
	GenerateCertificate bool // Whether to generate full certificate bundle
}

// DefaultBuildOptions returns the default build options.
func DefaultBuildOptions() *BuildOptions {
	return &BuildOptions{
		SynthesizeCircuit:   true,
		ComputeChoi:         true,
		ComputeIdeal:        true,
		VerifyCorrectness:   true,
		AnalyzeSecurity:     false,
		AnalyzeNoise:        false,
		IncludeAttacks:      false,
		Verbose:             false,
		ErrorRate:           big.NewRat(0, 1),
		AdversaryModel:      "coherent",
		NoiseModel:          nil,
		NoiseModels:         []string{"depolarizing"},
		GenerateCertificate: false,
	}
}

// FullBuildOptions returns options for comprehensive model building.
func FullBuildOptions(errorRate *big.Rat) *BuildOptions {
	return &BuildOptions{
		SynthesizeCircuit:   true,
		ComputeChoi:         true,
		ComputeIdeal:        true,
		VerifyCorrectness:   true,
		AnalyzeSecurity:     true,
		AnalyzeNoise:        true,
		IncludeAttacks:      true,
		Verbose:             true,
		ErrorRate:           errorRate,
		AdversaryModel:      "coherent",
		NoiseModel:          analysis.Depolarizing(new(big.Rat).Mul(errorRate, big.NewRat(3, 2))),
		NoiseModels:         []string{"depolarizing", "amplitude_damping", "phase_damping"},
		GenerateCertificate: true,
	}
}

// QuickBuildOptions returns minimal options for fast model building.
func QuickBuildOptions() *BuildOptions {
	return &BuildOptions{
		SynthesizeCircuit:   true,
		ComputeChoi:         false,
		ComputeIdeal:        false,
		VerifyCorrectness:   false,
		AnalyzeSecurity:     false,
		AnalyzeNoise:        false,
		IncludeAttacks:      false,
		Verbose:             false,
		ErrorRate:           big.NewRat(0, 1),
		AdversaryModel:      "coherent",
		NoiseModel:          nil,
		NoiseModels:         nil,
		GenerateCertificate: false,
	}
}

// GetChoiMatrix returns the Choi matrix representation of the model.
func (m *Model) GetChoiMatrix() *runtime.Matrix {
	return m.choiMatrix
}

// GetIdealChannel returns the ideal channel Choi matrix.
func (m *Model) GetIdealChannel() *runtime.Matrix {
	return m.idealChannel
}

// GetCircuitQGID returns the QGID of the synthesized circuit.
func (m *Model) GetCircuitQGID() [32]byte {
	return m.circuitQGID
}

// GetStore returns the runtime store containing the synthesized circuit.
func (m *Model) GetStore() *runtime.Store {
	return m.store
}

// IsCorrect returns true if the model has been verified correct.
func (m *Model) IsCorrect() bool {
	if m.CorrectnessResult == nil {
		return false
	}
	return m.CorrectnessResult.Correct
}

// IsSecure returns true if the model has been verified secure.
func (m *Model) IsSecure() bool {
	if m.SecurityResult == nil {
		return false
	}
	return m.SecurityResult.IsSecure
}

// GetKeyRate returns the computed key rate, if available.
func (m *Model) GetKeyRate() *analysis.Entropy {
	if m.SecurityResult == nil {
		return nil
	}
	return m.SecurityResult.KeyRate
}

// GetSecurityThreshold returns the security threshold for this protocol.
func (m *Model) GetSecurityThreshold() *big.Rat {
	if m.Protocol == nil {
		return nil
	}
	return analysis.GetSecurityThreshold(m.Protocol.Name)
}

// ToValue converts the model to a runtime.Value for serialization.
func (m *Model) ToValue() runtime.Value {
	if m.Protocol == nil {
		return runtime.MakeNil()
	}

	// Build model value with all components
	var choiVal, idealVal runtime.Value = runtime.MakeNil(), runtime.MakeNil()
	if m.choiMatrix != nil {
		choiVal = runtime.MatrixToValue(m.choiMatrix)
	}
	if m.idealChannel != nil {
		idealVal = runtime.MatrixToValue(m.idealChannel)
	}

	var correctnessVal, securityVal, noiseVal runtime.Value = runtime.MakeNil(), runtime.MakeNil(), runtime.MakeNil()
	if m.CorrectnessResult != nil {
		correctnessVal = m.CorrectnessResult.ToValue()
	}
	if m.SecurityResult != nil {
		securityVal = m.SecurityResult.ToValue()
	}
	if m.NoiseResult != nil {
		noiseVal = m.NoiseResult.ToValue()
	}

	var certVal runtime.Value = runtime.MakeNil()
	if m.Certificate != nil {
		certVal = m.Certificate.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("certify-model"),
		runtime.MakeSeq(
			m.Protocol.ToValue(),
			runtime.MakeBytes(m.circuitQGID[:]),
			choiVal,
			idealVal,
			correctnessVal,
			securityVal,
			noiseVal,
			certVal,
		),
	)
}

// ModelFromValue deserializes a Model from a runtime.Value.
func ModelFromValue(v runtime.Value) (*Model, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "certify-model" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 8 {
		return nil, false
	}

	model := &Model{
		store: runtime.NewStore(),
	}

	// Parse protocol
	proto, ok := protocol.ProtocolFromValue(seq.Items[0])
	if !ok {
		return nil, false
	}
	model.Protocol = proto

	// Parse circuit QGID
	qgidBytes, ok := seq.Items[1].(runtime.Bytes)
	if ok && len(qgidBytes.V) == 32 {
		copy(model.circuitQGID[:], qgidBytes.V)
	}

	// Parse Choi matrix
	if _, isNil := seq.Items[2].(runtime.Nil); !isNil {
		model.choiMatrix, _ = runtime.MatrixFromValue(seq.Items[2])
	}

	// Parse ideal channel
	if _, isNil := seq.Items[3].(runtime.Nil); !isNil {
		model.idealChannel, _ = runtime.MatrixFromValue(seq.Items[3])
	}

	// Parse correctness result
	if _, isNil := seq.Items[4].(runtime.Nil); !isNil {
		model.CorrectnessResult, _ = analysis.CorrectnessResultFromValue(seq.Items[4])
	}

	// Parse security result
	if _, isNil := seq.Items[5].(runtime.Nil); !isNil {
		model.SecurityResult, _ = analysis.SecurityResultFromValue(seq.Items[5])
	}

	// Parse noise result
	if _, isNil := seq.Items[6].(runtime.Nil); !isNil {
		model.NoiseResult, _ = analysis.NoiseToleranceResultFromValue(seq.Items[6])
	}

	// Parse certificate
	if _, isNil := seq.Items[7].(runtime.Nil); !isNil {
		model.Certificate, _ = certificate.FullAnalysisBundleFromValue(seq.Items[7])
	}

	return model, true
}

// BuildAllModels builds models for all registered protocols.
func BuildAllModels(options *BuildOptions) (map[string]*Model, error) {
	if options == nil {
		options = DefaultBuildOptions()
	}

	models := make(map[string]*Model)
	for _, name := range certificate.RegisteredProtocols() {
		model, err := BuildModel(name, options)
		if err != nil {
			// Continue with other protocols
			continue
		}
		models[name] = model
	}

	return models, nil
}

// VerifyModel performs verification on an existing model.
func VerifyModel(m *Model) error {
	if m == nil || m.Protocol == nil {
		return fmt.Errorf("nil model or protocol")
	}

	// Verify correctness
	result, err := analysis.VerifyCorrectness(m.Protocol, m.store)
	if err != nil {
		return fmt.Errorf("correctness verification failed: %w", err)
	}
	m.CorrectnessResult = result

	return nil
}

// AnalyzeModelSecurity performs security analysis on an existing model.
func AnalyzeModelSecurity(m *Model, errorRate *big.Rat, adversaryModel string) error {
	if m == nil || m.Protocol == nil {
		return fmt.Errorf("nil model or protocol")
	}

	secResult, err := analysis.ComputeSecurityBounds(m.Protocol, adversaryModel)
	if err != nil {
		return fmt.Errorf("security analysis failed: %w", err)
	}
	m.SecurityResult = secResult

	return nil
}

// GetProtocol is re-exported from certificate package for convenience.
var GetProtocol = certificate.GetProtocol

// RegisteredProtocols is re-exported from certificate package for convenience.
var RegisteredProtocols = certificate.RegisteredProtocols

// ProtocolInfo is re-exported from certificate package for convenience.
var ProtocolInfo = certificate.ProtocolInfo

// CertifyModel represents the complete certify model for embedding.
// This bundles all protocols and their synthesized circuits into a single
// embeddable binary format for distribution.
type CertifyModel struct {
	Name      string
	Version   string
	Protocols []string
	Store     *runtime.Store
}

// ToValue converts the CertifyModel to a runtime.Value for serialization.
func (m *CertifyModel) ToValue() runtime.Value {
	protos := make([]runtime.Value, len(m.Protocols))
	for i, p := range m.Protocols {
		protos[i] = runtime.MakeText(p)
	}

	return runtime.MakeTag(
		runtime.MakeText("certify-model"),
		runtime.MakeSeq(
			runtime.MakeText(m.Name),
			runtime.MakeText(m.Version),
			runtime.MakeSeq(protos...),
		),
	)
}

// CertifyModelFromValue deserializes a CertifyModel from a runtime.Value.
func CertifyModelFromValue(v runtime.Value) (*CertifyModel, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "certify-model" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
		return nil, false
	}

	name, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	version, ok := seq.Items[1].(runtime.Text)
	if !ok {
		return nil, false
	}
	protoSeq, ok := seq.Items[2].(runtime.Seq)
	if !ok {
		return nil, false
	}

	protocols := make([]string, len(protoSeq.Items))
	for i, item := range protoSeq.Items {
		text, ok := item.(runtime.Text)
		if !ok {
			return nil, false
		}
		protocols[i] = text.V
	}

	return &CertifyModel{
		Name:      name.V,
		Version:   version.V,
		Protocols: protocols,
		Store:     runtime.NewStore(),
	}, true
}
