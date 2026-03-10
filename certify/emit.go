// emit.go provides .qmb file emission for certified protocols.
//
// This file implements serialization of certified protocol models
// to the .qmb binary format with embedded certificates.
package certify

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"qbtm/certify/certificate"
	"qbtm/runtime"
)

// OutputFormat specifies the output format for emission.
type OutputFormat int

const (
	FormatText OutputFormat = iota
	FormatJSON
	FormatQMB
	FormatValue
)

// ParseOutputFormat parses a format string.
func ParseOutputFormat(s string) (OutputFormat, bool) {
	switch strings.ToLower(s) {
	case "text", "txt":
		return FormatText, true
	case "json":
		return FormatJSON, true
	case "qmb", "binary":
		return FormatQMB, true
	case "value", "val":
		return FormatValue, true
	default:
		return FormatText, false
	}
}

// Emitter handles .qmb file generation.
type Emitter struct {
	model      *Model
	outputPath string
	format     OutputFormat
}

// NewEmitter creates a new .qmb emitter.
func NewEmitter(model *Model, outputPath string) *Emitter {
	return &Emitter{
		model:      model,
		outputPath: outputPath,
		format:     FormatQMB,
	}
}

// NewEmitterWithFormat creates an emitter with specified format.
func NewEmitterWithFormat(model *Model, outputPath string, format OutputFormat) *Emitter {
	return &Emitter{
		model:      model,
		outputPath: outputPath,
		format:     format,
	}
}

// SetFormat sets the output format.
func (e *Emitter) SetFormat(format OutputFormat) {
	e.format = format
}

// Emit writes the certified model to a .qmb file.
func (e *Emitter) Emit() error {
	if e.model == nil {
		return fmt.Errorf("nil model")
	}

	value := e.model.ToValue()
	return e.emitValue(value)
}

// EmitWithCertificate writes the model with its certificate bundle.
func (e *Emitter) EmitWithCertificate(certValue runtime.Value) error {
	if e.model == nil {
		return fmt.Errorf("nil model")
	}

	bundle := runtime.MakeTag(
		runtime.MakeText("certified-protocol"),
		runtime.MakeSeq(
			e.model.ToValue(),
			certValue,
		),
	)

	return e.emitValue(bundle)
}

// emitValue writes a value in the configured format.
func (e *Emitter) emitValue(value runtime.Value) error {
	switch e.format {
	case FormatText:
		return e.emitText(value)
	case FormatJSON:
		return e.emitJSON(value)
	case FormatQMB:
		return e.emitQMB(value)
	case FormatValue:
		return e.emitQMB(value) // Same as QMB
	default:
		return e.emitText(value)
	}
}

// emitText writes a human-readable text representation.
func (e *Emitter) emitText(value runtime.Value) error {
	var writer io.Writer = os.Stdout
	if e.outputPath != "" && e.outputPath != "-" {
		f, err := os.Create(e.outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		writer = f
	}

	text := formatValueAsText(value, 0)
	_, err := writer.Write([]byte(text))
	return err
}

// emitJSON writes a JSON representation.
func (e *Emitter) emitJSON(value runtime.Value) error {
	var writer io.Writer = os.Stdout
	if e.outputPath != "" && e.outputPath != "-" {
		f, err := os.Create(e.outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		writer = f
	}

	// Convert to JSON-friendly structure
	jsonVal := valueToJSON(value)
	data, err := json.MarshalIndent(jsonVal, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	_, err = writer.Write(data)
	if err != nil {
		return err
	}
	_, err = writer.Write([]byte("\n"))
	return err
}

// emitQMB writes the binary .qmb format.
func (e *Emitter) emitQMB(value runtime.Value) error {
	encoded := value.Encode()

	if e.outputPath == "" || e.outputPath == "-" {
		_, err := os.Stdout.Write(encoded)
		return err
	}

	return os.WriteFile(e.outputPath, encoded, 0644)
}

// formatValueAsText converts a value to human-readable text.
func formatValueAsText(value runtime.Value, indent int) string {
	prefix := strings.Repeat("  ", indent)

	switch v := value.(type) {
	case runtime.Nil:
		return prefix + "nil\n"
	case runtime.Bool:
		return prefix + fmt.Sprintf("%v\n", v.V)
	case runtime.Int:
		return prefix + fmt.Sprintf("%s\n", v.V.String())
	case runtime.Rat:
		return prefix + fmt.Sprintf("%s\n", v.V.RatString())
	case runtime.Text:
		return prefix + fmt.Sprintf("%q\n", v.V)
	case runtime.Bytes:
		return prefix + fmt.Sprintf("%x\n", v.V)
	case runtime.Seq:
		var sb strings.Builder
		sb.WriteString(prefix + "[\n")
		for _, item := range v.Items {
			sb.WriteString(formatValueAsText(item, indent+1))
		}
		sb.WriteString(prefix + "]\n")
		return sb.String()
	case runtime.Tag:
		var sb strings.Builder
		labelText := formatValueAsText(v.Label, 0)
		sb.WriteString(prefix + "(" + strings.TrimSpace(labelText) + ":\n")
		sb.WriteString(formatValueAsText(v.Payload, indent+1))
		sb.WriteString(prefix + ")\n")
		return sb.String()
	default:
		return prefix + fmt.Sprintf("%v\n", value)
	}
}

// valueToJSON converts a runtime.Value to a JSON-friendly structure.
func valueToJSON(value runtime.Value) interface{} {
	switch v := value.(type) {
	case runtime.Nil:
		return nil
	case runtime.Bool:
		return v.V
	case runtime.Int:
		return v.V.String()
	case runtime.Rat:
		return v.V.RatString()
	case runtime.Text:
		return v.V
	case runtime.Bytes:
		return fmt.Sprintf("%x", v.V)
	case runtime.Seq:
		items := make([]interface{}, len(v.Items))
		for i, item := range v.Items {
			items[i] = valueToJSON(item)
		}
		return items
	case runtime.Tag:
		return map[string]interface{}{
			"tag":     valueToJSON(v.Label),
			"payload": valueToJSON(v.Payload),
		}
	default:
		return fmt.Sprintf("%v", value)
	}
}

// EmitModel is the main entry point for emitting a certified model.
// It builds the model, runs verification if requested, and emits the result.
func EmitModel(protocolName string, outputPath string, options *EmitOptions) error {
	if options == nil {
		options = DefaultEmitOptions()
	}

	// Build the model
	buildOpts := &BuildOptions{
		SynthesizeCircuit:   true,
		ComputeChoi:         options.ComputeChoi,
		ComputeIdeal:        options.ComputeChoi,
		VerifyCorrectness:   options.SelfVerify,
		AnalyzeSecurity:     options.IncludeSecurity,
		AnalyzeNoise:        options.IncludeNoise,
		IncludeAttacks:      options.IncludeAttacks,
		Verbose:             options.Verbose,
		ErrorRate:           options.ErrorRate,
		AdversaryModel:      options.AdversaryModel,
		NoiseModels:         options.NoiseModels,
		GenerateCertificate: options.IncludeCertificate,
	}

	model, err := BuildModel(protocolName, buildOpts)
	if err != nil {
		return fmt.Errorf("failed to build model: %w", err)
	}

	// Self-verify if requested
	if options.SelfVerify {
		if model.CorrectnessResult != nil && !model.CorrectnessResult.Correct {
			if options.StrictVerify {
				return fmt.Errorf("correctness verification failed: %s", model.CorrectnessResult.ErrorMessage)
			}
			fmt.Fprintf(os.Stderr, "Warning: correctness verification failed: %s\n", model.CorrectnessResult.ErrorMessage)
		}
	}

	// Create emitter
	emitter := NewEmitterWithFormat(model, outputPath, options.Format)

	// Emit with or without certificate
	if options.IncludeCertificate && model.Certificate != nil {
		return emitter.EmitWithCertificate(model.Certificate.ToValue())
	}

	return emitter.Emit()
}

// EmitOptions configures model emission.
type EmitOptions struct {
	Format             OutputFormat
	ComputeChoi        bool
	SelfVerify         bool
	StrictVerify       bool
	IncludeCertificate bool
	IncludeSecurity    bool
	IncludeNoise       bool
	IncludeAttacks     bool
	Verbose            bool
	ErrorRate          *big.Rat
	AdversaryModel     string
	NoiseModels        []string
}

// DefaultEmitOptions returns default emission options.
func DefaultEmitOptions() *EmitOptions {
	return &EmitOptions{
		Format:             FormatQMB,
		ComputeChoi:        true,
		SelfVerify:         true,
		StrictVerify:       false,
		IncludeCertificate: true,
		IncludeSecurity:    false,
		IncludeNoise:       false,
		IncludeAttacks:     false,
		Verbose:            false,
		ErrorRate:          nil,
		AdversaryModel:     "coherent",
		NoiseModels:        []string{"depolarizing"},
	}
}

// FullEmitOptions returns options for comprehensive emission.
func FullEmitOptions() *EmitOptions {
	return &EmitOptions{
		Format:             FormatQMB,
		ComputeChoi:        true,
		SelfVerify:         true,
		StrictVerify:       true,
		IncludeCertificate: true,
		IncludeSecurity:    true,
		IncludeNoise:       true,
		IncludeAttacks:     true,
		Verbose:            true,
		ErrorRate:          nil,
		AdversaryModel:     "coherent",
		NoiseModels:        []string{"depolarizing", "amplitude_damping", "phase_damping"},
	}
}

// EmitBundle emits a full analysis bundle.
func EmitBundle(bundle *certificate.FullAnalysisBundle, outputPath string, format OutputFormat) error {
	if bundle == nil {
		return fmt.Errorf("nil bundle")
	}

	value := bundle.ToValue()

	switch format {
	case FormatText:
		summary := bundle.GenerateSummary()
		if outputPath == "" || outputPath == "-" {
			fmt.Print(summary)
			return nil
		}
		return os.WriteFile(outputPath, []byte(summary), 0644)

	case FormatJSON:
		jsonVal := valueToJSON(value)
		data, err := json.MarshalIndent(jsonVal, "", "  ")
		if err != nil {
			return err
		}
		if outputPath == "" || outputPath == "-" {
			fmt.Println(string(data))
			return nil
		}
		return os.WriteFile(outputPath, data, 0644)

	case FormatQMB, FormatValue:
		encoded := value.Encode()
		if outputPath == "" || outputPath == "-" {
			_, err := os.Stdout.Write(encoded)
			return err
		}
		return os.WriteFile(outputPath, encoded, 0644)

	default:
		return fmt.Errorf("unsupported format")
	}
}

// EmitCommandResult emits a command result in the specified format.
func EmitCommandResult(result *CommandResult, outputPath string, format OutputFormat) error {
	if result == nil {
		return fmt.Errorf("nil result")
	}

	switch format {
	case FormatText:
		if outputPath == "" || outputPath == "-" {
			fmt.Print(result.Message)
			return nil
		}
		return os.WriteFile(outputPath, []byte(result.Message), 0644)

	case FormatJSON:
		jsonData := map[string]interface{}{
			"success": result.Success,
			"message": result.Message,
		}
		if result.Data != nil {
			jsonData["data"] = result.Data
		}
		data, err := json.MarshalIndent(jsonData, "", "  ")
		if err != nil {
			return err
		}
		if outputPath == "" || outputPath == "-" {
			fmt.Println(string(data))
			return nil
		}
		return os.WriteFile(outputPath, data, 0644)

	case FormatQMB, FormatValue:
		if result.Value == nil {
			result.Value = runtime.MakeNil()
		}
		encoded := result.Value.Encode()
		if outputPath == "" || outputPath == "-" {
			_, err := os.Stdout.Write(encoded)
			return err
		}
		return os.WriteFile(outputPath, encoded, 0644)

	default:
		return fmt.Errorf("unsupported format")
	}
}

// LoadModel loads a model from a .qmb file.
// Note: This requires the file to be an embedded binary format.
// For raw value files, use LoadModelFromJSON.
func LoadModel(inputPath string) (*Model, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to decode as embedded binary
	binary, err := runtime.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode binary: %w", err)
	}

	// Create a runner to get access to the store
	runner, err := runtime.NewRunner(data)
	if err != nil {
		return nil, fmt.Errorf("failed to create runner: %w", err)
	}

	// Get the entrypoint value
	value, ok := runner.GetValue(binary.Entrypoint)
	if !ok {
		return nil, fmt.Errorf("entrypoint value not found")
	}

	model, ok := ModelFromValue(value)
	if !ok {
		return nil, fmt.Errorf("failed to parse model from value")
	}

	return model, nil
}

// LoadBundle loads a certificate bundle from a .qmb file.
// Note: This requires the file to be an embedded binary format.
func LoadBundle(inputPath string) (*certificate.FullAnalysisBundle, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to decode as embedded binary
	binary, err := runtime.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode binary: %w", err)
	}

	// Create a runner to get access to the store
	runner, err := runtime.NewRunner(data)
	if err != nil {
		return nil, fmt.Errorf("failed to create runner: %w", err)
	}

	// Get the entrypoint value
	value, ok := runner.GetValue(binary.Entrypoint)
	if !ok {
		return nil, fmt.Errorf("entrypoint value not found")
	}

	bundle, ok := certificate.FullAnalysisBundleFromValue(value)
	if !ok {
		return nil, fmt.Errorf("failed to parse bundle from value")
	}

	return bundle, nil
}

// VerifyLoadedBundle verifies a loaded bundle.
func VerifyLoadedBundle(bundle *certificate.FullAnalysisBundle) (bool, string) {
	if bundle == nil {
		return false, "nil bundle"
	}

	if bundle.Bundle == nil {
		return false, "no certificate bundle"
	}

	allVerified := bundle.Bundle.VerifyAll()
	if allVerified {
		return true, "all evidence verified"
	}

	// Find which evidence failed
	var failed []string
	for i, ev := range bundle.Bundle.Evidence {
		if !ev.Verify() {
			failed = append(failed, fmt.Sprintf("evidence[%d]", i))
		}
	}

	return false, fmt.Sprintf("verification failed for: %v", failed)
}
