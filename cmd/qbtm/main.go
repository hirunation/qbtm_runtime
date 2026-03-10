// QBTM: Quantum Block Type Morphisms
// A self-contained executor for typed quantum circuits over C*-algebra block structures.
//
// This is the standalone AGPL-licensed distribution of the QBTM runtime.
// It can load, execute, inspect, and synthesize .qmb (Quantum Model Binary) files.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"qbtm/runtime"
)

const version = "2.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "help", "--help", "-h":
		printUsage()
	case "version", "--version", "-v":
		printVersion()
	case "run":
		err = runQMB(args)
	case "inspect":
		err = inspectQMB(args)
	case "bootstrap":
		err = runBootstrap(args)
	case "synthesize":
		err = synthesizeGate(args)
	case "verify":
		err = verifyFixpoint(args)
	case "info":
		err = showInfo(args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`qbtm - Quantum Block Type Morphisms Runtime v%s

A self-contained executor for typed quantum circuits over C*-algebra block structures.
Circuits are morphisms in FdC*_CP (finite-dimensional C*-algebras, CP maps).

USAGE:
    qbtm <command> [options]

COMMANDS:
    run <file.qmb>              Execute a .qmb binary
    inspect <file.qmb>          Inspect structure and store contents
    bootstrap                   Demonstrate the self-reproducing fixpoint
    synthesize <gate>            Synthesize a gate circuit and emit .qmb
    verify <a.qmb> <b.qmb>     Verify two binaries are identical (fixpoint check)
    info                        Show runtime architecture information

GATES (for synthesize):
    identity, Hadamard, PauliX, PauliY, PauliZ, CNOT, SWAP,
    zero, discard, swap, prepare

OPTIONS:
    -o <file>       Output file for synthesize (default: stdout summary)
    --help, -h      Show this help message
    --version, -v   Show version information

EXAMPLES:
    qbtm bootstrap
    qbtm synthesize Hadamard -o hadamard.qmb
    qbtm run hadamard.qmb
    qbtm inspect examples/qbtm_generator_v3.qmb
    qbtm verify v2.qmb v3.qmb

LICENSE:
    AGPL-3.0 - See LICENSE file for details
`, version)
}

func printVersion() {
	fmt.Printf("qbtm version %s\n", version)
	fmt.Println("Quantum Block Type Morphisms Runtime")
	fmt.Println("Self-contained quantum circuit executor with synthesis")
	fmt.Println("License: AGPL-3.0")
}

// runQMB executes a .qmb binary and displays the result.
func runQMB(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: qbtm run <file.qmb>")
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	runner, err := runtime.NewRunner(data)
	if err != nil {
		return fmt.Errorf("load failed: %w", err)
	}

	ep := runner.Entrypoint()
	fmt.Printf("Loaded: %s v%s\n", runner.Name(), runner.Version())
	fmt.Printf("Entrypoint: %s\n", hex.EncodeToString(ep[:]))

	// Determine input dimension from entrypoint circuit
	dim := 1
	if c, ok := runner.GetCircuit(ep); ok {
		dim = runtime.BlockDim(c.Domain)
	}

	// Execute with identity input of the right dimension
	input := runtime.Identity(dim)
	result, err := runner.Run(input)
	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	fmt.Println()
	printMatrix("Output", result)

	return nil
}

// inspectQMB shows detailed structure of a .qmb file.
func inspectQMB(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: qbtm inspect <file.qmb>")
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	binary, err := runtime.Decode(data)
	if err != nil {
		return fmt.Errorf("decode failed: %w", err)
	}

	hash := sha256.Sum256(data)

	fmt.Printf("QMB Binary: %s\n", args[0])
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  Name:        %s\n", binary.Name)
	fmt.Printf("  Version:     %s\n", binary.Version)
	fmt.Printf("  Entrypoint:  %s\n", hex.EncodeToString(binary.Entrypoint[:]))
	fmt.Printf("  SHA-256:     %s\n", hex.EncodeToString(hash[:]))
	fmt.Printf("  Store:       %d bytes\n", len(binary.StoreData))
	fmt.Printf("  Total:       %d bytes\n", len(data))

	// Try to load the store and show contents
	runner, err := runtime.NewRunner(data)
	if err != nil {
		fmt.Printf("\n  (Store could not be fully parsed: %v)\n", err)
		return nil
	}

	fmt.Printf("  Entries:     %d\n", runner.StoreSize())

	// Try to get the entrypoint circuit
	c, ok := runner.GetCircuit(binary.Entrypoint)
	if ok {
		fmt.Println()
		fmt.Println("Entrypoint Circuit:")
		printCircuit("  ", c, runner)
	}

	return nil
}

// runBootstrap demonstrates the self-reproducing fixpoint property.
func runBootstrap(args []string) error {
	fmt.Println("QBTM Bootstrap: Self-Reproducing Fixpoint Demonstration")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	v1, v2, fixpoint, log := runtime.Bootstrap()

	for _, entry := range log {
		fmt.Println(entry)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("-", 60))

	v1Hash := sha256.Sum256(v1)
	v2Hash := sha256.Sum256(v2)

	fmt.Printf("v1.qmb:  %d bytes  SHA-256: %s\n", len(v1), hex.EncodeToString(v1Hash[:]))
	fmt.Printf("v2.qmb:  %d bytes  SHA-256: %s\n", len(v2), hex.EncodeToString(v2Hash[:]))
	fmt.Println()

	if fixpoint {
		fmt.Println("FIXPOINT VERIFIED")
		fmt.Println("  v2 and v3 are byte-identical.")
		fmt.Println("  The normalized toolchain reproduces itself exactly.")
		fmt.Println("  This proves the synthesis system is self-consistent.")
	} else {
		fmt.Println("FIXPOINT FAILED")
		fmt.Println("  v2 and v3 differ. The system is not self-consistent.")
		return fmt.Errorf("bootstrap fixpoint verification failed")
	}

	// Save files if -o flag provided
	for i, arg := range args {
		if arg == "-o" && i+1 < len(args) {
			dir := args[i+1]
			os.MkdirAll(dir, 0755)
			if err := os.WriteFile(dir+"/v1.qmb", v1, 0644); err != nil {
				return err
			}
			if err := os.WriteFile(dir+"/v2.qmb", v2, 0644); err != nil {
				return err
			}
			fmt.Printf("\nSaved to %s/v1.qmb and %s/v2.qmb\n", dir, dir)
		}
	}

	return nil
}

// synthesizeGate creates a circuit for a named gate and optionally writes a .qmb file.
func synthesizeGate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: qbtm synthesize <gate> [-o output.qmb]")
	}

	gateName := args[0]

	// Determine domain/codomain based on gate name
	spec := gateSpec(gateName)
	if spec == nil {
		rules := runtime.AllSynthesisRules()
		names := make([]string, len(rules))
		for i, r := range rules {
			names[i] = r.Name
		}
		return fmt.Errorf("unknown gate %q\nAvailable: %s", gateName, strings.Join(names, ", "))
	}

	store := runtime.NewStore()
	c, ok := runtime.Synthesize(store, *spec)
	if !ok {
		return fmt.Errorf("synthesis failed for %q", gateName)
	}

	id := store.Put(c)

	fmt.Printf("Synthesized: %s\n", gateName)
	fmt.Printf("  QGID: %s\n", hex.EncodeToString(id[:]))
	fmt.Printf("  Prim: %s\n", runtime.PrimName(c.Prim))
	fmt.Printf("  Domain: %s\n", formatObject(c.Domain))
	fmt.Printf("  Codomain: %s\n", formatObject(c.Codomain))

	// Execute to show what it does
	dim := runtime.BlockDim(c.Domain)
	input := runtime.Identity(dim)
	exec := runtime.NewExecutor(store)
	result, err := exec.Execute(c, input)
	if err == nil {
		fmt.Println()
		printMatrix("Channel applied to I", result)
	}

	// Write .qmb if -o specified
	for i, arg := range args {
		if arg == "-o" && i+1 < len(args) {
			outFile := args[i+1]
			binary := runtime.Embed(store, id, gateName, version)
			data := binary.Encode()
			if err := os.WriteFile(outFile, data, 0644); err != nil {
				return fmt.Errorf("write failed: %w", err)
			}
			hash := sha256.Sum256(data)
			fmt.Printf("\nWritten: %s (%d bytes, SHA-256: %s)\n",
				outFile, len(data), hex.EncodeToString(hash[:]))
		}
	}

	return nil
}

// verifyFixpoint checks whether two .qmb files are byte-identical.
func verifyFixpoint(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: qbtm verify <a.qmb> <b.qmb>")
	}

	dataA, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[0], err)
	}
	dataB, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[1], err)
	}

	hashA := sha256.Sum256(dataA)
	hashB := sha256.Sum256(dataB)

	fmt.Printf("%s: %d bytes  SHA-256: %s\n", args[0], len(dataA), hex.EncodeToString(hashA[:]))
	fmt.Printf("%s: %d bytes  SHA-256: %s\n", args[1], len(dataB), hex.EncodeToString(hashB[:]))
	fmt.Println()

	if hashA == hashB {
		fmt.Println("IDENTICAL - Fixpoint verified.")
		return nil
	}

	fmt.Println("DIFFERENT - Files do not match.")

	// Show metadata comparison
	binA, errA := runtime.Decode(dataA)
	binB, errB := runtime.Decode(dataB)
	if errA == nil && errB == nil {
		if binA.Name != binB.Name {
			fmt.Printf("  Name: %q vs %q\n", binA.Name, binB.Name)
		}
		if binA.Version != binB.Version {
			fmt.Printf("  Version: %q vs %q\n", binA.Version, binB.Version)
		}
		if len(binA.StoreData) != len(binB.StoreData) {
			fmt.Printf("  Store: %d bytes vs %d bytes\n", len(binA.StoreData), len(binB.StoreData))
		}
	}

	return nil
}

func showInfo(args []string) error {
	fmt.Printf("QBTM Runtime v%s\n", version)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	fmt.Println("Architecture:")
	fmt.Println("  Self-contained runtime with zero external dependencies.")
	fmt.Println("  Exact rational arithmetic over Gaussian rationals Q(i).")
	fmt.Println("  Content-addressed storage via QGID (SHA-256).")
	fmt.Println("  Typed quantum circuits as morphisms in FdC*_CP.")
	fmt.Println()
	fmt.Println("Supported Primitives (23):")
	fmt.Println("  Structural:   Id, Compose, Tensor, Swap")
	fmt.Println("  Biproduct:    Bisum, Inject, Project")
	fmt.Println("  Classical:    Copy, Delete, Encode, Decode")
	fmt.Println("  Quantum:      Unitary, Choi, Kraus, Prepare, Discard, Trace")
	fmt.Println("  Arithmetic:   Add, Scale, Zero")
	fmt.Println("  Verification: Assert, Witness")
	fmt.Println("  Measurement:  Instrument, Branch")
	fmt.Println()
	fmt.Println("Type System:")
	fmt.Println("  Objects are C*-algebras: ⊕_i M_{n_i}(C)")
	fmt.Println("  Q(n) = single block M_n(C)  (n-dimensional quantum)")
	fmt.Println("  C(k) = k copies of C        (k-level classical)")
	fmt.Println("  I    = unit object           (trivial)")
	fmt.Println()
	fmt.Println("Synthesis Rules (12):")
	for _, r := range runtime.AllSynthesisRules() {
		fmt.Printf("  %s\n", r.Name)
	}
	fmt.Println()
	fmt.Println("Rewrite Rules (4):")
	for _, r := range runtime.AllRewriteRules() {
		fmt.Printf("  %s\n", r.Name)
	}
	fmt.Println()
	fmt.Println("File Format:")
	fmt.Println("  .qmb = Quantum Model Binary")
	fmt.Println("  Magic: QMB\\x01 (4 bytes)")
	fmt.Println("  Layout: magic | entrypoint QGID | name | version | store")

	return nil
}

// --- Helpers ---

func printMatrix(label string, m *runtime.Matrix) {
	tr := runtime.Trace(m)
	fmt.Printf("%s: %dx%d matrix\n", label, m.Rows, m.Cols)

	if m.Rows <= 8 && m.Cols <= 8 {
		for i := 0; i < m.Rows; i++ {
			fmt.Print("  [")
			for j := 0; j < m.Cols; j++ {
				if j > 0 {
					fmt.Print("  ")
				}
				fmt.Print(formatQI(m.Get(i, j)))
			}
			fmt.Println("]")
		}
	}
	fmt.Printf("  Trace: %s\n", formatQI(tr))
}

func formatQI(q runtime.QI) string {
	re := q.Re.RatString()
	im := q.Im.RatString()

	if q.Im.Sign() == 0 {
		return re
	}
	if q.Re.Sign() == 0 {
		if im == "1" {
			return "i"
		}
		if im == "-1" {
			return "-i"
		}
		return im + "i"
	}
	if q.Im.Sign() > 0 {
		return re + "+" + im + "i"
	}
	return re + im + "i"
}

func formatObject(obj runtime.Object) string {
	if len(obj.Blocks) == 0 {
		return "I"
	}
	parts := make([]string, len(obj.Blocks))
	for i, b := range obj.Blocks {
		if b == 1 {
			parts[i] = "C(1)"
		} else {
			parts[i] = fmt.Sprintf("Q(%d)", b)
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts, " + ")
}

func printCircuit(indent string, c runtime.Circuit, runner *runtime.Runner) {
	fmt.Printf("%sPrim: %s\n", indent, runtime.PrimName(c.Prim))
	fmt.Printf("%sDomain: %s\n", indent, formatObject(c.Domain))
	fmt.Printf("%sCodomain: %s\n", indent, formatObject(c.Codomain))

	if len(c.Children) > 0 {
		fmt.Printf("%sChildren: %d\n", indent, len(c.Children))
		for i, childID := range c.Children {
			child, ok := runner.GetCircuit(childID)
			if ok {
				fmt.Printf("%s  [%d] %s (%s -> %s)\n", indent, i,
					runtime.PrimName(child.Prim),
					formatObject(child.Domain),
					formatObject(child.Codomain))
			} else {
				fmt.Printf("%s  [%d] %s\n", indent, i, hex.EncodeToString(childID[:8]))
			}
		}
	}
}

func gateSpec(name string) *runtime.SynthesisSpec {
	qubit := runtime.Object{Blocks: []uint32{2}}
	twoQubit := runtime.Object{Blocks: []uint32{2, 2}}
	unit := runtime.Object{}

	switch name {
	case "identity":
		return &runtime.SynthesisSpec{Name: "identity", Domain: qubit, Codomain: qubit}
	case "Hadamard":
		return &runtime.SynthesisSpec{Name: "Hadamard", Domain: qubit, Codomain: qubit}
	case "PauliX":
		return &runtime.SynthesisSpec{Name: "PauliX", Domain: qubit, Codomain: qubit}
	case "PauliY":
		return &runtime.SynthesisSpec{Name: "PauliY", Domain: qubit, Codomain: qubit}
	case "PauliZ":
		return &runtime.SynthesisSpec{Name: "PauliZ", Domain: qubit, Codomain: qubit}
	case "CNOT":
		return &runtime.SynthesisSpec{Name: "CNOT", Domain: twoQubit, Codomain: twoQubit}
	case "SWAP":
		return &runtime.SynthesisSpec{Name: "SWAP", Domain: twoQubit, Codomain: twoQubit}
	case "zero":
		return &runtime.SynthesisSpec{Name: "zero", Domain: qubit, Codomain: qubit}
	case "discard":
		return &runtime.SynthesisSpec{Name: "discard", Domain: qubit, Codomain: unit}
	case "swap":
		return &runtime.SynthesisSpec{Name: "swap", Domain: twoQubit, Codomain: twoQubit}
	case "prepare":
		return &runtime.SynthesisSpec{Name: "prepare", Domain: unit, Codomain: qubit}
	default:
		return nil
	}
}

