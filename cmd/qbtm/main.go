// QBTM: Quantum Block Type Morphisms
// A self-contained executor for typed quantum circuits over C*-algebra block structures.
//
// This is the standalone AGPL-licensed distribution of the QBTM runtime.
// It can load and execute .qmb (Quantum Model Binary) files.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"qbtm/runtime"
)

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
	fmt.Println(`qbtm - Quantum Block Type Morphisms Runtime

A self-contained executor for typed quantum circuits over C*-algebra block structures.
Circuits are morphisms in FdC*_CP (finite-dimensional C*-algebras, CP maps).

USAGE:
    qbtm <command> [options]

COMMANDS:
    run         Execute a .qmb binary
    inspect     Inspect a .qmb file structure
    info        Show information about the runtime

OPTIONS:
    --help, -h      Show this help message
    --version, -v   Show version information

EXAMPLES:
    qbtm run circuit.qmb
    qbtm inspect model.qmb
    qbtm info

CONCEPTS:
    Block Type    C*-algebra as direct sum of matrix algebras: ⊕ M_nᵢ(ℂ)
    Morphism      Completely positive map between block types
    QGID          Content-addressed identity (32-byte hash)
    .qmb          Quantum Model Binary format

LICENSE:
    AGPL-3.0 - See LICENSE file for details`)
}

func printVersion() {
	fmt.Println("qbtm version 1.0.0")
	fmt.Println("Quantum Block Type Morphisms Runtime")
	fmt.Println("Self-contained quantum circuit executor")
	fmt.Println("License: AGPL-3.0")
}

func runQMB(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: qbtm run <file.qmb>")
	}

	filename := args[0]

	// Read the file
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Create runner
	runner, err := runtime.NewRunner(data)
	if err != nil {
		return fmt.Errorf("failed to create runner: %w", err)
	}

	fmt.Printf("Loaded: %s\n", runner.Name())
	fmt.Printf("Version: %s\n", runner.Version())
	ep := runner.Entrypoint()
	fmt.Printf("Entrypoint: %s\n", hex.EncodeToString(ep[:]))

	// Execute with identity input
	input := runtime.Identity(1)
	result, err := runner.Run(input)
	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	fmt.Println("\nExecution result:")
	fmt.Printf("  Output matrix: %dx%d\n", result.Rows, result.Cols)
	fmt.Printf("  Trace: %v\n", runtime.Trace(result))

	return nil
}

func inspectQMB(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: qbtm inspect <file.qmb>")
	}

	filename := args[0]

	// Read the file
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Decode
	binary, err := runtime.Decode(data)
	if err != nil {
		return fmt.Errorf("failed to decode: %w", err)
	}

	fmt.Printf("QMB Binary: %s\n", filename)
	fmt.Printf("  Magic: %s\n", string(binary.Magic[:3]))
	fmt.Printf("  Name: %s\n", binary.Name)
	fmt.Printf("  Version: %s\n", binary.Version)
	fmt.Printf("  Entrypoint: %s\n", hex.EncodeToString(binary.Entrypoint[:]))
	fmt.Printf("  Store size: %d bytes\n", len(binary.StoreData))
	fmt.Printf("  Total size: %d bytes\n", len(data))

	return nil
}

func showInfo(args []string) error {
	fmt.Println("QBTM Runtime Information")
	fmt.Println("========================")
	fmt.Println()
	fmt.Println("Architecture:")
	fmt.Println("  - Self-contained runtime with zero external dependencies")
	fmt.Println("  - Exact rational arithmetic (no floating point)")
	fmt.Println("  - Gaussian rationals Q(i) for complex numbers")
	fmt.Println("  - Content-addressed storage via QGID")
	fmt.Println()
	fmt.Println("Supported Primitives:")
	fmt.Println("  Structural: Id, Compose, Tensor, Swap")
	fmt.Println("  Quantum:    Unitary, Choi, Prepare, Discard")
	fmt.Println("  Arithmetic: Add, Scale, Zero")
	fmt.Println()
	fmt.Println("Type System:")
	fmt.Println("  Objects are C*-algebras: ⊕ᵢ M_nᵢ(ℂ)")
	fmt.Println("  Q(n) = single block M_n(ℂ) (n-dimensional quantum)")
	fmt.Println("  C(k) = k copies of ℂ (k-level classical)")
	fmt.Println("  I    = unit object (trivial)")
	fmt.Println()
	fmt.Println("File Format:")
	fmt.Println("  .qmb = Quantum Model Binary")
	fmt.Println("  Magic: QMB\\x01")
	fmt.Println("  Contains: entrypoint QGID + serialized store")

	return nil
}
