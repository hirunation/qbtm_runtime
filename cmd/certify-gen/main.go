// cmd/certify-gen generates the qbtm_certify.qmb model file.
//
// This program synthesizes all registered protocols and attacks,
// bundles them into a single embedded binary, and outputs the
// result to models/certify/qbtm_certify.qmb.
//
// Usage:
//
//	go run cmd/certify-gen/main.go
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"qbtm/certify"
	"qbtm/certify/attack"
	"qbtm/certify/certificate"
	"qbtm/runtime"
)

func main() {
	fmt.Println("Generating qbtm_certify.qmb...")

	// 1. Create store for all components
	store := runtime.NewStore()

	// 2. Register all protocols
	protocols := certificate.RegisteredProtocols()
	fmt.Printf("Registering %d protocols...\n", len(protocols))

	for _, name := range protocols {
		proto, err := certificate.GetProtocol(name)
		if err != nil {
			fmt.Printf("  Warning: could not get protocol %s: %v\n", name, err)
			continue
		}

		// Synthesize circuit
		qgid, err := proto.Synthesize(store)
		if err != nil {
			fmt.Printf("  Warning: could not synthesize %s: %v\n", name, err)
			continue
		}
		fmt.Printf("  %s: %s\n", name, hex.EncodeToString(qgid[:8]))
	}

	// 3. Register attack library
	attacks := attack.AllAttacks()
	fmt.Printf("Registering %d attacks...\n", len(attacks))
	for _, atk := range attacks {
		val := atk.ToValue()
		store.PutValue(val)
	}

	// 4. Create model entry point
	model := certify.CertifyModel{
		Name:      "qbtm_certify",
		Version:   "1.0.0",
		Protocols: protocols,
		Store:     store,
	}

	entrypoint := store.PutValue(model.ToValue())

	// 5. Create embedded binary
	binary := runtime.Embed(store, entrypoint, "qbtm_certify", "1.0.0")

	// 6. Compute QGID
	binaryData := binary.Encode()
	qgid := runtime.QGID(runtime.MakeBytes(binaryData))
	fmt.Printf("Model QGID: %s\n", hex.EncodeToString(qgid[:]))

	// 7. Write to file
	outputDir := "models/certify"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	outputPath := filepath.Join(outputDir, "qbtm_certify.qmb")
	if err := os.WriteFile(outputPath, binaryData, 0644); err != nil {
		fmt.Printf("Error writing model: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Model written to: %s (%d bytes)\n", outputPath, len(binaryData))

	// 8. Self-verification
	fmt.Println("\nSelf-verification...")
	runner, err := runtime.NewRunner(binaryData)
	if err != nil {
		fmt.Printf("Error loading model: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Name: %s\n", runner.Name())
	fmt.Printf("  Version: %s\n", runner.Version())
	entrypointBytes := runner.Entrypoint()
	fmt.Printf("  Entrypoint: %s\n", hex.EncodeToString(entrypointBytes[:8]))

	fmt.Println("\nGeneration complete!")
}
