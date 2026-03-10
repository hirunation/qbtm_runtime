// Package communication provides quantum communication protocol implementations.
//
// This package implements certified quantum communication protocols:
//
//   - Quantum Teleportation: State transfer via entanglement and classical bits
//   - Superdense Coding: Transmit 2 classical bits via 1 qubit
//   - Quantum Repeater: Extend quantum communication range
//   - Entanglement Swapping: Create entanglement between distant parties
//
// Each protocol provides:
//
//   - Complete specification as qbtm/certify/protocol.Protocol
//   - Fidelity bounds over Q(i)
//   - Resource requirements
//   - Composability guarantees
//
// # Usage
//
//	import "qbtm/certify/protocol/communication"
//
//	// Get teleportation protocol
//	teleport := communication.Teleportation()
//
//	// Get superdense coding
//	sdc := communication.SuperdenseCoding()
package communication
