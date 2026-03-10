// Package qkd provides quantum key distribution protocol implementations.
//
// This package implements certified QKD protocols with exact security bounds:
//
//   - BB84: Bennett-Brassard 1984 (four-state protocol)
//   - E91: Ekert 1991 (entanglement-based)
//   - B92: Bennett 1992 (two-state protocol)
//   - Six-State: Bruss 2002 (six-state protocol)
//   - SARG04: Scarani-Acin-Ribordy-Gisin 2004
//
// Each protocol provides:
//
//   - Complete specification as qbtm/certify/protocol.Protocol
//   - Exact security bounds over Q(i)
//   - Attack resistance analysis
//   - Noise tolerance thresholds
//
// # Usage
//
//	import "qbtm/certify/protocol/qkd"
//
//	// Get BB84 protocol specification
//	bb84 := qkd.BB84()
//
//	// Get E91 with custom parameters
//	e91 := qkd.E91(qkd.WithNParties(3))
package qkd
