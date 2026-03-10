# QBTM: Quantum Block Type Morphisms

A self-contained runtime for typed quantum circuits over C*-algebra block structures, with integrated protocol certification.

## Overview

QBTM provides exact quantum circuit execution using rational arithmetic. Circuits are morphisms in FdC*_CP (the category of finite-dimensional C*-algebras with completely positive maps).

**Key Features:**
- Zero external dependencies (pure Go, standard library only)
- Exact arithmetic via rational numbers and Gaussian rationals Q(i)
- Content-addressed storage with QGID (32-byte hashes)
- Self-contained .qmb binary format
- **Protocol Certifier**: 14 quantum protocols with formal security proofs

## Quick Start

### Runtime CLI

```bash
go build -o qbtm ./cmd/qbtm
./qbtm info
./qbtm inspect examples/qbtm_generator_v3.qmb
```

### Protocol Certifier CLI

```bash
go build -o certify ./cmd/certify
./certify list                      # List 14 protocols
./certify full-analysis BB84        # Full security analysis
./certify security E91 --error-rate 0.05
./certify verify Teleportation
```

### Generate Certified Model

```bash
go run ./cmd/certify-gen            # Creates models/certify/qbtm_certify.qmb
```

## Two-Minute Tour

```bash
# 1. Build both tools
go build ./...

# 2. See available protocols
./certify list
# Output: BB84, E91, B92, Six-State, SARG04, Teleportation, ...

# 3. Analyze BB84 QKD
./certify security BB84
# Output: Key rate, threshold (11%), attack resistance

# 4. Verify teleportation correctness
./certify verify Teleportation
# Output: Fidelity = 1 (perfect)

# 5. Run the runtime on bootstrap models
./qbtm inspect examples/qbtm_generator_v3.qmb
```

## Type System

Objects are C*-algebras represented as direct sums of matrix algebras:

| Type | Meaning | Structure |
|------|---------|-----------|
| `Q(n)` | n-dimensional quantum | M_n(C) |
| `C(k)` | k-level classical | C^k |
| `I` | Unit object | C |

Morphisms are completely positive maps between these types.

## Circuit Primitives

**Structural:**
- `Id` - Identity morphism
- `Compose` - Sequential composition
- `Tensor` - Parallel composition
- `Swap` - Swaps tensor factors

**Quantum:**
- `Unitary` - Unitary gates (Hadamard, CNOT, Pauli, etc.)
- `Choi` - General quantum channels via Choi representation
- `Prepare` - State preparation
- `Discard` - Partial trace

**Arithmetic:**
- `Add` - Probabilistic mixture
- `Scale` - Scalar multiplication
- `Zero` - Zero morphism

## File Format

The `.qmb` (Quantum Model Binary) format:

```
Magic:      "QMB\x01" (4 bytes)
Name:       length-prefixed string
Version:    length-prefixed string
Entrypoint: QGID (32 bytes)
Store:      serialized value store
```

## Architecture

```
qbtm/
├── cmd/
│   ├── qbtm/             # Runtime CLI
│   ├── certify/          # Protocol Certifier CLI
│   └── certify-gen/      # Model generator
├── runtime/              # Self-contained executor (zero imports)
│   ├── value.go          # Value types (Int, Rat, Seq, Tag, etc.)
│   ├── arithmetic.go     # Exact Q(i) arithmetic, matrices
│   ├── exec.go           # Circuit interpreter
│   └── embed.go          # Binary format encoder/decoder
├── certify/              # Protocol Certification System
│   ├── protocol/         # 14 quantum protocols
│   │   ├── qkd/          # BB84, E91, B92, Six-State, SARG04
│   │   ├── communication/ # Teleportation, Superdense, Swapping
│   │   ├── multiparty/   # GHZ, W-State, Secret Sharing
│   │   └── cryptographic/ # Coin Flip, Bit Commitment, OT
│   ├── attack/           # 21 attack models
│   ├── analysis/         # Correctness, security, noise, composition
│   └── certificate/      # Evidence, witnesses, bundles
├── models/certify/       # Generated artifacts & documentation
│   ├── qbtm_certify.qmb  # Certified model
│   ├── README.md         # Certifier quick start
│   ├── PROTOCOLS.md      # Protocol catalog
│   └── SPECIFICATION.md  # Technical spec
├── examples/             # Bootstrap model files
└── LICENSE               # AGPL-3.0
```

## Protocol Certifier

The `certify/` package provides formal security analysis for quantum protocols:

### Supported Protocols (14)

| Category | Protocols |
|----------|-----------|
| **QKD** | BB84, E91, B92, Six-State, SARG04 |
| **Communication** | Teleportation, Superdense Coding, Entanglement Swapping |
| **Multi-party** | GHZ Distribution, W-State, Secret Sharing |
| **Cryptographic** | Coin Flip, Bit Commitment, Oblivious Transfer |

### Analysis Capabilities

| Analysis | Description |
|----------|-------------|
| **Correctness** | Choi matrix comparison to ideal functionality |
| **Security** | Key rates, thresholds (e.g., BB84: 11%) |
| **Attacks** | 21 models (intercept-resend, PNS, coherent, etc.) |
| **Noise** | Depolarizing, amplitude damping, phase damping |
| **Composition** | Sequential/parallel with security propagation |

### Example: Full BB84 Analysis

```bash
./certify full-analysis BB84 --format=json
```

Output includes:
- Protocol specification
- Synthesized circuit (QGID)
- Correctness certificate
- Security bounds for individual/collective/coherent attacks
- Noise tolerance thresholds
- Applicable attack analysis

See [models/certify/README.md](models/certify/README.md) for complete documentation.

## Bootstrap Models

The `examples/` directory contains the bootstrap sequence demonstrating self-reproduction:

1. `qbtm_generator_v1.qmb` - Initial hand-written model
2. `qbtm_generator_v2.qmb` - Generated from v1
3. `qbtm_generator_v3.qmb` - Generated from v2 (identical hash to v2 = fixpoint)

The fixpoint proves the synthesis system correctly generates itself.

## Mathematical Foundation

QBTM implements morphisms in **FdC*_CP**:
- **Objects**: Finite-dimensional C*-algebras (direct sums of matrix algebras)
- **Morphisms**: Completely positive maps (Kraus representations)
- **Monoidal structure**: Tensor product of algebras

This categorical framework ensures:
- Type safety (domain/codomain matching)
- Composition correctness
- Complete positivity preservation

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details.

This means:
- Free to use, modify, and distribute
- Modifications must be shared under AGPL-3.0
- Network use requires source disclosure
