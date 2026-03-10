# QBTM: Quantum Block Type Morphisms

A self-contained runtime for typed quantum circuits over C*-algebra block structures, with integrated protocol certification.

**v2.0.0** -- Complete executor, synthesis engine, and self-reproducing bootstrap fixpoint.

## Overview

QBTM provides exact quantum circuit execution using rational arithmetic. Circuits are morphisms in FdC*_CP (the category of finite-dimensional C*-algebras with completely positive maps).

**Key Features:**
- Zero external dependencies (pure Go, standard library only)
- Exact arithmetic via rational numbers and Gaussian rationals Q(i)
- Content-addressed storage with QGID (32-byte hashes)
- Self-contained .qmb binary format with complete round-trip serialization
- All 23 circuit primitives fully implemented
- Synthesis engine with 12 synthesis rules and 4 rewrite rules
- Self-reproducing bootstrap fixpoint (verified via SHA-256)
- **Protocol Certifier**: 14 quantum protocols with formal security proofs
- **127 tests** all passing

## Quick Start

### Runtime CLI

```bash
go build -o qbtm ./cmd/qbtm
./qbtm info                         # Show all primitives, synthesis rules, rewrite rules
./qbtm bootstrap                    # Run the self-reproducing fixpoint demo
./qbtm synthesize Hadamard -o h.qmb # Synthesize a Hadamard gate to .qmb
./qbtm run h.qmb                    # Execute the synthesized gate
./qbtm inspect h.qmb                # Inspect store entries, entrypoint circuit
./qbtm verify v2.qmb v3.qmb        # Verify two binaries are identical (fixpoint)
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
# 1. Build the runtime
go build -o qbtm ./cmd/qbtm

# 2. Run the bootstrap demo (self-reproducing fixpoint)
./qbtm bootstrap
# Output:
#   v1 (with intentional redundancy) → normalize → v2
#   v2 → rebuild → v3
#   SHA-256(v2) == SHA-256(v3) → FIXPOINT VERIFIED

# 3. Synthesize a Hadamard gate and write to .qmb
./qbtm synthesize Hadamard -o hadamard.qmb
# Output: QGID, domain Q(2)→Q(2), channel matrix

# 4. Run the synthesized gate
./qbtm run hadamard.qmb
# Output: 2x2 matrix H|0><0|H† = [[1/2, 1/2], [1/2, 1/2]]

# 5. Inspect the binary
./qbtm inspect hadamard.qmb
# Output: store entries, entrypoint circuit details

# 6. Verify a fixpoint (byte-identical check)
./qbtm bootstrap -o /tmp/bootstrap
./qbtm verify /tmp/bootstrap/v1.qmb /tmp/bootstrap/v2.qmb
# Output: DIFFERENT (v1 has redundancy)
```

## Type System

Objects are C*-algebras represented as direct sums of matrix algebras:

| Type | Meaning | Structure |
|------|---------|-----------|
| `Q(n)` | n-dimensional quantum | M_n(C) |
| `C(k)` | k-level classical | C^k |
| `I` | Unit object | C |

Morphisms are completely positive maps between these types.

## Circuit Primitives (23)

**Structural (4):**
- `Id` - Identity morphism
- `Compose` - Sequential composition
- `Tensor` - Parallel composition (Kronecker product)
- `Swap` - Swaps tensor factors (correct permutation matrix)

**Biproduct (3):**
- `Bisum` - Component-wise morphism over direct sums
- `Inject` - Injection into coproduct
- `Project` - Projection from biproduct

**Classical (4):**
- `Copy` - Diagonal (cloning for classical systems)
- `Delete` - Counit (discard classical data)
- `Encode` - Prepare classical bits
- `Decode` - Measure to classical (extract diagonal)

**Quantum (6):**
- `Unitary` - Unitary gates via conjugation Ad_U(rho) = U rho U*
- `Choi` - General quantum channels via Choi-Jamiolkowski isomorphism
- `Kraus` - Quantum channels via Kraus operators
- `Prepare` - State preparation
- `Discard` - Complete trace (trace out entire system)
- `Trace` - Partial trace

**Arithmetic (3):**
- `Add` - Probabilistic mixture (sum of channels)
- `Scale` - Scalar multiplication
- `Zero` - Zero morphism

**Verification (2):**
- `Assert` - Type assertion with predicate
- `Witness` - Attach certificate / proof artifact

## File Format

The `.qmb` (Quantum Model Binary) format supports complete round-trip serialization. All 8 value types (Int, Rat, Bytes, Text, Seq, Tag, Bool, Nil) fully round-trip through binary encoding/decoding.

```
Magic:      "QMB\x01" (4 bytes)
Entrypoint: QGID (32 bytes)
Name:       length-prefixed string
Version:    length-prefixed string
Store:      Seq of Tag("entry", Seq(Bytes(qgid), value)) pairs
```

## Architecture

```
qbtm/
├── cmd/
│   ├── qbtm/             # Runtime CLI (run, inspect, bootstrap, synthesize, verify, info)
│   ├── certify/          # Protocol Certifier CLI
│   └── certify-gen/      # Model generator
├── runtime/              # Self-contained executor (zero imports)
│   ├── value.go          # Value types (Int, Rat, Seq, Tag, etc.) with complete encoding
│   ├── arithmetic.go     # Exact Q(i) arithmetic, matrices
│   ├── exec.go           # Circuit interpreter (all 23 primitives)
│   ├── embed.go          # Binary format encoder/decoder with complete round-trip
│   └── synth.go          # Synthesis engine (12 rules, 4 rewrites, bootstrap)
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

## Bootstrap & Self-Reproduction

The runtime includes a built-in bootstrap demonstration (`qbtm bootstrap`) that proves the synthesis system is self-consistent.

### The Bootstrap Process

1. **v1 (redundant)**: Build the toolchain with intentional redundancy (`Compose(toolchain, Id)`)
2. **v2 (normalized)**: Apply rewrite rules (LeftIdentity removes the redundant Id)
3. **v3 (rebuilt)**: Rebuild from v2's normalized form
4. **Fixpoint**: Verify `SHA-256(v2) == SHA-256(v3)` -- the normalized toolchain reproduces itself exactly

### Bootstrap Model Files

The `examples/` directory contains pre-built bootstrap artifacts:

1. `qbtm_generator_v1.qmb` - Initial model with intentional redundancy
2. `qbtm_generator_v2.qmb` - Normalized (redundancy removed)
3. `qbtm_generator_v3.qmb` - Rebuilt from v2 (identical hash to v2 = fixpoint)

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
