# QBTM: Quantum Block Type Morphisms

A self-contained runtime for typed quantum circuits over C*-algebra block structures.

## Overview

QBTM provides exact quantum circuit execution using rational arithmetic. Circuits are morphisms in FdC*_CP (the category of finite-dimensional C*-algebras with completely positive maps).

**Key Features:**
- Zero external dependencies (pure Go, standard library only)
- Exact arithmetic via rational numbers and Gaussian rationals Q(i)
- Content-addressed storage with QGID (32-byte hashes)
- Self-contained .qmb binary format

## Installation

```bash
go install ./cmd/qbtm
```

Or build from source:

```bash
go build -o qbtm ./cmd/qbtm
```

## Usage

```bash
# Show runtime information
qbtm info

# Inspect a .qmb binary
qbtm inspect circuit.qmb

# Execute a .qmb binary
qbtm run circuit.qmb
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
├── cmd/qbtm/         # CLI tool
│   └── main.go
├── runtime/          # Self-contained executor
│   ├── value.go      # Value types (Int, Rat, Seq, Tag, etc.)
│   ├── arithmetic.go # Exact rational/Gaussian arithmetic
│   ├── exec.go       # Circuit interpreter
│   └── embed.go      # Binary format encoder/decoder
├── examples/         # Bootstrap model files
│   ├── qbtm_generator_v1.qmb
│   ├── qbtm_generator_v2.qmb
│   └── qbtm_generator_v3.qmb
└── LICENSE           # AGPL-3.0
```

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
