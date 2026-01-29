# QBTM Capabilities & Limitations

A deep technical analysis of what the Quantum Block Type Morphisms engine can and cannot do.

---

## 1. Specification Language

### Format

Specs are structured data with four components:

```
SynthesisSpec {
    Name        string         // Gate name (e.g., "Hadamard", "CNOT")
    Description string         // Natural language hint
    Domain      object.Object  // Input type
    Codomain    object.Object  // Output type
}
```

### Type Notation

Objects are C*-algebras (direct sums of matrix algebras):

| Notation | Meaning | Mathematical Form |
|----------|---------|-------------------|
| `Q(n)` | n-dimensional quantum system | M_n(ℂ) |
| `Q(2)` | Single qubit | M_2(ℂ) |
| `Q(4)` | Two qubits | M_4(ℂ) |
| `C(k)` | k-level classical system | ℂ ⊕ ℂ ⊕ ... (k times) |
| `I` | Unit (trivial system) | ℂ |
| `CQ(2,1,1)` | Hybrid | M_2(ℂ) ⊕ ℂ ⊕ ℂ |

### Example Specs

```go
// Simple: just the name (domain/codomain inferred)
Spec("Hadamard")

// Full specification
Spec{
    Name:     "CNOT",
    Domain:   Q(4),    // 2 qubits in
    Codomain: Q(4),    // 2 qubits out
}

// Typed identity
Spec("identity", Q(2))

// Zero map between arbitrary types
Spec("zero", Q(2), C(3))
```

---

## 2. Circuit Families

### 25 Primitive Gates

**Structural (4)** - Category theory backbone
| Primitive | Type | Description |
|-----------|------|-------------|
| `Id` | A → A | Identity morphism |
| `Compose` | A → C | Sequential: f then g |
| `Tensor` | A⊗C → B⊗D | Parallel: f alongside g |
| `Swap` | A⊗B → B⊗A | Exchange order |

**Biproduct (3)** - Direct sums
| Primitive | Type | Description |
|-----------|------|-------------|
| `Bisum` | A₀⊕...⊕Aₙ → B₀⊕...⊕Bₙ | Component-wise morphism |
| `Inject` | Aᵢ → A₀⊕...⊕Aₙ | Injection into coproduct |
| `Project` | A₀⊕...⊕Aₙ → Aᵢ | Projection out |

**Classical (4)** - Copying and deletion
| Primitive | Type | Description |
|-----------|------|-------------|
| `Copy` | A → A⊗A | Diagonal (cloning for classical) |
| `Delete` | A → I | Counit (discard classical) |
| `Encode` | I → C(2^n) | Prepare classical bits |
| `Decode` | A → C(dim A) | Measure to classical |

**Quantum Channels (5)** - Core quantum operations
| Primitive | Type | Description |
|-----------|------|-------------|
| `Discard` | A → I | Complete trace (trace out) |
| `Trace` | A⊗B → B | Partial trace |
| `Choi` | A → B | Channel from Choi matrix J |
| `Kraus` | A → B | Channel from Kraus ops [K₁...Kₙ] |
| `Unitary` | A → A | Conjugation Ad_U(ρ) = UρU† |

**Measurement (3)** - Quantum-classical interface
| Primitive | Type | Description |
|-----------|------|-------------|
| `Instrument` | A → C(k)⊗B | Measure with quantum output |
| `Branch` | C(k)⊗A → B | Classical control |
| `Prepare` | I → A | State preparation |

**Cone (3)** - Probabilistic mixing
| Primitive | Type | Description |
|-----------|------|-------------|
| `Add` | A → B | Sum f + g (mixture) |
| `Scale` | A → B | Scalar r·f |
| `Zero` | A → B | Zero map |

**Meta (2)** - Proof artifacts
| Primitive | Type | Description |
|-----------|------|-------------|
| `Assert` | A → A | Type assertion with predicate |
| `Witness` | A → A | Attach certificate |

### Built-in Synthesis Rules (12)

| Rule | Spec | Result |
|------|------|--------|
| Identity | `identity` on A | PrimId |
| Hadamard | `Hadamard` | Unitary with H = 1/√2 [[1,1],[1,-1]] |
| Pauli-X | `X` or `NOT` | Unitary [[0,1],[1,0]] |
| Pauli-Y | `Y` | Unitary [[0,-i],[i,0]] |
| Pauli-Z | `Z` | Unitary [[1,0],[0,-1]] |
| CNOT | `CNOT` | 4×4 controlled-NOT |
| SWAP | `SWAP` | 4×4 swap |
| Zero | `zero` A→B | PrimZero |
| Discard | `discard` A | PrimDiscard |
| Prepare | `prepare` | Default \|0⟩⟨0\| |
| Compose | Sequential | f ; g |
| Tensor | Parallel | f ⊗ g |

---

## 3. Synthesis Algorithm

### Beam Search

```
Configuration:
  BeamWidth:     10    (candidates per level)
  MaxDepth:      20    (search iterations)
  MaxExpansions: 1000  (total nodes before exhaustion)
```

### Search Process

1. **Initialize** with target spec
2. **Expand** candidates using rewriting rules
3. **Score** partial circuits by cost heuristic
4. **Prune** to top-k (beam width)
5. **Repeat** until solution found or limits hit

### Rewriting Rules (18 total)

**Structural (4)**
- Identity composition: `id ; f = f = f ; id`
- Associativity: `(f ; g) ; h = f ; (g ; h)`
- Tensor-compose interchange
- Swap involution: `swap ; swap = id`

**Quantum (8)**
- Discard absorption: `f ; discard = discard`
- Zero absorption: `zero ; f = zero`
- Unitary composition
- Kraus/Choi decomposition
- Trace properties

**Classical (6)**
- Copy naturality
- Delete naturality
- Encode/decode relationships
- Classical-quantum interaction

---

## 4. Known Limitations

### Hard Limits

| Constraint | Limit | Impact |
|------------|-------|--------|
| Search depth | 20 levels | Deep circuits may not synthesize |
| Beam width | 10 candidates | May miss optimal solutions |
| Expansions | 1000 total | Complex specs may exhaust |
| Synthesis rules | 12 fixed | No custom gate definitions |

### Arithmetic Constraints

```
Number System: Gaussian Rationals Q(i) = {a + bi : a,b ∈ ℚ}

✓ Can represent: 1/2, 3/4, (1+2i)/5, ...
✗ Cannot represent: √2, π, e, ...
```

**Implication**: Gates like Hadamard that mathematically require √2 are handled via:
- Symbolic representation (defer normalization)
- Rational approximation where exact form unavailable

### Type System Constraints

| Operation | Requirement |
|-----------|-------------|
| Compose f;g | codomain(f) = domain(g) |
| Copy | codomain = domain ⊗ domain |
| Delete/Discard | codomain = I |
| Prepare | domain = I |
| Swap A,B | Must have valid A⊗B structure |

### Not Supported

- **Parametric gates**: No `Rz(θ)` with variable angle
- **Custom primitives**: Cannot add new gate types
- **Infinite dimensions**: Finite-dimensional only
- **Continuous variables**: No bosonic modes
- **Dynamic circuits**: No mid-circuit measurement feedback (static only)

---

## 5. Failure Modes

### Graceful Failures

```go
// Spec not recognized
ErrResult("SYNTH requires valid synthesis specification")

// Search exhausted
fmt.Errorf("search exhausted at depth %d", depth)
fmt.Errorf("search exhausted after %d expansions", expansions)

// Type mismatch
TypeError{
    Primitive: "Compose",
    Message:   "codomain/domain mismatch",
    Expected:  "Q(2)",
    Got:       "Q(4)",
}

// Binary format invalid
fmt.Errorf("invalid magic")  // Not QMB\x01
```

### What Causes Synthesis Failure

1. **Unknown gate name**: Spec doesn't match any rule
2. **Type impossible**: Requested domain/codomain incompatible
3. **Search exhaustion**: Valid circuit exists but too complex
4. **Missing data**: Unitary requested but no matrix provided

### Recovery

- All failures return structured error results
- No panics on invalid input
- Type errors caught before synthesis begins
- Binary parsing validates magic bytes first

---

## 6. Largest Synthesized Circuits

### The Bootstrap Model (Most Complex)

The **toolchain circuit** is the most complex artifact:

```
Structure:
  - Encodes all 12 synthesis rules
  - Encodes the synthesis algorithm itself
  - Type: I → I (trivial domain/codomain)
  - Primitive: PrimPrepare with embedded model data

Size:
  - v1.qmb: 3,442 bytes
  - v2.qmb: 3,452 bytes
  - v3.qmb: 3,452 bytes (identical to v2)
```

### Fixpoint Verification

```
v1 (hand-written) → synthesize → v2
v2 (generated)    → synthesize → v3

SHA256(v2) = SHA256(v3) = FIXPOINT!

This proves: The synthesis model correctly generates itself.
```

### Circuit Complexity Hierarchy

| Circuit | Depth | Children | Notes |
|---------|-------|----------|-------|
| Single gate | 0 | 0 | Primitive |
| f ; g | 1 | 2 | Sequential |
| f ⊗ g | 1 | 2 | Parallel |
| (f;g) ⊗ (h;k) | 2 | 4 | Nested |
| Toolchain | 1 | 1 | Meta (embeds model) |

---

## 7. Design Intent

### Mathematical Foundation

QBTM implements the category **FdC*_CP**:
- **Objects**: Finite-dimensional C*-algebras
- **Morphisms**: Completely positive maps
- **Structure**: Symmetric monoidal with biproducts

This is the mathematically correct framework for:
- Quantum channels (noise, decoherence)
- Measurements (POVMs, instruments)
- Classical-quantum interaction
- Mixed states (density matrices)

### Why This Matters

```
Traditional Quantum Computing     QBTM
────────────────────────────────────────────────
Unitary gates only               All CP maps
Pure states                      Mixed states
No measurement model             Full instruments
Ad-hoc composition               Categorical laws
```

### Intended Applications

1. **Formal Verification**: Prove circuit properties exactly
2. **Certified Compilation**: Verify compiler correctness via bootstrap
3. **Reproducible Research**: Content-addressed circuits
4. **Educational**: Learn categorical quantum mechanics
5. **Hybrid Systems**: Model quantum-classical interaction properly

---

## 8. Robustness Assessment

### Strengths

| Property | Benefit |
|----------|---------|
| Exact arithmetic | No numerical errors accumulate |
| Content addressing | Reproducible across machines |
| Type safety | Invalid circuits rejected at construction |
| Self-bootstrap | Proof of implementation correctness |
| Zero dependencies | Runs anywhere Go compiles |

### Weaknesses

| Limitation | Impact |
|------------|--------|
| Fixed rule set | Cannot extend without code changes |
| No parametric gates | Cannot do variational algorithms |
| Search limits | May miss valid complex circuits |
| Q(i) only | Some coefficients need symbolic handling |

### Verdict

**QBTM is robust for its designed purpose**: typed quantum circuit synthesis with formal guarantees. It trades flexibility (no custom gates) for correctness (self-verifying bootstrap).

Best suited for:
- Generating verified standard gates
- Composing typed circuits safely
- Packaging reproducible quantum artifacts
- Educational/research use

Not suited for:
- Variational quantum algorithms (need θ parameters)
- Large-scale simulation (not a simulator)
- Custom gate libraries (fixed primitives)

---

## Summary Table

| Aspect | Status |
|--------|--------|
| Spec language | Typed (Name + Domain + Codomain) |
| Gate primitives | 25 built-in |
| Synthesis rules | 12 (structural, quantum, classical) |
| Search algorithm | Beam search (10-wide, 20-deep, 1000-expand) |
| Number system | Gaussian rationals Q(i) |
| Type system | FdC*_CP categorical |
| Largest circuit | Self-bootstrap toolchain (3.5KB) |
| Failure handling | Graceful errors, no panics |
| Self-verification | v2 = v3 fixpoint proven |
