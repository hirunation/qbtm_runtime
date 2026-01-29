# QBTM Architecture

Technical documentation for the Quantum Block Type Morphisms runtime.

## Design Principles

1. **Zero Dependencies**: Only Go standard library
2. **Exact Arithmetic**: No floating-point approximations
3. **Content Addressing**: Values identified by cryptographic hashes (QGID)
4. **Self-Containment**: .qmb files include all required data

## Module Structure

### `runtime/value.go`

Core value types for the quantum model representation:

```go
type Value interface {
    valueTag()
    Encode() []byte
}
```

**Primitive Types:**
| Type | Description | Encoding Prefix |
|------|-------------|-----------------|
| `Int` | Arbitrary-precision integer | 0x00-0x7F (small) or 0x40/0x80 |
| `Rat` | Arbitrary-precision rational | 0x90 |
| `Bytes` | Raw byte sequence | 0xA0 |
| `Text` | UTF-8 string | 0xB0 |
| `Seq` | Ordered sequence of values | 0xC0 |
| `Tag` | Labeled value (discriminated union) | 0xD0 |
| `Bool` | Boolean | 0xE0/0xE1 |
| `Nil` | Unit value | 0xF0 |

**QGID Computation:**
```go
func QGID(v Value) [32]byte {
    return sha256.Sum256(v.Encode())
}
```

### `runtime/arithmetic.go`

Exact arithmetic over Gaussian rationals Q(i) = {a + bi : a,b in Q}:

```go
type Gaussian struct {
    Re *big.Rat  // Real part
    Im *big.Rat  // Imaginary part
}
```

**Matrix Type:**
```go
type Matrix struct {
    Rows, Cols int
    Data       []Gaussian  // Row-major order
}
```

**Operations:**
- `MatMul(A, B)` - Matrix multiplication
- `KronProd(A, B)` - Kronecker (tensor) product
- `ConjTranspose(M)` - Conjugate transpose
- `Trace(M)` - Matrix trace
- `ApplyKraus(rho, kraus)` - Apply Kraus channel

### `runtime/exec.go`

Circuit interpreter that executes quantum morphisms:

```go
type Executor struct {
    store map[[32]byte]Value
}

func (e *Executor) Execute(circuit Value, input Matrix) (Matrix, error)
```

**Dispatch by Tag:**
```go
switch tag.Label.(Text).V {
case "Id":       return input
case "Compose":  return e.executeCompose(tag.Payload, input)
case "Tensor":   return e.executeTensor(tag.Payload, input)
case "Swap":     return e.executeSwap(tag.Payload, input)
case "Unitary":  return e.executeUnitary(tag.Payload, input)
case "Choi":     return e.executeChoi(tag.Payload, input)
// ...
}
```

### `runtime/embed.go`

Binary format handling:

```go
type QMBBinary struct {
    Magic      [4]byte   // "QMB\x01"
    Name       string
    Version    string
    Entrypoint [32]byte  // QGID of entrypoint circuit
    StoreData  []byte    // Serialized value store
}
```

**Encoding:**
1. Write magic bytes
2. Write name (length-prefixed)
3. Write version (length-prefixed)
4. Write entrypoint QGID
5. Write store as serialized map

## Execution Model

### Type Objects

Block types represent C*-algebras:

```
Object{Blocks: []uint32}
```

- `Q(n)` = `Object{Blocks: []uint32{n}}` - n-dimensional quantum
- `C(k)` = `Object{Blocks: []uint32{1,1,...,1}}` - k classical levels
- `I` = `Object{Blocks: []uint32{1}}` - trivial

### Circuit Execution

1. **Load**: Parse .qmb, populate value store
2. **Resolve**: Lookup entrypoint QGID in store
3. **Execute**: Recursively evaluate circuit structure
4. **Output**: Final matrix representing the morphism

### Matrix Semantics

- **State**: Density matrix rho (positive, trace 1)
- **Channel**: CPTP map (completely positive, trace-preserving)
- **Effect**: POVM element (positive, bounded by I)

Composition: `(g . f)(rho) = g(f(rho))`
Tensor: `(f x g)(rho x sigma) = f(rho) x g(sigma)`

## Self-Bootstrap Property

The QBTM system is self-reproducing:

```
v1.qmb --> [synthesize] --> v2.qmb
v2.qmb --> [synthesize] --> v3.qmb
SHA256(v2) == SHA256(v3)  // Fixpoint!
```

This proves correctness: the synthesizer, when run on itself, produces an identical output.

## Memory Model

All values are immutable. The store is a pure function from QGID to Value:

```
store : [32]byte -> Value
```

Content addressing provides:
- Automatic deduplication
- Referential transparency
- Cryptographic verification

## Performance Characteristics

| Operation | Complexity |
|-----------|-----------|
| QGID lookup | O(1) hash table |
| Matrix multiply (n x n) | O(n^3) |
| Kronecker product (m x n) | O(mn) space |
| Rational arithmetic | Depends on bit-length |

Note: Exact arithmetic can lead to exponential growth in numerator/denominator sizes for deep circuits. The runtime makes no attempt to limit this.

## Error Handling

The runtime returns errors for:
- Invalid magic bytes in .qmb
- Missing QGID references
- Type mismatches (dimension errors)
- Malformed value encodings

All errors are wrapped with context for debugging.

## Security Considerations

- .qmb files are not sandboxed (execute arbitrary circuit logic)
- Large circuits can exhaust memory (no resource limits)
- Untrusted .qmb files should be inspected before execution
