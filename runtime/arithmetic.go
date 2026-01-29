package runtime

import (
	"math/big"
)

// QI represents a Gaussian rational: a + bi where a, b ∈ ℚ.
type QI struct {
	Re *big.Rat
	Im *big.Rat
}

// NewQI creates a Gaussian rational.
func NewQI(re, im *big.Rat) QI {
	return QI{
		Re: new(big.Rat).Set(re),
		Im: new(big.Rat).Set(im),
	}
}

// QIZero returns the zero Gaussian rational.
func QIZero() QI {
	return QI{
		Re: new(big.Rat),
		Im: new(big.Rat),
	}
}

// QIOne returns the Gaussian rational 1.
func QIOne() QI {
	return QI{
		Re: big.NewRat(1, 1),
		Im: new(big.Rat),
	}
}

// QII returns the imaginary unit i.
func QII() QI {
	return QI{
		Re: new(big.Rat),
		Im: big.NewRat(1, 1),
	}
}

// QINeg returns -q.
func QINeg(q QI) QI {
	return QI{
		Re: new(big.Rat).Neg(q.Re),
		Im: new(big.Rat).Neg(q.Im),
	}
}

// QIAdd returns a + b.
func QIAdd(a, b QI) QI {
	return QI{
		Re: new(big.Rat).Add(a.Re, b.Re),
		Im: new(big.Rat).Add(a.Im, b.Im),
	}
}

// QISub returns a - b.
func QISub(a, b QI) QI {
	return QI{
		Re: new(big.Rat).Sub(a.Re, b.Re),
		Im: new(big.Rat).Sub(a.Im, b.Im),
	}
}

// QIMul returns a * b.
// (a + bi)(c + di) = (ac - bd) + (ad + bc)i
func QIMul(a, b QI) QI {
	ac := new(big.Rat).Mul(a.Re, b.Re)
	bd := new(big.Rat).Mul(a.Im, b.Im)
	ad := new(big.Rat).Mul(a.Re, b.Im)
	bc := new(big.Rat).Mul(a.Im, b.Re)

	return QI{
		Re: new(big.Rat).Sub(ac, bd),
		Im: new(big.Rat).Add(ad, bc),
	}
}

// QIConj returns the complex conjugate of q.
func QIConj(q QI) QI {
	return QI{
		Re: new(big.Rat).Set(q.Re),
		Im: new(big.Rat).Neg(q.Im),
	}
}

// QINormSq returns |q|² = a² + b².
func QINormSq(q QI) *big.Rat {
	reSq := new(big.Rat).Mul(q.Re, q.Re)
	imSq := new(big.Rat).Mul(q.Im, q.Im)
	return new(big.Rat).Add(reSq, imSq)
}

// QIInv returns 1/q = conj(q)/|q|².
func QIInv(q QI) (QI, bool) {
	normSq := QINormSq(q)
	if normSq.Sign() == 0 {
		return QIZero(), false
	}
	conj := QIConj(q)
	return QI{
		Re: new(big.Rat).Quo(conj.Re, normSq),
		Im: new(big.Rat).Quo(conj.Im, normSq),
	}, true
}

// QIDiv returns a/b.
func QIDiv(a, b QI) (QI, bool) {
	inv, ok := QIInv(b)
	if !ok {
		return QIZero(), false
	}
	return QIMul(a, inv), true
}

// QIEqual checks if two Gaussian rationals are equal.
func QIEqual(a, b QI) bool {
	return a.Re.Cmp(b.Re) == 0 && a.Im.Cmp(b.Im) == 0
}

// QIIsZero checks if q is zero.
func QIIsZero(q QI) bool {
	return q.Re.Sign() == 0 && q.Im.Sign() == 0
}

// QIScale multiplies q by a rational.
func QIScale(q QI, r *big.Rat) QI {
	return QI{
		Re: new(big.Rat).Mul(q.Re, r),
		Im: new(big.Rat).Mul(q.Im, r),
	}
}

// Matrix represents a matrix over Gaussian rationals.
type Matrix struct {
	Rows int
	Cols int
	Data []QI
}

// NewMatrix creates a zero matrix.
func NewMatrix(rows, cols int) *Matrix {
	data := make([]QI, rows*cols)
	for i := range data {
		data[i] = QIZero()
	}
	return &Matrix{
		Rows: rows,
		Cols: cols,
		Data: data,
	}
}

// Get returns the element at (i, j).
func (m *Matrix) Get(i, j int) QI {
	return m.Data[i*m.Cols+j]
}

// Set sets the element at (i, j).
func (m *Matrix) Set(i, j int, v QI) {
	m.Data[i*m.Cols+j] = v
}

// Identity creates an identity matrix.
func Identity(n int) *Matrix {
	m := NewMatrix(n, n)
	for i := 0; i < n; i++ {
		m.Set(i, i, QIOne())
	}
	return m
}

// Zero creates a zero matrix.
func Zero(rows, cols int) *Matrix {
	return NewMatrix(rows, cols)
}

// MatMul computes A * B.
func MatMul(A, B *Matrix) *Matrix {
	if A.Cols != B.Rows {
		return nil
	}
	C := NewMatrix(A.Rows, B.Cols)
	for i := 0; i < A.Rows; i++ {
		for j := 0; j < B.Cols; j++ {
			sum := QIZero()
			for k := 0; k < A.Cols; k++ {
				product := QIMul(A.Get(i, k), B.Get(k, j))
				sum = QIAdd(sum, product)
			}
			C.Set(i, j, sum)
		}
	}
	return C
}

// MatAdd computes A + B.
func MatAdd(A, B *Matrix) *Matrix {
	if A.Rows != B.Rows || A.Cols != B.Cols {
		return nil
	}
	C := NewMatrix(A.Rows, A.Cols)
	for i := 0; i < len(A.Data); i++ {
		C.Data[i] = QIAdd(A.Data[i], B.Data[i])
	}
	return C
}

// MatSub computes A - B.
func MatSub(A, B *Matrix) *Matrix {
	if A.Rows != B.Rows || A.Cols != B.Cols {
		return nil
	}
	C := NewMatrix(A.Rows, A.Cols)
	for i := 0; i < len(A.Data); i++ {
		C.Data[i] = QISub(A.Data[i], B.Data[i])
	}
	return C
}

// MatScale computes r * A.
func MatScale(A *Matrix, r *big.Rat) *Matrix {
	C := NewMatrix(A.Rows, A.Cols)
	for i := 0; i < len(A.Data); i++ {
		C.Data[i] = QIScale(A.Data[i], r)
	}
	return C
}

// Dagger computes the conjugate transpose.
func Dagger(A *Matrix) *Matrix {
	B := NewMatrix(A.Cols, A.Rows)
	for i := 0; i < A.Rows; i++ {
		for j := 0; j < A.Cols; j++ {
			B.Set(j, i, QIConj(A.Get(i, j)))
		}
	}
	return B
}

// Trace computes the trace of a square matrix.
func Trace(A *Matrix) QI {
	if A.Rows != A.Cols {
		return QIZero()
	}
	sum := QIZero()
	for i := 0; i < A.Rows; i++ {
		sum = QIAdd(sum, A.Get(i, i))
	}
	return sum
}

// Kronecker computes the Kronecker product A ⊗ B.
func Kronecker(A, B *Matrix) *Matrix {
	rows := A.Rows * B.Rows
	cols := A.Cols * B.Cols
	C := NewMatrix(rows, cols)

	for i := 0; i < A.Rows; i++ {
		for j := 0; j < A.Cols; j++ {
			for k := 0; k < B.Rows; k++ {
				for l := 0; l < B.Cols; l++ {
					row := i*B.Rows + k
					col := j*B.Cols + l
					C.Set(row, col, QIMul(A.Get(i, j), B.Get(k, l)))
				}
			}
		}
	}
	return C
}

// OuterProduct computes |u⟩⟨v| (u * v†).
func OuterProduct(u, v *Matrix) *Matrix {
	if u.Cols != 1 || v.Cols != 1 {
		return nil
	}
	vDag := Dagger(v)
	return MatMul(u, vDag)
}

// MatrixEqual checks if two matrices are equal.
func MatrixEqual(A, B *Matrix) bool {
	if A.Rows != B.Rows || A.Cols != B.Cols {
		return false
	}
	for i := 0; i < len(A.Data); i++ {
		if !QIEqual(A.Data[i], B.Data[i]) {
			return false
		}
	}
	return true
}

// Clone creates a copy of the matrix.
func (m *Matrix) Clone() *Matrix {
	result := NewMatrix(m.Rows, m.Cols)
	for i := range m.Data {
		result.Data[i] = NewQI(m.Data[i].Re, m.Data[i].Im)
	}
	return result
}

// Encoding for matrices

// MatrixToValue converts a matrix to a Value.
func MatrixToValue(m *Matrix) Value {
	items := make([]Value, len(m.Data))
	for i, q := range m.Data {
		items[i] = MakeTag(
			MakeText("qi"),
			MakeSeq(
				MakeBigRat(q.Re),
				MakeBigRat(q.Im),
			),
		)
	}
	return MakeTag(
		MakeText("matrix"),
		MakeSeq(
			MakeInt(int64(m.Rows)),
			MakeInt(int64(m.Cols)),
			MakeSeq(items...),
		),
	)
}

// MatrixFromValue parses a matrix from a Value.
func MatrixFromValue(v Value) (*Matrix, bool) {
	tag, ok := v.(Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(Text)
	if !ok || label.V != "matrix" {
		return nil, false
	}
	seq, ok := tag.Payload.(Seq)
	if !ok || len(seq.Items) < 3 {
		return nil, false
	}
	rows, ok := seq.Items[0].(Int)
	if !ok {
		return nil, false
	}
	cols, ok := seq.Items[1].(Int)
	if !ok {
		return nil, false
	}
	data, ok := seq.Items[2].(Seq)
	if !ok {
		return nil, false
	}

	m := NewMatrix(int(rows.V.Int64()), int(cols.V.Int64()))
	for i, item := range data.Items {
		qi, ok := qiFromValue(item)
		if !ok {
			return nil, false
		}
		m.Data[i] = qi
	}
	return m, true
}

// qiFromValue parses a QI from a Value.
func qiFromValue(v Value) (QI, bool) {
	tag, ok := v.(Tag)
	if !ok {
		return QIZero(), false
	}
	label, ok := tag.Label.(Text)
	if !ok || label.V != "qi" {
		return QIZero(), false
	}
	seq, ok := tag.Payload.(Seq)
	if !ok || len(seq.Items) < 2 {
		return QIZero(), false
	}
	re, ok := seq.Items[0].(Rat)
	if !ok {
		return QIZero(), false
	}
	im, ok := seq.Items[1].(Rat)
	if !ok {
		return QIZero(), false
	}
	return NewQI(re.V, im.V), true
}
