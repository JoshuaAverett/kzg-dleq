export interface Membership<T> {
	readonly isMember: (a: T) => boolean
}

export interface Eq<T> {
	readonly eq: (a: T, b: T) => boolean
	readonly ne: (a: T, b: T) => boolean
}

export interface Ord<T> {
	readonly lt: (a: T, b: T) => boolean
	readonly gt: (a: T, b: T) => boolean
	readonly le: (a: T, b: T) => boolean
	readonly ge: (a: T, b: T) => boolean
	readonly compare: (a: T, b: T) => number
}

export interface AdditiveSemigroup<T> {
	readonly add: (a: T, b: T) => T
}

export interface AdditiveMonoid<T> extends AdditiveSemigroup<T> {
	readonly zero: T
}

export interface AdditiveGroup<T> extends AdditiveMonoid<T> {
	readonly neg: (a: T) => T
	readonly sub: (a: T, b: T) => T
}

export interface MultiplicativeSemigroup<T> {
	readonly mul: (a: T, b: T) => T
}

export interface MultiplicativeMonoid<T> extends MultiplicativeSemigroup<T> {
	readonly one: T
}

export interface MultiplicativeGroup<T> extends MultiplicativeMonoid<T> {
	readonly inv: (a: T) => T
	readonly div: (a: T, b: T) => T
}

export interface Ring<T> extends Eq<T>, AdditiveGroup<T>, MultiplicativeMonoid<T> {
	// Distributivity is an assumed law; not encoded at type level
}

export interface CommutativeRing<T> extends Ring<T> {
	// Multiplication is commutative (assumed law)
}

export interface Field<T> extends CommutativeRing<T>, MultiplicativeGroup<T> {
	readonly exp: (base: T, exponent: T) => T
}

export interface FiniteField<T> extends Field<T>, Membership<T> {
	readonly modulus: bigint
	// Optional helpers specific to modulo representations
	readonly mod?: (a: T) => T
	// Back-compat alias
	readonly isInField?: (a: T) => boolean

  // Vector creation
  newVector(length: number): Vector<T>
  newVectorFrom(values: ReadonlyArray<T>): Vector<T>
  pluckVector(v: Vector<T>, skip: number, times: number): Vector<T>
  truncateVector(v: Vector<T>, newLength: number): Vector<T>
  duplicateVector(v: Vector<T>, times?: number): Vector<T>

  // Vector element-wise ops
  addVectorElements(a: Vector<T>, b: T | Vector<T>): Vector<T>
  subVectorElements(a: Vector<T>, b: T | Vector<T>): Vector<T>
  mulVectorElements(a: Vector<T>, b: T | Vector<T>): Vector<T>
  divVectorElements(a: Vector<T>, b: T | Vector<T>): Vector<T>
  expVectorElements(a: Vector<T>, b: T | Vector<T>): Vector<T>
  invVectorElements(v: Vector<T>): Vector<T>
  negVectorElements(v: Vector<T>): Vector<T>

  // Vector combinations
  combineVectors(a: Vector<T>, b: Vector<T>): T
  combineManyVectors(vectors: ReadonlyArray<Vector<T>>, coeffs: Vector<T>): Vector<T>

  // Matrix creation
  newMatrix(rows: number, cols: number): Matrix<T>
  newMatrixFrom(values: ReadonlyArray<ReadonlyArray<T>>): Matrix<T>
  vectorToMatrix(v: Vector<T>, columns: number): Matrix<T>

  // Matrix element-wise ops
  addMatrixElements(a: Matrix<T>, b: T | Matrix<T>): Matrix<T>
  subMatrixElements(a: Matrix<T>, b: T | Matrix<T>): Matrix<T>
  mulMatrixElements(a: Matrix<T>, b: T | Matrix<T>): Matrix<T>
  divMatrixElements(a: Matrix<T>, b: T | Matrix<T>): Matrix<T>
  expMatrixElements(a: Matrix<T>, b: T | Matrix<T>): Matrix<T>
  invMatrixElements(m: Matrix<T>): Matrix<T>
  negMatrixElements(m: Matrix<T>): Matrix<T>

  // Matrix algebra
  mulMatrixes(a: Matrix<T>, b: Matrix<T>): Matrix<T>
  mulMatrixByVector(m: Matrix<T>, v: Vector<T>): Vector<T>
  mulMatrixRows(m: Matrix<T>, v: Vector<T>): Matrix<T>
  matrixRowsToVectors(m: Matrix<T>): Vector<T>[]

  // Polynomial operations (polynomials encoded as vectors, coeffs in reverse order)
  addPolys(a: Vector<T>, b: Vector<T>): Vector<T>
  subPolys(a: Vector<T>, b: Vector<T>): Vector<T>
  mulPolys(a: Vector<T>, b: Vector<T>): Vector<T>
  divPolys(a: Vector<T>, b: Vector<T>): Vector<T>
  mulPolyByConstant(p: Vector<T>, c: T): Vector<T>

  // Polynomial evaluation and interpolation
  evalPolyAt(p: Vector<T>, x: T): T
  evalPolyAtRoots(p: Vector<T>, rootsOfUnity: Vector<T>): Vector<T>
  evalPolysAtRoots(p: Matrix<T>, rootsOfUnity: Vector<T>): Matrix<T>
  evalQuarticBatch(polys: Matrix<T>, x: T | Vector<T>): Vector<T>
  interpolate(xs: Vector<T>, ys: Vector<T>): Vector<T>
  interpolateRoots(rootsOfUnity: Vector<T>, ys: Vector<T> | Matrix<T>): Vector<T> | Matrix<T>
  interpolateQuarticBatch(xSets: Matrix<T>, ySets: Matrix<T>): Matrix<T>

  // Misc
  rand(): T
  prng(seed: T | Uint8Array, length?: number): Vector<T> | T
  getRootOfUnity(order: number): T
  getPowerSeries(base: T, length: number): Vector<T>
}

export interface Group<G, S> {
  add(a: G, b: G): G
  sub(a: G, b: G): G
  neg(a: G): G
  eq(a: G, b: G): boolean
  identity(): G
  scalarMul(element: G, scalar: S): G
  field: Field<S>
}

export interface Vector<T> {
  readonly length: number
  // Galois-style accessors
  getValue(index: number): T
  toValues(): ReadonlyArray<T>
  // Convenience accessors
  get(index: number): T
  set(index: number, value: T): Vector<T>
  toArray(): ReadonlyArray<T>
  [Symbol.iterator](): IterableIterator<T>
}

export interface Matrix<T> {
  readonly rows: number
  readonly cols: number
  // Galois-style accessors
  getValue(row: number, col: number): T
  toValues(): ReadonlyArray<ReadonlyArray<T>>
  // Convenience accessors
  get(row: number, col: number): T
  set(row: number, col: number, value: T): Matrix<T>
  row(index: number): Vector<T>
  col(index: number): Vector<T>
}

export interface Polynomial<T> {
	readonly coefficients: ReadonlyArray<T>
	readonly degree: number
	readonly evaluate: (x: T) => T
	readonly add: (other: Polynomial<T>) => Polynomial<T>
	readonly sub: (other: Polynomial<T>) => Polynomial<T>
	readonly mul: (other: Polynomial<T>) => Polynomial<T>
	readonly div: (other: Polynomial<T>) => Polynomial<T>
}

export interface Tensor<T> {
	readonly shape: number[]
	readonly values: ReadonlyArray<T>
	readonly get: (indices: number[]) => T
	readonly set: (indices: number[], value: T) => void
}
