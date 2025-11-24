import { randomBytes } from './bytes.js'
import { N, mod, hkdfKeccak } from './crypto.js'

/**
 * Bit-level utilities and compact vector / matrix types built on top of a
 * single dense Uint8Array backing store.
 *
 * We now pack bits densely: 8 bits per byte in little-endian bit order
 * (bit i is stored at byte[i >> 3], position (i & 7)). This keeps the public
 * API in terms of bit indexes, while making XOR and matrix operations
 * byte-oriented and easier to accelerate or port to WASM later.
 */

export class BitVector {
	readonly data: Uint8Array
	readonly length: number // number of bits

	constructor(length: number, data?: Uint8Array) {
		if (length < 0) throw new Error('BitVector: length must be non-negative')
		const byteLen = Math.ceil(length / 8)
		if (data && data.length !== byteLen) {
			throw new Error('BitVector: data length mismatch')
		}
		this.length = length
		this.data = data ?? new Uint8Array(byteLen)
	}

	static random(length: number): BitVector {
		// Generate packed random bits directly
		const byteLen = Math.ceil(length / 8)
		const bytes = randomBytes(byteLen)
		return new BitVector(length, bytes)
	}

	static fromBytes(bytes: Uint8Array): BitVector {
		// Interpret all bits in `bytes` as a bit-vector (length = 8 * bytes.length)
		return new BitVector(bytes.length * 8, bytes.slice())
	}

	get(i: number): boolean {
		if (i < 0 || i >= this.length) {
			throw new Error('BitVector.get: index out of range')
		}
		const byte = this.data[i >> 3]
		const bit = (byte >> (i & 7)) & 1
		return bit != 0
	}

	set(i: number, bit: boolean): void {
		if (i < 0 || i >= this.length) {
			throw new Error('BitVector.set: index out of range')
		}
		const idx = i >> 3
		const offset = i & 7
		const mask = 1 << offset
		if (bit) {
			this.data[idx] |= mask
		} else {
			this.data[idx] &= ~mask
		}
	}

	xor(other: BitVector): BitVector {
		if (other.length !== this.length) {
			throw new Error('BitVector.xor: length mismatch')
		}
		const out = xorBytes(this.data, other.data)
		return new BitVector(this.length, out)
	}
}

/**
 * XOR two equal-length byte arrays, returning a new Uint8Array with the result.
 */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
	if (a.length !== b.length) {
		throw new Error('xorBytes: length mismatch')
	}
	const out = new Uint8Array(a.length)
	for (let i = 0; i < a.length; i++) {
		out[i] = a[i] ^ b[i]
	}
	return out
}

/**
 * Require that a bit-length is positive and that \(2^{bitLength} < N\) so that
 * bit-decomposition into the scalar field F_N is injective.
 */
export function ensureInjectiveBitLength(bitLength: number): void {
	if (bitLength <= 0) {
		throw new Error('ROLE: bitLength must be positive')
	}
	const maxValue = 1n << BigInt(bitLength)
	if (maxValue >= N) {
		throw new Error('ROLE: bitLength too large; require 2^bitLength < N for injective mapping into F_N')
	}
}

/**
 * Interpret a slice of bits as a scalar in F_N via little‑endian bit
 * decomposition:
 *
 *   x = Σ_{j=0}^{bitLength-1} bit[offset + j] · 2^j  (mod N).
 *
 * If the requested range extends past the end of `choiceBits`, it is
 * truncated to the available length.
 */
export function scalarFromBits(choiceBits: BitVector, offset: number, bitLength: number): bigint {
	let x = 0n
	const maxBits = Math.min(bitLength, choiceBits.length - offset)
	for (let j = 0; j < maxBits; j++) {
		if (choiceBits.get(offset + j)) {
			x += 1n << BigInt(j)
		}
	}
	return mod(x, N)
}

/**
 * Simple row-major binary matrix backed by a single dense Uint8Array.
 *
 * Layout: data[row * cols + col] ∈ {0,1}.
 */
export class BitMatrix {
	readonly rows: number
	readonly cols: number
	readonly data: Uint8Array

	constructor(rows: number, cols: number, data?: Uint8Array) {
		if (rows < 0 || cols < 0) {
			throw new Error('BitMatrix: rows/cols must be non-negative')
		}
		const bits = rows * cols
		const byteLen = Math.ceil(bits / 8)
		if (data && data.length !== byteLen) {
			throw new Error('BitMatrix: data length mismatch')
		}
		this.rows = rows
		this.cols = cols
		this.data = data ?? new Uint8Array(byteLen)
	}

	static random(rows: number, cols: number, seed?: Uint8Array): BitMatrix {
		const bits = rows * cols
		const byteLen = Math.ceil(bits / 8)

		let vec: Uint8Array
		if (!seed) {
			// Purely random matrix
			vec = randomBytes(byteLen)
		} else {
			// Deterministic matrix derived from seed using HKDF(Keccak-256)
			const info = new Uint8Array(8)
			const view = new DataView(info.buffer)
			view.setUint32(0, rows, false)
			view.setUint32(4, cols, false)
			vec = hkdfKeccak(seed, new Uint8Array(0), info, byteLen)
		}

		return new BitMatrix(rows, cols, vec)
	}

	get(row: number, col: number): boolean {
		if (row < 0 || row >= this.rows || col < 0 || col >= this.cols) {
			throw new Error('BitMatrix.get: index out of range')
		}
		const bitIndex = row * this.cols + col
		const byte = this.data[bitIndex >> 3]
		const bit = (byte >> (bitIndex & 7)) & 1
		return bit != 0
	}

	set(row: number, col: number, bit: boolean): void {
		if (row < 0 || row >= this.rows || col < 0 || col >= this.cols) {
			throw new Error('BitMatrix.set: index out of range')
		}
		const bitIndex = row * this.cols + col
		const idx = bitIndex >> 3
		const offset = bitIndex & 7
		const mask = 1 << offset
		if (bit) {
			this.data[idx] |= mask
		} else {
			this.data[idx] &= ~mask
		}
	}

	/**
	 * Return a copy of the given row as a BitVector.
	 */
	row(row: number): BitVector {
		if (row < 0 || row >= this.rows) {
			throw new Error('BitMatrix.row: index out of range')
		}
		const bv = new BitVector(this.cols)
		for (let c = 0; c < this.cols; c++) {
			bv.set(c, this.get(row, c))
		}
		return bv
	}

	/**
	 * Overwrite the given row from a BitVector (length must equal `cols`).
	 */
	setRow(row: number, bits: BitVector): void {
		if (row < 0 || row >= this.rows) {
			throw new Error('BitMatrix.setRow: index out of range')
		}
		if (bits.length !== this.cols) {
			throw new Error('BitMatrix.setRow: BitVector length mismatch')
		}
		for (let c = 0; c < this.cols; c++) {
			this.set(row, c, bits.get(c))
		}
	}

	/**
	 * Return a copy of the given column as a BitVector.
	 */
	column(col: number): BitVector {
		if (col < 0 || col >= this.cols) {
			throw new Error('BitMatrix.column: index out of range')
		}
		const bv = new BitVector(this.rows)
		for (let r = 0; r < this.rows; r++) {
			bv.set(r, this.get(r, col))
		}
		return bv
	}

	/**
	 * Overwrite the given column from a BitVector (length must equal `rows`).
	 */
	setColumn(col: number, bits: BitVector): void {
		if (col < 0 || col >= this.cols) {
			throw new Error('BitMatrix.setColumn: index out of range')
		}
		if (bits.length !== this.rows) {
			throw new Error('BitMatrix.setColumn: BitVector length mismatch')
		}
		for (let r = 0; r < this.rows; r++) {
			this.set(r, col, bits.get(r))
		}
	}
}
