import {
	N,
	GX, GY,
	mod, modInverse,
	ecMul, ecSub,
	ecAddress,
	randomScalar,
	Field,
} from './crypto.js'
import type { DLEQProof } from '../types/index.js'
import { buildChallenge } from './challenge.js'

/**
 * Generate a simplified DLEQ proof carrying only the essential fields.
 * Keeps the same math but returns minimal data shape.
 */
export async function generateProof(
	x: bigint,
	p: bigint[],
	s: bigint,
): Promise<DLEQProof> {
	// Normalize coefficients and confirm p(x) = 0
	const p_norm = p.map(c => mod(c, N))
	const px = Field.evalPolyAt(Field.newVectorFrom(p_norm), x)
	if (px !== 0n) {
		throw new Error(`Polynomial does not evaluate to zero at x=${x}: p(${x}) = ${px}`)
	}

	// Compute p(s), commitment C, witness W, public point P
	const ps = Field.evalPolyAt(Field.newVectorFrom(p_norm), s)
	const [Cx, Cy] = ecMul(GX, GY, ps)
	const s_minus_x_inv = modInverse(mod(s - x, N), N)
	const w = mod(ps * s_minus_x_inv, N)
	const [Wx, Wy] = ecMul(GX, GY, w)
	const [Px, Py] = ecMul(GX, GY, s)

	// Nonce and commitments
	const kScalar = randomScalar()
	const [A1x, A1y] = ecMul(GX, GY, kScalar)
	const [Xx, Xy] = ecMul(GX, GY, x)
	const [Tx, Ty] = ecSub(Px, Py, Xx, Xy)
	const [A2x, A2y] = ecMul(Tx, Ty, kScalar)

	// Fiat–Shamir challenge using on-chain packing shape
	const A1addr = ecAddress(A1x, A1y)
	const A2addr = ecAddress(A2x, A2y)
	const parity = Number((Cy & 1n) | ((Wy & 1n) << 1n))
	const e = buildChallenge(Cx, Wx, Px, Py, A1addr, A2addr, x, parity)

	// Response
	const z = mod(kScalar + mod(e * w, N), N)

	return {
		C: { x: Cx, y: Cy },
		W: { x: Wx, y: Wy },
		P: { x: Px, y: Py },
		A1: { x: A1x, y: A1y },
		A2: { x: A2x, y: A2y },
		x,
		z,
	}
}
