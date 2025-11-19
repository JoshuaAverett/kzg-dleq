import {
	P, N,
	ecAddress,
	ecMul, ecSub,
	GX, GY,
	isOnCurve,
	Point
} from './crypto.js'
import { buildChallenge } from './challenge.js'


/**
 * Simplified DLEQ proof carrying only essential data.
 * Points are provided in affine coordinates scalars are bigints.
 */
export interface DLEQProof {
	C: Point   // commitment point
	W: Point   // witness point
	P: Point   // public point s*G
	A1: Point  // Schnorr commitment zG - eW
	A2: Point  // Schnorr commitment zT - eC
	x: bigint  // evaluation point
	z: bigint  // response
}

/**
 * Minimal verifier for the DLEQ proof.
 * Accepts only the essential points and scalars and recomputes the rest.
 */
export function verifyProof(proof: DLEQProof): boolean {
	// Basic scalar range checks
	if (proof.x === 0n || proof.x >= N) return false
	if (proof.z === 0n || proof.z >= N) return false

	// Coordinate range checks
	const coords = [
		proof.C.x, proof.C.y,
		proof.W.x, proof.W.y,
		proof.P.x, proof.P.y,
		proof.A1.x, proof.A1.y,
		proof.A2.x, proof.A2.y,
	]
	if (coords.some(c => c >= P || c < 0n)) return false

	// On-curve checks
	if (!isOnCurve(proof.C.x, proof.C.y)) return false
	if (!isOnCurve(proof.W.x, proof.W.y)) return false
	if (!isOnCurve(proof.P.x, proof.P.y)) return false
	if (!isOnCurve(proof.A1.x, proof.A1.y)) return false
	if (!isOnCurve(proof.A2.x, proof.A2.y)) return false

	// Compute challenge using the same packing as on-chain
	const A1addr = ecAddress(proof.A1.x, proof.A1.y)
	const A2addr = ecAddress(proof.A2.x, proof.A2.y)
	const parity = Number((proof.C.y & 1n) | ((proof.W.y & 1n) << 1n))
	const e = buildChallenge(
		proof.C.x,
		proof.W.x,
		proof.P.x,
		proof.P.y,
		A1addr,
		A2addr,
		proof.x,
		parity
	)

	// Recompute relations:
	// A1 ?= zG - eW
	const [zGx, zGy] = ecMul(GX, GY, proof.z)
	const [eWx, eWy] = ecMul(proof.W.x, proof.W.y, e)
	const [A1x, A1y] = ecSub(zGx, zGy, eWx, eWy)
	if (A1x !== proof.A1.x || A1y !== proof.A1.y) return false

	// A2 ?= zT - eC, where T = P - X and X = xG
	const [Xx, Xy] = ecMul(GX, GY, proof.x)
	const [Tx, Ty] = ecSub(proof.P.x, proof.P.y, Xx, Xy)
	const [zTx, zTy] = ecMul(Tx, Ty, proof.z)
	const [eCx, eCy] = ecMul(proof.C.x, proof.C.y, e)
	const [A2x, A2y] = ecSub(zTx, zTy, eCx, eCy)
	if (A2x !== proof.A2.x || A2y !== proof.A2.y) return false

	return true
}
