import {
	GX, GY,
	ecMul, ecAdd, ecSub,
	ecAddress,
	Field,
	deterministicNonce,
} from './crypto.js'
import type { Point, DLEQProof } from '../types/index.js'
import type { Vector } from '@guildofweavers/galois'
import { buildChallenge } from './challenge.js'


// Sent to all nodes involved in the threshold proof
export interface PolyEvalProofStart {
	x: bigint
	p: Vector
	srsShare: Vector
	P: Point
}

// Local state for the prover for this round
// NOTE: This is secret and must not be revealed to any party.
export interface PolyEvalProofState {
	k: bigint
	wi: bigint
}

// After the nodes have computed their share of the proof, they send this to the aggregator
export interface PolyEvalProof {
	Ci: Point
	Wi: Point
	A1i: Point
	A2i: Point
}

// The aggregator computes the challenge and sends it to all nodes
export interface PolyEvalProofChallenge {
	// Inputs for aggregation (array of previous step outputs)
	shares: PolyEvalProof[]
	// Public context
	x: bigint
	P: Point
	// Aggregated values and challenge
	C: Point
	W: Point
	A1: Point
	A2: Point
	e: bigint
}

// The nodes compute their response and send it to the aggregator
export interface PolyEvalProofResponse {
	z: bigint
}

// The aggregator computes the final proof and sends it to the verifier
export interface PolyEvalProofFinal {
	// Inputs for finalization (array of previous step outputs)
	challenge: PolyEvalProofChallenge
	responses: PolyEvalProofResponse[]
	// Final proof for the verifier
	proof: DLEQProof
}

/**
 * Generate a per-node share for the DLEQ proof using an SRS share.
 * - p: polynomial coefficients vector a_0..a_d (mod N)
 * - x: evaluation point
 * - srsShare: vector containing additive shares of s^k for k=0..d
 * - P: public point s*G
 */
export async function proverStart(
	message: PolyEvalProofStart,
): Promise<{ message: PolyEvalProof, state: PolyEvalProofState }> {
	// Compute ps_i = <p, s_share_pows>
	const degree = message.p.length - 1
	if (message.srsShare.length - 1 < degree) {
		throw new Error(`SRS share length ${message.srsShare.length} is less than polynomial degree ${degree}`)
	}
	const srsTrunc = Field.truncateVector(message.srsShare, message.p.length)
	const psShare = Field.combineVectors(message.p, srsTrunc)

	// Compute quotient Q(X) = (P(X) - P(x)) / (X - x) using library poly ops.
	// Since polynomials are encoded as [a0, a1, ..., ad], divisor (X - x) is [-x, 1].
	const divisor = Field.newVectorFrom([Field.neg(message.x), 1n])
	const qVec = Field.divPolys(message.p, divisor)
	const srsForQ = Field.truncateVector(message.srsShare, qVec.length)
	const wi = Field.combineVectors(qVec, srsForQ)

	// Points for this share (independent of nonce)
	const [Cix, Ciy] = ecMul(GX, GY, psShare)
	const [Wix, Wiy] = ecMul(GX, GY, wi)

	// Per-node deterministic nonce derived from secret wi and context
	const k = deterministicNonce(wi, [message.x, message.P.x, message.P.y, Cix, Wix])
	const [A1ix, A1iy] = ecMul(GX, GY, k)

	// T = P - X
	const [Xx, Xy] = ecMul(GX, GY, message.x)
	const [Tx, Ty] = ecSub(message.P.x, message.P.y, Xx, Xy)
	const [A2ix, A2iy] = ecMul(Tx, Ty, k)

	return {
		state: { k, wi },
		message: {
			Ci: { x: Cix, y: Ciy },
			Wi: { x: Wix, y: Wiy },
			A1i: { x: A1ix, y: A1iy },
			A2i: { x: A2ix, y: A2iy },
		},
	}
}

/**
 * Aggregation: combine Ci, Wi, A1i, A2i and compute challenge e.
 */
export async function proverChallenge(
	message: PolyEvalProofChallenge,
): Promise<PolyEvalProofChallenge> {
	if (message.shares.length === 0) throw new Error('No shares provided')

	// Aggregate points: C = sum Ci, W = sum Wi, A1 = sum A1i, A2 = sum A2i
	const sumPoints = (pts: Point[]): Point => {
		let acc = pts[0]
		for (let i = 1; i < pts.length; i++) {
			const [nx, ny] = ecAdd(acc.x, acc.y, pts[i].x, pts[i].y)
			acc = { x: nx, y: ny }
		}
		return acc
	}

	const C = sumPoints(message.shares.map(s => s.Ci))
	const W = sumPoints(message.shares.map(s => s.Wi))
	const A1 = sumPoints(message.shares.map(s => s.A1i))
	const A2 = sumPoints(message.shares.map(s => s.A2i))

	// Challenge
	const A1addr = ecAddress(A1.x, A1.y)
	const A2addr = ecAddress(A2.x, A2.y)
	const parity = Number((C.y & 1n) | ((W.y & 1n) << 1n))
	const e = buildChallenge(C.x, W.x, message.P.x, message.P.y, A1addr, A2addr, message.x, parity)

	return { ...message, C, W, A1, A2, e }
}

/**
 * Round 2 (node): verify e against (C, W, A1, A2) and output z_i.
 * z_i = k_i + e * w_i (mod N).
 */
export function proverRespond(
	message: PolyEvalProofChallenge,
	state: PolyEvalProofState,
): PolyEvalProofResponse {
	const A1addr = ecAddress(message.A1.x, message.A1.y)
	const A2addr = ecAddress(message.A2.x, message.A2.y)
	const parity = Number((message.C.y & 1n) | ((message.W.y & 1n) << 1n))
	const e2 = buildChallenge(message.C.x, message.W.x, message.P.x, message.P.y, A1addr, A2addr, message.x, parity)
	if (e2 !== message.e) {
		throw new Error('Challenge mismatch; refusing to release z share')
	}
	const z = Field.add(state.k, Field.mul(message.e, state.wi))
	return { z }
}

/**
 * Aggregator helper: sum z_i shares and emit the final DLEQProof.
 */
export function proverFinalize(
	message: PolyEvalProofFinal,
): PolyEvalProofFinal {
	if (message.responses.length === 0) {
		throw new Error('No z-shares provided')
	}
	const zVec = Field.newVectorFrom(message.responses.map(r => r.z))
	const ones = Field.newVectorFrom(Array(message.responses.length).fill(1n))
	const z = Field.combineVectors(zVec, ones)
	const proof: DLEQProof = {
		C: message.challenge.C,
		W: message.challenge.W,
		P: message.challenge.P,
		A1: message.challenge.A1,
		A2: message.challenge.A2,
		x: message.challenge.x,
		z,
	}
	return { ...message, proof }
}
