import {
	GX,
	GY,
	ecMul,
	ecAdd,
	ecSub,
	ecAddress,
	Field,
	deterministicNonce,
	Point,
	N,
	isOnCurve,
	P as CURVE_P,
} from './crypto.js'
import type { DLEQProof } from './verifier.js'
import { buildChallenge } from './challenge.js'
import type { ROLESenderOLE, ROLEReceiverOLE } from './role.js'
import type { Vector } from '@guildofweavers/galois'

/**
 * VOLE-based variant of the threshold polynomial DLEQ prover.
 *
 * Design goal:
 *   - Same high-level semantics as `prover.ts` (prove that a polynomial with
 *     shared SRS evaluates to 0 at x, yielding the usual DLEQ proof).
 *   - Replace the explicit challenge/response round
 *       z_i = k_i + e * w_i
 *     with a single message from each node and an OLE-based online step at the
 *     aggregator.
 *
 * Usage model (high level, network-agnostic):
 *
 *   1. Offline, each node and the aggregator precompute a pool of OLE samples
 *      using `role.ts`, with the node in the **sender** role and the aggregator
 *      as **receiver**. For sample index i the parties hold:
 *         - Node (sender):   (a_i, b_i)
 *         - Aggregator (rec): (x_i, y_i) with y_i = a_i * x_i + b_i.
 *
 *   2. Online, for a *single* polynomial evaluation:
 *        - Each node:
 *            a) Runs `proverVoleStart` (this file) on its SRS share to obtain:
 *                 - local secrets w_i, k_i (kept private),
 *                 - a single OLE sender sample (a_i, b_i),
 *                 - a public message containing:
 *                       (C_i, W_i, A1_i, A2_i, Δw_i, Δk_i, oleIndex_i)
 *                 where:
 *                       Δw_i = w_i - a_i
 *                       Δk_i = k_i - b_i.
 *            b) Sends that *single* message to the aggregator.
 *
 *        - Aggregator:
 *            a) Aggregates all node messages to C, W, A1, A2 and computes the
 *               challenge e using `buildChallenge(...)`.
 *            b) For each node i, uses the precomputed OLE pool to obtain the
 *               receiver view (x_i, y_i) for the same oleIndex_i, with its
 *               own chosen input x_i = e (via the chosen-input OLE API).
 *            c) Recovers that node's response share as:
 *                    z_i = y_i + e * Δw_i + Δk_i
 *               since:
 *                    y_i      = a_i * e + b_i
 *                    Δw_i     = w_i - a_i
 *                    Δk_i     = k_i - b_i
 *                 so:
 *                    z_i = (a_i * e + b_i) + e * (w_i - a_i) + (k_i - b_i)
 *                        = e * w_i + k_i.
 *            d) Sums z = Σ_i z_i and outputs the final `DLEQProof`.
 *
 * Security sketch:
 *
 *   - Privacy of SRS shares:
 *       Each node's secrets (w_i, k_i) are masked by a *fresh* random pair
 *       (a_i, b_i) from OLE:
 *           Δw_i = w_i - a_i
 *           Δk_i = k_i - b_i.
 *       The aggregator learns only:
 *           (Δw_i, Δk_i, e, y_i = a_i * e + b_i),
 *       which is a single linear relation in the unknowns (a_i, b_i, w_i, k_i).
 *       Without reusing the same (a_i, b_i) at multiple challenge points, the
 *       aggregator cannot solve for w_i or k_i; many tuples produce the same
 *       observed values, so the node's SRS share remains hidden.
 *
 *   - One-time evaluation of z at e:
 *       If an OLE sample (a_i, b_i) is ever reused with the *same* node but a
 *       different input x', the aggregator could obtain two equations:
 *           y_i      = a_i * e  + b_i
 *           y'_i     = a_i * e' + b_i
 *       and solve for (a_i, b_i), which together with Δw_i, Δk_i would reveal
 *       (w_i, k_i). To prevent this, each OLE sample must be *single-use*.
 *       The OLE pool APIs (`oleSenderNext` / `oleReceiverNext`) are designed to
 *       be consumed monotonically; higher-level code MUST NOT reuse the same
 *       (oleIndex, a, b) with more than one challenge.
 *
 *   - Soundness:
 *       Once the aggregator fixes e (via Fiat–Shamir over C, W, P, A1, A2, x),
 *       each node's effective response share is still:
 *           z_i = k_i + e * w_i,
 *       exactly as in the two-round protocol in `prover.ts`. The masking via
 *       OLE is purely additive and cancels out in the algebra above, so the
 *       final DLEQ proof verified by `verifier.ts` has the same correctness
 *       guarantees, assuming the OLE is instantiated securely.
 */

// -----------------------------------------------------------------------------
// 1. Types mirroring `prover.ts`
// -----------------------------------------------------------------------------

/**
 * Sent to each node participating in the threshold proof.
 * Same as `PolyEvalProofStart` in `prover.ts`.
 */
export interface PolyEvalVoleStart {
	x: bigint
	p: Vector
	srsShare: Vector
	P: Point
}

/**
 * Node-local secret state for the VOLE-based prover.
 * NOTE: This state must never be revealed to the aggregator.
 */
export interface PolyEvalVoleState {
	// Schnorr nonce share for this node
	k: bigint
	// Quotient evaluation share for this node
	wi: bigint
	// OLE sample index (ties this node's masking to a unique OLE instance)
	oleIndex: number
	// Random masks from OLE (kept on the node)
	a: bigint
	b: bigint
}

/**
 * Single message sent from a node to the aggregator in the VOLE-based scheme.
 *
 * This replaces the pair of messages in the original protocol:
 *   - Round 1 share:  (C_i, W_i, A1_i, A2_i)
 *   - Round 2 share:  z_i = k_i + e * w_i
 *
 * Here we send once:
 *   - The same EC points as before.
 *   - Two masked scalars (Δw_i, Δk_i) tied to a specific OLE instance.
 */
export interface PolyEvalVoleShare {
	// EC points, identical to `PolyEvalProof` in `prover.ts`
	Ci: Point
	Wi: Point
	A1i: Point
	A2i: Point

	// Masked scalars: Δw_i = w_i - a_i, Δk_i = k_i - b_i
	deltaW: bigint
	deltaK: bigint

	// Index identifying which OLE sample (a_i, b_i) was used
	oleIndex: number
}

// -----------------------------------------------------------------------------
// 2. Node-side: prepare share + OLE masks (single outgoing message)
// -----------------------------------------------------------------------------

/**
 * Node-side VOLE prover entry point.
 *
 * Inputs:
 *   - message: polynomial, evaluation point, SRS share, and public point P = s*G.
 *   - oleSample: a single precomputed OLE sender sample (a, b) tied to some
 *                unique index. This should come from `roleSenderNext(...)` on
 *                the node's ROLE sender state.
 *
 * Outputs:
 *   - `state`:   node-local secrets (k, w_i, OLE masks); must be kept private.
 *   - `share`:   the single message the node sends to the aggregator.
 */
export async function proverVoleStart(
	message: PolyEvalVoleStart,
	oleSample: ROLESenderOLE,
): Promise<{ state: PolyEvalVoleState, share: PolyEvalVoleShare }> {
	// Compute ps_i = <p, s_share_pows>
	const degree = message.p.length - 1
	if (message.srsShare.length - 1 < degree) {
		throw new Error(
			`SRS share length ${message.srsShare.length} is less than polynomial degree ${degree}`,
		)
	}
	const srsTrunc = Field.truncateVector(message.srsShare, message.p.length)
	const psShare = Field.combineVectors(message.p, srsTrunc)

	// Compute quotient Q(X) = (P(X) - P(x)) / (X - x) as in `prover.ts`.
	const divisor = Field.newVectorFrom([Field.neg(message.x), 1n])
	const qVec = Field.divPolys(message.p, divisor)
	const srsForQ = Field.truncateVector(message.srsShare, qVec.length)
	const wi = Field.combineVectors(qVec, srsForQ)

	// Points for this share (independent of nonce and OLE)
	const [Cix, Ciy] = ecMul(GX, GY, psShare)
	const [Wix, Wiy] = ecMul(GX, GY, wi)

	// Per-node deterministic nonce from wi and context (same convention as `prover.ts`)
	const k = deterministicNonce(wi, [message.x, message.P.x, message.P.y, Cix, Wix])

	// OLE masks from the provided sender sample
	const { index: oleIndex, a, b } = oleSample

	// Masked secrets exposed to the aggregator
	const deltaW = Field.sub(wi, a)
	const deltaK = Field.sub(k, b)

	// Schnorr-style commitments, as in `prover.ts`
	const [A1ix, A1iy] = ecMul(GX, GY, k)
	const [Xx, Xy] = ecMul(GX, GY, message.x)
	const [Tx, Ty] = ecSub(message.P.x, message.P.y, Xx, Xy)
	const [A2ix, A2iy] = ecMul(Tx, Ty, k)

	const state: PolyEvalVoleState = {
		k,
		wi,
		oleIndex,
		a,
		b,
	}

	const share: PolyEvalVoleShare = {
		Ci: { x: Cix, y: Ciy },
		Wi: { x: Wix, y: Wiy },
		A1i: { x: A1ix, y: A1iy },
		A2i: { x: A2ix, y: A2iy },
		deltaW,
		deltaK,
		oleIndex,
	}

	return { state, share }
}

// -----------------------------------------------------------------------------
// 3. Aggregator-side: reconstruct z using VOLE shares and OLE outputs
// -----------------------------------------------------------------------------

/**
 * Aggregator helper: given all node shares and the corresponding OLE receiver
 * samples (for the same indices and a *single* challenge e), reconstruct the
 * final DLEQ proof.
 *
 * Preconditions (must be enforced by the caller):
 *   - Each `oleSample` corresponds to exactly one `share` (matching `oleIndex`).
 *   - The receiver's input x for each OLE sample is the same challenge e
 *     computed from the aggregated points (C, W, P, A1, A2, x).
 *   - Each OLE sample is used at most once (single-use).
 */
export function proverVoleFinalize(
	shares: PolyEvalVoleShare[],
	oleSamples: ROLEReceiverOLE[],
	x: bigint,
	P: Point,
): DLEQProof {
	if (shares.length === 0) {
		throw new Error('proverVoleFinalize: no shares provided')
	}
	if (oleSamples.length !== shares.length) {
		throw new Error('proverVoleFinalize: shares / OLE samples length mismatch')
	}

	// Map OLE samples by index for quick lookup
	const oleByIndex = new Map<number, ROLEReceiverOLE>()
	for (const s of oleSamples) {
		if (oleByIndex.has(s.index)) {
			throw new Error('proverVoleFinalize: duplicate OLE index')
		}
		oleByIndex.set(s.index, s)
	}

	// Aggregate points: C = sum Ci, W = sum Wi, A1 = sum A1i, A2 = sum A2i
	const sumPoints = (pts: Point[]): Point => {
		if (pts.length === 0) {
			throw new Error('proverVoleFinalize: empty point list')
		}
		let acc = pts[0]!
		for (let i = 1; i < pts.length; i++) {
			const p = pts[i]!
			const [nx, ny] = ecAdd(acc.x, acc.y, p.x, p.y)
			acc = { x: nx, y: ny }
		}
		return acc
	}

	const C = sumPoints(shares.map(s => s.Ci))
	const W = sumPoints(shares.map(s => s.Wi))
	const A1 = sumPoints(shares.map(s => s.A1i))
	const A2 = sumPoints(shares.map(s => s.A2i))

	// Basic scalar and point sanity checks mirroring `verifyProof`
	if (x === 0n || x >= N) {
		throw new Error('proverVoleFinalize: invalid x scalar')
	}

	const coords = [
		C.x, C.y,
		W.x, W.y,
		P.x, P.y,
		A1.x, A1.y,
		A2.x, A2.y,
	]
	if (coords.some(c => c >= CURVE_P || c < 0n)) {
		throw new Error('proverVoleFinalize: coordinate out of range')
	}

	if (!isOnCurve(C.x, C.y)) {
		throw new Error('proverVoleFinalize: C not on curve')
	}
	if (!isOnCurve(W.x, W.y)) {
		throw new Error('proverVoleFinalize: W not on curve')
	}
	if (!isOnCurve(P.x, P.y)) {
		throw new Error('proverVoleFinalize: P not on curve')
	}
	if (!isOnCurve(A1.x, A1.y)) {
		throw new Error('proverVoleFinalize: A1 not on curve')
	}
	if (!isOnCurve(A2.x, A2.y)) {
		throw new Error('proverVoleFinalize: A2 not on curve')
	}

	// Challenge e (same convention as `prover.ts` and `verifier.ts`)
	const A1addr = ecAddress(A1.x, A1.y)
	const A2addr = ecAddress(A2.x, A2.y)
	const parity = Number((C.y & 1n) | ((W.y & 1n) << 1n))
	const e = buildChallenge(C.x, W.x, P.x, P.y, A1addr, A2addr, x, parity)

	// Reconstruct per-node z_i and aggregate
	let z = 0n
	for (const share of shares) {
		const ole = oleByIndex.get(share.oleIndex)
		if (!ole) {
			throw new Error(`proverVoleFinalize: missing OLE sample for index ${share.oleIndex}`)
		}

		// Optional strictness: enforce that the OLE input x matches the challenge.
		if (ole.x !== e) {
			throw new Error('proverVoleFinalize: OLE sample x does not match challenge e')
		}

		// z_i = y_i + e * Δw_i + Δk_i
		const term = Field.add(
			ole.y,
			Field.add(Field.mul(e, share.deltaW), share.deltaK),
		)
		z = Field.add(z, term)
	}

	if (z === 0n || z >= N) {
		throw new Error('proverVoleFinalize: invalid aggregated z scalar')
	}

	const proof: DLEQProof = {
		C,
		W,
		P,
		A1,
		A2,
		x,
		z,
	}

	return proof
}
