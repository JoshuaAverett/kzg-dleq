import { otReceiverInit, otSenderEncrypt, otReceiverDecrypt } from './ot.js'
import type { OTReceiverMessage1, OTSenderMessage, OTReceiverState, OTParams } from './ot.js'
import { BitVector, BitMatrix } from './bits.js'
import { hash, randomScalar } from './crypto.js'

/**
 * IKNP OT extension (Random OT) built on top of the base OT in `ot.ts`.
 *
 * This implements the IKNP03 construction in its ROT (Random OT) form:
 *
 *   - From `k` base OTs, we derive `n` random OT instances.
 *   - The IKNP sender (Alice) obtains for each i:
 *       K0_i, K1_i  (two 32‑byte random keys per OT)
 *   - The IKNP receiver (Bob) chooses a bit r_i for each i and obtains:
 *       K_{r_i, i}  (one 32‑byte random key per OT)
 *
 * Note: This is Random OT (ROT), not Chosen Message OT (COT). The output
 * consists of random keys, not user-chosen messages. To convert to COT, the
 * sender can encrypt their chosen messages using these random keys (e.g., via
 * XOR or authenticated encryption) and send the ciphertexts to the receiver.
 *
 */

// --- Public types -----------------------------------------------------------------------------

/**
 * Sender's output for IKNP ROT: for each OT index i we have two 32‑byte keys.
 */
export interface IKNPSenderOutput {
	// Key for message 0 in OT i
	k0: Uint8Array[]
	// Key for message 1 in OT i
	k1: Uint8Array[]
}

/**
 * Receiver's output for IKNP ROT: for each OT index i, the chosen bit r_i and
 * the corresponding 32‑byte key k_i = K_{r_i, i}.
 */
export interface IKNPReceiverOutput {
	choices: BitVector   // length = n bits
	keys: Uint8Array[]   // length = n, 32‑byte keys
}

/**
 * Internal sender state after IKNP round 1.
 * Mirrors the style of `OTReceiverState` in `ot.ts`.
 */
export interface IKNPSenderState {
	numOTs: number
	k: number                    // number of base OTs / matrix columns
	c: BitVector                 // selector vector of length k
	baseState: OTReceiverState   // batched base OT receiver state over k columns
}

/**
 * Sender's first message: batched base OT receiver messages (one per column).
 */
export interface IKNPSenderMessage1 {
	baseMessage: OTReceiverMessage1    // batched base OT receiver messages
}

/**
 * Receiver state (not currently used in later rounds, but exposed for symmetry).
 */
export interface IKNPReceiverState {
	numOTs: number
	k: number                 // number of base OTs / matrix columns
	choices: BitVector        // normalized 0/1 choices, length = numOTs
	T: BitMatrix              // random matrix T ∈ {0,1}^{numOTs × k}
}

/**
 * Receiver's reply in IKNP: batched base OT sender responses (one per column).
 */
export interface IKNPReceiverMessage1 {
	baseResponses: OTSenderMessage[] // length = k
}

/**
 * Convenience helper: hash each row of a binary matrix with Keccak‑256.
 *
 * Returns an array of 32‑byte hashes, one per row.
 */
function hashMatrixRowsKeccak(matrix: BitMatrix): Uint8Array[] {
	const keys: Uint8Array[] = new Array(matrix.rows)
	for (let i = 0; i < matrix.rows; i++) {
		const rowBits: BitVector = matrix.row(i)
		keys[i] = hash(rowBits.data)
	}
	return keys
}

// --- Round‑isolated IKNP API ------------------------------------------------------------------

/**
 * IKNP round 1 (sender / Alice):
 *
 *   - Alice samples selector vector s ∈ {0,1}^k.
 *   - For each column j, she starts a base OT as receiver with choice bit s[j].
 *
 * The returned `IKNPSenderMessage1` bundles all base OT receiver messages;
 * the local `IKNPSenderState` keeps s and base OT receiver states for round 2.
 *
 * @param numOTs - Number of extended OTs to derive
 * @param k - Number of base OTs / columns in the IKNP matrix (security parameter)
 * @param params - Base OT parameters shared between both parties
 */
export function iknpSenderRound1(
	numOTs: number,
	k: number,
	params: OTParams,
): { state: IKNPSenderState, message: IKNPSenderMessage1 } {
	if (numOTs <= 0) {
		throw new Error('iknpSenderRound1: numOTs must be positive')
	}

	if (k <= 0) {
		throw new Error('iknpSenderRound1: k must be positive')
	}

	const c = BitVector.random(k)
	const { state: baseState, message: baseMessage } = otReceiverInit(c, params)

	const state: IKNPSenderState = {
		numOTs,
		k,
		c,
		baseState,
	}
	const message: IKNPSenderMessage1 = {
		baseMessage,
	}

	return { state, message }
}

/**
 * IKNP round 1 (receiver / Bob):
 *
 *   - Bob samples random choice bits r ∈ {0,1}^n for the extended OTs (for ROT),
 *     or uses provided choice bits (for flexibility in higher-level protocols).
 *   - For each column j, he samples a random column T[j] ∈ {0,1}^n and sets
 *       T'[j] = T[j] ⊕ r.
 *   - Using Alice's base OT messages, he acts as base OT sender with messages
 *       (T[j], T'[j]) to produce responses for each column.
 *   - From T, Bob can already derive his per‑row keys k_i = H(T_i).
 *
 * The returned `IKNPReceiverMessage1` bundles all base OT responses. Bob's
 * `IKNPReceiverOutput` is final; no further rounds are needed on his side.
 */
export function iknpReceiverRound1(
	numOTs: number,
	senderMsg: IKNPSenderMessage1,
	params: OTParams,
	choices?: BitVector,
): { state: IKNPReceiverState, message: IKNPReceiverMessage1, output: IKNPReceiverOutput } {
	if (numOTs <= 0) {
		throw new Error('iknpReceiverRound1: numOTs must be positive')
	}
	const k = senderMsg.baseMessage.Bx.length
	if (k <= 0) {
		throw new Error('iknpReceiverRound1: senderMsg must contain at least one base message')
	}

	// Sample random choice bits r ∈ {0,1}^n for Random OT, or use provided choices
	if (choices === undefined) {
		choices = BitVector.random(numOTs)
	} else if (choices.length !== numOTs) {
		throw new Error('iknpReceiverRound1: choices.length must equal numOTs')
	}

	// Random T ∈ {0,1}^{numOTs × k} in row‑major form
	const T = BitMatrix.random(numOTs, k)
	const m0s: Uint8Array[] = new Array(k)
	const m1s: Uint8Array[] = new Array(k)
	for (let j = 0; j < k; j++) {
		const TcolBits = T.column(j)
		const TprimeBits = TcolBits.xor(choices)
		m0s[j] = TcolBits.data
		m1s[j] = TprimeBits.data
	}
	const { responses } = otSenderEncrypt(senderMsg.baseMessage, m0s, m1s, params)

	// Bob's per‑row keys are H(T_i); delegate row hashing to linear_code helpers
	const receiverKeys: Uint8Array[] = hashMatrixRowsKeccak(T)

	const state: IKNPReceiverState = {
		numOTs,
		k,
		choices,
		T,
	}

	const message: IKNPReceiverMessage1 = {
		baseResponses: responses,
	}

	const output: IKNPReceiverOutput = {
		choices,
		keys: receiverKeys,
	}

	return { state, message, output }
}

/**
 * IKNP round 2 (sender / Alice):
 *
 *   - Given her round‑1 state (s, baseStates) and Bob's base OT responses,
 *     Alice reconstructs the matrix Q column‑wise via base OT decryption.
 *   - For each row i, she sets:
 *       t_i      = i‑th row of Q
 *       K0_i     = H(t_i)
 *       K1_i     = H(t_i ⊕ s)
 * @param params - Base OT parameters shared between both parties
 */
export function iknpSenderRound2(
	state: IKNPSenderState,
	receiverMsg: IKNPReceiverMessage1,
	params: OTParams,
): IKNPSenderOutput {
	const { numOTs, k, c, baseState } = state
	if (receiverMsg.baseResponses.length !== k) {
		throw new Error('iknpSenderRound2: unexpected number of base responses from receiver')
	}
	if (baseState.b.length !== k || baseState.choices.length !== k) {
		throw new Error('iknpSenderRound2: invalid sender state (baseState size)')
	}

	// Reconstruct Q ∈ {0,1}^{numOTs × k} from base OT decryption, column by column
	const Q = new BitMatrix(numOTs, k)
	const Qcols: Uint8Array[] = otReceiverDecrypt(baseState, receiverMsg.baseResponses, params)
	for (let j = 0; j < k; j++) {
		const QcolBytes = Qcols[j]!
		const expectedBytes = Math.ceil(numOTs / 8)
		if (QcolBytes.length !== expectedBytes) {
			throw new Error('iknpSenderRound2: unexpected column length from base OT')
		}
		const QcolBits = new BitVector(numOTs, QcolBytes)
		Q.setColumn(j, QcolBits)
	}

	const senderK0: Uint8Array[] = new Array(numOTs)
	const senderK1: Uint8Array[] = new Array(numOTs)

	for (let i = 0; i < numOTs; i++) {
		const tiBits = Q.row(i)
		const tiXorS = tiBits.xor(c)
		senderK0[i] = hash(tiBits.data)
		senderK1[i] = hash(tiXorS.data)
	}

	return {
		k0: senderK0,
		k1: senderK1,
	}
}

/**
 * Example function: locally simulate both sides of IKNP ROT in one call,
 * using the round‑isolated API above. This is useful for tests;
 * real protocols should use the explicit rounds.
 * @param params - Base OT parameters shared between both parties
 */
export function iknpExtend(
	numOTs: number,
	k: number,
	params: OTParams,
): { sender: IKNPSenderOutput, receiver: IKNPReceiverOutput } {
	const { state: senderState, message: msg1 } = iknpSenderRound1(numOTs, k, params)
	const { message: msg2, output: receiverOut } = iknpReceiverRound1(numOTs, msg1, params)
	const senderOut = iknpSenderRound2(senderState, msg2, params)
	return { sender: senderOut, receiver: receiverOut }
}
