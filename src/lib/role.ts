import {
	iknpSenderRound1,
	iknpReceiverRound1,
	iknpSenderRound2,
	type IKNPSenderState,
	type IKNPSenderMessage1,
	type IKNPReceiverState,
	type IKNPReceiverMessage1,
	type IKNPReceiverOutput,
	type IKNPSenderOutput,
} from './iknp.js'
import { BitVector, BitMatrix, scalarFromBits, ensureInjectiveBitLength } from './bits.js'
import { concat } from './bytes.js'
import { N, mod, bytesToBigInt, bigIntToBytes, hash, randomScalar } from './crypto.js'
import { deriveOTParams, type OTParams } from './ot.js'
import {
	beaverEncryptFromRandomOT,
	beaverDecryptFromRandomOT,
} from './beaver.js'

/**
 * Random Oblivious Linear Evaluation (ROLE) built on top of IKNP random OT using a
 * simple bit‑decomposition construction.
 *
 * This file exposes:
 *
 *   1. A **round‑based precomputation API** that mirrors `iknp.ts`:
 *        - `roleSenderRound1`
 *        - `roleReceiverRound1` (random OLE)
 *        - `roleReceiverRound1WithInputs` (chosen-input OLE)
 *        - `roleSenderRound2`
 *      States and messages are captured in explicit interfaces.
 *   2. Convenience helpers:
 *        - `roleExtendRandom` - precompute a pool of random OLEs
 *        - `roleExtendWithInputs` - precompute a pool of chosen-input OLEs
 *   3. An online API (`roleSenderNext` / `roleReceiverNext`) that lets each
 *      side consume precomputed OLEs as needed.
 *
 * An individual OLE sample consists of:
 *   - Sender:   (a_i, b_i) ∈ F_N^2
 *   - Receiver: (x_i, y_i) ∈ F_N^2  with  y_i = a_i * x_i + b_i (mod N)
 *
 * **Random OLE**: The receiver's inputs x_i are derived from random IKNP choice
 * bits via fixed‑width bit decomposition, so x_i is uniformly random and hidden
 * from the sender.
 *
 * **Chosen-input OLE**: The receiver can specify x_i values, which are encoded
 * into choice bits. The sender still doesn't learn x_i, and the receiver still
 * doesn't learn a_i or b_i.
 *
 * Higher‑level protocols can treat the resulting states as a reusable pool of
 * offline OLEs.
 */

// --- Public types ---------------------------------------------------------------------------

/**
 * Shared parameters for one ROLE precomputation.
 */
export interface ROLEParams {
	numOLEs: number
	bitLength: number
	k: number
	otParams: OTParams
}

/**
 * Sender state after ROLE round 1 (before deriving a_i, b_i).
 * Mirrors `IKNPSenderState` but scoped to ROLE parameters.
 */
export interface ROLESenderState1 {
	params: ROLEParams
	iknpState: IKNPSenderState
}

/**
 * Sender's first message in ROLE precomputation: wraps IKNP's first message
 * together with the ROLE parameters so the receiver can infer sizes.
 */
export interface ROLESenderMessage1 {
	params: ROLEParams
	iknp: IKNPSenderMessage1
}

/**
 * Receiver state after ROLE round 1.
 *
 * At this point the receiver has:
 *   - Its random choice bits (defining the x_i bit‑decomposition).
 *   - IKNP receiver state/output, from which x_i can be reconstructed.
 *   - A slot to later hold the precomputed x_i, y_i values.
 */
export interface ROLEReceiverState1 {
	params: ROLEParams
	iknpState: IKNPReceiverState
	iknpOutput: IKNPReceiverOutput
	choices: BitVector // length = numOLEs * bitLength
}

/**
 * Receiver's reply in ROLE precomputation: wraps IKNP's sender responses.
 */
export interface ROLEReceiverMessage1 {
	iknp: IKNPReceiverMessage1
}

/**
 * Sender's second message in ROLE precomputation: packed chosen‑OT ciphertexts
 * derived from IKNP random OT keys via Beaver's trick.
 *
 * For each extended OT index t ∈ {0,…,numOLEs * bitLength − 1}:
 *   - c0[t] encrypts the field element corresponding to choice bit 0.
 *   - c1[t] encrypts the field element corresponding to choice bit 1.
 */
export interface ROLESenderMessage2 {
	c0: Uint8Array[]
	c1: Uint8Array[]
}

/**
 * Sender-side long-lived state for a pool of precomputed random OLEs.
 */
export interface ROLESenderState {
	params: ROLEParams
	nextIndex: number
	a: bigint[] // coefficients a_i
	b: bigint[] // offsets b_i
}

/**
 * Receiver-side long-lived state for a pool of precomputed random OLEs.
 */
export interface ROLEReceiverState {
	params: ROLEParams
	nextIndex: number
	x: bigint[] // inputs x_i
	y: bigint[] // outputs y_i = a_i * x_i + b_i
}

/**
 * One OLE instance as seen by the sender during the online phase.
 */
export interface ROLESenderOLE {
	index: number
	a: bigint
	b: bigint
}

/**
 * One OLE instance as seen by the receiver during the online phase.
 */
export interface ROLEReceiverOLE {
	index: number
	x: bigint
	y: bigint
}

// --- Local helpers --------------------------------------------------------------------------

const ROLE_OT_TAG = new TextEncoder().encode('role-ot')

function scalarFromSeed(tag: string, seed: Uint8Array): bigint {
	const tagBytes = new TextEncoder().encode(tag)
	const h = hash(concat(tagBytes, seed))
	return mod(bytesToBigInt(h), N)
}

/**
 * Encode chosen scalar inputs x_i into choice bits for IKNP.
 *
 * For each OLE i, encodes x_i as a bitLength-bit little-endian representation.
 * The resulting BitVector has length = numOLEs * bitLength.
 *
 * @param xs Array of numOLEs scalar values, each in [0, 2^bitLength)
 * @param numOLEs Number of OLE instances
 * @param bitLength Bit width for encoding each x_i
 */
function encodeInputsToChoices(
	xs: bigint[],
	numOLEs: number,
	bitLength: number,
): BitVector {
	if (xs.length !== numOLEs) {
		throw new Error('encodeInputsToChoices: xs.length must equal numOLEs')
	}
	const maxVal = 1n << BigInt(bitLength)
	const totalBits = numOLEs * bitLength
	const choices = new BitVector(totalBits)

	for (let i = 0; i < numOLEs; i++) {
		const x = xs[i]!
		if (x < 0n || x >= maxVal) {
			throw new Error('encodeInputsToChoices: x out of range for configured bitLength')
		}
		let v = x
		for (let j = 0; j < bitLength; j++) {
			const bit = Number(v & 1n) as 0 | 1
			if (bit) {
				choices.set(i * bitLength + j, 1)
			}
			v >>= 1n
		}
	}

	return choices
}

// --- ROLE precomputation rounds (offline phase) ----------------------------------------------

/**
 * ROLE sender round 1:
 *   - Choose IKNP selector bits and start `numOTs = numOLEs * bitLength` base OTs.
 */
export function roleSenderRound1(
	params: ROLEParams,
): { state: ROLESenderState1, message: ROLESenderMessage1 } {
	const { numOLEs, bitLength, k, otParams } = params
	if (numOLEs <= 0) throw new Error('roleSenderRound1: numOLEs must be positive')
	ensureInjectiveBitLength(bitLength)
	if (k <= 0) throw new Error('roleSenderRound1: k must be positive')

	const totalOTs = numOLEs * bitLength
	const { state: iknpState, message: iknpMsg } = iknpSenderRound1(totalOTs, k, otParams)

	return {
		state: { params, iknpState },
		message: { params, iknp: iknpMsg },
	}
}

/**
 * ROLE receiver round 1 (random OLE):
 *   - Sample random choice bits for all `numOLEs * bitLength` extended OTs.
 *   - Run IKNP receiver round 1 using the sender's base OT messages.
 *
 * The receiver already knows its choice bits and IKNP output; these will later
 * be turned into x_i and y_i when we derive the final ROLE pool.
 *
 * This function implements **random OLE** where x_i values are uniformly random.
 */
export function roleReceiverRound1(
	params: ROLEParams,
	senderMsg: ROLESenderMessage1,
): { state: ROLEReceiverState1, message: ROLEReceiverMessage1 } {
	return roleReceiverRound1WithInputs(params, senderMsg, undefined)
}

/**
 * ROLE receiver round 1 with chosen inputs (chosen-input OLE):
 *   - Encode provided x_i values into choice bits for IKNP.
 *   - Run IKNP receiver round 1 using the sender's base OT messages.
 *
 * If `xs` is provided, implements **chosen-input OLE** where the receiver
 * specifies x_i values. If `xs` is undefined, falls back to random OLE.
 *
 * @param params ROLE parameters
 * @param senderMsg Sender's first message
 * @param xs Optional array of numOLEs scalar values in [0, 2^bitLength).
 *           If undefined, uses random inputs (random OLE).
 */
export function roleReceiverRound1WithInputs(
	params: ROLEParams,
	senderMsg: ROLESenderMessage1,
	xs?: bigint[],
): { state: ROLEReceiverState1, message: ROLEReceiverMessage1 } {
	const { numOLEs, bitLength, k, otParams } = params
	if (numOLEs <= 0) throw new Error('roleReceiverRound1: numOLEs must be positive')
	ensureInjectiveBitLength(bitLength)
	if (k <= 0) throw new Error('roleReceiverRound1: k must be positive')
	if (senderMsg.params.numOLEs !== numOLEs || senderMsg.params.bitLength !== bitLength || senderMsg.params.k !== k) {
		throw new Error('roleReceiverRound1: sender parameters mismatch')
	}

	const totalOTs = numOLEs * bitLength

	// Encode chosen inputs to choice bits, or use random if not provided
	const choices = xs !== undefined
		? encodeInputsToChoices(xs, numOLEs, bitLength)
		: undefined

	const { state: iknpState, message: iknpMsg, output } = iknpReceiverRound1(
		totalOTs,
		senderMsg.iknp,
		otParams,
		choices,
	)

	const recvState: ROLEReceiverState1 = {
		params,
		iknpState,
		iknpOutput: output,
		choices: output.choices,
	}

	const message: ROLEReceiverMessage1 = {
		iknp: iknpMsg,
	}

	return { state: recvState, message }
}

/**
 * ROLE sender round 2:
 *   - Finish IKNP extension using the receiver's base OT responses.
 *   - Use the resulting random OT keys to implement chosen OTs (Beaver's trick)
 *     that realize a bit‑decomposed random OLE:
 *
 *       For each OLE i and bit j:
 *         - Receiver's choice bit is x_{i,j}.
 *         - Sender prepares (m0, m1) = (r_{i,j}, r_{i,j} + 2^j a_i).
 *         - Receiver learns exactly one value m_{x_{i,j}}.
 *
 *       With b_i = Σ_j r_{i,j} and x_i = Σ_j x_{i,j} 2^j we obtain
 *         y_i = Σ_j m_{x_{i,j}} = b_i + a_i x_i  (mod N).
 *
 * Returns:
 *   - A long‑lived sender ROLE state holding (a_i, b_i).
 *   - A second message with all chosen‑OT ciphertexts for the receiver.
 */
export function roleSenderRound2(
	state1: ROLESenderState1,
	receiverMsg: ROLEReceiverMessage1,
): { state: ROLESenderState, message: ROLESenderMessage2 } {
	const { numOLEs, bitLength, k, otParams } = state1.params
	const totalOTs = numOLEs * bitLength

	const iknpOut: IKNPSenderOutput = iknpSenderRound2(state1.iknpState, receiverMsg.iknp, otParams)

	if (iknpOut.k0.length !== totalOTs || iknpOut.k1.length !== totalOTs) {
		throw new Error('roleSenderRound2: IKNP sender output size mismatch')
	}

	const aArr = new Array<bigint>(numOLEs)
	const bArr = new Array<bigint>(numOLEs)
	const m0Arr = new Array<Uint8Array>(totalOTs)
	const m1Arr = new Array<Uint8Array>(totalOTs)

	// Use a binary linear code-style PRG seeded from IKNP keys to derive all
	// per‑bit masks r_{i,j} in a VOLE‑style way.
	const seedR = hash(
		concat(
			ROLE_OT_TAG,
			iknpOut.k0[0]!,
			iknpOut.k1[0]!,
		),
	)
	const Rmat = BitMatrix.random(totalOTs, 256, seedR)

	let otIndex = 0
	for (let i = 0; i < numOLEs; i++) {
		const base = i * bitLength

		// Per‑OLE coefficient derived from IKNP sender keys for the first OT in this block.
		const seedA = concat(iknpOut.k0[base], iknpOut.k1[base])
		const a = scalarFromSeed('role-a', seedA)
		aArr[i] = a

		let b = 0n

		for (let j = 0; j < bitLength; j++, otIndex++) {
			const k0 = iknpOut.k0[otIndex]!
			const k1 = iknpOut.k1[otIndex]!

			// Sender-only random mask r_{i,j} derived from the PRG-backed
			// binary matrix row corresponding to this extended OT.
			const rowBits = Rmat.row(otIndex)
			const r = mod(bytesToBigInt(rowBits.data), N)

			const twoPowJ = 1n << BigInt(j)
			const m0 = r
			const m1 = mod(r + a * twoPowJ, N)

			b = mod(b + r, N)

			const m0Bytes = bigIntToBytes(mod(m0, N), 32)
			const m1Bytes = bigIntToBytes(mod(m1, N), 32)

			m0Arr[otIndex] = m0Bytes
			m1Arr[otIndex] = m1Bytes
		}

		bArr[i] = b
	}

	const { c0, c1 } = beaverEncryptFromRandomOT(
		iknpOut.k0,
		iknpOut.k1,
		m0Arr,
		m1Arr,
		ROLE_OT_TAG,
	)

	const state: ROLESenderState = {
		params: state1.params,
		nextIndex: 0,
		a: aArr,
		b: bArr,
	}
	const message: ROLESenderMessage2 = {
		c0,
		c1,
	}

	return { state, message }
}

/**
 * ROLE receiver round 2:
 *   - Given the receiver's IKNP output and the sender's chosen‑OT ciphertexts,
 *     recover per‑bit field elements and aggregate them into x_i, y_i.
 *
 * The receiver learns:
 *   - x_i from its choice bits (bit‑decomposition).
 *   - y_i = a_i * x_i + b_i via the OT‑protected field elements.
 * The sender never learns x_i, and the receiver never learns a_i or b_i.
 */
export function roleReceiverRound2(
	state1: ROLEReceiverState1,
	senderMsg: ROLESenderMessage2,
): ROLEReceiverState {
	const { numOLEs, bitLength } = state1.params
	const totalOTs = numOLEs * bitLength

	const { choices, iknpOutput } = state1

	if (choices.length !== totalOTs) {
		throw new Error('roleReceiverRound2: invalid choices length')
	}
	if (iknpOutput.keys.length !== totalOTs) {
		throw new Error('roleReceiverRound2: IKNP receiver keys size mismatch')
	}
	if (senderMsg.c0.length !== totalOTs || senderMsg.c1.length !== totalOTs) {
		throw new Error('roleReceiverRound2: sender ciphertext size mismatch')
	}

	const xArr = new Array<bigint>(numOLEs)
	const yArr = new Array<bigint>(numOLEs)

	// Recover all per-bit masked field elements m_{x_{i,j}} via Beaver wrapper.
	const perOtValues = beaverDecryptFromRandomOT(
		choices,
		iknpOutput.keys,
		senderMsg.c0,
		senderMsg.c1,
		ROLE_OT_TAG,
	)

	let otIndex = 0
	for (let i = 0; i < numOLEs; i++) {
		const base = i * bitLength
		const x = scalarFromBits(choices, base, bitLength)
		let y = 0n

		for (let j = 0; j < bitLength; j++, otIndex++) {
			const mBytes = perOtValues[otIndex]!
			const m = mod(bytesToBigInt(mBytes), N)
			y = mod(y + m, N)
		}

		xArr[i] = x
		yArr[i] = y
	}

	return {
		params: state1.params,
		nextIndex: 0,
		x: xArr,
		y: yArr,
	}
}

// --- Online phase: consume precomputed OLEs -------------------------------------------------

/**
 * Sender consumes the next available precomputed OLE from its pool.
 */
export function roleSenderNext(state: ROLESenderState): ROLESenderOLE {
	if (state.nextIndex >= state.params.numOLEs) {
		throw new Error('roleSenderNext: no precomputed OLEs left')
	}
	const index = state.nextIndex++
	return {
		index,
		a: state.a[index]!,
		b: state.b[index]!,
	}
}

/**
 * Receiver consumes the next available precomputed OLE from its pool.
 */
export function roleReceiverNext(state: ROLEReceiverState): ROLEReceiverOLE {
	if (state.nextIndex >= state.params.numOLEs) {
		throw new Error('roleReceiverNext: no precomputed OLEs left')
	}
	const index = state.nextIndex++
	return {
		index,
		x: state.x[index]!,
		y: state.y[index]!,
	}
}

/**
 * Convenience helper: locally simulate both parties to precompute a full pool
 * of random OLEs using the round‑based ROLE API.
 */
export function roleExtendRandom(
	params: ROLEParams,
): { sender: ROLESenderState, receiver: ROLEReceiverState } {
	const { state: senderState1, message: msg1 } = roleSenderRound1(params)
	const { state: receiverState1, message: msg2 } = roleReceiverRound1(params, msg1)
	const { state: senderState, message: msg3 } = roleSenderRound2(senderState1, msg2)
	const receiverState = roleReceiverRound2(receiverState1, msg3)
	return { sender: senderState, receiver: receiverState }
}

/**
 * Convenience helper: locally simulate both parties to precompute a pool of
 * chosen-input OLEs where the receiver specifies x_i values.
 *
 * @param params ROLE parameters
 * @param xs Array of numOLEs scalar values in [0, 2^bitLength) for the receiver's inputs
 */
export function roleExtendWithInputs(
	params: ROLEParams,
	xs: bigint[],
): { sender: ROLESenderState, receiver: ROLEReceiverState } {
	const { state: senderState1, message: msg1 } = roleSenderRound1(params)
	const { state: receiverState1, message: msg2 } = roleReceiverRound1WithInputs(params, msg1, xs)
	const { state: senderState, message: msg3 } = roleSenderRound2(senderState1, msg2)
	const receiverState = roleReceiverRound2(receiverState1, msg3)
	return { sender: senderState, receiver: receiverState }
}

