import { GX, GY, randomScalar, ecdh, ecMul, ecAdd, ecSub, hkdfKeccak, isOnCurve, hash } from './crypto.js'
import { chacha20 } from '@noble/ciphers/chacha.js'
import { concat, bytesEqual, randomBytes } from './bytes.js'
import { BitVector } from './bits.js'

/**
 * This file implements a 1-out-of-2 OT closely following the “simplest OT”
 * protocol of Chou–Orlandi [CO15, ePrint 2015/267], adapted to secp256k1.
 *
 * We fix a long‑term sender secret a and public point A = a·G. The protocol:
 *   - Receiver with choice bit c picks random b and sends
 *       B = b·G         if c = 0
 *       B = A + b·G     if c = 1
 *   - Sender derives keys
 *       k0 = H( a·B )
 *       k1 = H( a·(B − A) )
 *     and encrypts M0, M1 under k0, k1.
 *   - Receiver derives k_c = H( b·A ) and decrypts only M_c.
 *
 * Security (1-out-of-2) follows from the CDH assumption, as in [CO15].
 */

// OT parameters shared between the two parties:
//   - `senderSk` is the long‑term sender secret a.
//   - `A = a·G` is the corresponding public point.
//
// Callers must construct parameters via `deriveOTParams` and pass them
// explicitly into all public APIs in this file.
export interface OTParams {
	senderSk: bigint
	A: {
		x: bigint
		y: bigint
	}
}

/**
 * Derive OT parameters (secret + public point) from a sender secret scalar.
 */
export function deriveOTParams(senderSk: bigint): OTParams {
	const [Ax, Ay] = ecMul(GX, GY, senderSk)
	return {
		senderSk,
		A: { x: Ax, y: Ay },
	}
}

/**
 * Receiver's first message in 1-out-of-2 OT protocol.
 *
 * In the Chou–Orlandi protocol this is the point B that encodes the choice bit.
 */
export interface OTReceiverMessage1 {
	Bx: bigint[]
	By: bigint[]
}

/**
 * Sender's response in 1-out-of-2 OT protocol: ciphertexts only.
 */
export interface OTSenderMessage {
	c0: Uint8Array
	c1: Uint8Array
	nonce0: Uint8Array
	nonce1: Uint8Array
	tag0: Uint8Array
	tag1: Uint8Array
}

/**
 * Receiver state for OT protocol
 */
export interface OTReceiverState {
	// Receiver secret scalars b_i
	b: bigint[]
	// Choice bits for each OT (length = n)
	choices: BitVector
	// Encoded points B_i = b_i·G  or  A + b_i·G
	Bx: bigint[]
	By: bigint[]
}

/**
 * Sender state for OT protocol
 */
export interface OTSenderState {}

// Note: Batched OT operations are exposed directly via vectorized functions
// (`otReceiverInit`, `otSenderEncrypt`, `otReceiverDecrypt`); no separate
// batch state wrappers are needed.

/**
 * Vectorized receiver init: run multiple independent OTs in parallel.
 *
 * @param choices - BitVector indicating which message to receive in each OT
 * @param params - OT parameters (sender secret/public)
 * @returns Batched receiver state and first message (struct-of-arrays)
 */
export function otReceiverInit(
	choices: BitVector,
	params: OTParams,
): { state: OTReceiverState, message: OTReceiverMessage1 } {
	const n = choices.length
	const bArr = new Array<bigint>(n)
	const BxArr = new Array<bigint>(n)
	const ByArr = new Array<bigint>(n)

	for (let i = 0; i < n; i++) {
		const bit = choices.get(i)
		const b = randomScalar()

		// Base point b·G
		const [bGx, bGy] = ecMul(GX, GY, b)

		// B = b·G           if choice = 0
		// B = A + b·G      if choice = 1
		let Bx = bGx
		let By = bGy
		if (bit) {
			;[Bx, By] = ecAdd(params.A.x, params.A.y, bGx, bGy)
		}

		bArr[i] = b
		BxArr[i] = Bx
		ByArr[i] = By
	}

	const state: OTReceiverState = {
		b: bArr,
		choices,
		Bx: BxArr,
		By: ByArr,
	}
	const message: OTReceiverMessage1 = {
		Bx: BxArr,
		By: ByArr,
	}

	return { state, message }
}

/**
 * Vectorized sender encrypt: process many base OTs in one call.
 *
 * @param message - Receiver messages (points B) for each OT (struct-of-arrays)
 * @param m0s - Array of first messages
 * @param m1s - Array of second messages
 * @param params - OT parameters (sender secret/public)
 * @returns Encrypted responses, one per OT
 */
export function otSenderEncrypt(
	message: OTReceiverMessage1,
	m0s: Uint8Array[],
	m1s: Uint8Array[],
	params: OTParams,
): { responses: OTSenderMessage[] } {
	const n = m0s.length
	if (m1s.length !== n || message.Bx.length !== n || message.By.length !== n) {
		throw new Error('otSenderEncrypt: length mismatch between messages and payload arrays')
	}

	const responses = new Array<OTSenderMessage>(n)

	for (let i = 0; i < n; i++) {
		const m0 = m0s[i]!
		const m1 = m1s[i]!

		const Bx = message.Bx[i]!
		const By = message.By[i]!

		// Basic validation of receiver point B to avoid invalid-curve attacks
		if (!isOnCurve(Bx, By)) {
			throw new Error('OT sender: receiver point B is not on curve')
		}

		// B - A
		const [BminusAx, BminusAy] = ecSub(Bx, By, params.A.x, params.A.y)

		// Shared secrets using sender secret a and points B, B-A:
		//   s0 = a·B
		//   s1 = a·(B − A)
		const s0 = ecdh(params.senderSk, Bx, By)
		const s1 = ecdh(params.senderSk, BminusAx, BminusAy)

		// Derive encryption and MAC keys from shared secrets
		const salt = new Uint8Array(0)
		const info = new TextEncoder().encode('ot-key-derivation')
		const keyMat0 = hkdfKeccak(s0, salt, info, 64)
		const keyMat1 = hkdfKeccak(s1, salt, info, 64)
		const key0 = keyMat0.slice(0, 32)   // ChaCha20 key
		const macKey0 = keyMat0.slice(32)   // MAC key
		const key1 = keyMat1.slice(0, 32)
		const macKey1 = keyMat1.slice(32)
		
		// Generate random nonces (12 bytes for ChaCha20)
		const nonce0 = randomBytes(12)
		const nonce1 = randomBytes(12)
		
		// Encrypt messages using ChaCha20 (stream cipher, encryption = decryption)
		const c0 = chacha20(key0, nonce0, m0)
		const c1 = chacha20(key1, nonce1, m1)

		// Compute MAC tags over (nonce || ciphertext) using Keccak-256
		const tag0 = hash(concat(macKey0, nonce0, c0))
		const tag1 = hash(concat(macKey1, nonce1, c1))
		
		responses[i] = {
			c0,
			c1,
			nonce0,
			nonce1,
			tag0,
			tag1,
		}
	}

	return { responses }
}

/**
 * Vectorized receiver decrypt: decrypt many OTs in one call.
 *
 * @param state - Batched receiver state from `otReceiverInit`
 * @param responses - Per-OT sender responses from `otSenderEncrypt`
 * @param params - OT parameters (sender secret/public); uses internal default if omitted
 * @returns Decrypted messages, one per OT
 */
export function otReceiverDecrypt(
	state: OTReceiverState,
	responses: OTSenderMessage[],
	params: OTParams,
): Uint8Array[] {
	const n = responses.length
	if (state.b.length !== n || state.Bx.length !== n || state.By.length !== n || state.choices.length !== n) {
		throw new Error('otReceiverDecrypt: length mismatch between state and responses')
	}

	const out: Uint8Array[] = new Array(n)

	for (let i = 0; i < n; i++) {
		const response = responses[i]!	

		const choiceBit = state.choices.get(i)
		const cb = choiceBit ? response.c1 : response.c0
		const nonceb = choiceBit ? response.nonce1 : response.nonce0
		const tagb = choiceBit ? response.tag1 : response.tag0
		
		// Compute shared secret: sb = ECDH(b_i, A) = b_i·A
		const sb = ecdh(state.b[i]!, params.A.x, params.A.y)
		
		// Derive decryption and MAC keys
		const salt = new Uint8Array(0)
		const info = new TextEncoder().encode('ot-key-derivation')
		const keyMat = hkdfKeccak(sb, salt, info, 64)
		const keyb = keyMat.slice(0, 32)
		const macKey = keyMat.slice(32)

		// Verify MAC tag before decryption
		const expectedTag = hash(concat(macKey, nonceb, cb))
		if (!bytesEqual(expectedTag, tagb)) {
			throw new Error('OT receiver: MAC verification failed')
		}
		
		// Decrypt message using ChaCha20 (stream cipher, encryption = decryption)
		const mb = chacha20(keyb, nonceb, cb)
		out[i] = mb
	}

	return out
}


/**
 * Complete 1-out-of-2 OT protocol execution.
 * Example function that runs the full protocol.
 * 
 * @param choices - Receiver's choice bits as a BitVector
 * @param m0s - First messages (one per OT)
 * @param m1s - Second messages (one per OT)
 * @param params - OT parameters (sender secret/public)
 * @returns Decrypted messages, one per OT
 */
export function otExecute(
	choices: BitVector,
	m0s: Uint8Array[],
	m1s: Uint8Array[],
	params: OTParams,
): Uint8Array[] {
	const { state, message } = otReceiverInit(choices, params)
	const { responses } = otSenderEncrypt(message, m0s, m1s, params)
	return otReceiverDecrypt(state, responses, params)
}

