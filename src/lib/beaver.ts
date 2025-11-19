import { BitVector, xorBytes } from './bits.js'
import { concat } from './bytes.js'
import { hash } from './crypto.js'

/**
 * Helpers for converting IKNP-style random OT keys into chosen OTs using
 * Beaver's trick.
 *
 * Given:
 *   - Sender holds per-OT random keys (k0[i], k1[i]).
 *   - Receiver holds for each OT an index bit c[i] and the corresponding key
 *     k_{c[i]}[i].
 *
 * We can implement a 1-out-of-2 OT on arbitrary payloads m0[i], m1[i] by
 * masking them with hashes of the random OT keys:
 *
 *   ct0[i] = m0[i] ⊕ H(tag || k0[i])
 *   ct1[i] = m1[i] ⊕ H(tag || k1[i])
 *
 * The receiver picks ct_{c[i]}[i] and unmasks it using its key k_{c[i]}[i].
 */

/**
 * Sender-side wrapper: convert random OT keys into chosen OTs for payloads
 * `m0[i]`, `m1[i]`.
 *
 * All arrays must have the same length.
 */
export function beaverEncryptFromRandomOT(
	k0: Uint8Array[],
	k1: Uint8Array[],
	m0: Uint8Array[],
	m1: Uint8Array[],
	tag: Uint8Array,
): { c0: Uint8Array[]; c1: Uint8Array[] } {
	const n = k0.length
	if (k1.length !== n || m0.length !== n || m1.length !== n) {
		throw new Error('beaverEncryptFromRandomOT: array length mismatch')
	}

	const c0 = new Array<Uint8Array>(n)
	const c1 = new Array<Uint8Array>(n)

	for (let i = 0; i < n; i++) {
		const m0i = m0[i]!
		const m1i = m1[i]!

		const mask0 = hash(concat(tag, k0[i]!))
		const mask1 = hash(concat(tag, k1[i]!))

		if (mask0.length !== m0i.length || mask1.length !== m1i.length) {
			throw new Error('beaverEncryptFromRandomOT: mask length mismatch')
		}

		c0[i] = xorBytes(m0i, mask0)
		c1[i] = xorBytes(m1i, mask1)
	}

	return { c0, c1 }
}

/**
 * Receiver-side wrapper: given random OT output keys and Beaver ciphertexts,
 * recover the chosen messages for each OT.
 *
 * `choices[i]` determines whether `c0[i]` or `c1[i]` is selected; `keys[i]`
 * must hold the corresponding random OT key k_{choices[i]}.
 *
 * All arrays must have the same length.
 */
export function beaverDecryptFromRandomOT(
	choices: BitVector,
	keys: Uint8Array[],
	c0: Uint8Array[],
	c1: Uint8Array[],
	tag: Uint8Array,
): Uint8Array[] {
	const n = choices.length
	if (keys.length !== n || c0.length !== n || c1.length !== n) {
		throw new Error('beaverDecryptFromRandomOT: array length mismatch')
	}

	const out = new Array<Uint8Array>(n)

	for (let i = 0; i < n; i++) {
		const choice = choices.get(i)
		const key = keys[i]!
		const ct = choice === 0 ? c0[i]! : c1[i]!

		const mask = hash(concat(tag, key))
		if (mask.length !== ct.length) {
			throw new Error('beaverDecryptFromRandomOT: mask length mismatch')
		}

		out[i] = xorBytes(ct, mask)
	}

	return out
}


