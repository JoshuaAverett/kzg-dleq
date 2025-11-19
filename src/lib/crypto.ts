import { secp256k1 } from '@noble/curves/secp256k1.js'
import { mod, invert } from '@noble/curves/abstract/modular.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { createPrimeField } from '@guildofweavers/galois'
import { concat, encodeU256, encodeAddress, encodeUtf8, randomBytes } from './bytes.js'

export { mod }
export interface Point {
	x: bigint
	y: bigint
}

// Secp256k1 curve constants
export const P = secp256k1.Point.CURVE().p
export const N = secp256k1.Point.CURVE().n
export const G = secp256k1.Point.BASE
export const GX = G.toAffine().x
export const GY = G.toAffine().y

// Shared finite field over scalar modulus N
export const Field = createPrimeField(N)

// Utility functions
export const bytesToBigInt = bytesToNumberBE
export const bigIntToBytes = numberToBytesBE

/**
 * Hash helper: Keccak-256 over a single byte array.
 */
export function hash(data: Uint8Array): Uint8Array {
	return keccak_256(data)
}

/**
 * Compute modular inverse: a^(-1) mod m
 */
export function modInverse(a: bigint, m: bigint): bigint {
	return invert(a, m)
}

/**
 * Generate a random scalar in [1, N)
 */
export function randomScalar(): bigint {
	return mod(bytesToBigInt(randomBytes(32)), N - 1n) + 1n
}

/**
 * Derive a deterministic nonce in [1, N) from a secret scalar and context.
 * This is intended to protect against RNG failure and nonce reuse.
 */
export function deterministicNonce(secret: bigint, parts: Array<bigint | string | Uint8Array>): bigint {
	const enc32 = (v: bigint): Uint8Array => encodeU256(mod(v, N), 32)

	// domain separation
	const chunks: Uint8Array[] = [encodeUtf8('dleq-nonce-v1'), enc32(secret)]
	for (const p of parts) {
		if (typeof p === 'bigint') chunks.push(enc32(p))
		else if (typeof p === 'string') {
			if (/^0x[0-9a-fA-F]{40}$/.test(p)) chunks.push(encodeAddress(p))
			else chunks.push(encodeUtf8(p))
		} else {
			chunks.push(p)
		}
	}

	const buf = concat(...chunks)
	const h = hash(buf)
	// Map to [1, N)
	return mod(bytesToBigInt(h), N - 1n) + 1n
}

/**
 * Multiply an elliptic curve point by a scalar
 */
export function ecMul(x: bigint, y: bigint, scalar: bigint): [bigint, bigint] {
	const point = secp256k1.Point.fromAffine({ x, y })
	const result = point.multiply(mod(scalar, N))
	const affine = result.toAffine()
	return [affine.x, affine.y]
}

/**
 * Add two elliptic curve points
 */
export function ecAdd(x1: bigint, y1: bigint, x2: bigint, y2: bigint): [bigint, bigint] {
	const p1 = secp256k1.Point.fromAffine({ x: x1, y: y1 })
	const p2 = secp256k1.Point.fromAffine({ x: x2, y: y2 })
	const result = p1.add(p2)
	const affine = result.toAffine()
	return [affine.x, affine.y]
}

/**
 * Subtract two elliptic curve points: A - B
 */
export function ecSub(Ax: bigint, Ay: bigint, Bx: bigint, By: bigint): [bigint, bigint] {
	const pA = secp256k1.Point.fromAffine({ x: Ax, y: Ay })
	const pB = secp256k1.Point.fromAffine({ x: Bx, y: By })
	const result = pA.subtract(pB)
	const affine = result.toAffine()
	return [affine.x, affine.y]
}

/**
 * Check if a point is on the secp256k1 curve
 */
export function isOnCurve(x: bigint, y: bigint): boolean {
	try {
		secp256k1.Point.fromAffine({ x, y })
		return true
	} catch {
		return false
	}
}

/**
 * Compute Ethereum address from an EC point (last 20 bytes of keccak256(x || y))
 */
export function ecAddress(x: bigint, y: bigint): string {
	const xBytes = bigIntToBytes(x, 32)
	const yBytes = bigIntToBytes(y, 32)
	const packed = concat(xBytes, yBytes)
	
	const digest = hash(packed)
	return '0x' + Array.from(digest.slice(-20)).map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * ECDH over secp256k1: compute shared secret given our secret scalar and peer public point.
 * Returns 32-byte big-endian X coordinate of shared point.
 */
export function ecdh(secret: bigint, peerX: bigint, peerY: bigint): Uint8Array {
	const peer = secp256k1.Point.fromAffine({ x: peerX, y: peerY })
	const shared = peer.multiply(mod(secret, N)).toAffine()
	return bigIntToBytes(shared.x, 32)
}

/**
 * HKDF (Keccak-256) one-shot.
 */
export function hkdfKeccak(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length = 32): Uint8Array {
	return hkdf(keccak_256, ikm, salt, info, length)
}
