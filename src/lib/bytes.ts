import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js'

/**
 * Byte manipulation utilities for encoding and concatenating data.
 */

/**
 * Generate cryptographically secure random bytes.
 */
export function randomBytes(length: number): Uint8Array {
	return nobleRandomBytes(length)
}

/**
 * Concatenate multiple Uint8Array instances into a single array.
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
	let total = 0
	for (const a of arrays) total += a.length
	const out = new Uint8Array(total)
	let offset = 0
	for (const a of arrays) {
		out.set(a, offset)
		offset += a.length
	}
	return out
}

/**
 * Encode a number as a single byte (uint8).
 */
export function encodeU8(value: number): Uint8Array {
	const out = new Uint8Array(1)
	out[0] = value & 0xff
	return out
}

/**
 * Encode a number as a 32-bit unsigned integer (4 bytes, big-endian).
 */
export function encodeU32(value: number): Uint8Array {
	const out = new Uint8Array(4)
	for (let i = 0; i < 4; i++) {
		out[i] = (value >> (8 * (3 - i))) & 0xff
	}
	return out
}

/**
 * Encode a bigint as a 256-bit unsigned integer (32 bytes, big-endian).
 */
export function encodeU256(value: bigint, length: number = 32): Uint8Array {
	const out = new Uint8Array(length)
	for (let i = 0; i < length; i++) {
		out[i] = Number((value >> BigInt(8 * (length - 1 - i))) & 0xFFn)
	}
	return out
}

/**
 * Encode an Ethereum address (20 bytes) from a hex string.
 * Handles both '0x' prefixed and unprefixed hex strings.
 */
export function encodeAddress(addr: string): Uint8Array {
	const addrBytes = addr.startsWith('0x') ? addr.slice(2) : addr
	const out = new Uint8Array(20)
	for (let i = 0; i < 20; i++) {
		out[i] = parseInt(addrBytes.slice(i * 2, i * 2 + 2), 16) || 0
	}
	return out
}

/**
 * Encode a UTF-8 string to bytes.
 */
export function encodeUtf8(s: string): Uint8Array {
	return new TextEncoder().encode(s)
}

/**
 * Constant-time comparison of two byte arrays.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false
	let diff = 0
	for (let i = 0; i < a.length; i++) {
		diff |= a[i] ^ b[i]
	}
	return diff === 0
}

