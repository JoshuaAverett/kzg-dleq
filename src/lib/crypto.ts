import { secp256k1 } from '@noble/curves/secp256k1.js'
import { mod, invert } from '@noble/curves/abstract/modular.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { createPrimeField } from '@guildofweavers/galois'

export { mod }

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
  const packed = new Uint8Array(64)
  packed.set(xBytes, 0)
  packed.set(yBytes, 32)
  
  const hash = keccak_256(packed)
  return '0x' + Array.from(hash.slice(-20)).map(b => b.toString(16).padStart(2, '0')).join('')
}

