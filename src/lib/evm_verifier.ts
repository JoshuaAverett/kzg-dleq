import { keccak256, toBytes } from 'viem'
import type { DLEQProof, VerificationResult } from '../types/index.js'
import { P, N, GX, GY, ecMul, ecSub, mod, modInverse, ecAddress, isOnCurve } from './crypto.js'
import { buildChallenge } from './challenge.js'

/**
 * Encode calldata for Verifier.verifyPolynomial() (assembly-optimized) using the minimal proof.
 * Derives the contract-expected intermediates (X, zT, eC, Hinv, Hinv2, addresses, parity).
 */
export function encodeVerifyPolynomialCalldata(proof: DLEQProof, version: bigint = 1n): `0x${string}` {
  // Derive challenge inputs
  const Cx = proof.C.x
  const Cy = proof.C.y
  const Wx = proof.W.x
  const Wy = proof.W.y
  const Px = proof.P.x
  const Py = proof.P.y
  const x = proof.x
  const z = proof.z

  // Input validation for negative tests: if any input is out-of-range or points are invalid,
  // avoid EC ops and inverses that would throw in JS. We'll produce clearly-invalid calldata
  // that the contract will reject.
  const isValidScalar = (s: bigint) => s > 0n && s < N
  const isValidCoord = (a: bigint) => a > 0n && a < P
  const isValidPoint = (ax: bigint, ay: bigint) =>
    isValidCoord(ax) && isValidCoord(ay) && isOnCurve(ax, ay)

  const inputsInvalid =
    !isValidScalar(x) ||
    !isValidScalar(z) ||
    !isValidPoint(Cx, Cy) ||
    !isValidPoint(Wx, Wy) ||
    !isValidPoint(Px, Py)

  // X = x * G, T = P - X (only if inputs are valid)
  let Xx: bigint = 0n, Xy: bigint = 0n
  let Tx: bigint = 0n, Ty: bigint = 0n
  if (!inputsInvalid) {
    ;[Xx, Xy] = ecMul(GX, GY, x)
    ;[Tx, Ty] = ecSub(Px, Py, Xx, Xy)
  }

  // Addresses and parity for challenge packing
  const A1addr = ecAddress(proof.A1.x, proof.A1.y)
  const A2addr = ecAddress(proof.A2.x, proof.A2.y)
  const parity = Number((Cy & 1n) | ((Wy & 1n) << 1n))

  // Fiat–Shamir challenge
  const e = buildChallenge(Cx, Wx, Px, Py, A1addr, A2addr, x, parity)

  // Derived points
  let zTx: bigint = 0n, zTy: bigint = 0n
  let eCx: bigint = 0n, eCy: bigint = 0n
  if (!inputsInvalid) {
    ;[zTx, zTy] = ecMul(Tx, Ty, z)
    ;[eCx, eCy] = ecMul(Cx, Cy, e)
  }

  // Inverses used by contract slope steps
  let Hinv: bigint = 0n
  let Hinv2: bigint = 0n
  if (!inputsInvalid) {
    Hinv = modInverse(mod(Px - Xx, P), P)
    Hinv2 = modInverse(mod(zTx - eCx, P), P)
  }

  const selector = keccak256(toBytes('verifyPolynomial()')).slice(0, 10)
  const hex = [
    version.toString(16).padStart(2, '0'),
    Cx.toString(16).padStart(64, '0'),
    Wx.toString(16).padStart(64, '0'),
    Xx.toString(16).padStart(64, '0'),
    Xy.toString(16).padStart(64, '0'),
    zTx.toString(16).padStart(64, '0'),
    zTy.toString(16).padStart(64, '0'),
    eCx.toString(16).padStart(64, '0'),
    eCy.toString(16).padStart(64, '0'),
    Hinv.toString(16).padStart(64, '0'),
    Hinv2.toString(16).padStart(64, '0'),
    z.toString(16).padStart(64, '0'),
    x.toString(16).padStart(64, '0'),
    A1addr.slice(2).padStart(40, '0'),
    A2addr.slice(2).padStart(40, '0'),
    BigInt(parity).toString(16).padStart(2, '0'),
  ].join('')
  return `${selector}${hex}` as `0x${string}`
}

/**
 * Send a transaction invoking the assembly-optimized verifier with the provided proof.
 * Returns a VerificationResult with gas usage and tx hash on success.
 */
export async function verifyOnChainAssembly(
  contractAddress: `0x${string}`,
  proof: DLEQProof,
  walletClient: any,
  publicClient: any,
  version: bigint = 1n
): Promise<VerificationResult> {
  const data = encodeVerifyPolynomialCalldata(proof, version)
  try {
    const hash: `0x${string}` = await walletClient.sendTransaction({
      to: contractAddress,
      data,
    })
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    const success = receipt.status === 'success'
    return {
      valid: success,
      gasUsed: receipt.gasUsed,
      transactionHash: hash,
    }
  } catch (e: any) {
    return {
      valid: false,
      error: e?.message ?? String(e),
    }
  }
}
