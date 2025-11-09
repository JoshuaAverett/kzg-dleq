import { keccak256 } from "viem";
import {
  P, N, GX, GY,
  mod, modInverse,
  ecMul, ecAdd, ecSub,
  ecPointAddress,
  evalPoly,
  randomScalar,
} from "./crypto.js";
import type { DLEQProof } from "../types/index.js";

export type SRSEntry = [bigint, bigint];
export type SRS = SRSEntry[];

/**
 * Generate a simple SRS: [G, s*G, s^2*G, ..., s^maxDegree*G]
 */
export function generateSRS(secret: bigint, maxDegree: number): SRS {
  if (maxDegree < 0) throw new Error("maxDegree must be >= 0");
  // Normalize s into [0, N); must not be zero to match deployed P = s*G
  const s = mod(secret, N);
  if (s === 0n) {
    throw new Error("secret must be non-zero modulo N");
  }

  const srs: SRS = [];
  // G^s^0
  let current: SRSEntry = [GX, GY];
  srs.push(current);
  for (let i = 1; i <= maxDegree; i++) {
    const [nx, ny] = ecMul(current[0], current[1], s);
    current = [nx, ny];
    srs.push(current);
  }
  return srs;
}

/**
 * Commit to a polynomial using the SRS:
 * C = sum_i c_i * (s^i * G) = p(s) * G
 */
export function commitPolynomial(coefficients: bigint[], srs: SRS): SRSEntry {
  if (coefficients.length === 0) return [0n, 0n] as unknown as SRSEntry; // not used in practice
  if (coefficients.length > srs.length) {
    throw new Error("Polynomial degree exceeds SRS length");
  }
  let accPoint: SRSEntry | null = null;
  for (let i = 0; i < coefficients.length; i++) {
    const coeff = mod(coefficients[i], N);
    if (coeff === 0n) continue;
    const [px, py] = ecMul(srs[i][0], srs[i][1], coeff);
    accPoint = accPoint === null ? [px, py] : ecAdd(accPoint[0], accPoint[1], px, py);
  }
  if (accPoint === null) {
    // commitment to zero polynomial is point at infinity; we don't have an explicit infinity encoding here.
    // For our usage, coefficients won't all be zero. Guard anyway:
    throw new Error("Commitment to zero polynomial is not supported");
  }
  return accPoint;
}

/**
 * Generate a DLEQ-style proof that p(x) = 0 using SRS (requires knowledge of the setup secret).
 * - Computes commitment C from SRS
 * - Computes witness W as commitment to q(X) = p(X)/(X - x)
 * - Produces the same proof shape as prover.generateProof
 */
export function generateProofUsingSRS(
  x: bigint,
  polynomial: bigint[],
  secret: bigint,
  srs: SRS
): DLEQProof {
  if (polynomial.length === 0) {
    throw new Error("Polynomial must have at least one coefficient");
  }
  if (polynomial.length > srs.length) {
    throw new Error("Polynomial degree exceeds SRS length");
  }
  const xNorm = mod(x, N);
  if (xNorm === 0n) {
    throw new Error("x must be non-zero");
  }

  // Normalize coefficients mod N
  const coeffs = polynomial.map(c => mod(c, N));

  // Verify p(x) = 0
  const px = evalPoly(coeffs, xNorm);
  if (px !== 0n) {
    throw new Error(`Polynomial does not evaluate to zero at x=${xNorm}: p(x) = ${px}`);
  }

  // Commitment C = p(s) * G (via SRS)
  const [Cx, Cy] = commitPolynomial(coeffs, srs);

  // Compute quotient q(X) = p(X) / (X - x) via synthetic division (ascending coeffs)
  // b[d] = c[d]; b[i] = c[i] + x*b[i+1]; remainder = b[0]; q = [b[1]..b[d]]
  const d = coeffs.length - 1;
  const b = new Array<bigint>(coeffs.length);
  b[d] = coeffs[d];
  for (let i = d - 1; i >= 0; i--) {
    b[i] = mod(coeffs[i] + mod(xNorm * b[i + 1], N), N);
  }
  const remainder = b[0];
  if (remainder !== 0n) {
    throw new Error("Division failed: p(x) != 0");
  }
  const qCoeffs = b.slice(1); // length d

  // Witness W = q(s) * G (via SRS)
  const [Wx /* Wy is parity used below but we only need x for contract inputs */, Wy] = commitPolynomial(qCoeffs, srs);

  // Public P = s * G = SRS[1]
  if (srs.length < 2) {
    throw new Error("SRS must have at least 2 elements (G, sG)");
  }
  const [Px, Py] = srs[1];

  // X = x * G
  const [Xx, Xy] = ecMul(GX, GY, xNorm);

  // T = P - X
  const [Tx, Ty] = ecSub(Px, Py, Xx, Xy);

  // Random nonce k
  const k = randomScalar();

  // A1 = k * G
  const [A1x, A1y] = ecMul(GX, GY, k);
  const A1addr = ecPointAddress(A1x, A1y);

  // A2 = k * T
  const [A2x, A2y] = ecMul(Tx, Ty, k);
  const A2addr = ecPointAddress(A2x, A2y);

  // parity flags (bit0 = Cy parity, bit1 = Wy parity)
  const parity = Number((Cy & 1n) | ((Wy & 1n) << 1n));

  // Fiat-Shamir challenge - matches contract's abi.encodePacked(Cx, Wx, Px, Py, A1addr, A2addr, x, parity)
  const challengeData = new Uint8Array(1 + 32 * 5 + 20 * 2 + 1);
  let offset = 0;
  challengeData[offset++] = 0x01;
  const writeUint256 = (value: bigint) => {
    for (let i = 0; i < 32; i++) {
      challengeData[offset + i] = Number((value >> BigInt(8 * (31 - i))) & 0xFFn);
    }
    offset += 32;
  };
  const writeAddress = (addr: string) => {
    const addrBytes = addr.startsWith('0x') ? addr.slice(2) : addr;
    for (let i = 0; i < 20; i++) {
      challengeData[offset + i] = parseInt(addrBytes.slice(i * 2, i * 2 + 2), 16);
    }
    offset += 20;
  };
  writeUint256(Cx);
  writeUint256(Wx);
  writeUint256(Px);
  writeUint256(Py);
  writeAddress(A1addr);
  writeAddress(A2addr);
  writeUint256(xNorm);
  challengeData[offset] = parity & 0xff;

  const e = mod(BigInt(keccak256(challengeData)), N);

  // Compute w = q(s) scalar to produce z = k + e*w
  const s = mod(secret, N);
  // Evaluate q(s)
  let w = 0n;
  let sPow = 1n;
  for (const qc of qCoeffs) {
    w = mod(w + mod(qc * sPow, N), N);
    sPow = mod(sPow * s, N);
  }

  const z = mod(k + mod(e * w, N), N);

  // z*T and e*C
  const [zTx, zTy] = ecMul(Tx, Ty, z);
  const [eCx, eCy] = ecMul(Cx, Cy, e);

  // Precomputed inverses per on-chain verifier expectations
  const Hinv = modInverse(mod(Px - Xx, P), P);
  const Hinv2 = modInverse(mod(zTx - eCx, P), P);

  return {
    Cx,
    Wx,
    Px, Py,
    x: xNorm,
    Xx, Xy,
    A1x, A1y,
    A1addr,
    zTx, zTy,
    eCx, eCy,
    A2addr,
    Hinv,
    Hinv2,
    z,
    parity
  };
}
