import { keccak256 } from "viem";
import {
  P, N, GX, GY,
  mod, modInverse,
  ecMul, ecSub,
  ecPointAddress,
  evalPoly
} from "./crypto.js";
import type { DLEQProof } from "../types/index.js";

/**
 * Generate a DLEQ proof for KZG zero evaluation
 * 
 * @param x Evaluation point where p(x) = 0
 * @param p Polynomial coefficients [c0, c1, c2, ...] representing c0 + c1*x + c2*x^2 + ...
 * @param s Trusted setup secret
 * @param keccak256Fn Optional keccak256 function (for compatibility)
 * @returns DLEQ proof
 */
export async function generateProof(
  x: bigint,
  p: bigint[],
  s: bigint,
): Promise<DLEQProof> {
  // Normalize all polynomial coefficients to be in [0, N)
  const p_norm = p.map(c => mod(c, N));
  
  // Verify that p(x) = 0
  const px = evalPoly(p_norm, x);
  if (px !== 0n) {
    throw new Error(`Polynomial does not evaluate to zero at x=${x}: p(${x}) = ${px}`);
  }
  
  // Compute p(s)
  const ps = evalPoly(p_norm, s);
  
  // Compute C = p(s) * G (commitment)
  const [Cx, Cy] = ecMul(GX, GY, ps);
  
  // Compute W = (s - x)^(-1) * C = q(s) * G (witness)
  // Since C = p(s)*G and p(s) = (s-x)*q(s), we have W = q(s)*G
  const s_minus_x_inv = modInverse(mod(s - x, N), N);
  const w = mod(ps * s_minus_x_inv, N); // w = q(s)
  const [Wx, Wy] = ecMul(GX, GY, w);
  
  // Compute P = s * G (public point)
  const [Px, Py] = ecMul(GX, GY, s);
  
  // Compute X = x * G
  const [Xx, Xy] = ecMul(GX, GY, x);
  
  // Compute T = P - X = (s - x) * G
  const [Tx, Ty] = ecSub(Px, Py, Xx, Xy);
  
  // Generate random nonce k for DLEQ proof
  const k = mod(BigInt("0x" + Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('')), N - 1n) + 1n;
  
  // Compute A1 = k * G (first commitment)
  const [A1x, A1y] = ecMul(GX, GY, k);
  const A1addr = ecPointAddress(A1x, A1y);
  
  // Compute A2 = k * T (second commitment)
  const [A2x, A2y] = ecMul(Tx, Ty, k);
  
  // Compute A2 address
  const A2addr = ecPointAddress(A2x, A2y);
  
  // Compute parity flags (bit0 = Cy parity, bit1 = Wy parity)
  const parity = Number((Cy & 1n) | ((Wy & 1n) << 1n));

  // Fiat-Shamir challenge - matches contract's abi.encodePacked(Cx, Wx, Px, Py, A1addr, A2addr, x, parity)
  // abi.encodePacked concatenates without padding
  // Domain separation: prepend 0x01 (uint8)
  const challengeData = new Uint8Array(1 + 32 * 5 + 20 * 2 + 1); // 1 byte prefix + 5 uint256s + 2 addresses + 1 byte
  let offset = 0;

  // prefix
  challengeData[offset] = 0x01;
  offset += 1;
  
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
  writeUint256(x);
  challengeData[offset] = parity & 0xff;
  
  const e = mod(BigInt(keccak256(challengeData)), N);
  
  // Compute response z = k + e*w mod N
  const z = mod(k + mod(e * w, N), N);
  
  // Compute z * T
  const [zTx, zTy] = ecMul(Tx, Ty, z);
  
  // Compute e * C
  const [eCx, eCy] = ecMul(Cx, Cy, e);
  
  // Compute Hinv = (Px - Xx)^{-1} mod P
  const Hinv = modInverse(mod(Px - Xx, P), P);
  
  // Compute Hinv2 = (zTx - eCx)^{-1} mod P
  const Hinv2 = modInverse(mod(zTx - eCx, P), P);
  
  return {
    Cx,
    Wx,
    Px, Py,
    x,
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

