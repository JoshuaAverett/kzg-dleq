import { keccak256, encodeAbiParameters, toBytes } from "viem";
import {
  P, N,
  mod, modInverse,
  ecPointAddress,
  ecMul, ecSub,
  GX, GY,
  bigIntToBytes,
  isOnCurve
} from "./crypto.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import type { DLEQProof, VerificationResult } from "../types/index.js";

/**
 * Verify DLEQ proof using Solidity-style computation with explicit Hinv
 */
function ecSubWithHinv(
  Ax: bigint,
  Ay: bigint,
  Bx: bigint,
  By: bigint,
  Hinv: bigint
): [bigint, bigint] {
  const H = mod(Ax - Bx, P);
  
  // Verify Hinv
  if (mod(H * Hinv, P) !== 1n) {
    throw new Error(`InvalidHInv: H=${H}, Hinv=${Hinv}, H*Hinv mod P = ${mod(H * Hinv, P)}`);
  }
  
  const num = mod(Ay + By, P);
  const lam = mod(num * Hinv, P);
  const lam2 = mod(lam * lam, P);
  
  const Rx = mod(lam2 - Ax - Bx, P);
  const Ax_minus_Rx = mod(Ax - Rx, P);
  const Ry = mod(lam * Ax_minus_Rx - Ay, P);
  
  return [Rx, Ry];
}

/**
 * Verify a KZG zero evaluation DLEQ proof (TypeScript implementation)
 * 
 * @param proof The DLEQ proof to verify
 * @param verbose Whether to output detailed verification steps
 * @returns true if the proof is valid, false otherwise
 */
export function verifyProof(proof: DLEQProof, verbose: boolean = false): boolean {
  if (verbose) {
    console.log("\n=== TypeScript Verifier ===");
  }
  
  // Step 1: Verify input ranges
  if (verbose) {
    console.log("Step 1: Checking input ranges...");
  }
  if (proof.Xx >= P || proof.Xy >= P || proof.Cx >= P || proof.Wx >= P || proof.Px >= P || proof.Py >= P) {
    if (verbose) console.log("  ❌ InvalidInput: coordinate out of range");
    return false;
  }
  if (proof.x === 0n || proof.x >= N || proof.z === 0n || proof.z >= N) {
    if (verbose) console.log("  ❌ InvalidInput: scalar out of range or zero");
    return false;
  }
  if (proof.Hinv === 0n || proof.Hinv >= P || proof.Hinv2 === 0n || proof.Hinv2 >= P) {
    if (verbose) console.log("  ❌ InvalidInput: Hinv out of range");
    return false;
  }
  if (proof.A1addr === "0x0000000000000000000000000000000000000000") {
    if (verbose) console.log("  ❌ InvalidInput: A1addr is zero address");
    return false;
  }
  if (proof.A2addr === "0x0000000000000000000000000000000000000000") {
    if (verbose) console.log("  ❌ InvalidInput: A2addr is zero address");
    return false;
  }
  if (verbose) {
    console.log("  ✅ All inputs in valid range");
  }
  
  // Step 2: Check X = x * G
  if (verbose) {
    console.log("\nStep 2: Verifying X = x * G...");
    console.log(`  X = (${proof.Xx}, ${proof.Xy})`);
    console.log(`  X on curve: ${isOnCurve(proof.Xx, proof.Xy)}`);
  }
  
  // Step 3: Compute T = P - X
  if (verbose) {
    console.log("\nStep 3: Computing T = P - X...");
  }
  let Tx: bigint, Ty: bigint;
  try {
    [Tx, Ty] = ecSubWithHinv(proof.Px, proof.Py, proof.Xx, proof.Xy, proof.Hinv);
    if (verbose) {
      console.log(`  ✅ T = (${Tx}, ${Ty})`);
      console.log(`  T on curve: ${isOnCurve(Tx, Ty)}`);
    }
  } catch (e: any) {
    if (verbose) console.log(`  ❌ ${e.message}`);
    return false;
  }
  
  // Step 4: Fiat-Shamir challenge - must match contract's abi.encodePacked(uint8(1), Cx, Wx, Px, Py, A1addr, A2addr, x, parity)
  if (verbose) {
    console.log("\nStep 4: Computing Fiat-Shamir challenge...");
  }
  
  // abi.encodePacked concatenates without padding: uint256s are 32 bytes, addresses are 20 bytes
  // Domain separation prefix: 1 byte
  const challengeData = new Uint8Array(1 + 32 * 5 + 20 * 2 + 1); // 1 byte + 5 uint256s + 2 addresses + 1 byte
  let offset = 0;

  // prefix 0x01
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
  
  writeUint256(proof.Cx);
  writeUint256(proof.Wx);
  writeUint256(proof.Px);
  writeUint256(proof.Py);
  writeAddress(proof.A1addr);
  writeAddress(proof.A2addr);
  writeUint256(proof.x);
  challengeData[offset] = proof.parity & 0xff;
  
  const e = mod(BigInt(keccak256(challengeData)), N);
  if (verbose) {
    console.log(`  e = ${e}`);
  }
  
  // Step 5: Verify z * G - e * W == A1
  if (verbose) {
    console.log("\nStep 5: Verifying z * G - e * W == A1...");
    console.log(`  A1 = (${proof.A1x}, ${proof.A1y})`);
    console.log(`  A1 on curve: ${isOnCurve(proof.A1x, proof.A1y)}`);
  }
  // Reconstruct W from Wx and Wy parity bit (bit1)
  try {
    const wyOdd = ((proof.parity >> 1) & 1) === 1;
    const wxBytes = bigIntToBytes(proof.Wx, 32);
    const wCompressed = new Uint8Array(33);
    wCompressed[0] = wyOdd ? 0x03 : 0x02;
    wCompressed.set(wxBytes, 1);
    const W = secp256k1.Point.fromHex(wCompressed).toAffine();
    
    const [zGx, zGy] = ecMul(GX, GY, proof.z);
    const [eWx, eWy] = ecMul(proof.Wx, W.y, e);
    const [A1rx, A1ry] = ecSub(zGx, zGy, eWx, eWy);
    if (verbose) {
      console.log(`  A1 recomputed = (${A1rx}, ${A1ry})`);
    }
    if (A1rx !== proof.A1x || A1ry !== proof.A1y) {
      if (verbose) console.log("  ❌ InvalidA1: coordinate mismatch");
      return false;
    }
    const A1_computed_addr = ecPointAddress(A1rx, A1ry);
    if (A1_computed_addr.toLowerCase() !== proof.A1addr.toLowerCase()) {
      if (verbose) console.log("  ❌ InvalidA1: address mismatch");
      return false;
    }
  } catch (eAny: any) {
    if (verbose) console.log(`  ❌ A1 reconstruction failed: ${eAny?.message ?? String(eAny)}`);
    return false;
  }
  
  // Step 6: Verify z * T and e * C
  if (verbose) {
    console.log("\nStep 6: Verifying z * T and e * C...");
    console.log(`  zT = (${proof.zTx}, ${proof.zTy})`);
    console.log(`  zT on curve: ${isOnCurve(proof.zTx, proof.zTy)}`);
    console.log(`  eC = (${proof.eCx}, ${proof.eCy})`);
    console.log(`  eC on curve: ${isOnCurve(proof.eCx, proof.eCy)}`);
  }
  
  // Step 7: Compute A2 = zT - eC
  if (verbose) {
    console.log("\nStep 7: Computing A2 = zT - eC...");
  }
  let A2rx: bigint, A2ry: bigint;
  try {
    [A2rx, A2ry] = ecSubWithHinv(proof.zTx, proof.zTy, proof.eCx, proof.eCy, proof.Hinv2);
    if (verbose) {
      console.log(`  ✅ A2 = (${A2rx}, ${A2ry})`);
      console.log(`  A2 on curve: ${isOnCurve(A2rx, A2ry)}`);
    }
    
    const A2_computed_addr = ecPointAddress(A2rx, A2ry);
    if (verbose) {
      console.log(`  A2 computed address: ${A2_computed_addr}`);
      console.log(`  A2 provided address: ${proof.A2addr}`);
    }
    
    if (A2_computed_addr.toLowerCase() !== proof.A2addr.toLowerCase()) {
      if (verbose) console.log("  ❌ InvalidA2: address mismatch");
      return false;
    }
    if (verbose) {
      console.log("  ✅ A2 address matches");
    }
  } catch (e: any) {
    if (verbose) console.log(`  ❌ ${e.message}`);
    return false;
  }
  
  if (verbose) {
    console.log("\n✅ All checks passed in TypeScript verifier!");
  }
  return true;
}

/**
 * Encode calldata for Verifier.verifyPolynomial() (assembly-optimized) using the proof
 * Layout matches the contract's expected packed calldata.
 */
export function encodeVerifyPolynomialCalldata(proof: DLEQProof, version: bigint = 1n): `0x${string}` {
  const selector = keccak256(toBytes("verifyPolynomial()")).slice(0, 10);
  const hex = [
    version.toString(16).padStart(2, "0"),
    proof.Cx.toString(16).padStart(64, "0"),
    proof.Wx.toString(16).padStart(64, "0"),
    proof.Xx.toString(16).padStart(64, "0"),
    proof.Xy.toString(16).padStart(64, "0"),
    proof.zTx.toString(16).padStart(64, "0"),
    proof.zTy.toString(16).padStart(64, "0"),
    proof.eCx.toString(16).padStart(64, "0"),
    proof.eCy.toString(16).padStart(64, "0"),
    proof.Hinv.toString(16).padStart(64, "0"),
    proof.Hinv2.toString(16).padStart(64, "0"),
    proof.z.toString(16).padStart(64, "0"),
    proof.x.toString(16).padStart(64, "0"),
    proof.A1addr.slice(2).padStart(40, "0"),
    proof.A2addr.slice(2).padStart(40, "0"),
    BigInt(proof.parity).toString(16).padStart(2, "0"),
  ].join("");
  return `${selector}${hex}` as `0x${string}`;
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
  const data = encodeVerifyPolynomialCalldata(proof, version);
  try {
    const hash: `0x${string}` = await walletClient.sendTransaction({
      to: contractAddress,
      data,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const success = receipt.status === "success";
    return {
      valid: success,
      gasUsed: receipt.gasUsed,
      transactionHash: hash,
    };
  } catch (e: any) {
    return {
      valid: false,
      error: e?.message ?? String(e),
    };
  }
}

