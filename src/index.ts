/**
 * KZG-DLEQ Client Library
 * 
 * A client library for generating and verifying KZG zero evaluation proofs using DLEQ.
 */

// Export types
export type { DLEQProof, VerificationResult } from "./types/index.js";

// Export crypto utilities
export {
  P, N, G, GX, GY,
  mod,
  modInverse,
  randomScalar,
  ecMul,
  ecAdd,
  ecSub,
  isOnCurve,
  ecPointAddress,
  evalPoly,
  hashToScalar,
  bytesToBigInt,
  bigIntToBytes,
  createKeccak256Fn
} from "./lib/crypto.js";

// Export prover
export { generateProof } from "./lib/prover.js";

// Export verifier
export { verifyProof, encodeVerifyPolynomialCalldata, verifyOnChainAssembly } from "./lib/verifier.js";

// Re-export for convenience
import { generateProof } from "./lib/prover.js";
import { verifyProof } from "./lib/verifier.js";
import type { DLEQProof } from "./types/index.js";

/**
 * Main client class for KZG-DLEQ operations
 */
export class KZGDLEQClient {
  /**
   * Generate a proof that p(x) = 0 for a given polynomial and trusted setup
   * 
   * @param x Evaluation point where p(x) = 0
   * @param polynomial Polynomial coefficients [c0, c1, c2, ...] representing c0 + c1*x + c2*x^2 + ...
   * @param trustedSetupSecret The secret value s from the trusted setup
   * @returns A DLEQ proof
   */
  async prove(
    x: bigint,
    polynomial: bigint[],
    trustedSetupSecret: bigint
  ): Promise<DLEQProof> {
    const { createKeccak256Fn } = await import("./lib/crypto.js");
    return generateProof(x, polynomial, trustedSetupSecret, createKeccak256Fn());
  }

  /**
   * Verify a DLEQ proof (TypeScript implementation)
   * 
   * @param proof The proof to verify
   * @param verbose Whether to output detailed verification steps
   * @returns true if the proof is valid, false otherwise
   */
  verify(proof: DLEQProof, verbose: boolean = false): boolean {
    return verifyProof(proof, verbose);
  }

  /**
   * Verify a DLEQ proof on-chain via the assembly-optimized verifier
   */
  async verifyOnChain(
    contractAddress: `0x${string}`,
    proof: DLEQProof,
    walletClient: any,
    publicClient: any,
    version: bigint = 1n
  ) {
    const { verifyOnChainAssembly } = await import("./lib/verifier.js");
    return verifyOnChainAssembly(contractAddress, proof, walletClient, publicClient, version);
  }
}

// Export default instance
export const client = new KZGDLEQClient();

