/**
 * KZG-DLEQ Client Library
 * 
 * A client library for generating and verifying KZG zero evaluation proofs using DLEQ.
 */

import { generateProof } from "./lib/cheat_prover.js";
import { verifyProofSimple } from "./lib/verifier.js";
import { verifyOnChainAssembly } from "./lib/evm_verifier.js";
import type { DLEQProof } from "./types/index.js";

// Export types
export type { VerificationResult, Point, DLEQProof as SimpleDLEQProof } from "./types/index.js";

// Export crypto utilities
export {
  P, N, G, GX, GY,
  Field,
  mod,
  modInverse,
  randomScalar,
  ecMul,
  ecAdd,
  ecSub,
  isOnCurve,
  ecAddress as ecPointAddress,
  bytesToBigInt,
  bigIntToBytes
} from "./lib/crypto.js";

// Export prover
export { generateProof as generateSimpleProof } from "./lib/cheat_prover.js";

// Export verifier
export { verifyProofSimple } from "./lib/verifier.js";
export { encodeVerifyPolynomialCalldata, verifyOnChainAssembly } from "./lib/evm_verifier.js";

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
    return generateProof(x, polynomial, trustedSetupSecret);
  }

  /**
   * Verify a DLEQ proof (TypeScript implementation)
   * 
   * @param proof The proof to verify
   * @param verbose Whether to output detailed verification steps
   * @returns true if the proof is valid, false otherwise
   */
  verify(proof: DLEQProof, verbose: boolean = false): boolean {
    return verifyProofSimple(proof, verbose);
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
    return verifyOnChainAssembly(contractAddress, proof, walletClient, publicClient, version);
  }
}

// Export default instance
export const client = new KZGDLEQClient();

