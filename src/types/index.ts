/**
 * Verification result with detailed information
 */
export interface VerificationResult {
  valid: boolean
  error?: string
  gasUsed?: bigint
  transactionHash?: string
}

/**
 * Minimal point representation
 */
export interface Point {
  x: bigint
  y: bigint
}

/**
 * Simplified DLEQ proof carrying only essential data.
 * Points are provided in affine coordinates scalars are bigints.
 */
export interface DLEQProof {
  C: Point   // commitment point
  W: Point   // witness point
  P: Point   // public point s*G
  A1: Point  // Schnorr commitment zG - eW
  A2: Point  // Schnorr commitment zT - eC
  x: bigint  // evaluation point
  z: bigint  // response
}
