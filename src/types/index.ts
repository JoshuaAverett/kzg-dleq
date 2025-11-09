/**
 * DLEQ Proof structure for KZG Zero Evaluation proofs
 */
export interface DLEQProof {
  Cx: bigint;
  Wx: bigint;
  Px: bigint;
  Py: bigint;
  x: bigint;
  Xx: bigint;
  Xy: bigint;
  A1x: bigint;
  A1y: bigint;
  A1addr: string;
  zTx: bigint;
  zTy: bigint;
  eCx: bigint;
  eCy: bigint;
  A2addr: string;
  Hinv: bigint;
  Hinv2: bigint;
  z: bigint;
  parity: number; // bit0: Cy parity, bit1: Wy parity
}

/**
 * Verification result with detailed information
 */
export interface VerificationResult {
  valid: boolean;
  error?: string;
  gasUsed?: bigint;
  transactionHash?: string;
}

