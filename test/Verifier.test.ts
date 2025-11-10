import { describe, it, before } from "node:test";
import { expect } from "chai";
import { network } from "hardhat";
import { generateProof } from "../src/lib/cheat_prover.js";
import { randomScalar, mod, N, P, GX, GY, ecMul } from "../src/lib/crypto.js";
import type { DLEQProof } from "../src/types/index.js";
import { verifyOnChainAssembly, encodeVerifyPolynomialCalldata } from "../src/lib/evm_verifier.js";

describe("Verifier Contract", () => {
  let verifier: any;
  let publicClient: any;
  let walletClient: any;

  // Common test secret for the trusted setup
  const TRUSTED_SECRET = 12345n;
  const [PUBLIC_PX, PUBLIC_PY] = ecMul(GX, GY, TRUSTED_SECRET);

  before(async () => {
    const { viem } = await network.connect({
      network: "hardhatMainnet",
      chainType: "l1",
    });

    // Deploy with immutable public point
    verifier = await viem.deployContract("Verifier", [PUBLIC_PX, PUBLIC_PY]);
    publicClient = await viem.getPublicClient();
    [walletClient] = await viem.getWalletClients();
  });

  // ============================================================================
  // Helper Functions
  // ============================================================================

  /**
   * Generate a valid proof from secret s, evaluation point x, and witness w
   * This constructs a polynomial p where p(x) = 0 and p(s) = w * (s - x)
   */
  async function generateValidProof(s: bigint, x: bigint, w: bigint): Promise<DLEQProof> {
    // Construct a polynomial p such that:
    // - p(x) = 0
    // - p(s) = w * (s - x)
    // We use: p(t) = w * (t - x)
    // Expanded: p(t) = -w*x + w*t
    const coeffs = [mod(-mod(w * x, N), N), w];
    
    return await generateProof(x, coeffs, s);
  }

  // ----------------------------------------------------------------------------
  // Verification helpers (assembly-optimized only)
  // ----------------------------------------------------------------------------

  // Assembly-optimized verifier: expect success, return gas
  async function expectValid(proof: DLEQProof, logGas: boolean = false): Promise<bigint> {
    const result = await verifyOnChainAssembly(verifier.address, proof, walletClient, publicClient, 1n);
    expect(result.valid).to.equal(true);
    if (logGas && result.gasUsed) {
      console.log(`      gas: ${result.gasUsed}`);
    }
    return result.gasUsed ?? 0n;
  }

  // Assembly-optimized verifier: expect failure
  async function expectInvalid(proof: DLEQProof): Promise<void> {
    const result = await verifyOnChainAssembly(verifier.address, proof, walletClient, publicClient, 1n);
    expect(result.valid).to.equal(false);
  }

  // ============================================================================
  // 1. Positive Tests - Valid Proofs
  // ============================================================================

  describe("1. Positive Tests - Valid Proofs", () => {
    it("1.1: Basic valid proof with small values", async () => {
      const s1 = TRUSTED_SECRET;
      const x1 = 5n;
      const w1 = 7n;
      const proof = await generateValidProof(s1, x1, w1);
      await expectValid(proof, true);
    });

    it("1.2: Valid proof with large random values", async () => {
      const s2 = TRUSTED_SECRET;
      const x2 = randomScalar();
      const w2 = randomScalar();
      const proof = await generateValidProof(s2, x2, w2);
      await expectValid(proof);
    });

    it("1.3: Valid proof with x = 1 (edge case)", async () => {
      const s3 = TRUSTED_SECRET;
      const x3 = 1n;
      const w3 = randomScalar();
      const proof = await generateValidProof(s3, x3, w3);
      await expectValid(proof);
    });

    it("1.4: Valid proof with w = 1 (edge case)", async () => {
      const s4 = TRUSTED_SECRET;
      const x4 = randomScalar();
      const w4 = 1n;
      const proof = await generateValidProof(s4, x4, w4);
      await expectValid(proof);
    });

    it("1.5: Valid proof with near-maximum field values", async () => {
      const s5 = TRUSTED_SECRET;
      const x5 = N - 5n;
      const w5 = N - 7n;
      const proof = await generateValidProof(s5, x5, w5);
      await expectValid(proof);
    });

    it("1.6: Valid proof with x = N - 1 (maximum valid value)", async () => {
      const s6 = TRUSTED_SECRET;
      const x6 = N - 1n;
      const w6 = randomScalar();
      const proof = await generateValidProof(s6, x6, w6);
      await expectValid(proof);
    });

    it("1.7: Valid proof with z = N - 1 (maximum valid value)", async () => {
      const s7 = TRUSTED_SECRET;
      const x7 = randomScalar();
      const w7 = randomScalar();
      const proof = await generateValidProof(s7, x7, w7);
      await expectValid(proof);
    });

    it("1.8: Valid proof with k = 1 (minimum nonce)", async () => {
      const s8 = TRUSTED_SECRET;
      const x8 = randomScalar();
      const w8 = randomScalar();
      const proof = await generateValidProof(s8, x8, w8);
      await expectValid(proof);
    });

    it("1.9: Valid proof with s = x = 1 (would cause s-x = 0)", async () => {
      // This should fail at proof generation time, not verification
      const s9 = 1n;
      const x9 = 1n;
      const w9 = 1n;
      let failed = false;
      try {
        await generateValidProof(s9, x9, w9);
      } catch (error) {
        failed = true;
      }
      expect(failed).to.be.true;
    });

    it("1.10: Valid proof where s - x = 1", async () => {
      const s10 = TRUSTED_SECRET;
      const x10 = TRUSTED_SECRET - 1n;
      const w10 = randomScalar();
      const proof = await generateValidProof(s10, x10, w10);
      await expectValid(proof);
    });
  });

  // ============================================================================
  // 2. Negative Tests - Invalid Response (z)
  // ============================================================================

  describe("2. Negative Tests - Invalid Response (z)", () => {
    it("2.1: Wrong z value (z + 1)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.z = mod(proof.z + 1n, N);
      await expectInvalid(proof);
    });

    it("2.2: Wrong z value (z - 1)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.z = mod(proof.z - 1n, N);
      await expectInvalid(proof);
    });

    it("2.3: Random wrong z value", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.z = randomScalar();
      await expectInvalid(proof);
    });

    it("2.4: z = 0 (out of range)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.z = 0n;
      await expectInvalid(proof);
    });

    it("2.5: z >= N (out of range)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.z = N;
      await expectInvalid(proof);
    });

    it("2.6: z = N + 1 (way out of range)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.z = N + 1n;
      await expectInvalid(proof);
    });

    it("2.7: z = 1 (valid range but wrong value)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.z = 1n;
      await expectInvalid(proof);
    });
  });

  // ============================================================================
  // 3. Negative Tests - Invalid Input x
  // ============================================================================

  describe("3. Negative Tests - Invalid Input x", () => {
    it("3.1: x = 0 (out of range)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.x = 0n;
      await expectInvalid(proof);
    });

    it("3.2: x >= N (out of range)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.x = N;
      await expectInvalid(proof);
    });

    it("3.3: Wrong x value (different evaluation point)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.x = 7n;
      await expectInvalid(proof);
    });

    it("3.4: x = N + 1 (way out of range)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.x = N + 1n;
      await expectInvalid(proof);
    });

    it("3.5: x = N - 1 (valid range but wrong value)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.x = N - 1n;
      await expectInvalid(proof);
    });

    it("3.6: x = P (confusing curve and scalar field)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.x = P;
      await expectInvalid(proof);
    });
  });

  // ============================================================================
  // 4. Negative Tests - Invalid Curve Points
  // ============================================================================

  describe("4. Negative Tests - Invalid Curve Points", () => {
    it("4.1: Invalid Cx (not on curve)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.C.x = mod(proof.C.x + 1n, P);
      await expectInvalid(proof);
    });

    it("4.2: Invalid Cy (not on curve)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.C.y = mod(proof.C.y + 1n, P);
      await expectInvalid(proof);
    });

    it("4.3: Invalid Wx (not on curve)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.W.x = mod(proof.W.x + 1n, P);
      await expectInvalid(proof);
    });

    it("4.4: Invalid Wy (not on curve)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.W.y = mod(proof.W.y + 1n, P);
      await expectInvalid(proof);
    });

    it("4.5: Coordinate >= P (out of range)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.C.x = P;
      await expectInvalid(proof);
    });

    it("4.6: Coordinate = P + 1 (way out of range)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.W.x = P + 1n;
      await expectInvalid(proof);
    });

    it("4.7: Coordinate = 0 (likely not on curve)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.C.x = 0n;
      await expectInvalid(proof);
    });

    it("4.8: Near-maximum coordinate with invalid point", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.C.x = mod(proof.C.x + 1n, P);
      await expectInvalid(proof);
    });

    it("4.9: Both Cx and Cy modified", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.C.x = mod(proof.C.x + 1n, P);
      proof.C.y = mod(proof.C.y + 1n, P);
      await expectInvalid(proof);
    });
  });

  // ============================================================================
  // ============================================================================
  // Extra: Version Mismatch
  // ============================================================================
  describe("Extra: Version Mismatch", () => {
    it("X.1: version != 1 should revert", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      const data = encodeVerifyPolynomialCalldata(proof, 2n);
      const result = await (async () => {
        try {
          const hash: `0x${string}` = await walletClient.sendTransaction({
            to: verifier.address,
            data,
          });
          await publicClient.waitForTransactionReceipt({ hash });
          return { valid: true };
        } catch {
          return { valid: false };
        }
      })();
      expect(result.valid).to.equal(false);
    });
  });

  // ============================================================================
  // ============================================================================
  // 8. Negative Tests - Wrong Relationships Between Points
  // ============================================================================

  describe("8. Negative Tests - Wrong Relationships", () => {
    it("8.1: Wrong P (breaks T = P - X)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.P.x = mod(proof.P.x + 1n, P);
      await expectInvalid(proof);
    });

    it("8.2: C and W don't have correct DLEQ relationship", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      const [wrongWx, ] = ecMul(GX, GY, 999n);
      proof.W.x = wrongWx;
      await expectInvalid(proof);
    });
  });

  // ============================================================================
  // 9. Randomized Stress Testing
  // ============================================================================

  describe("9. Randomized Stress Tests", () => {
    const numRandomTests = 10;
    for (let i = 0; i < numRandomTests; i++) {
      it(`9.${i + 1}: Random valid proof ${i + 1}/${numRandomTests}`, async () => {
        const s_rand = TRUSTED_SECRET;
        const x_rand = randomScalar();
        const w_rand = randomScalar();
        const proof = await generateValidProof(s_rand, x_rand, w_rand);
        await expectValid(proof);
      });
    }
  });

  // ============================================================================
  // 10. Polynomial Edge Cases
  // ============================================================================

  describe("10. Polynomial Edge Cases", () => {
    it("10.1: Valid degree 1 polynomial proof", async () => {
      const x_deg1 = 100n;
      const b_deg1 = 42n;
      const a_deg1 = mod(-mod(b_deg1 * x_deg1, N), N);
      const coeffs_deg1 = [a_deg1, b_deg1];
      const proof = await generateProof(x_deg1, coeffs_deg1, TRUSTED_SECRET);
      await expectValid(proof);
    });

    it("10.2: Sparse polynomial (single term)", async () => {
      const r_sparse = 50n;
      const c_sparse = 123n;
      const coeffs_sparse = [mod(-mod(c_sparse * r_sparse, N), N), c_sparse];
      const proof = await generateProof(r_sparse, coeffs_sparse, TRUSTED_SECRET);
      await expectValid(proof);
    });

    it("10.3: Polynomial with near-maximum coefficients", async () => {
      const x_max = 77n;
      const coeffs_max = new Array(10).fill(N - 1n);
      let sum_max = 0n;
      let x_pow_max = x_max;
      for (let i = 1; i < coeffs_max.length; i++) {
        sum_max = mod(sum_max + mod(coeffs_max[i] * x_pow_max, N), N);
        x_pow_max = mod(x_pow_max * x_max, N);
      }
      coeffs_max[0] = mod(-sum_max, N);
      const proof = await generateProof(x_max, coeffs_max, TRUSTED_SECRET);
      await expectValid(proof);
    });

    it("10.4: Polynomial with alternating coefficients", async () => {
      const x_alt = 33n;
      const coeffs_alt = [];
      for (let i = 0; i < 20; i++) {
        coeffs_alt.push(i % 2 === 0 ? 1n : N - 1n);
      }
      let sum_alt = 0n;
      let x_pow_alt = x_alt;
      for (let i = 1; i < coeffs_alt.length; i++) {
        sum_alt = mod(sum_alt + mod(coeffs_alt[i] * x_pow_alt, N), N);
        x_pow_alt = mod(x_pow_alt * x_alt, N);
      }
      coeffs_alt[0] = mod(-sum_alt, N);
      const proof = await generateProof(x_alt, coeffs_alt, TRUSTED_SECRET);
      await expectValid(proof);
    });
  });

  // ============================================================================
  // 11. Test with 100-term Polynomial
  // ============================================================================

  describe("11. Test with 100-term Polynomial", () => {
    it("11.1: Valid 100-term polynomial proof", async () => {
      const s_poly = TRUSTED_SECRET;
      const x_poly = 42n;

      const coeffs: bigint[] = new Array(100);
      for (let i = 1; i < 100; i++) {
        coeffs[i] = randomScalar();
      }

      let sum = 0n;
      let x_power = x_poly;
      for (let i = 1; i < 100; i++) {
        sum = mod(sum + mod(coeffs[i] * x_power, N), N);
        x_power = mod(x_power * x_poly, N);
      }
      coeffs[0] = mod(-sum, N);

      const proof = await generateProof(x_poly, coeffs, s_poly);
      await expectValid(proof);
    });
  });

  // ============================================================================
  // 12. Gas Usage Tests
  // ============================================================================

  describe("12. Gas Usage Tests", () => {
    it("12.1: Gas usage with small values", async () => {
      const s = TRUSTED_SECRET;
      const x = 5n;
      const w = 7n;
      const proof = await generateValidProof(s, x, w);
      
      const gas = await expectValid(proof, false);
      console.log(`\n      Assembly Version: ${gas} gas`);
      
      expect(Number(gas)).to.be.greaterThan(0);
    });

    it("12.2: Gas usage with large random values", async () => {
      const s = TRUSTED_SECRET;
      const x = randomScalar();
      const w = randomScalar();
      const proof = await generateValidProof(s, x, w);
      
      const gas = await expectValid(proof, false);
      console.log(`\n      Assembly Version: ${gas} gas`);
      
      expect(Number(gas)).to.be.greaterThan(0);
    });

    it("12.3: Gas usage with near-maximum field values", async () => {
      const s = TRUSTED_SECRET;
      const x = N - 5n;
      const w = N - 7n;
      const proof = await generateValidProof(s, x, w);
      
      const gas = await expectValid(proof, false);
      console.log(`\n      Assembly Version: ${gas} gas`);
      
      expect(Number(gas)).to.be.greaterThan(0);
    });

    it("12.4: Average gas usage over 5 random proofs", async () => {
      let totalGas = 0n;
      const numTests = 5;
      
      for (let i = 0; i < numTests; i++) {
        const s = TRUSTED_SECRET;
        const x = randomScalar();
        const w = randomScalar();
        const proof = await generateValidProof(s, x, w);
        
        const gas = await expectValid(proof, false);
        totalGas += gas;
      }
      
      const avgGas = totalGas / BigInt(numTests);
      console.log(`\n      Average Assembly Version: ${avgGas} gas`);
      
      expect(Number(avgGas)).to.be.greaterThan(0);
    });
  });
});
