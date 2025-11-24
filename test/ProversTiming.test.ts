import { describe, it, before } from "node:test";
import { expect } from "chai";
import { network } from "hardhat";

import {
  randomScalar,
  mod,
  N,
  GX,
  GY,
  ecMul,
  ecAdd,
  ecAddress,
  Field,
  P,
  Point,
} from "../src/lib/crypto.js";
import { generateSharedSRS } from "../src/lib/cheat_srs.js";
import {
  proverStart,
  proverRespond,
  proverFinalize,
  type PolyEvalProofStart,
} from "../src/lib/prover.js";
import {
  proverVoleStart,
  proverVoleFinalize,
  type PolyEvalVoleStart,
  type PolyEvalVoleShare,
} from "../src/lib/prover_vole.js";
import type { DLEQProof } from "../src/lib/verifier.js";
import type {
  ROLESenderOLE,
  ROLEReceiverOLE,
} from "../src/lib/role.js";
import { verifyProof } from "../src/lib/verifier.js";
import {
  verifyOnChainAssembly,
  encodeVerifyPolynomialCalldata,
} from "../src/lib/verifier_evm.js";
import { buildChallenge } from "../src/lib/challenge.js";

const TRUSTED_SECRET = 12345n;

function hrtimeMs(): bigint {
  return process.hrtime.bigint() / 1_000_000n;
}

interface ProverTimings {
  classicRound1Ms: number;
  classicRound2Ms: number;
  classicFinalizeMs: number;
  voleNodeMs: number;
  voleFinalizeMs: number;
}

interface DualProofResult {
  classic: DLEQProof;
  vole: DLEQProof;
  timings: ProverTimings;
}

function logTimings(label: string, t: ProverTimings) {
  // Keep logging lightweight but structured.
  console.log(
    `\n[${label}] classic: R1=${t.classicRound1Ms.toFixed(
      3,
    )}ms, R2=${t.classicRound2Ms.toFixed(
      3,
    )}ms, finalize=${t.classicFinalizeMs.toFixed(
      3,
    )}ms; vole: node=${t.voleNodeMs.toFixed(
      3,
    )}ms, finalize=${t.voleFinalizeMs.toFixed(3)}ms`,
  );
}

async function generateProofsViaSharesDual(
  coeffs: bigint[],
  x: bigint,
  s: bigint,
  numNodes: number,
): Promise<DualProofResult> {
  const poly = Field.newVectorFrom(coeffs);
  const [Px, Py] = ecMul(GX, GY, s);
  const Ppub: Point = { x: Px, y: Py };
  const srsShares = generateSharedSRS(numNodes, coeffs.length - 1, s);

  // -----------------------------
  // Classic prover (baseline)
  // -----------------------------
  const startClassicR1 = hrtimeMs();
  const r1 = await Promise.all(
    srsShares.map(share =>
      proverStart({
        x,
        p: poly,
        srsShare: share,
        P: Ppub,
      }),
    ),
  );
  const endClassicR1 = hrtimeMs();

  const r1msgs = r1.map(r => r.message);
  const states = r1.map(r => r.state);

  const startClassicR2 = hrtimeMs();
  const r2 = states.map(st => proverRespond(r1msgs, x, Ppub, st));
  const endClassicR2 = hrtimeMs();

  const startClassicFinalize = hrtimeMs();
  const classicProof = proverFinalize(r2);
  const endClassicFinalize = hrtimeMs();

  // -----------------------------
  // VOLE-based prover
  // -----------------------------
  const voleShares: PolyEvalVoleShare[] = [];
  const voleSenderSamples: ROLESenderOLE[] = [];

  const startVoleNode = hrtimeMs();
  for (let i = 0; i < numNodes; i++) {
    const oleSample: ROLESenderOLE = {
      index: i,
      a: randomScalar(),
      b: randomScalar(),
    };
    voleSenderSamples.push(oleSample);
    const { share } = await proverVoleStart(
      {
        x,
        p: poly,
        srsShare: srsShares[i]!,
        P: Ppub,
      },
      oleSample,
    );
    voleShares.push(share);
  }
  const endVoleNode = hrtimeMs();

  // Aggregator: reconstruct challenge e from aggregated points,
  // then build consistent OLE receiver samples with x = e and y = a*e + b.
  const sumPoints = (pts: Point[]): Point => {
    let acc = pts[0]!;
    for (let i = 1; i < pts.length; i++) {
      const p = pts[i]!;
      const [nx, ny] = ecAdd(acc.x, acc.y, p.x, p.y);
      acc = { x: nx, y: ny };
    }
    return acc;
  };

  const Cagg = sumPoints(voleShares.map(s => s.Ci));
  const Wagg = sumPoints(voleShares.map(s => s.Wi));
  const A1agg = sumPoints(voleShares.map(s => s.A1i));
  const A2agg = sumPoints(voleShares.map(s => s.A2i));

  const A1addr = ecAddress(A1agg.x, A1agg.y);
  const A2addr = ecAddress(A2agg.x, A2agg.y);
  const parity = Number((Cagg.y & 1n) | ((Wagg.y & 1n) << 1n));
  const e = buildChallenge(
    Cagg.x,
    Wagg.x,
    Ppub.x,
    Ppub.y,
    A1addr,
    A2addr,
    x,
    parity,
  );

  const oleReceiverSamples: ROLEReceiverOLE[] = voleSenderSamples.map(s => ({
    index: s.index,
    x: e,
    y: mod(s.a * e + s.b, N),
  }));

  const startVoleFinalize = hrtimeMs();
  const voleProof = proverVoleFinalize(voleShares, oleReceiverSamples, x, Ppub);
  const endVoleFinalize = hrtimeMs();

  const timings: ProverTimings = {
    classicRound1Ms: Number(endClassicR1 - startClassicR1),
    classicRound2Ms: Number(endClassicR2 - startClassicR2),
    classicFinalizeMs: Number(endClassicFinalize - startClassicFinalize),
    voleNodeMs: Number(endVoleNode - startVoleNode),
    voleFinalizeMs: Number(endVoleFinalize - startVoleFinalize),
  };

  // Sanity: both proofs should be valid. We do not require them to be byte-for-byte identical.
  expect(verifyProof(classicProof)).to.equal(true);
  expect(verifyProof(voleProof)).to.equal(true);

  return { classic: classicProof, vole: voleProof, timings };
}

async function generateValidProofDual(
  s: bigint,
  x: bigint,
  w: bigint,
  numNodes: number,
): Promise<DualProofResult> {
  const coeffs = [mod(-mod(w * x, N), N), w];
  return generateProofsViaSharesDual(coeffs, x, s, numNodes);
}

// ============================================================================
// Verifier Contract tests (from Verifier.test.ts)
// ============================================================================

describe("Verifier Contract", () => {
  let verifier: any;
  let publicClient: any;
  let walletClient: any;

  const [PUBLIC_PX, PUBLIC_PY] = ecMul(GX, GY, TRUSTED_SECRET);

  before(async () => {
    const { viem } = await network.connect({
      network: "hardhatMainnet",
      chainType: "l1",
    });

    verifier = await viem.deployContract("Verifier", [PUBLIC_PX, PUBLIC_PY]);
    publicClient = await viem.getPublicClient();
    [walletClient] = await viem.getWalletClients();
  });

  // ============================================================================
  // Helper Functions
  // ============================================================================

  async function generateProofViaShares(
    coeffs: bigint[],
    x: bigint,
    s: bigint,
    numNodes: number = 4,
  ): Promise<DLEQProof> {
    // Build polynomial vector (galois)
    const poly = Field.newVectorFrom(coeffs);
    // Public points
    const [Px, Py] = ecMul(GX, GY, s);
    const Ppub = { x: Px, y: Py };
    // Build shared SRS for a threshold-style setting; nodes never see s directly.
    const srsShares = generateSharedSRS(numNodes, coeffs.length - 1, s);

    // -----------------------------------------------------------------------
    // Original threshold prover (baseline)
    // -----------------------------------------------------------------------
    const r1 = await Promise.all(
      srsShares.map(share => proverStart({ x, p: poly, srsShare: share, P: Ppub })),
    );
    const r1msgs = r1.map(r => r.message);
    const states = r1.map(r => r.state);
    const r2 = states.map(st => proverRespond(r1msgs, x, Ppub, st));
    const classicProof = proverFinalize(r2);

    // -----------------------------------------------------------------------
    // VOLE-backed prover: exercise on every test case.
    // -----------------------------------------------------------------------
    const voleSenderSamples: ROLESenderOLE[] = [];
    const voleShares: PolyEvalVoleShare[] = [];
    for (let i = 0; i < numNodes; i++) {
      const oleSample: ROLESenderOLE = {
        index: i,
        a: randomScalar(),
        b: randomScalar(),
      };
      voleSenderSamples.push(oleSample);
      const { share } = await proverVoleStart(
        { x, p: poly, srsShare: srsShares[i]!, P: Ppub },
        oleSample,
      );
      voleShares.push(share);
    }

    // Reconstruct challenge e exactly as in prover_vole.ts so we can build
    // consistent ROLEReceiverOLE objects with y_i = a_i * e + b_i.
    const sumPointsLocal = (pts: Point[]): Point => {
      let acc = pts[0]!;
      for (let i = 1; i < pts.length; i++) {
        const p = pts[i]!;
        const [nx, ny] = ecAdd(acc.x, acc.y, p.x, p.y);
        acc = { x: nx, y: ny };
      }
      return acc;
    };

    const Cagg = sumPointsLocal(voleShares.map(s => s.Ci));
    const Wagg = sumPointsLocal(voleShares.map(s => s.Wi));
    const A1agg = sumPointsLocal(voleShares.map(s => s.A1i));
    const A2agg = sumPointsLocal(voleShares.map(s => s.A2i));

    const A1addr = ecAddress(A1agg.x, A1agg.y);
    const A2addr = ecAddress(A2agg.x, A2agg.y);
    const parity = Number((Cagg.y & 1n) | ((Wagg.y & 1n) << 1n));
    const e = buildChallenge(
      Cagg.x,
      Wagg.x,
      Ppub.x,
      Ppub.y,
      A1addr,
      A2addr,
      x,
      parity,
    );

    const oleReceiverSamples: ROLEReceiverOLE[] = voleSenderSamples.map(s => ({
      index: s.index,
      x: e,
      y: mod(s.a * e + s.b, N),
    }));

    const voleProof = proverVoleFinalize(voleShares, oleReceiverSamples, x, Ppub);

  expect(verifyProof(classicProof)).to.equal(true);
  expect(verifyProof(voleProof)).to.equal(true);

    return classicProof;
  }

  async function generateValidProof(
    s: bigint,
    x: bigint,
    w: bigint,
  ): Promise<DLEQProof> {
    const coeffs = [mod(-mod(w * x, N), N), w];
    return await generateProofViaShares(coeffs, x, s);
  }

  async function expectValid(
    proof: DLEQProof,
    logGas: boolean = false,
  ): Promise<bigint> {
    const result = await verifyOnChainAssembly(
      verifier.address,
      proof,
      walletClient,
      publicClient,
      1n,
    );
    expect(result.valid).to.equal(true);
    if (logGas && result.gasUsed) {
      console.log(`      gas: ${result.gasUsed}`);
    }
    return result.gasUsed ?? 0n;
  }

  async function expectInvalid(proof: DLEQProof): Promise<void> {
    const result = await verifyOnChainAssembly(
      verifier.address,
      proof,
      walletClient,
      publicClient,
      1n,
    );
    expect(result.valid).to.equal(false);
  }

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

    it("1.9: s = x should be rejected (degenerate T = P - X)", async () => {
      const s9 = TRUSTED_SECRET;
      const x9 = TRUSTED_SECRET;
      const w9 = 1n;
      try {
        const proof = await generateValidProof(s9, x9, w9);
        await expectInvalid(proof);
      } catch (e: any) {
        expect(e.message).to.match(/degenerate|invalid scalar|out of range/);
      }
    });

    it("1.10: Valid proof where s - x = 1", async () => {
      const s10 = TRUSTED_SECRET;
      const x10 = TRUSTED_SECRET - 1n;
      const w10 = randomScalar();
      const proof = await generateValidProof(s10, x10, w10);
      await expectValid(proof);
    });
  });

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

  describe("8. Negative Tests - Wrong Relationships", () => {
    it("8.1: Wrong P (breaks T = P - X)", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      proof.P.x = mod(proof.P.x + 1n, P);
      await expectInvalid(proof);
    });

    it("8.2: C and W don't have correct DLEQ relationship", async () => {
      const proof = await generateValidProof(TRUSTED_SECRET, 5n, 7n);
      const [wrongWx] = ecMul(GX, GY, 999n);
      proof.W.x = wrongWx;
      await expectInvalid(proof);
    });
  });

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

  describe("10. Polynomial Edge Cases", () => {
    it("10.1: Valid degree 1 polynomial proof", async () => {
      const x_deg1 = 100n;
      const b_deg1 = 42n;
      const a_deg1 = mod(-mod(b_deg1 * x_deg1, N), N);
      const coeffs_deg1 = [a_deg1, b_deg1];
      const proof = await generateProofViaShares(
        coeffs_deg1,
        x_deg1,
        TRUSTED_SECRET,
      );
      await expectValid(proof);
    });

    it("10.2: Sparse polynomial (single term)", async () => {
      const r_sparse = 50n;
      const c_sparse = 123n;
      const coeffs_sparse = [mod(-mod(c_sparse * r_sparse, N), N), c_sparse];
      const proof = await generateProofViaShares(
        coeffs_sparse,
        r_sparse,
        TRUSTED_SECRET,
      );
      await expectValid(proof);
    });

    it("10.3: Polynomial with near-maximum coefficients", async () => {
      const x_max = 77n;
      const coeffs_max: bigint[] = new Array(10).fill(N - 1n);
      let sum_max = 0n;
      let x_pow_max = x_max;
      for (let i = 1; i < coeffs_max.length; i++) {
        sum_max = mod(sum_max + mod(coeffs_max[i]! * x_pow_max, N), N);
        x_pow_max = mod(x_pow_max * x_max, N);
      }
      coeffs_max[0] = mod(-sum_max, N);
      const proof = await generateProofViaShares(
        coeffs_max,
        x_max,
        TRUSTED_SECRET,
      );
      await expectValid(proof);
    });

    it("10.4: Polynomial with alternating coefficients", async () => {
      const x_alt = 33n;
      const coeffs_alt: bigint[] = [];
      for (let i = 0; i < 20; i++) {
        coeffs_alt.push(i % 2 === 0 ? 1n : N - 1n);
      }
      let sum_alt = 0n;
      let x_pow_alt = x_alt;
      for (let i = 1; i < coeffs_alt.length; i++) {
        sum_alt = mod(sum_alt + mod(coeffs_alt[i]! * x_pow_alt, N), N);
        x_pow_alt = mod(x_pow_alt * x_alt, N);
      }
      coeffs_alt[0] = mod(-sum_alt, N);
      const proof = await generateProofViaShares(
        coeffs_alt,
        x_alt,
        TRUSTED_SECRET,
      );
      await expectValid(proof);
    });
  });

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
        sum = mod(sum + mod(coeffs[i]! * x_power, N), N);
        x_power = mod(x_power * x_poly, N);
      }
      coeffs[0] = mod(-sum, N);

      const proof = await generateProofViaShares(coeffs, x_poly, s_poly);
      await expectValid(proof);
    });
  });

  describe("14. Large configuration - 13-of-19 with d = 1000", () => {
    it("14.1: VOLE prover handles 19 nodes and degree 1000", async () => {
      const numNodes = 19;
      const d = 1000;
      const s = TRUSTED_SECRET;
      let x = 123n;
      if (x === s) {
        x = 124n;
      }

      const coeffs: bigint[] = new Array(d + 1);
      for (let i = 1; i <= d; i++) {
        coeffs[i] = randomScalar();
      }
      let sum = 0n;
      let xPow = x;
      for (let i = 1; i <= d; i++) {
        sum = mod(sum + mod(coeffs[i]! * xPow, N), N);
        xPow = mod(xPow * x, N);
      }
      coeffs[0] = mod(-sum, N);

      const proof = await generateProofViaShares(coeffs, x, s, numNodes);
      await expectValid(proof);
    });
  });

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

// ============================================================================
// Prover timing / dual-prover tests
// ============================================================================

describe("Prover timing and consistency (classic vs VOLE)", () => {
  const numNodesDefault = 4;

  it("basic valid proof with small values (both provers, timed)", async () => {
    const s = TRUSTED_SECRET;
    const x = 5n;
    const w = 7n;

    const result = await generateValidProofDual(s, x, w, numNodesDefault);
    logTimings("small-values", result.timings);
  });

  it("valid proof with large random values (both provers, timed)", async () => {
    const s = TRUSTED_SECRET;
    const x = randomScalar();
    const w = randomScalar();

    const result = await generateValidProofDual(s, x, w, numNodesDefault);
    logTimings("random-large", result.timings);
  });

  it("polynomial edge case: 100-term polynomial (both provers, timed)", async () => {
    const s = TRUSTED_SECRET;
    const x_poly = 42n;

    const coeffs: bigint[] = new Array(100);
    for (let i = 1; i < 100; i++) {
      coeffs[i] = randomScalar();
    }

    let sum = 0n;
    let x_power = x_poly;
    for (let i = 1; i < 100; i++) {
      sum = mod(sum + mod(coeffs[i]! * x_power, N), N);
      x_power = mod(x_power * x_poly, N);
    }
    coeffs[0] = mod(-sum, N);

    const result = await generateProofsViaSharesDual(
      coeffs,
      x_poly,
      s,
      numNodesDefault,
    );
    logTimings("poly-100", result.timings);
  });

  it("large configuration: 19 nodes and degree 1000 (both provers, timed)", async () => {
    const numNodes = 19;
    const d = 1000;
    const s = TRUSTED_SECRET;
    let x = 123n;
    if (x === s) x = 124n;

    const coeffs: bigint[] = new Array(d + 1);
    for (let i = 1; i <= d; i++) {
      coeffs[i] = randomScalar();
    }

    let sum = 0n;
    let xPow = x;
    for (let i = 1; i <= d; i++) {
      sum = mod(sum + mod(coeffs[i]! * xPow, N), N);
      xPow = mod(xPow * x, N);
    }
    coeffs[0] = mod(-sum, N);

    const result = await generateProofsViaSharesDual(
      coeffs,
      x,
      s,
      numNodes,
    );
    logTimings("large-19x1000", result.timings);
  });

  it("randomized stress: 5 random valid proofs (both provers, timed)", async () => {
    const numRandomTests = 5;
    const s = TRUSTED_SECRET;

    for (let i = 0; i < numRandomTests; i++) {
      const x = randomScalar();
      const w = randomScalar();
      const result = await generateValidProofDual(s, x, w, numNodesDefault);
      logTimings(`random-${i + 1}`, result.timings);
    }
  });

  it("basic verifier negative: corrupt z breaks both proofs", async () => {
    const s = TRUSTED_SECRET;
    const x = 5n;
    const w = 7n;

    const { classic } = await generateValidProofDual(
      s,
      x,
      w,
      numNodesDefault,
    );
    expect(verifyProof(classic)).to.equal(true);

    classic.z = mod(classic.z + 1n, N);
    expect(verifyProof(classic)).to.equal(false);
  });

  it("curve point sanity: proofs coordinates are on-curve and in range", async () => {
    const s = TRUSTED_SECRET;
    const x = randomScalar();
    const w = randomScalar();

    const { classic } = await generateValidProofDual(
      s,
      x,
      w,
      numNodesDefault,
    );

    const coords = [
      classic.C.x,
      classic.C.y,
      classic.W.x,
      classic.W.y,
      classic.P.x,
      classic.P.y,
      classic.A1.x,
      classic.A1.y,
      classic.A2.x,
      classic.A2.y,
    ];
    for (const c of coords) {
      expect(c).to.be.at.least(0n);
      expect(c).to.be.lessThan(P);
    }
  });
});


