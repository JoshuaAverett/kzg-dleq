import { describe, it, before } from "node:test";
import { expect } from "chai";
import { network } from "hardhat";
import { randomScalar, mod, N, GX, GY, ecMul } from "../src/lib/crypto.js";
import { generateSRS, commitPolynomial, generateProofUsingSRS } from "../src/lib/srs_prover.js";
import { verifyOnChainAssembly } from "../src/lib/verifier.js";

describe("SRS-based Prover", () => {
  let verifier: any;
  let publicClient: any;
  let walletClient: any;

  const TRUSTED_SECRET = 12345n;
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

  describe("SRS generation", () => {
    it("produces [G, sG, s^2G, ...]", () => {
      const maxDegree = 5;
      const srs = generateSRS(TRUSTED_SECRET, maxDegree);
      expect(srs.length).to.equal(maxDegree + 1);

      // s^i * G check
      let sPow = 1n;
      for (let i = 0; i <= maxDegree; i++) {
        const [expX, expY] = ecMul(GX, GY, sPow);
        expect(srs[i][0]).to.equal(expX);
        expect(srs[i][1]).to.equal(expY);
        sPow = mod(sPow * TRUSTED_SECRET, N);
      }
    });
  });

  describe("Commitment via SRS", () => {
    it("matches p(s) * G", () => {
      const maxDegree = 8;
      const srs = generateSRS(TRUSTED_SECRET, maxDegree);

      // Build random polynomial (length <= maxDegree + 1)
      const degree = 6;
      const coeffs: bigint[] = new Array(degree + 1).fill(0n).map((_, i) => i === 0 ? 0n : randomScalar());

      // Compute p(s)
      let ps = 0n;
      let sPow = 1n;
      for (let i = 0; i < coeffs.length; i++) {
        ps = mod(ps + mod(coeffs[i] * sPow, N), N);
        sPow = mod(sPow * TRUSTED_SECRET, N);
      }

      const [Cx, Cy] = commitPolynomial(coeffs, srs);
      const [Ex, Ey] = ecMul(GX, GY, ps);
      expect(Cx).to.equal(Ex);
      expect(Cy).to.equal(Ey);
    });

    it("throws if polynomial degree exceeds SRS length", () => {
      const srs = generateSRS(TRUSTED_SECRET, 2); // supports up to degree 2
      const coeffs = [1n, 2n, 3n, 4n]; // degree 3
      let threw = false;
      try {
        commitPolynomial(coeffs, srs);
      } catch {
        threw = true;
      }
      expect(threw).to.equal(true);
    });
  });

  describe("End-to-end proof using SRS", () => {
    async function expectValid(proof: any): Promise<void> {
      const result = await verifyOnChainAssembly(verifier.address, proof, walletClient, publicClient, 1n);
      expect(result.valid).to.equal(true);
    }

    it("verifies p(t) = w*(t - x) with small values", async () => {
      const x = 5n;
      const w = 7n;
      const coeffs = [mod(-mod(w * x, N), N), w]; // p(t) = -w*x + w*t

      const srs = generateSRS(TRUSTED_SECRET, 1);
      const proof = generateProofUsingSRS(x, coeffs, TRUSTED_SECRET, srs);
      await expectValid(proof);
    });

    it("verifies with random x and w", async () => {
      const x = randomScalar();
      const w = randomScalar();
      const coeffs = [mod(-mod(w * x, N), N), w];

      const srs = generateSRS(TRUSTED_SECRET, 1);
      const proof = generateProofUsingSRS(x, coeffs, TRUSTED_SECRET, srs);
      await expectValid(proof);
    });

    it("rejects when p(x) != 0 at construction time", () => {
      const x = 42n;
      const coeffs = [1n, 2n, 3n]; // random; likely p(x) != 0
      const srs = generateSRS(TRUSTED_SECRET, 3);

      let threw = false;
      try {
        generateProofUsingSRS(x, coeffs, TRUSTED_SECRET, srs);
      } catch {
        threw = true;
      }
      expect(threw).to.equal(true);
    });
  });
});


