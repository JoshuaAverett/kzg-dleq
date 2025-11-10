import { N, mod, randomScalar, Field } from './crypto.js'

export function generateSharedSRS(
  numNodes: number,
  maxDegree: number,
  secret: bigint
): bigint[][] {
  const s = mod(secret, N)
  if (s === 0n) {
    throw new Error('secret must be non-zero modulo N')
  }

  // Precompute powers: s^0 .. s^maxDegree (mod N) via Galois
  const powers: bigint[] = Field.getPowerSeries(s, maxDegree + 1).toValues()

  // Initialize node shares
  const nodes: bigint[][] = Array.from({ length: numNodes }, () => [])

  // For each k, create additive shares of s^k and attach curve points
  for (let k = 0; k <= maxDegree; k++) {
    const target = powers[k]

    // Generate numNodes - 1 random shares via field PRNG last share closes the sum to target
    const scalars: bigint[] = new Array<bigint>(numNodes)
    let partialSum = 0n
    const prng = Field.prng(randomScalar(), numNodes - 1)
    const rands = prng.toValues()
    for (let i = 0; i < numNodes - 1; i++) {
      const r = rands[i]
      scalars[i] = r
      partialSum = mod(partialSum + r, N)
    }
    scalars[numNodes - 1] = mod(target - partialSum, N)

    // Store only scalar shares points can be derived on demand
    for (let i = 0; i < numNodes; i++) {
      nodes[i].push(scalars[i])
    }
  }

  return nodes
}
