import { N, mod, randomScalar, Field } from './crypto.js'
import type { Vector } from '@guildofweavers/galois'

export function generateSharedSRS(
	numNodes: number,
	maxDegree: number,
	secret: bigint
): Vector[] {
	if (numNodes < 1) {
		throw new Error('numNodes must be at least 1')
	}
	if (maxDegree < 0) {
		throw new Error('maxDegree must be non-negative')
	}

	const s = mod(secret, N)
	if (s === 0n) {
		throw new Error('secret must be non-zero modulo N')
	}

	// Target column vector: [s^0, s^1, ..., s^maxDegree]
	const targets = Field.getPowerSeries(s, maxDegree + 1)

	// Edge case: single node gets the full targets vector
	if (numNodes === 1) {
		return [targets]
	}

	// Generate all random shares with a single PRNG call and reshape into a matrix:
	// shape = [(numNodes - 1) rows, (maxDegree + 1) columns]
	const rows = numNodes - 1
	const cols = maxDegree + 1
	const flat = Field.prng(randomScalar(), rows * cols) as Vector
	const randomMatrix = Field.splitVector(flat, rows)
	const randomRows: Vector[] = Field.matrixRowsToVectors(randomMatrix)

	// Sum random rows element-wise using a vector of ones as coefficients
	const ones = Field.getPowerSeries(1n, rows)
	const sumRandoms = Field.combineManyVectors(randomRows, ones)

	// Final share vector ensures per-degree sums equal targets
	const last = Field.subVectorElements(targets, sumRandoms)
	randomRows.push(last)
	return randomRows
}
