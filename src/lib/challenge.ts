import { keccak256 } from 'viem'
import { mod, N } from './crypto.js'
import { concat, encodeU8, encodeU256, encodeAddress } from './bytes.js'

/**
 * Build Fiat–Shamir challenge e using the exact packing expected on-chain:
 * domain byte 0x01 || Cx || Wx || Px || Py || A1addr || A2addr || x || parity
 */
export function buildChallenge(
	Cx: bigint,
	Wx: bigint,
	Px: bigint,
	Py: bigint,
	A1addr: string,
	A2addr: string,
	x: bigint,
	parity: number
): bigint {
	const challengeData = concat(
		encodeU8(0x01),
		encodeU256(Cx),
		encodeU256(Wx),
		encodeU256(Px),
		encodeU256(Py),
		encodeAddress(A1addr),
		encodeAddress(A2addr),
		encodeU256(x),
		encodeU8(parity)
	)

	return mod(BigInt(keccak256(challengeData)), N)
}
