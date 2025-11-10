import { keccak256 } from 'viem'
import { mod, N } from './crypto.js'

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
	const challengeData = new Uint8Array(1 + 32 * 5 + 20 * 2 + 1)
	let offset = 0

	const writeUint8 = (value: number) => {
		challengeData[offset++] = value & 0xff
	}

	const writeUint256 = (value: bigint) => {
		for (let i = 0; i < 32; i++) {
			challengeData[offset + i] = Number((value >> BigInt(8 * (31 - i))) & 0xFFn)
		}
		offset += 32
	}

	const writeAddress = (addr: string) => {
		const addrBytes = addr.startsWith('0x') ? addr.slice(2) : addr
		for (let i = 0; i < 20; i++) {
			challengeData[offset + i] = parseInt(addrBytes.slice(i * 2, i * 2 + 2), 16)
		}
		offset += 20
	}

	writeUint8(0x01)
	writeUint256(Cx)
	writeUint256(Wx)
	writeUint256(Px)
	writeUint256(Py)
	writeAddress(A1addr)
	writeAddress(A2addr)
	writeUint256(x)
	writeUint8(parity)

	return mod(BigInt(keccak256(challengeData)), N)
}
