// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Verifier {
	// Constants for Secp256k1
	// Source: https://en.bitcoin.it/wiki/Secp256k1
	uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
	uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
	uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
	uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

	// Type shift constants
	uint256 constant SHIFT_GET_1 = 256 - 1 * 8;
	uint256 constant SHIFT_GET_20 = 256 - 20 * 8;
	uint256 constant MASK_ADDRESS = 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff;

	// Input offset constants
	uint256 constant OFFSET_VERSION = 4;
	uint256 constant OFFSET_CX      = 4 + 1;
	uint256 constant OFFSET_WX      = 4 + 1 + 32;
	uint256 constant OFFSET_XX      = 4 + 1 + 32 *  2;
	uint256 constant OFFSET_XY      = 4 + 1 + 32 *  3;
	uint256 constant OFFSET_ZTX     = 4 + 1 + 32 *  4;
	uint256 constant OFFSET_ZTY     = 4 + 1 + 32 *  5;
	uint256 constant OFFSET_ECX     = 4 + 1 + 32 *  6;
	uint256 constant OFFSET_ECY     = 4 + 1 + 32 *  7;
	uint256 constant OFFSET_HINV    = 4 + 1 + 32 *  8;
	uint256 constant OFFSET_HINV2   = 4 + 1 + 32 *  9;
	uint256 constant OFFSET_Z       = 4 + 1 + 32 * 10;
	uint256 constant OFFSET_X       = 4 + 1 + 32 * 11;
	uint256 constant OFFSET_A1ADDR  = 4 + 1 + 32 * 12;
	uint256 constant OFFSET_A2ADDR  = 4 + 1 + 32 * 12 + 20;
	uint256 constant OFFSET_PARITY  = 4 + 1 + 32 * 12 + 20 * 2;

	// Challenge offset constants
	uint256 constant CHALLENGE_OFFSET_CX     = 1;
	uint256 constant CHALLENGE_OFFSET_WX     = 1 + 32;
	uint256 constant CHALLENGE_OFFSET_PX     = 1 + 32 * 2;
	uint256 constant CHALLENGE_OFFSET_PY     = 1 + 32 * 3;
	uint256 constant CHALLENGE_OFFSET_A1ADDR = 1 + 32 * 4;
	uint256 constant CHALLENGE_OFFSET_A2ADDR = 1 + 32 * 4 + 20;
	uint256 constant CHALLENGE_OFFSET_X      = 1 + 32 * 4 + 20 * 2;
	uint256 constant CHALLENGE_OFFSET_PARITY = 1 + 32 * 4 + 20 * 2 + 32;
	uint256 constant CHALLENGE_LENGTH        = 1 + 32 * 4 + 20 * 2 + 32 + 1;

	// Ecrecover offset constants
	uint256 constant OFFSET_ECRECOVER_V = 32;
	uint256 constant OFFSET_ECRECOVER_R = 64;
	uint256 constant OFFSET_ECRECOVER_S = 96;
	uint256 constant LENGTH_ECRECOVER_BUFFER = 128;
	uint256 constant LENGTH_ECRECOVER_RESULT = 32;
	uint256 constant ADDRESS_ECRECOVER = 0x01;
	uint256 constant ECRECOVER_V_OFFSET = 27;

	// Immutable public point P = s*G
	uint256 public immutable PX;
	uint256 public immutable PY;

	error InvalidInput();

	constructor(uint256 px, uint256 py) {
		if (px >= P || py >= P) revert InvalidInput();
		if (!isOnCurve(px, py)) revert InvalidInput();
		PX = px;
		PY = py;
	}

	// Validate that a point is on the curve y^2 = x^3 + 7 mod P
	function isOnCurve(uint256 x, uint256 y) private pure returns (bool) {
		bool in_field = (x < P) && (y < P);
		bool on_curve = mulmod(y, y, P) == addmod(mulmod(x, mulmod(x, x, P), P), 7, P);
		return in_field && on_curve;
	}

	function verifyPolynomial() external view {
		uint256 px = PX;
		uint256 py = PY;
		assembly ("memory-safe") {
			// Gas estimate: 3100
			function ecrecover(digest, v, r, s, buffer, expected) -> success {
        mstore(buffer, digest)
        mstore(add(buffer, OFFSET_ECRECOVER_V), v)
        mstore(add(buffer, OFFSET_ECRECOVER_R), r)
        mstore(add(buffer, OFFSET_ECRECOVER_S), s)
        success := staticcall(gas(), ADDRESS_ECRECOVER, buffer, LENGTH_ECRECOVER_BUFFER, buffer, LENGTH_ECRECOVER_RESULT)
        success := and(success, eq(expected, mload(buffer)))
      }

			// Gas estimate: 200
			function ecSub(Ax, Ay, Bx, By, Hinv) -> valid, Rx, Ry {
				valid := eq(mulmod(addmod(Ax, sub(P, Bx), P), Hinv, P), 1)
				let lam := mulmod(addmod(Ay, By, P), Hinv, P)
				Rx := addmod(mulmod(lam, lam, P), sub(P, addmod(Ax, Bx, P)), P)
				Ry := addmod(mulmod(lam, addmod(Ax, sub(P, Rx), P), P), sub(P, Ay), P)
			}

			// Load the inputs
			// Gas estimate: 120
			let version := shr(SHIFT_GET_1, calldataload(OFFSET_VERSION))
			let cx := calldataload(OFFSET_CX)
			let wx := calldataload(OFFSET_WX)
			let xx := calldataload(OFFSET_XX)
			let xy := calldataload(OFFSET_XY)
			let zdx := calldataload(OFFSET_ZTX)
			let zdy := calldataload(OFFSET_ZTY)
			let ecx := calldataload(OFFSET_ECX)
			let ecy := calldataload(OFFSET_ECY)
			let hinv := calldataload(OFFSET_HINV)
			let hinv2 := calldataload(OFFSET_HINV2)
			let z := calldataload(OFFSET_Z)
			let x := calldataload(OFFSET_X)
			let a1addr := shr(SHIFT_GET_20, calldataload(OFFSET_A1ADDR))
			let a2addr := shr(SHIFT_GET_20, calldataload(OFFSET_A2ADDR))
			let parity := shr(SHIFT_GET_1, calldataload(OFFSET_PARITY))

			// Check if the inputs are valid
			// Gas estimate: 120
			let all_valid
			{
				let version_valid := eq(version, 1)
				let cx_valid := lt(cx, P)
				let wx_valid := lt(wx, P)
				let x_valid := lt(x, N)
				let z_valid := lt(z, N)
				let a12_valid := not(or(or(iszero(a1addr), iszero(a2addr)), or(iszero(x), iszero(z))))
				all_valid := and(and(and(and(and(version_valid, cx_valid), wx_valid), x_valid), z_valid), a12_valid)
			}

			// Generate the challenge
			// Gas estimate: 260
			let buffer := mload(0x40)
			mstore(buffer, shl(SHIFT_GET_1, version)) // TODO: Expand to give more domain separation
			mstore(add(buffer, CHALLENGE_OFFSET_CX), cx)
			mstore(add(buffer, CHALLENGE_OFFSET_WX), wx)
			mstore(add(buffer, CHALLENGE_OFFSET_PX), px)
			mstore(add(buffer, CHALLENGE_OFFSET_PY), py)
			mstore(add(buffer, CHALLENGE_OFFSET_A1ADDR), shl(SHIFT_GET_20, a1addr))
			mstore(add(buffer, CHALLENGE_OFFSET_A2ADDR), shl(SHIFT_GET_20, a2addr))
			mstore(add(buffer, CHALLENGE_OFFSET_X), x)
			mstore(add(buffer, CHALLENGE_OFFSET_PARITY), shl(SHIFT_GET_1, parity))
			let challenge := mod(keccak256(buffer, CHALLENGE_LENGTH), N)

			// Verify X = x * G
			// Gas estimate: 3200
			mstore(0, xx)
			mstore(32, xy)
			let xAddr := and(keccak256(0, 64), MASK_ADDRESS)
			all_valid := and(all_valid, ecrecover(0, ECRECOVER_V_OFFSET, GX, mulmod(x, GX, N), buffer, xAddr))

			// Compute D = P - X using provided Hinv
			// Gas estimate: 200
			let d_valid, dx, dy := ecSub(px, py, xx, xy, hinv)
			all_valid := and(all_valid, d_valid)

			// Check z * G - e * W == A1
			// ecrecover relation: Q = (s/r) * R - (m/r) * G, where R has x = r and parity v
			// Set m = (N - a) * r and s = b * r to obtain Q = a*G + b*X in a single call
			// Gas estimate: 3200
			let a1_m := mulmod(sub(N, z), wx, N)
			let a1_v := add(ECRECOVER_V_OFFSET, and(shr(1, parity), 1))
			let a1_s := mulmod(sub(N, challenge), wx, N)
			all_valid := and(all_valid, ecrecover(a1_m, a1_v, wx, a1_s, buffer, a1addr))

			// Check z * D
			// Gas estimate: 3200
			mstore(0, zdx)
			mstore(32, zdy)
			let zt_addr := and(keccak256(0, 64), MASK_ADDRESS)
			let zt_y := add(ECRECOVER_V_OFFSET, and(dy, 1))
			all_valid := and(all_valid, ecrecover(0, zt_y, dx, mulmod(z, dx, N), buffer, zt_addr))
			
			// Check e * C
			// Gas estimate: 3200
			mstore(0, ecx)
			mstore(32, ecy)
			let ecaddr := and(keccak256(0, 64), MASK_ADDRESS)
			let ec_y := add(ECRECOVER_V_OFFSET, and(parity, 1))
			all_valid := and(all_valid, ecrecover(0, ec_y, cx, mulmod(challenge, cx, N), buffer, ecaddr))
			
			// Compute A2 = z * D - e * C
			// Gas estimate: 200
			let a2_valid, A2rx, A2ry := ecSub(zdx, zdy, ecx, ecy, hinv2)
			all_valid := and(all_valid, a2_valid)

			// Check address(A2) == A2addr
			// Gas estimate: 100, total should be ~13.8k + ~6.9k for calldata = ~20.7k
			mstore(0, A2rx)
			mstore(32, A2ry)
			let a2r_valid := eq(and(keccak256(0, 64), MASK_ADDRESS), a2addr)
			all_valid := and(all_valid, a2r_valid)

			if iszero(all_valid) {
				revert(0, 0)
			}
		}
	}
}
