# KZG-DLEQ

A TypeScript library for generating and verifying polynomials using DLEQ (Discrete Logarithm Equality) proofs, with efficient on-chain verification via optimized Solidity assembly.

## Overview

This library implements a protocol for proving that a polynomial evaluates to zero at a specific point (p(x) = 0) using KZG commitments and DLEQ proofs. The proof generation and verification can be performed both off-chain (TypeScript) and on-chain (Solidity) with gas-optimized assembly.

### Key Features

- **Zero Evaluation Proofs**: Prove that p(x) = 0 for a committed polynomial
- **DLEQ Protocol**: Uses Discrete Logarithm Equality proofs for security
- **Dual Verification**: TypeScript and Solidity implementations
- **Gas Optimized**: Assembly-optimized on-chain verifier (~13.8k gas + calldata)
- **Secp256k1 Curve**: Uses the same elliptic curve as Bitcoin/Ethereum
- **Ecrecover Optimization**: Leverages native precompiles for efficient EC operations

## Installation

```shell
npm install
```

## Usage

### Basic Proof Generation and Verification

```typescript
import { KZGDLEQClient } from 'kzg-dleq';

const client = new KZGDLEQClient();

// Generate a proof
const x = 5n; // evaluation point
const polynomial = [1n, 2n, 3n]; // coefficients: 1 + 2x + 3x²
const trustedSetupSecret = 42n;

const proof = await client.prove(x, polynomial, trustedSetupSecret);

// Verify off-chain
const isValid = client.verify(proof, verbose = true);
console.log('Proof valid:', isValid);
```

### On-Chain Verification

```typescript
import { verifyOnChainAssembly } from 'kzg-dleq';

// Deploy verifier contract with trusted setup point P = s*G
const verifierAddress = '0x...';

// Verify proof on-chain
const result = await client.verifyOnChain(
  verifierAddress,
  proof,
  walletClient,
  publicClient
);
```

## Testing

Run the test suite:

```shell
npx hardhat test
```

The test suite includes:
- TypeScript verifier tests
- On-chain Solidity verifier tests
- Gas estimation benchmarks

## Architecture

### Components

- **Prover** (`src/lib/cheat_prover.ts`): Generates DLEQ proofs for zero evaluation
- **Verifier** (`src/lib/verifier.ts`): TypeScript implementation of proof verification
- **EVM Verifier** (`contracts/verifier.sol`): Gas-optimized Solidity verifier using assembly
- **Crypto Utils** (`src/lib/crypto.ts`): Elliptic curve operations on Secp256k1

### Protocol

1. **Commitment**: Prover commits to polynomial using trusted setup
2. **Challenge**: Fiat-Shamir challenge derived from proof elements
3. **DLEQ Proof**: Proves discrete log equality without revealing secrets
4. **Verification**: Verifier checks proof equations using EC operations
