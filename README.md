# OP_RAND: VRF on Bitcoin

[![Paper](https://img.shields.io/badge/paper-arXiv-red.svg)](https://arxiv.org/pdf/2501.16451)

This is a method of emulation of OP_RAND opcode on Bitcoin through a trustless
interactive game between transaction counterparties. The game result is probabilistic and doesn’t allow 
any party to cheat, increasing their chance of winning on any protocol step. The protocol is
organized in a way unrecognizable to any external party and doesn’t require any specific scripts
or Bitcoin protocol updates.

## 📖 Overview

OP_RAND allows two (currently) users to create the set of transactions, the UTXO of the final one of which 
can be spent with some probability by each counterparty. For that, OP_RAND uses:

- **Commitments**: The protocol allows the challenger to create commitments on random values, only one of each 
is used for the final address formation. An acceptor also mast create the commitment for their final public key, but 
without the knowledge if that can be spent.
- **Zero-Knowledge Proofs**: For proving the correctness of all actions (with hiding the secret data) between challenger 
and acceptor it uses Noir circuits with Barretenberg backend. 
- **Bitcoin Script**: OP_RAND doesn't require and update of the Bitcoin protocol or appearance of new op codes
- **Interactive Protocol**: Two-party commit-reveal scheme

### Key Features

- 🎲 **True Randomness**: Cryptographically secure 50/50 outcomes
- 🔒 **Trustless**: No third parties or oracles required
- 🕵️ **Private**: Commitment selection hidden until revelation
- ✅ **Verifiable**: All parties can verify proof correctness
- 🏃 **Fast**: Efficient zero-knowledge proof generation and verification
- 💰 **Economic**: Winner-takes-all incentive mechanism
- 👻 **Stealthy**: Appears as normal Bitcoin transactions

## 🏗️ Architecture

The project consists of several key components:

### Core Crates

- **`op-rand-types`** - Fundamental data structures and commitment types
- **`op-rand-prover`** - Zero-knowledge proof generation and verification using Barretenberg
- **`op-rand-transaction-builder`** - Bitcoin transaction construction utilities

### Applications

- **`apps/cli`** - Full-featured command-line interface for protocol interaction

### Circuits

- **`circuits/crates/challenger_circuit`** - ZK circuit for challenger proofs
- **`circuits/crates/acceptor_circuit`** - ZK circuit for acceptor proofs
- **`circuits/crates/common`** - Shared cryptographic utilities

## 🚀 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/distributed-lab/op_rand
cd op_rand

# Build the project
cargo build --release

# Install the CLI globally
cargo install --path apps/cli
```

### Verify Installation

```bash
op-rand-cli --help
```

## 🎮 Quick Start

### 1. Setup Configuration

Create a `config.toml` file:

```toml
# Your Bitcoin private key (WIF format)
private_key = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy"

# Esplora API endpoint
esplora_url = "https://blockstream.info/testnet/api"

# Bitcoin network (testnet, regtest, bitcoin)
network = "testnet"
```

> ⚠️ **Security Warning**: Never use mainnet private keys with real funds in development environments.

### 2. Complete Workflow Example

#### As Challenger (Party A):

```bash
# Create a 100,000 satoshi challenge
op-rand-cli create-challenge --amount 100000 --locktime 144

# This creates:
# - challenger.json (share with acceptor)
# - private_challenger.json (keep secret)
```

#### As Acceptor (Party B):

```bash
# Inspect the challenge first
op-rand-cli info --challenge-file challenger.json

# Accept the challenge by selecting a commitment
op-rand-cli accept-challenge \
  --challenge-file challenger.json \
  --selected-commitment 0

# This creates:
# - acceptor.json (send back to challenger)
```

#### Complete the Challenge (Challenger):

```bash
# Finalize and broadcast the challenge
op-rand-cli complete-challenge \
  --challenger-file challenger.json \
  --challenger-private-file private_challenger.json \
  --acceptor-file acceptor.json

# Returns: Transaction ID and reveals the random outcome
```

#### Claim Winnings:

```bash
# The winner can spend the locked funds
op-rand-cli try-spend \
  --challenge-tx "transaction_hex_from_previous_step" \
  --challenger  # or --acceptor depending on who won
```

## 🧩 SDK Usage

For developers who want to integrate OP_RAND into their applications, you can use the SDK crates directly instead of the CLI.

### Basic SDK Flow

> ⚠️ **Security Critical**: Always verify proofs from the counterparty before proceeding with any transaction. Skipping verification can lead to loss of funds.

> 📝 **Note**: The following is a simplified example for educational purposes. It omits many practical aspects like data serialization/sharing between parties, proper UTXO management, network communication, comprehensive error handling, and transaction broadcasting. This code is **not intended to compile** as-is and serves only to illustrate the core cryptographic and transaction flow.

```rust
use bitcoin::{Amount, OutPoint, PublicKey, WPubkeyHash, secp256k1::SecretKey};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, rand::thread_rng};
use bitcoin::absolute::{Height, LockTime};
use op_rand_types::{Commitments, FirstRankCommitment, ThirdRankCommitment};
use op_rand_prover::{BarretenbergProver, OpRandProver, OpRandProof};
use op_rand_transaction_builder::{TransactionBuilder, validate_deposit_transaction, validate_challenge_psbt};
use std::str::FromStr;

// 1. Create Challenge (Challenger)
let challenger_secret = SecretKey::new(&mut thread_rng());
let secp = bitcoin::secp256k1::Secp256k1::new();
let challenger_pubkey = challenger_secret.public_key(&secp);

// Generate commitments
let commitments = Commitments::generate(&secp, &mut thread_rng())?;
let first_rank_commitments = commitments.first_rank_commitments();
let third_rank_commitments = commitments.third_rank_commitments();

// Pick a random first rank commitment
let selected_first_rank_commitment = commitments
    .pick_random_first_rank_commitment(&mut thread_rng())?;

// Create prover and setup circuits
let prover = BarretenbergProver::default();
prover.setup_challenger_circuit()?;

// Generate challenger proof
let challenger_pubkey_hash = PublicKey::new(challenger_pubkey).wpubkey_hash();
let proof = prover.generate_challenger_proof(
    first_rank_commitments.clone(),
    third_rank_commitments.clone(),
    &challenger_pubkey,
    challenger_pubkey_hash.to_byte_array(),
)?;

// Build deposit transaction
let transaction_builder = TransactionBuilder::from(challenger_secret);
let prevouts = vec![(outpoint, Amount::from_sat(150_000))]; // your UTXOs
let deposit_tx = transaction_builder.build_deposit_transaction(
    selected_first_rank_commitment.clone(),
    prevouts,
    Amount::from_sat(100_000),
    None,
    None,
)?;

// 2. Accept Challenge (Acceptor)
let acceptor_secret = SecretKey::new(&mut thread_rng());
let acceptor_pubkey = acceptor_secret.public_key(&secp);
let selected_commitment_index = 0; // Acceptor's choice
let selected_commitment = third_rank_commitments[selected_commitment_index].clone();

// IMPORTANT: Verify challenger's proof before proceeding
prover.verify_challenger_proof(
    third_rank_commitments.clone(),
    &challenger_pubkey,
    challenger_pubkey_hash.to_byte_array(),
    &proof,
)?;

// Validate the challenger's deposit transaction
validate_deposit_transaction(&deposit_tx, &challenger_pubkey_hash, 0)?;

// Setup acceptor circuit and generate proof
prover.setup_acceptor_circuit()?;

// Create correct signature for acceptor proof
// 1. Combine acceptor's public key with selected commitment
let pk_combined = acceptor_pubkey.combine(&selected_commitment.inner())?;
let acceptor_pubkey_hash = PublicKey::new(pk_combined).wpubkey_hash()?;

// 2. Create message by double-hashing the combined pubkey hash
let message = Message::from_digest(
    sha256::Hash::hash(acceptor_pubkey_hash.as_byte_array()).to_byte_array()
);

// 3. Sign the message with acceptor's private key
let acceptor_signature = secp.sign_ecdsa(&message, &acceptor_secret);

let acceptor_proof = prover.generate_acceptor_proof(
    &acceptor_pubkey,
    &acceptor_signature,
    acceptor_pubkey_hash.to_byte_array(),
    third_rank_commitments.clone(),
)?;

// Build challenge transaction (PSBT)
let acceptor_tx_builder = TransactionBuilder::from(acceptor_secret);
let acceptor_prevouts = vec![(outpoint, Amount::from_sat(150_000))]; // Your utxos
let challenge_psbt = acceptor_tx_builder.build_challenge_tx(
    &PublicKey::from(challenger_pubkey),
    OutPoint::new(deposit_tx.compute_txid(), 0),
    selected_commitment,
    bitcoin::absolute::LockTime::Blocks(bitcoin::absolute::Height::from_consensus(144)?),
    Amount::from_sat(100_000),
    acceptor_prevouts,
    None,
    None,
)?;

// 3. Complete Challenge (Challenger)
// Verify acceptor proof first
prover.verify_acceptor_proof(
    acceptor_pubkey_hash.to_byte_array(),
    third_rank_commitments.clone(),
    &acceptor_proof,
)?;

// IMPORTANT: Validate the challenge PSBT before proceeding
validate_challenge_psbt(
    &challenge_psbt,
    acceptor_pubkey_hash,
    PublicKey::from(challenger_pubkey),
    LockTime::Blocks(Height::from_consensus(144)?),
    0, // output index
)?;

// Complete the challenge transaction
let completed_tx = transaction_builder.complete_challenge_tx(
    challenge_psbt,
    Amount::from_sat(100_000),
    0, // deposit input index
    selected_first_rank_commitment.clone(),
)?;

// 4. Spend Winnings (Winner)
// The winner can use sweep methods to claim funds
let sweep_tx = transaction_builder.sweep_challenge_output_acceptor(
    &completed_tx,
    &PublicKey::from(challenger_pubkey),
    None, // use acceptor's pubkey
    bitcoin::absolute::LockTime::Blocks(bitcoin::absolute::Height::from_consensus(144)?),
    Amount::from_sat(1000), // fee
)?;
```

### SDK Building Blocks

The SDK is built on three main crates that provide different levels of abstractions:

#### Core Crate APIs

- **`op_rand_types`** - Core data structures
  - `Commitments` - Generate and manage first/third rank commitments
  - `FirstRankCommitment` - Private commitments for challengers
  - `ThirdRankCommitment` - Public commitments for acceptors
- **`op_rand_prover`** - ZK proof system
  - `BarretenbergProver` - Main prover implementation
  - `OpRandProof` - Proof container with verification key
  - `OpRandProver` trait - Common interface for proof operations
- **`op_rand_transaction_builder`** - Bitcoin transaction utilities
  - `TransactionBuilder` - Build deposit, challenge, and sweep transactions
  - `TransactionSigner` - Handle transaction signing with commitment tweaks

#### Mid-Level Components

- **Circuit Setup** - `setup_challenger_circuit()` and `setup_acceptor_circuit()`
- **Proof Generation** - `generate_challenger_proof()` and `generate_acceptor_proof()`
- **Proof Verification** - `verify_challenger_proof()` and `verify_acceptor_proof()`
- **Transaction Flow** - `build_deposit_transaction()`, `build_challenge_tx()`, `complete_challenge_tx()`

#### Low-Level Primitives

- **Commitment Operations** - `combine()`, `add_tweak()`, `inner()` methods
- **Secp256k1 Integration** - Direct access to Bitcoin cryptographic primitives
- **PSBT Handling** - Partially Signed Bitcoin Transaction support
- **Script Generation** - P2WPKH and P2WSH script creation

### Error Handling

The SDK provides comprehensive error types:

```rust
use op_rand_prover::ProverError;
use op_rand_transaction_builder::TransactionError;
use bitcoin::secp256k1::Error as Secp256k1Error;

// Prover errors
match prover.generate_challenger_proof(/* ... */) {
    Ok(proof) => {
        // Success case
    }
    Err(ProverError::SetupError(msg)) => {
        eprintln!("Circuit setup failed: {}", msg);
    }
    Err(ProverError::ProofGenerationError(msg)) => {
        eprintln!("Proof generation failed: {}", msg);
    }
    Err(ProverError::InvalidProof) => {
        eprintln!("Proof verification failed");
    }
    Err(e) => {
        eprintln!("Prover error: {}", e);
    }
}

// Transaction builder errors
match transaction_builder.build_deposit_transaction(/* ... */) {
    Ok(tx) => {
        // Success case
    }
    Err(TransactionError::Secp256k1(secp_err)) => {
        eprintln!("Cryptographic error: {}", secp_err);
    }
    Err(TransactionError::InputIndexOutOfBounds) => {
        eprintln!("Invalid input index");
    }
    Err(TransactionError::ExtractTransactionFailed) => {
        eprintln!("Failed to extract transaction from PSBT");
    }
    Err(e) => {
        eprintln!("Transaction error: {}", e);
    }
}
```

## 🚧 Areas for Improvement

The current implementation has several areas that could be enhanced for better developer experience and production readiness:

### SDK & Developer Experience

- **Simplified High-Level API**: The current flow requires understanding of multiple low-level concepts. A unified `OpRandClient` could abstract away the complexity
- **Better Error Messages**: More descriptive error messages with suggested fixes
- **Async/Await Support**: Current implementation is synchronous; async support would improve integration
- **Builder Pattern Improvements**: More fluent APIs with better validation and defaults
- **Type Safety**: Stronger type system to prevent runtime errors (e.g., using phantom types for protocol states)

### Documentation & Examples

- **Interactive Tutorials**: Step-by-step guides for common use cases
- **API Documentation**: Comprehensive rustdoc with examples for all public APIs
- **Integration Examples**: Real-world examples for web apps, mobile apps, and server applications
- **Protocol Visualization**: Interactive diagrams explaining the cryptographic flow
- **Video Tutorials**: Visual explanations of the protocol and implementation

### Performance & Scalability

- **Proof Generation Optimization**: Faster ZK proof generation
- **Memory Optimization**: Reduce memory footprint for resource-constrained environments
- **Batch Operations**: Support for processing multiple challenges efficiently

### Security & Robustness

- **Public signals verification**: Extract public signals from the proof and verify they are correct
- **Audit Trail**: Better logging and monitoring for production deployments
- **Input Validation**: Comprehensive validation of all user inputs and external data

### Protocol Enhancements

- **Multi-Party Support**: Extend beyond two-party challenges
- **Configurable Outcomes**: Support for non-50/50 probability distributions
- **Lightning Network Integration**: Support for off-chain OP_RAND operations

### Testing & Quality Assurance

- **Comprehensive Test Suite**: Unit, integration, and end-to-end tests
- **Property-Based Testing**: Automated testing of cryptographic properties
- **Fuzzing**: Automated discovery of edge cases and potential vulnerabilities
- **Benchmark Suite**: Performance regression testing

## 📚 Documentation

- **[CLI Reference](apps/cli/README.md)** - Complete command-line interface documentation
- **[Research Paper](https://arxiv.org/pdf/2501.16451)** - "Emulating OP_RAND in Bitcoin" by Rarimo Protocol

## 🔬 How It Works

### Protocol Overview

1. **Commitment Phase**: Challenger generates cryptographic commitments to secret values
2. **Challenge Creation**: Zero-knowledge proof demonstrates commitment validity
3. **Acceptance Phase**: Acceptor blindly selects one commitment and provides their own proof
4. **Revelation Phase**: Challenger reveals selected commitment, determining the winner
5. **Settlement Phase**: Winner can claim the locked Bitcoin funds

### Cryptographic Guarantees

- **Unpredictability**: Neither party can predict the outcome
- **Fairness**: Each party has exactly 50% probability of winning
- **Binding**: Commitments cannot be changed after creation
- **Hiding**: Commitment selection remains private until revelation
- **Verifiability**: All proofs can be independently verified

### Zero-Knowledge Circuits

The protocol uses two main ZK circuits:

- **Challenger Circuit**: Proves knowledge of commitment secrets without revealing them
- **Acceptor Circuit**: Proves valid signature and commitment selection

## 🛠️ Development

### Project Structure

```
op_rand/
├── apps/
│   └── cli/                    # Command-line interface
├── crates/
│   ├── types/                  # Core data structures
│   ├── prover/                 # ZK proof system
│   └── transaction-builder/    # Bitcoin transaction utilities
├── circuits/
│   └── crates/
│       ├── challenger_circuit/ # Challenger ZK circuit
│       ├── acceptor_circuit/   # Acceptor ZK circuit
│       └── common/             # Shared circuit utilities
└── target/                     # Build artifacts
```

## 🏢 About

Developed by [Distributed Lab](https://distributedlab.com/)

## 🔗 Links

- 📖 **[CLI Documentation](apps/cli/README.md)**
- 📄 **[Research Paper](https://arxiv.org/pdf/2501.16451)**

## 🙏 Acknowledgments

Special thanks to [passport-zk-circuits-noir](https://github.com/rarimo/passport-zk-circuits-noir) contributors for secp256k1 circuits which were instrumental in implementing the cryptographic primitives for this project.

---

_Build trustless randomness on Bitcoin with cryptographic guarantees._
