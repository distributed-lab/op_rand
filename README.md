# OP_RAND: Trustless Randomness Generation on Bitcoin

[![Paper](https://img.shields.io/badge/paper-arXiv-red.svg)](https://arxiv.org/pdf/2501.16451)

This is a method of emulation of OP_RAND opcode on Bitcoin through a trustless
interactive game between transaction counterparties. The game result is probabilistic and doesn’t
allow any party to cheat, increasing their chance of winning on any protocol step. The protocol is
organized in a way unrecognizable to any external party and doesn’t require any specific scripts
or Bitcoin protocol updates.

## 📖 Overview

OP_RAND brings trustless randomness to Bitcoin through the combination of:

- **Cryptographic Commitments**: Multi-layered commitment scheme ensuring unpredictability
- **Zero-Knowledge Proofs**: Powered by Noir circuits and Barretenberg backend for privacy and verification
- **Bitcoin Script Integration**: Native Bitcoin transactions without protocol modifications
- **Interactive Protocol**: Two-party challenge-response mechanism

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
