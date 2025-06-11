# OP_RAND CLI

A command-line interface for the OP_RAND protocol - a trustless interactive cryptographic game system that emulates randomness generation on Bitcoin without requiring protocol changes or recognizable on-chain patterns.

## Installation

### Installing from Source

```bash
# Clone the repository
git clone https://github.com/distributed-lab/op_rand
cd op_rand

# Install the CLI
cargo install --path apps/cli
```

## Configuration

Create a `config.toml` file with your Bitcoin network configuration:

```toml
# Your Bitcoin private key (WIF format)
private_key = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy"

# Esplora API endpoint
esplora_url = "https://blockstream.info/testnet/api"

# Bitcoin network (testnet, regtest, bitcoin)
network = "testnet"
```

**⚠️ Security Warning**: Never use mainnet private keys with real funds in development/testing environments.

## Commands

### Global Options

All commands support these global options:

- `--config <PATH>`: Path to configuration file (default: `config.toml`)
- `--verbose`: Increase verbosity level (can be used multiple times: `-v`, `-vv`, `-vvv`)
- `--help`: Show help information

### 1. create-challenge

Creates a new cryptographic challenge with hidden commitments and zero-knowledge proofs. The challenger generates secret randomness and commits to it cryptographically.

**Usage:**

```bash
op-rand-cli create-challenge --amount <AMOUNT> --locktime <LOCKTIME> [OPTIONS]
```

**Arguments:**

- `--amount <AMOUNT>`: Challenge amount in satoshis (required)
- `--locktime <LOCKTIME>`: Locktime for the challenge transaction (required)
- `--commitments-count <COUNT>`: Number of commitments to create (default: 2, currently only 2 is supported)
- `--change-pubkey <PUBKEY>`: Public key for change output (optional)
- `--public-output <PATH>`: Output file for public challenge data (default: `challenger.json`)
- `--private-output <PATH>`: Output file for private challenger data (default: `private_challenger.json`)

**Example:**

```bash
# Create a challenge with 100,000 satoshis and 144 block locktime
op-rand-cli create-challenge --amount 100000 --locktime 144

# Create a challenge with custom output files
op-rand-cli create-challenge \
  --amount 50000 \
  --locktime 288 \
  --public-output my_challenge.json \
  --private-output my_private_challenge.json
```

**What happens:**

- Generates cryptographic commitments with hidden randomness
- Creates zero-knowledge proofs of commitment validity
- Builds a deposit transaction structure
- Outputs public data (safe to share) and private data (keep secret)

### 2. accept-challenge

Accepts an existing challenge by generating acceptance proofs and creating a challenge transaction.

**Usage:**

```bash
op-rand-cli accept-challenge --selected-commitment <INDEX> [OPTIONS]
```

**Arguments:**

- `--challenge-file <PATH>`: Path to challenge JSON file (default: `challenger.json`)
- `--output <PATH>`: Output file for acceptor data (default: `acceptor.json`)
- `--selected-commitment <INDEX>`: Index of commitment to accept (0 or 1, required)

**Example:**

```bash
# Accept a challenge with commitment index 0
op-rand-cli accept-challenge \
  --challenge-file challenger.json \
  --selected-commitment 0

# Accept with custom input/output files
op-rand-cli accept-challenge \
  --challenge-file my_challenge.json \
  --output my_acceptor.json \
  --selected-commitment 1
```

**Output:**
Creates `acceptor.json` containing proof data and partially signed transaction to share with the challenger.

### 3. complete-challenge

Completes a challenge by verifying acceptor proofs and broadcasting transactions to the Bitcoin network.

**Usage:**

```bash
op-rand-cli complete-challenge [OPTIONS]
```

**Arguments:**

- `--challenger-file <PATH>`: Path to public challenger JSON file (default: `challenger.json`)
- `--challenger-private-file <PATH>`: Path to private challenger JSON file (default: `private_challenger.json`)
- `--acceptor-file <PATH>`: Path to acceptor JSON file (default: `acceptor.json`)

**Example:**

```bash
# Complete challenge with default files
op-rand-cli complete-challenge

# Complete challenge with custom files
op-rand-cli complete-challenge \
  --challenger-file my_challenge.json \
  --challenger-private-file my_private_challenge.json \
  --acceptor-file my_acceptor.json
```

**Process:**

1. Verifies acceptor's zero-knowledge proof
2. Co-signs the challenge transaction
3. Broadcasts both deposit and challenge transactions
4. Outputs the final challenge transaction ID

### 4. try-spend

Attempts to spend from a completed challenge transaction as either challenger or acceptor.

**Usage:**

```bash
op-rand-cli try-spend --challenge-tx <TX_HEX> --challenger|--acceptor [OPTIONS]
```

**Arguments:**

- `--challenge-tx <TX_HEX>`: Challenge transaction in hexadecimal format (required)
- `--challenger`: Attempt to spend as the challenger (mutually exclusive with --acceptor)
- `--acceptor`: Attempt to spend as the acceptor (mutually exclusive with --challenger)
- `--recipient-pubkey <PUBKEY>`: Recipient public key for funds (optional)
- `--challenge-file <PATH>`: Path to challenge JSON file (default: `challenger.json`)
- `--acceptor-file <PATH>`: Path to acceptor JSON file (default: `acceptor.json`)

**Examples:**

```bash
# Try to spend as challenger
op-rand-cli try-spend \
  --challenge-tx "020000000001..." \
  --challenger \
  --recipient-pubkey "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"

# Try to spend as acceptor
op-rand-cli try-spend \
  --challenge-tx "020000000001..." \
  --acceptor \
  --challenge-file my_challenge.json
```

### 5. info

Displays detailed information about a challenge, including cryptographic commitments, proof data, and transaction details in a formatted output.

**Usage:**

```bash
op-rand-cli info [OPTIONS]
```

**Arguments:**

- `--challenge-file <PATH>`: Path to challenge JSON file (default: `challenger.json`)

**Example:**

```bash
# Display info for default challenge file
op-rand-cli info

# Display info for a specific challenge file
op-rand-cli info --challenge-file my_challenge.json
```

**Output:**
Shows a formatted display including:

- Challenge ID and amount (in satoshis and BTC)
- Deposit transaction outpoint details
- Locktime information
- Challenger public key and hash
- Third-rank cryptographic commitments
- Zero-knowledge proof and verification key information

This command is useful for inspecting challenge files before accepting or completing them.

### 6. balance

Displays your wallet balance information, including confirmed and unconfirmed UTXOs. This command helps you check if you have sufficient funds before creating or accepting challenges.

**Usage:**

```bash
op-rand-cli balance
```

**Arguments:**

None - the command uses your configured wallet from `config.toml`.

**Example:**

```bash
# Check your wallet balance
op-rand-cli balance
```

**Output:**
Shows a formatted display including:

- Wallet address for your configured private key
- Confirmed balance (from UTXOs in confirmed blocks)
- Unconfirmed balance (from UTXOs in mempool)
- Total balance (sum of confirmed and unconfirmed)
- Individual UTXO details with transaction IDs and confirmation status
- Block height information for confirmed UTXOs

This command is essential for:

- Verifying you have enough funds before creating challenges
- Monitoring your wallet status during the challenge process
- Debugging funding issues with detailed UTXO information

## Workflow Example

Here's a complete workflow between two parties:

### Step 1: Challenger Creates Challenge

```bash
# Challenger creates a 100,000 satoshi challenge
op-rand-cli create-challenge --amount 100000 --locktime 144
# Outputs: challenger.json (share this) and private_challenger.json (keep private)
```

### Step 2: Acceptor Inspects and Accepts Challenge

```bash
# Acceptor receives challenger.json and inspects it first
op-rand-cli info --challenge-file challenger.json

# Acceptor blindly selects commitment 0
op-rand-cli accept-challenge \
  --challenge-file challenger.json \
  --selected-commitment 0
# Outputs: acceptor.json (send back to challenger)
```

### Step 3: Challenger Completes Challenge

```bash
# Challenger receives acceptor.json and finalizes the cryptographic game
op-rand-cli complete-challenge \
  --challenger-file challenger.json \
  --challenger-private-file private_challenger.json \
  --acceptor-file acceptor.json
# Broadcasts transactions and reveals the random outcome
```

### Step 4: Winner Takes All

```bash
# The cryptographic winner can spend the funds
op-rand-cli try-spend \
  --challenge-tx "transaction_hex_from_step_3" \
  --challenger  # or --acceptor depending on who won
```

## Cryptographic Properties

The OP_RAND protocol ensures:

- **Unpredictability**: Neither party can predict or control the outcome
- **Fairness**: Each party has exactly 50% chance of winning
- **Verifiability**: All parties can verify the correctness of proofs
- **Privacy**: The commitment selection remains hidden until revelation
- **Trustlessness**: No trusted third party required
- **Untraceability**: Appears as normal Bitcoin transactions to external observers

## File Formats

### challenger.json (Public Challenge Data)

Contains publicly shareable challenge information:

- Challenge ID and amount
- Deposit transaction outpoint
- Third-rank cryptographic commitments
- Challenger public key and hash
- Zero-knowledge proof and verification key

### private_challenger.json (Private Challenge Data)

Contains sensitive challenger information:

- First-rank commitments (cryptographic secrets)
- Selected commitment reveal data
- Complete deposit transaction

### acceptor.json (Acceptor Data)

Contains acceptor's cryptographic response:

- Acceptor public key hash
- Zero-knowledge proof and verification key
- Partially signed challenge transaction (PSBT format)

## Troubleshooting

### Common Issues

1. **"Failed to setup circuit"**

   - Ensure you have sufficient system resources (RAM/CPU)
   - This step can take several minutes on first run
   - The cryptographic circuit setup is computationally intensive

2. **"Insufficient funds"**

   - Check your wallet balance covers the challenge amount plus fees
   - Fees are automatically calculated (typically ~1000 satoshis)

3. **"Invalid proof verification"**

   - Ensure all input files are from the same challenge session
   - Check that files haven't been corrupted or modified
   - Cryptographic proofs are sensitive to any data changes

4. **"Network connection failed"**
   - Verify your `esplora_url` in the config file
   - Check internet connectivity

### Verbose Logging

Use verbose flags for debugging cryptographic operations:

```bash
# Basic verbose output
op-rand-cli -v create-challenge --amount 100000 --locktime 144

# Maximum verbosity (shows cryptographic details)
op-rand-cli -vvv create-challenge --amount 100000 --locktime 144
```

## References

- [Emulating OP_RAND in Bitcoin](https://arxiv.org/pdf/2501.16451) - Original research paper by Rarimo Protocol
