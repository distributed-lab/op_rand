use bitcoin::{
    Address, Amount, CompressedPublicKey, OutPoint, PublicKey, Txid,
    consensus::Encodable,
    hashes::{Hash, ripemd160, sha256},
    secp256k1::rand::thread_rng,
};
use clap::Args;
use color_eyre::{
    eyre,
    eyre::{OptionExt, ensure},
};
use console::style;
use op_rand_prover::{BarretenbergProver, OpRandProver};
use op_rand_types::Commitments;
use serde::{Deserialize, Serialize};
use std::{fs, str::FromStr};

use crate::{
    context::{Context, setup_progress_bar},
    ui::{self, CHAIN, CHECK, CLOCK, GEAR, KEY, SPARKLES, TARGET},
    util::{FEES, MIN_CHANGE, select_utxos},
};

#[derive(Args, Debug)]
pub struct CreateChallengeArgs {
    /// Challenge amount in satoshis.
    #[clap(long)]
    pub amount: u64,

    /// Number of commitments to create.s
    #[clap(long, default_value = "2")]
    pub commitments_count: u32,

    /// Change public key.
    #[clap(long)]
    pub change_pubkey: Option<String>,

    /// Output file path for the challenge JSON
    #[clap(long, default_value = "challenger.json")]
    pub public_output: String,

    /// Output file path for the private challenge JSON
    #[clap(long, default_value = "private_challenger.json")]
    pub private_output: String,

    /// Locktime for the challenge transaction.
    #[clap(long)]
    pub locktime: u32,
}

#[derive(Serialize, Deserialize)]
pub struct PublicChallengerData {
    pub id: String,
    pub amount: u64,
    pub deposit_outpoint: OutPoint,
    pub third_rank_commitments: [String; 2],
    pub challenger_pubkey: String,
    pub challenger_pubkey_hash: String,
    pub proof: String,
    pub vk: String,
    pub locktime: u32,
}

#[derive(Serialize, Deserialize)]
pub struct PrivateChallengerData {
    pub id: String,
    pub amount: u64,
    pub deposit_transaction: String,
    pub first_rank_commitments: [String; 2],
    pub selected_first_rank_commitment: String,
}

pub async fn run(
    CreateChallengeArgs {
        amount,
        commitments_count,
        public_output,
        private_output,
        change_pubkey,
        locktime,
    }: CreateChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    println!(
        "{}",
        ui::header("                        🎯 CREATING CHALLENGE 🎯")
    );

    ensure!(
        commitments_count == 2,
        "OP_RAND currently only supports 2 commitments"
    );

    println!(
        "\n{} {} {}",
        CHECK,
        style("Challenge amount:").bold().yellow(),
        ui::format_bitcoin_amount(amount)
    );

    println!(
        "{} {} {} blocks",
        CLOCK,
        style("Locktime:").bold().yellow(),
        style(locktime.to_string()).bright().cyan()
    );

    let cfg = ctx.config()?;
    let esplora_client = ctx.esplora_client()?;
    let transaction_builder = ctx.transaction_builder()?;
    let private_key = cfg.private_key;
    let secp = ctx.secp_ctx();
    let public_key = private_key.public_key(secp).inner;
    let address = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(secp, &private_key).unwrap(),
        cfg.network,
    );

    println!(
        "\n{} {}",
        GEAR,
        style("Preparing transaction inputs...").bold().blue()
    );

    let utxos = esplora_client.get_utxos(&address.to_string()).await?;
    let selected_utxos = select_utxos(utxos, amount + FEES)?;

    println!(
        "{} {} UTXOs selected for funding",
        CHECK,
        style(selected_utxos.len().to_string()).bold().green()
    );

    let prover = BarretenbergProver::default();

    let pb = setup_progress_bar("Setting up the challenger circuit...".into());
    let prover_clone = prover.clone();
    tokio::task::spawn_blocking(move || {
        prover_clone
            .setup_challenger_circuit()
            .expect("Failed to setup challenger circuit")
    })
    .await?;
    pb.finish_with_message("Challenger circuit is set up");

    println!(
        "\n{} {}",
        KEY,
        style("Generating cryptographic commitments...")
            .bold()
            .blue()
    );

    let commitments = Commitments::generate(secp, &mut thread_rng())?;

    let first_rank_commitments = commitments.first_rank_commitments();
    let random_first_rank_commitment = commitments
        .pick_random_first_rank_commitment(&mut thread_rng())
        .ok_or_eyre("No first rank commitments available")?;

    let (_commitment_sk, commitment_pk) = random_first_rank_commitment.inner();
    let tweaked_pk = public_key.combine(&commitment_pk)?;

    let third_rank_commitments = commitments.third_rank_commitments();

    let sha256_hash = sha256::Hash::hash(&tweaked_pk.serialize());
    let ripemd160_hash = ripemd160::Hash::hash(sha256_hash.as_byte_array());

    println!(
        "{} {} third-rank commitments generated",
        CHECK,
        style("2").bold().green()
    );

    let pb = setup_progress_bar("Generating the challenger proof...".into());
    let proof = prover.generate_challenger_proof(
        first_rank_commitments.to_owned(),
        third_rank_commitments.to_owned(),
        &public_key,
        ripemd160_hash.to_byte_array(),
    )?;
    pb.finish_with_message("Challenger proof generated");

    let inputs_sum = selected_utxos.iter().map(|utxo| utxo.value).sum::<u64>();
    let change_amount = inputs_sum - amount - FEES;
    let change = if change_amount < MIN_CHANGE {
        None
    } else {
        Some(Amount::from_sat(change_amount))
    };
    let prevouts = selected_utxos
        .iter()
        .map(|utxo| {
            Ok((
                OutPoint::new(Txid::from_str(&utxo.txid)?, utxo.vout),
                Amount::from_sat(utxo.value),
            ))
        })
        .collect::<Result<Vec<_>, eyre::Error>>()?;

    println!(
        "\n{} {}",
        CHAIN,
        style("Creating deposit transaction...").bold().blue()
    );

    let pb = setup_progress_bar("Creating a deposit transaction...".into());
    let deposit_tx = transaction_builder.build_deposit_transaction(
        random_first_rank_commitment.to_owned(),
        prevouts,
        Amount::from_sat(amount),
        change,
        change_pubkey.and_then(|pk| PublicKey::from_str(&pk).ok()),
    )?;

    pb.finish_with_message("Deposit transaction created");

    println!(
        "{} {} {}",
        CHECK,
        style("Deposit TXID:").bold().yellow(),
        style(&deposit_tx.compute_txid().to_string())
            .bright()
            .white()
    );

    let pb = setup_progress_bar("Assembling the challenger data...".into());
    let id = uuid::Uuid::new_v4().to_string();

    println!(
        "\n{} {}",
        SPARKLES,
        style("Finalizing challenge data...").bold().blue()
    );

    let public_challenge_output = PublicChallengerData {
        id: id.clone(),
        amount,
        deposit_outpoint: OutPoint::new(deposit_tx.compute_txid(), 0),
        third_rank_commitments: [
            hex::encode(third_rank_commitments[0].inner().serialize()),
            hex::encode(third_rank_commitments[1].inner().serialize()),
        ],
        challenger_pubkey: hex::encode(public_key.serialize()),
        challenger_pubkey_hash: hex::encode(ripemd160_hash.to_byte_array()),
        proof: hex::encode(proof.proof()),
        vk: hex::encode(proof.vk()),
        locktime,
    };

    let json_output = serde_json::to_string_pretty(&public_challenge_output)?;
    fs::write(&public_output, json_output)?;

    let mut tx_bytes = Vec::new();
    deposit_tx.consensus_encode(&mut tx_bytes)?;

    let private_challenge_output = PrivateChallengerData {
        id: id.clone(),
        amount,
        deposit_transaction: hex::encode(tx_bytes),
        first_rank_commitments: [
            hex::encode(first_rank_commitments[0].inner().0.secret_bytes()),
            hex::encode(first_rank_commitments[1].inner().0.secret_bytes()),
        ],
        selected_first_rank_commitment: hex::encode(
            random_first_rank_commitment.inner().0.secret_bytes(),
        ),
    };

    let private_json_output = serde_json::to_string_pretty(&private_challenge_output)?;
    fs::write(&private_output, private_json_output)?;

    pb.finish_with_message("Challenge data assembled");

    // Success message
    println!("{}", ui::success_footer("CHALLENGE CREATED SUCCESSFULLY!"));
    println!("{}", ui::section_header("CHALLENGE DETAILS"));
    println!("│");
    println!(
        "│ {} {} {}",
        TARGET,
        style("Challenge ID:").bold().yellow(),
        style(&id).bright().white()
    );
    println!(
        "│ {} {} {}",
        TARGET,
        style("Amount:").bold().yellow(),
        ui::format_bitcoin_amount(amount)
    );
    println!("│");
    println!("{}", ui::section_header("FILE OUTPUTS"));
    println!("│");
    println!(
        "│ {} {} {}",
        style("📤").bold(),
        style("Public data (share with acceptor):").bold().green(),
        style(&public_output).bright().white()
    );
    println!(
        "│ {} {} {}",
        style("🔒").bold(),
        style("Private data (keep secure):").bold().red(),
        style(&private_output).bright().white()
    );

    Ok(())
}
