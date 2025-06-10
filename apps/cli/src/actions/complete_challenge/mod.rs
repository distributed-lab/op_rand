use std::{fs, str::FromStr};

use crate::{
    actions::{
        accept_challenge::AcceptorData,
        create_challenge::{PrivateChallengerData, PublicChallengerData},
    },
    context::{Context, setup_progress_bar},
    ui::{self, CHECK, GEAR, SHIELD, RADIO, CHAIN},
};
use base64::{Engine as _, engine::general_purpose};
use bitcoin::{Amount, Psbt, consensus::Encodable};
use clap::Args;
use color_eyre::eyre;
use color_eyre::eyre::ensure;
use console::style;
use op_rand_prover::{BarretenbergProver, OpRandProof, OpRandProver};
use op_rand_types::{FirstRankCommitment, ThirdRankCommitment};

#[derive(Args, Debug)]
pub struct CompleteChallengeArgs {
    /// Path to the challenge JSON file
    #[clap(long, default_value = "challenger.json")]
    pub challenger_file: String,
    /// Path to the challenger's private key file
    #[clap(long, default_value = "private_challenger.json")]
    pub challenger_private_file: String,
    /// Path to the acceptor JSON file
    #[clap(long, default_value = "acceptor.json")]
    pub acceptor_file: String,
}

pub async fn run(
    CompleteChallengeArgs {
        challenger_file,
        challenger_private_file,
        acceptor_file,
    }: CompleteChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    println!("{}", ui::header("                      🏁 COMPLETING CHALLENGE 🏁"));

    println!(
        "\n{} {}",
        GEAR,
        style("Loading challenge data...").bold().blue()
    );

    let challenger_json = fs::read_to_string(&challenger_file)?;
    let challenger_data: PublicChallengerData = serde_json::from_str(&challenger_json)?;

    let challenger_private_json = fs::read_to_string(&challenger_private_file)?;
    let challenger_private_data: PrivateChallengerData =
        serde_json::from_str(&challenger_private_json)?;

    let acceptor_json = fs::read_to_string(&acceptor_file)?;
    let acceptor_data: AcceptorData = serde_json::from_str(&acceptor_json)?;

    println!(
        "{} {} {}",
        CHECK,
        style("Challenge ID:").bold().yellow(),
        style(&challenger_data.id).bright().white()
    );

    ensure!(
        challenger_data.id == acceptor_data.id,
        "Challenger and acceptor IDs do not match"
    );

    println!(
        "{} {}",
        CHECK,
        style("Challenge and acceptor IDs match!").bold().green()
    );

    let prover = BarretenbergProver::default();
    let acceptor_pubkey_hash = hex::decode(&acceptor_data.acceptor_pubkey_hash)?;

    println!(
        "\n{} {}",
        SHIELD,
        style("Validating commitments...").bold().blue()
    );

    let challenger_commitments = challenger_data
        .third_rank_commitments
        .iter()
        .map(|s| ThirdRankCommitment::from_str(s))
        .collect::<Result<Vec<_>, _>>()?;

    let acceptor_commitments = acceptor_data
        .third_rank_commitments
        .iter()
        .map(|s| ThirdRankCommitment::from_str(s))
        .collect::<Result<Vec<_>, _>>()?;

    ensure!(
        challenger_commitments
            .iter()
            .zip(acceptor_commitments.iter())
            .all(|(a, b)| a.inner() == b.inner()),
        "Third rank commitments do not match between challenger and acceptor"
    );

    println!(
        "{} {}",
        CHECK,
        style("Third rank commitments validated!").bold().green()
    );

    let proof = hex::decode(&acceptor_data.proof)?;
    let vk = hex::decode(&acceptor_data.vk)?;
    let proof_data = OpRandProof::new(proof, vk);

    let pb = setup_progress_bar("Setting up acceptor circuit...".into());
    let prover_clone = prover.clone();
    tokio::task::spawn_blocking(move || {
        prover_clone
            .setup_acceptor_circuit()
            .expect("Failed to setup acceptor circuit")
    })
    .await?;
    pb.finish_with_message("Acceptor circuit is set up");

    println!(
        "\n{} {}",
        SHIELD,
        style("Verifying acceptor proof...").bold().blue()
    );

    prover.verify_acceptor_proof(
        acceptor_pubkey_hash
            .try_into()
            .map_err(|_| eyre::eyre!("Failed to convert pubkey hash to array"))?,
        challenger_commitments
            .try_into()
            .map_err(|_| eyre::eyre!("Failed to convert commitments to array"))?,
        &proof_data,
    )?;

    println!(
        "{} {}",
        CHECK,
        style("Acceptor proof verified successfully!").bold().green()
    );

    // TODO: cosign the PSBT and broadcast the transaction
    let esplora_client = ctx.esplora_client()?;
    let transaction_builder = ctx.transaction_builder()?;
    let psbt_bytes = general_purpose::STANDARD.decode(&acceptor_data.psbt)?;

    let psbt = Psbt::deserialize(&psbt_bytes)?;
    let selected_first_rank_commitment =
        FirstRankCommitment::from_str(&challenger_private_data.selected_first_rank_commitment)?;

    println!(
        "\n{} {}",
        GEAR,
        style("Finalizing challenge transaction...").bold().blue()
    );

    let signed_challenge_transaction = transaction_builder.complete_challenge_tx(
        psbt,
        Amount::from_sat(challenger_data.amount),
        0,
        selected_first_rank_commitment,
    )?;

    let deposit_transaction = challenger_private_data.deposit_transaction;
    let mut challenge_transaction_bytes = Vec::new();
    signed_challenge_transaction.consensus_encode(&mut challenge_transaction_bytes)?;
    let challenge_transaction = hex::encode(challenge_transaction_bytes);

    println!(
        "\n{} {}",
        RADIO,
        style("Broadcasting transactions...").bold().blue()
    );

    esplora_client
        .broadcast_transaction(&deposit_transaction)
        .await?;

    println!(
        "{} {}",
        CHECK,
        style("Deposit transaction broadcasted!").bold().green()
    );

    esplora_client
        .broadcast_transaction(&challenge_transaction)
        .await?;

    println!(
        "{} {}",
        CHECK,
        style("Challenge transaction broadcasted!").bold().green()
    );

    // Success message
    println!("\n{}", ui::success_footer("CHALLENGE COMPLETED SUCCESSFULLY!"));
    println!("{}", ui::section_header("TRANSACTION DETAILS"));
    println!("│");
    println!(
        "│ {} {}",
        CHAIN,
        style("Challenge Transaction:").bold().yellow()
    );
    println!("│   {}", style(&challenge_transaction).dim());
    println!(
        "│   {} {}",
        style("TXID:").dim(),
        style(&signed_challenge_transaction.compute_txid().to_string()).bright().white()
    );

    Ok(())
}
