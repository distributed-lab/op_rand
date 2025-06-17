use std::fs;

use bitcoin::{Transaction, consensus::encode};
use clap::Args;
use console::style;

use crate::{
    actions::create_challenge::PublicChallengerData,
    ui::{CHAIN, CLOCK, KEY, LOCK, ROCKET, SHIELD},
};

#[derive(Args, Debug)]
pub struct ChallengeInfoArgs {
    /// Path to the challenge JSON file
    #[clap(long, default_value = "challenger.json")]
    pub challenge_file: String,
}

pub async fn run(ChallengeInfoArgs { challenge_file }: ChallengeInfoArgs) -> eyre::Result<()> {
    let challenge_json = fs::read_to_string(&challenge_file)?;
    let challenge_data: PublicChallengerData = serde_json::from_str(&challenge_json)?;

    println!("\n{}", "═".repeat(80));
    println!(
        "{}",
        style("                           🎯 CHALLENGE INFORMATION 🎯")
            .bold()
            .cyan()
    );
    println!("{}", "═".repeat(80));

    println!(
        "\n{} {}",
        style("Challenge ID:").bold().yellow(),
        style(&challenge_data.id).bright().white()
    );

    let btc_amount = challenge_data.amount as f64 / 100_000_000.0;
    println!(
        "{} {} {} satoshis ({} BTC)",
        CHAIN,
        style("Amount:").bold().yellow(),
        style(challenge_data.amount.to_string())
            .bright()
            .green()
            .bold(),
        style(format!("{:.8}", btc_amount)).bright().green()
    );

    let deposit_tx: Transaction =
        encode::deserialize_hex(&challenge_data.unsigned_deposit_transaction)?;

    // Deposit information
    println!("\n{}", style("┌─ DEPOSIT INFORMATION").bold().blue());
    println!("│");
    println!("│ {} {}", CHAIN, style("Outpoint:").bold().yellow());
    println!(
        "│   {} {}",
        style("TXID:").dim(),
        style(deposit_tx.compute_txid().to_string())
            .bright()
            .white()
    );
    println!("│   {} {}", style("VOUT:").dim(), style(0).bright().white());

    // Locktime information
    println!("│");
    println!(
        "│ {} {} {} blocks",
        CLOCK,
        style("Locktime:").bold().yellow(),
        style(challenge_data.locktime.to_string()).bright().cyan()
    );

    // Public key information
    println!("\n{}", style("┌─ CRYPTOGRAPHIC DATA").bold().magenta());
    println!("│");
    println!(
        "│ {} {}",
        KEY,
        style("Challenger Public Key:").bold().yellow()
    );
    println!("│   {}", style(&challenge_data.challenger_pubkey).dim());
    println!("│");
    println!("│ {} {}", LOCK, style("Public Key Hash:").bold().yellow());
    println!(
        "│   {}",
        style(&challenge_data.challenger_pubkey_hash).dim()
    );

    // Third rank commitments
    println!("\n{}", style("┌─ THIRD RANK COMMITMENTS").bold().green());
    println!("│");
    for (i, commitment) in challenge_data.third_rank_commitments.iter().enumerate() {
        println!(
            "│ {}",
            style(format!("Commitment {}:", i + 1)).bold().yellow(),
        );
        println!("│   {}", style(commitment).dim());
        if i < challenge_data.third_rank_commitments.len() - 1 {
            println!("│");
        }
    }

    // Zero-knowledge proof information
    println!("\n{}", style("┌─ ZERO-KNOWLEDGE PROOF").bold().red());
    println!("│");
    println!("│ {} {}", SHIELD, style("Proof:").bold().yellow());
    let proof_preview = if challenge_data.proof.len() > 64 {
        format!(
            "{}...{}",
            &challenge_data.proof[..32],
            &challenge_data.proof[challenge_data.proof.len() - 32..]
        )
    } else {
        challenge_data.proof.clone()
    };
    println!("│   {}", style(proof_preview).dim());
    println!(
        "│   {} {} bytes",
        style("Size:").dim(),
        style((challenge_data.proof.len() / 2).to_string())
            .bright()
            .white()
    );
    println!("│");
    println!(
        "│ {} {}",
        style("🔍").bold(),
        style("Verification Key:").bold().yellow()
    );
    let vk_preview = if challenge_data.vk.len() > 64 {
        format!(
            "{}...{}",
            &challenge_data.vk[..32],
            &challenge_data.vk[challenge_data.vk.len() - 32..]
        )
    } else {
        challenge_data.vk.clone()
    };
    println!("│   {}", style(vk_preview).dim());
    println!(
        "│   {} {} bytes",
        style("Size:").dim(),
        style((challenge_data.vk.len() / 2).to_string())
            .bright()
            .white()
    );

    // Footer
    println!("\n{}", "═".repeat(80));
    println!(
        "{} {}",
        ROCKET,
        style("Challenge ready for acceptance!").bold().green()
    );
    println!("{}", "═".repeat(80));
    println!();

    Ok(())
}
