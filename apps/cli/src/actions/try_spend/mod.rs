use std::{fs, str::FromStr};

use bitcoin::{
    Amount, PublicKey, Transaction,
    absolute::{Height, LockTime},
    consensus::Decodable,
};
use clap::{ArgGroup, Args};
use color_eyre::eyre;
use console::style;

use crate::{
    actions::{accept_challenge::AcceptorData, create_challenge::PublicChallengerData},
    context::Context,
    ui::{self, CHAIN, CHECK, GEAR, RADIO, SPARKLES},
    util::FEES,
};

#[derive(Args, Debug)]
#[clap(group(
    ArgGroup::new("try_spend")
        .required(true)
        .args(&["challenger", "acceptor"])
        .multiple(false),
))]
pub struct TrySpendArgs {
    /// Challenge transaction hex.
    #[clap(long)]
    pub challenge_tx: String,

    /// Recipient address
    #[clap(long)]
    pub recipient_pubkey: Option<String>,

    /// Path to the challenge JSON file
    #[clap(long, default_value = "challenger.json")]
    pub challenge_file: String,

    /// Path to the acceptor JSON file
    #[clap(long, default_value = "acceptor.json")]
    pub acceptor_file: String,

    #[clap(long, group = "try_spend")]
    pub challenger: bool,

    #[clap(long, group = "try_spend")]
    pub acceptor: bool,
}

pub async fn run(
    TrySpendArgs {
        challenge_tx,
        recipient_pubkey,
        challenge_file,
        acceptor_file,
        challenger,
        acceptor,
    }: TrySpendArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    let operation_type = if challenger { "CHALLENGER" } else { "ACCEPTOR" };
    println!(
        "{}",
        ui::header(&format!("                       {} SWEEP ", operation_type))
    );

    println!(
        "\n{} {}",
        GEAR,
        style("Loading challenge data...").bold().blue()
    );

    let challenger_json = fs::read_to_string(&challenge_file)?;
    let challenger_data: PublicChallengerData = serde_json::from_str(&challenger_json)?;

    let acceptor_json = fs::read_to_string(&acceptor_file)?;
    let acceptor_data: AcceptorData = serde_json::from_str(&acceptor_json)?;

    println!(
        "{} {} {}",
        CHECK,
        style("Challenge ID:").bold().yellow(),
        style(&challenger_data.id).bright().white()
    );

    let esplora_client = ctx.esplora_client()?;
    let tx_builder = ctx.transaction_builder()?;

    println!(
        "\n{} {}",
        CHAIN,
        style("Parsing challenge transaction...").bold().blue()
    );

    let challenge_tx_bytes = hex::decode(&challenge_tx)?;
    let challenge_transaction = Transaction::consensus_decode(&mut challenge_tx_bytes.as_slice())?;

    println!(
        "{} {} {}",
        CHECK,
        style("Challenge TXID:").bold().yellow(),
        style(&challenge_transaction.compute_txid().to_string())
            .bright()
            .white()
    );

    let fee_amount = Amount::from_sat(FEES);

    let recipient_pubkey = recipient_pubkey.and_then(|pk| PublicKey::from_str(&pk).ok());

    if challenger {
        println!(
            "\n{} {}",
            GEAR,
            style("Creating challenger sweep transaction...")
                .bold()
                .blue()
        );

        let witness_script =
            bitcoin::ScriptBuf::from_hex(&acceptor_data.challenge_output_witness_script)?;

        let sweep_tx = tx_builder.sweep_challenge_output_challenger(
            &challenge_transaction,
            &witness_script,
            LockTime::Blocks(Height::from_consensus(challenger_data.locktime)?),
            recipient_pubkey,
            fee_amount,
        )?;

        println!(
            "{} {}",
            CHECK,
            style("Challenger sweep transaction created!")
                .bold()
                .green()
        );
        println!(
            "   {} {}",
            style("TXID:").dim(),
            style(&sweep_tx.compute_txid().to_string()).bright().white()
        );

        println!(
            "\n{} {}",
            RADIO,
            style("Broadcasting challenger sweep transaction...")
                .bold()
                .blue()
        );

        esplora_client
            .broadcast_transaction(&bitcoin::consensus::encode::serialize_hex(&sweep_tx))
            .await?;

        println!(
            "{} {}",
            SPARKLES,
            style("Challenger sweep transaction broadcasted successfully!")
                .bold()
                .green()
        );
    }

    if acceptor {
        println!(
            "\n{} {}",
            GEAR,
            style("Creating acceptor sweep transaction...")
                .bold()
                .blue()
        );

        let witness_script_bytes = hex::decode(&acceptor_data.challenge_output_witness_script)?;
        let witness_script = bitcoin::ScriptBuf::from_bytes(witness_script_bytes);

        let challenger_pubkey_bytes = hex::decode(&challenger_data.challenger_pubkey)?;
        let challenger_pubkey = bitcoin::PublicKey::from_slice(&challenger_pubkey_bytes)?;

        let sweep_tx = tx_builder.sweep_challenge_output_acceptor(
            &challenge_transaction,
            &challenger_pubkey,
            &witness_script,
            recipient_pubkey,
            fee_amount,
        )?;

        println!(
            "{} {}",
            CHECK,
            style("Acceptor sweep transaction created!").bold().green()
        );
        println!(
            "   {} {}",
            style("TXID:").dim(),
            style(&sweep_tx.compute_txid().to_string()).bright().white()
        );

        println!(
            "\n{} {}",
            RADIO,
            style("Broadcasting acceptor sweep transaction...")
                .bold()
                .blue()
        );

        esplora_client
            .broadcast_transaction(&bitcoin::consensus::encode::serialize_hex(&sweep_tx))
            .await?;

        println!(
            "{} {}",
            SPARKLES,
            style("Acceptor sweep transaction broadcasted successfully!")
                .bold()
                .green()
        );
    }

    Ok(())
}
