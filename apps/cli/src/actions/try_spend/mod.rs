use std::{fs, str::FromStr};

use bitcoin::{
    Amount, PublicKey, Transaction,
    absolute::{Height, LockTime},
    consensus::Decodable,
};
use clap::{ArgGroup, Args};
use color_eyre::eyre;

use crate::{
    actions::{accept_challenge::AcceptorData, create_challenge::PublicChallengerData},
    context::Context,
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
    let challenger_json = fs::read_to_string(&challenge_file)?;
    let challenger_data: PublicChallengerData = serde_json::from_str(&challenger_json)?;

    let acceptor_json = fs::read_to_string(&acceptor_file)?;
    let acceptor_data: AcceptorData = serde_json::from_str(&acceptor_json)?;

    let esplora_client = ctx.esplora_client()?;
    let tx_builder = ctx.transaction_builder()?;

    let challenge_tx_bytes = hex::decode(&challenge_tx)?;
    let challenge_transaction = Transaction::consensus_decode(&mut challenge_tx_bytes.as_slice())?;

    let fee_amount = Amount::from_sat(FEES);

    let recipient_pubkey = recipient_pubkey.and_then(|pk| PublicKey::from_str(&pk).ok());

    if challenger {
        println!("Creating challenger sweep transaction...");

        // Parse the witness script from hex
        let witness_script =
            bitcoin::ScriptBuf::from_hex(&acceptor_data.challenge_output_witness_script)?;

        let sweep_tx = tx_builder.sweep_challenge_transaction_challenger(
            &challenge_transaction,
            &witness_script,
            LockTime::Blocks(Height::from_consensus(challenger_data.locktime)?),
            recipient_pubkey,
            fee_amount,
        )?;

        println!("Challenger sweep transaction created:");
        println!("TXID: {}", sweep_tx.compute_txid());
        println!(
            "Raw transaction: {}",
            bitcoin::consensus::encode::serialize_hex(&sweep_tx)
        );

        esplora_client
            .broadcast_transaction(&bitcoin::consensus::encode::serialize_hex(&sweep_tx))
            .await?;
    }

    if acceptor {
        println!("Creating acceptor sweep transaction...");

        // Parse the witness script from hex
        let witness_script_bytes = hex::decode(&acceptor_data.challenge_output_witness_script)?;
        let witness_script = bitcoin::ScriptBuf::from_bytes(witness_script_bytes);

        // Parse challenger pubkey from hex
        let challenger_pubkey_bytes = hex::decode(&challenger_data.challenger_pubkey)?;
        let challenger_pubkey = bitcoin::PublicKey::from_slice(&challenger_pubkey_bytes)?;

        let sweep_tx = tx_builder.sweep_challenge_transaction_acceptor(
            &challenge_transaction,
            &challenger_pubkey,
            &witness_script,
            recipient_pubkey,
            fee_amount,
        )?;

        println!("Acceptor sweep transaction created:");
        println!("TXID: {}", sweep_tx.compute_txid());
        println!(
            "Raw transaction: {}",
            bitcoin::consensus::encode::serialize_hex(&sweep_tx)
        );

        esplora_client
            .broadcast_transaction(&bitcoin::consensus::encode::serialize_hex(&sweep_tx))
            .await?;
    }

    Ok(())
}
