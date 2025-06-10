use bitcoin::{Address, CompressedPublicKey};
use clap::{ArgGroup, Args};
use color_eyre::eyre;

use std::str::FromStr;

use crate::context::Context;

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
    pub recipient_address: Option<String>,

    /// Path to the challenge JSON file
    #[clap(long, default_value = "challenger.json")]
    pub challenge_file: String,

    #[clap(long, group = "try_spend")]
    pub challenger: bool,

    #[clap(long, group = "try_spend")]
    pub acceptor: bool,
}

pub async fn run(
    TrySpendArgs {
        challenge_tx,
        recipient_address,
        challenge_file,
        challenger,
        acceptor,
    }: TrySpendArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    let cfg = ctx.config()?;
    let esplora_client = ctx.esplora_client()?;
    let tx_builder = ctx.transaction_builder()?;

    if challenger {
        println!("Challenger");
    }

    if acceptor {
        println!("Acceptor");
    }

    Ok(())
}
