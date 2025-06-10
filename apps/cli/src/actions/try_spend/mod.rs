use bitcoin::{Address, CompressedPublicKey};
use clap::Args;
use color_eyre::eyre;

use std::str::FromStr;

use crate::context::Context;

#[derive(Args, Debug)]
pub struct TrySpendArgs {
    /// Challenge amount in satoshis.
    #[clap(long, short)]
    pub txid: String,

    /// Tweak
    #[clap(long)]
    pub tweak: Option<String>,

    /// Recipient address
    #[clap(long)]
    pub recipient_address: Option<String>,
}

pub async fn run(
    TrySpendArgs {
        txid,
        tweak,
        recipient_address,
    }: TrySpendArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    let cfg = ctx.config()?;
    let esplora_client = ctx.esplora_client()?;
    let private_key = cfg.private_key;
    let secp = ctx.secp_ctx();

    let output_address = match recipient_address {
        Some(recipient_address) => Address::from_str(&recipient_address)
            .expect("Failed to parse recipient address")
            .assume_checked(),
        None => {
            let public_key = private_key.public_key(secp).inner;
            Address::p2wpkh(
                &CompressedPublicKey::from_private_key(secp, &private_key).unwrap(),
                cfg.network,
            )
        }
    };

    // TODO: sign and broadcast a transaction

    Ok(())
}
