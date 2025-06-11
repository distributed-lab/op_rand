use bitcoin::{Address, CompressedPublicKey};

use crate::{
    context::Context,
    ui::{self, CHAIN, CHECK, GEAR},
};
use console::style;

pub async fn run(mut ctx: Context) -> eyre::Result<()> {
    println!(
        "{}",
        ui::header("                          💰 WALLET BALANCE 💰")
    );

    println!(
        "\n{} {}",
        GEAR,
        style("Fetching wallet information...").bold().blue()
    );

    let cfg = ctx.config()?;
    let esplora_client = ctx.esplora_client()?;
    let private_key = cfg.private_key;
    let secp = ctx.secp_ctx();
    let address = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(secp, &private_key).unwrap(),
        cfg.network,
    );

    println!(
        "{} {} {}",
        CHECK,
        style("Wallet address:").bold().yellow(),
        style(&address.to_string()).bright().white()
    );

    println!(
        "\n{} {}",
        CHAIN,
        style("Querying UTXOs from Esplora...").bold().blue()
    );

    let utxos = esplora_client.get_utxos(&address.to_string()).await?;

    println!(
        "{} {} UTXOs found",
        CHECK,
        style(utxos.len().to_string()).bold().green()
    );

    // Calculate confirmed and unconfirmed balances
    let mut confirmed_balance: u64 = 0;
    let mut unconfirmed_balance: u64 = 0;

    for utxo in &utxos {
        if utxo.status.confirmed {
            confirmed_balance += utxo.value;
        } else {
            unconfirmed_balance += utxo.value;
        }
    }

    let total_balance = confirmed_balance + unconfirmed_balance;

    // Display balance information
    println!("\n{}", style("┌─ BALANCE SUMMARY").bold().blue());
    println!("│");

    if confirmed_balance > 0 {
        println!(
            "│ 💎 {} {}",
            style("Confirmed Balance:").bold().green(),
            ui::format_bitcoin_amount(confirmed_balance)
        );
    } else {
        println!(
            "│ 💎 {} {}",
            style("Confirmed Balance:").bold().green(),
            style("0 satoshis (0.00000000 BTC)").dim()
        );
    }

    if unconfirmed_balance > 0 {
        println!(
            "│ ⏳ {} {}",
            style("Unconfirmed Balance:").bold().yellow(),
            ui::format_bitcoin_amount(unconfirmed_balance)
        );
    } else {
        println!(
            "│ ⏳ {} {}",
            style("Unconfirmed Balance:").bold().yellow(),
            style("0 satoshis (0.00000000 BTC)").dim()
        );
    }

    println!("│");
    println!(
        "│ 🏆 {} {}",
        style("Total Balance:").bold().cyan(),
        ui::format_bitcoin_amount(total_balance)
    );

    if !utxos.is_empty() {
        println!("\n{}", style("┌─ UTXO DETAILS").bold().blue());
        println!("│");

        for (i, utxo) in utxos.iter().enumerate() {
            let status_icon = if utxo.status.confirmed { "✅" } else { "⏳" };
            let status_text = if utxo.status.confirmed {
                "confirmed"
            } else {
                "unconfirmed"
            };

            println!(
                "│ {} {} {}",
                status_icon,
                style(format!("UTXO {}:", i + 1)).bold(),
                style(ui::format_bitcoin_amount(utxo.value))
                    .bright()
                    .white()
            );
            println!(
                "│   {} {}:{}",
                style("Outpoint:").dim(),
                style(&utxo.txid[..16]).dim(),
                style(utxo.vout.to_string()).dim()
            );
            println!(
                "│   {} {}",
                style("Status:").dim(),
                if utxo.status.confirmed {
                    style(status_text).green()
                } else {
                    style(status_text).yellow()
                }
            );

            if let Some(block_height) = utxo.status.block_height {
                println!(
                    "│   {} {}",
                    style("Block Height:").dim(),
                    style(block_height.to_string()).dim()
                );
            }

            if i < utxos.len() - 1 {
                println!("│");
            }
        }
    }

    if total_balance == 0 {
        println!("\n{}", style("┌─ WALLET STATUS").bold().blue());
        println!("│");
        println!(
            "│ {} {}",
            style("Status:").dim(),
            style("Wallet is empty - no UTXOs found").yellow()
        );
        println!(
            "│ {} {}",
            style("Tip:").dim(),
            style("Send some funds to this address to see your balance").dim()
        );
    }

    println!("\n{}", "═".repeat(80));

    Ok(())
}
