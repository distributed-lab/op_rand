use color_eyre::eyre::ensure;

use crate::esplora::Utxo;

pub const FEES: u64 = 300;
pub const MIN_CHANGE: u64 = 500;

pub fn select_utxos(utxos: Vec<Utxo>, amount: u64) -> eyre::Result<Vec<Utxo>> {
    let mut selected_utxos = Vec::new();
    let mut remaining_amount = amount;

    for utxo in utxos {
        if remaining_amount == 0 {
            break;
        }

        remaining_amount = remaining_amount.saturating_sub(utxo.value);
        selected_utxos.push(utxo);
    }

    ensure!(
        remaining_amount == 0,
        "Not enough UTXOs to cover the amount"
    );

    Ok(selected_utxos)
}
