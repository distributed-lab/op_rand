use std::str::FromStr;

use bitcoin::OutPoint;
use eyre::ensure;

use crate::esplora::Utxo;

pub fn parse_outpoint(s: &str) -> Result<OutPoint, String> {
    OutPoint::from_str(s).map_err(|e| e.to_string())
}

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
