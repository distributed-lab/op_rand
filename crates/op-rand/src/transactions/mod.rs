use bitcoin::{Amount, OutPoint, PublicKey, ScriptBuf, Transaction};

use std::error::Error;
use bitcoin::absolute::LockTime;
use creating::*;
use pubkey_scripts::*;

mod creating;
mod pubkey_scripts;

/// Creates initial transactions as well as deposit transaction for choosing value to deposit
/// by first counterparty, returns both these transactions
/// - `out_points` refers to OutPoints from where to get amount for deposit TX
/// - `public_key` refers to first counterparty's public key
/// - `value_a` refers to random value chosen by first counterparty (called A in the paper)
pub fn create_initial_tx(
    out_points: Vec<OutPoint>,
    amount: Amount,
    public_key: &PublicKey,
    value_a: &PublicKey,
) -> Result<(Transaction, Transaction), Box<dyn Error>> {
    let dep_tx = create_deposit_tx(
        out_points, amount, public_key
    )?;
    
    let dep_out_point = OutPoint {
        txid: dep_tx.compute_txid(),
        vout: 0,
    };
    
    let init_script = create_init_output_script(public_key, value_a)?;
    
    let init_tx = match create_unsigned_initial_tx(
        dep_out_point, amount, init_script
    ) {
        Ok(tx) => tx,
        Err(e) => return Err(e),
    };
    
    // TODO: signing
    
    Ok((dep_tx, init_tx))
}

/// Creates closing transactions as well as deposit transaction for choosing value to deposit
/// by second counterparty, returns both these transactions
/// - `dep_out_points` refers to OutPoints from where to get amount for deposit TX
/// - `init_out_points` refers to initial TX outpoint
/// - `public_key_a` refers to first counterparty's public key
/// - `public_key_b` refers to second counterparty's public key
/// - `value_h` refers to random value chosen by second counterparty (called H1 in the paper)
pub fn create_closing_tx(
    dep_out_points: Vec<OutPoint>,
    init_out_point: OutPoint,
    amount: Amount,
    lock_time: LockTime,
    public_key_a: &PublicKey,
    public_key_b: &PublicKey,
    value_h: &PublicKey,
) -> Result<Transaction, Box<dyn Error>> {
    let dep_tx = create_deposit_tx(
        dep_out_points, amount, &public_key_b
    )?;
    
    let dep_out_point = OutPoint {
        txid: dep_tx.compute_txid(),
        vout: 0,
    };
    
    let close_script = create_close_output_script(
        public_key_a, public_key_b, value_h, lock_time
    )?;
    
    let close_tx = match create_unsigned_closing_tx(
        init_out_point, dep_out_point, lock_time, amount, close_script  
    ) {
        Ok(tx) => tx,
        Err(e) => return Err(e),
    };
    
    // TODO: signing
    
    Ok(close_tx)
}

fn create_deposit_tx(
    out_points: Vec<OutPoint>,
    amount: Amount,
    public_key: &PublicKey,
) -> Result<Transaction, Box<dyn Error>> {
    let dep_script = create_p2wpkh_script(&public_key)?;

    let dep_tx = match create_unsigned_deposit_tx(
        out_points, amount, dep_script
    ) {
        Ok(tx) => tx,
        Err(e) => return Err(e),
    };

    // TODO: signing
    
    Ok(dep_tx)
}