use bitcoin::{Amount, OutPoint, PublicKey, ScriptBuf, Transaction};

use std::error::Error;
use bitcoin::absolute::LockTime;
use creating::*;

mod creating;

pub fn create_initial_tx(
    out_points: Vec<OutPoint>,
    amount: Amount,
    public_key: PublicKey,
) -> Result<Transaction, Box<dyn Error>> {
    let dep_tx = match create_unsigned_deposit_tx(
        out_points, amount, ScriptBuf::new() // TODO: change to actual script!
    ) {
        Ok(tx) => tx,
        Err(e) => return Err(e),
    };
    
    // TODO: signing
    
    let dep_out_point = OutPoint {
        txid: dep_tx.compute_txid(),
        vout: 0,
    };
    
    let init_tx = match create_unsigned_initial_tx(
        dep_out_point, amount, ScriptBuf::new() // TODO: change to actual script!
    ) {
        Ok(tx) => tx,
        Err(e) => return Err(e),
    };
    
    // TODO: signing
    
    Ok(init_tx)
}

pub fn create_closing_tx(
    dep_out_points: Vec<OutPoint>,
    init_out_point: OutPoint,
    amount: Amount,
    lock_time: LockTime,
    public_key: PublicKey,
) -> Result<Transaction, Box<dyn Error>> {
    let dep_tx = match create_unsigned_deposit_tx(
        dep_out_points, amount, ScriptBuf::new() // TODO: change to actual script!
    ) {
        Ok(tx) => tx,
        Err(e) => return Err(e),
    };
    
    // TODO: signing
    
    let dep_out_point = OutPoint {
        txid: dep_tx.compute_txid(),
        vout: 0,
    };
    
    let cls_tx = match create_unsigned_closing_tx(
        init_out_point, dep_out_point, lock_time, amount, ScriptBuf::new() // TODO: change to actual script!  
    ) {
        Ok(tx) => tx,
        Err(e) => return Err(e),
    };
    
    // TODO: signing
    
    Ok(cls_tx)
}