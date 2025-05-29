use bitcoin::{Transaction, TxIn, TxOut, OutPoint, Amount, ScriptBuf, Sequence};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;

use std::{vec, error::Error};

/// Creates unsigned deposit transaction used by each counterparty to select amount for game,
/// called TX_a and TX_b in the paper
pub fn create_unsigned_deposit_tx(
    input_points: Vec<OutPoint>,
    value: Amount,
    script_pubkey: ScriptBuf,
) -> Result<Transaction, Box<dyn Error>> {
    let mut input: Vec<TxIn> = vec![];
    for input_point in input_points {
        let tx_in = get_unsigned_input(input_point);
        input.push(tx_in);
    }

    let output = vec![
        TxOut {
            value,
            script_pubkey,
        },
    ];

    let tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input,
        output,
    };

    Ok(tx)
}

/// Creates unsigned initial transaction, called TX_1 in the paper
/// - Takes `out_point` to previous tx, `script_pubkey` output conditions and `amount` to send
pub fn create_unsigned_initial_tx(
    out_point: OutPoint,
    value: Amount,
    script_pubkey: ScriptBuf,
) -> Result<Transaction, Box<dyn Error>> {
    let input = vec![
        get_unsigned_input(out_point),
    ];

    let output = vec![
        TxOut {
            value,
            script_pubkey,
        }
    ];

    let tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input,
        output,
    };

    Ok(tx)
}

/// Creates unsigned closing transaction, called TX_2 in the paper
/// - `init_out_point` refers to initial transaction,
/// - `dep_out_point` refers to second counterparty's deposit transaction
pub fn create_unsigned_closing_tx(
    init_out_point: OutPoint,
    dep_out_point: OutPoint,
    lock_time: LockTime,
    value: Amount,
    script_pubkey: ScriptBuf,
) -> Result<Transaction, Box<dyn Error>> {
    let input = vec![
        get_unsigned_input(init_out_point),
        get_unsigned_input(dep_out_point),
    ];

    let output = vec![
        TxOut {
            value,
            script_pubkey,
        }
    ];

    let tx = Transaction {
        version: Version::ONE,
        lock_time,
        input,
        output,
    };

    Ok(tx)
}

/// Returns input with given outpoint and sequence value needed for using locktime
fn get_unsigned_input(previous_output: OutPoint) -> TxIn {
    let mut tx_in = TxIn::default();
    
    tx_in.previous_output = previous_output;
    tx_in.sequence = Sequence::ENABLE_LOCKTIME_NO_RBF; // lets transaction have a locktime
    
    tx_in
}