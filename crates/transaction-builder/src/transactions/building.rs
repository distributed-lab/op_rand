use bitcoin::{
    transaction::Version,
    absolute::LockTime,
    Amount, Transaction, TxIn, TxOut, OutPoint, PublicKey, Psbt
};

use crate::transactions::{
    errors::TransactionError,
    pubkey_scripts::*,
};

/// `TransactionBuilder` performs building transaction with stored public key, needed for scripts.
/// Intended usage flow:
/// - Create new `TransactionBuilder` with `TransactionBuilder::from_pubkey(PublicKey)`
/// - Store deposit tx input from which to take coins for game transactions, you could either
/// build a new tx with `build_and_set_deposit_tx` or just set existing TxIn with `set_deposit_txin`
/// - Build initial transaction or closing partially signed transaction
pub struct TransactionBuilder {
    public_key: PublicKey,
    deposit_txin: Option<TxIn>,
}

impl TransactionBuilder {
    pub fn from_pubkey(public_key: PublicKey) -> TransactionBuilder {
        TransactionBuilder { public_key, deposit_txin: None }
    }

    /// Sets TxIn as deposit input for initial and closing transactions.
    /// Overrides any stored value as well
    pub fn set_deposit_txin(&mut self, txin: TxIn) {
        self.deposit_txin = Some(txin);
    }

    /// Builds deposit transaction from inputs, stores corresponding `TxIn` to `TransactionBuilder`
    /// (overriding previous value if stored) and returns built deposit transaction
    pub fn build_and_set_deposit_tx(
        &mut self,
        input: Vec<TxIn>,
        amount: Amount,
    ) -> Result<Transaction, TransactionError> {
        let script = create_p2wpkh_script(&self.public_key)?;

        let output = vec![ TxOut {
            value: amount,
            script_pubkey: script,
        }];

        let dep_tx = create_tx(input, output, None);

        let dep_tx_input = create_txin(&dep_tx, 0);

        self.deposit_txin = Some(dep_tx_input);

        Ok(dep_tx)
    }

    /// Builds initial transaction and returns it.
    /// Needs special tweak value to combine with Challenger's public key
    pub fn build_initial_tx(
        &self,
        tweak_value: &PublicKey,
        amount: Amount,
    ) -> Result<Transaction, TransactionError> {
        if self.deposit_txin.is_none() {
            return Err(TransactionError::NoDepositTxStored)
        }

        let script = create_init_output_script(&self.public_key, tweak_value)?;

        let output = vec![ TxOut {
            value: amount,
            script_pubkey: script,
        }];

        let initial_tx = create_tx(
            vec![self.deposit_txin.clone().unwrap()], output, None
        );

        Ok(initial_tx)
    }

    /// Builds closing transaction as PSBT and returns it. Needs an input from initial tx
    /// and Challenger's public key, which must be provided by the Challenger, as well as
    /// tweak value to combine with Acceptor's public key
    pub fn build_closing_tx(
        &self,
        input_from_initial: TxIn,
        challenger_pubkey: &PublicKey,
        tweak_value: &PublicKey,
        amount: Amount,
        lock_time: LockTime,
    ) -> Result<Psbt, TransactionError> {
        if self.deposit_txin.is_none() {
            return Err(TransactionError::NoDepositTxStored)
        }

        let script = create_close_output_script(
            challenger_pubkey, &self.public_key, tweak_value, lock_time,
        )?;

        let output = vec![TxOut {
            value: amount,
            script_pubkey: script,
        }];

        let closing_tx = create_tx(
            vec![input_from_initial, self.deposit_txin.clone().unwrap()],
            output, None // while we put LockTime in the script, we don't need it in the tx itself
        );

        Ok(Psbt::from_unsigned_tx(closing_tx)?)
    }
}

fn create_tx(
    input: Vec<TxIn>,
    output: Vec<TxOut>,
    lock_time: Option<LockTime>,
) -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: lock_time.unwrap_or(LockTime::ZERO),
        input,
        output,
    }
}

fn create_txin(tx: &Transaction, vout: u32) -> TxIn {
    let out_point = OutPoint {
        txid: tx.compute_txid(),
        vout
    };

    let mut tx_in = TxIn::default();
    tx_in.previous_output = out_point;

    tx_in
}