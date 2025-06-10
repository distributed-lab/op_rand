use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Transaction, TxIn, TxOut,
    absolute::LockTime,
    key::{Secp256k1, Verification},
    psbt::PsbtSighashType,
    secp256k1::{All, Context, Message, SecretKey, Signing},
    sighash::SighashCache,
    transaction::Version,
};
use miniscript::psbt::PsbtExt;
use op_rand_types::{FirstRankCommitment, ThirdRankCommitment};

use crate::{
    errors::TransactionError,
    scripts::{create_closing_p2wsh_script, create_p2wpkh_script},
};

/// `TransactionBuilder` performs building transaction with stored public key, needed for scripts.
/// Intended usage flow:
/// - Create new `TransactionBuilder` with `TransactionBuilder::from_pubkey(PublicKey)`
/// - Store deposit tx input from which to take coins for game transactions, you could either
/// build a new tx with `build_and_set_deposit_tx` or just set existing TxIn with `set_deposit_txin`
/// - Build initial transaction or closing partially signed transaction
#[derive(Debug, Clone)]
pub struct TransactionBuilder<C: Context> {
    secret_key: SecretKey,
    ctx: Secp256k1<C>,
}

impl From<SecretKey> for TransactionBuilder<All> {
    fn from(secret_key: SecretKey) -> Self {
        let ctx = Secp256k1::new();
        TransactionBuilder { secret_key, ctx }
    }
}

impl From<&SecretKey> for TransactionBuilder<All> {
    fn from(secret_key: &SecretKey) -> Self {
        let ctx = Secp256k1::new();
        TransactionBuilder {
            secret_key: *secret_key,
            ctx,
        }
    }
}

impl<C: Signing + Verification> TransactionBuilder<C> {
    pub fn new(secret_key: SecretKey, ctx: Secp256k1<C>) -> Self {
        TransactionBuilder { secret_key, ctx }
    }

    /// This method should be used by the Challenger to build a deposit transaction.
    /// Needs a first rank commitment to combine with Challenger's public key
    ///
    /// Note: fees must be handled by the caller
    pub fn build_deposit_transaction(
        &self,
        first_rank_commitment: FirstRankCommitment,
        previous_outputs: Vec<(OutPoint, Amount)>,
        deposit_amount: Amount,
        change_amount: Option<Amount>,
        change_pubkey: Option<PublicKey>,
    ) -> Result<Transaction, TransactionError> {
        let secp_public_key = self.secret_key.public_key(&self.ctx);
        let public_key = PublicKey::new(secp_public_key);
        let challenge_pubkey = first_rank_commitment.combine(&public_key.inner)?;
        let deposit_script = create_p2wpkh_script(&challenge_pubkey.into())?;

        let mut outputs = vec![TxOut {
            value: deposit_amount,
            script_pubkey: deposit_script,
        }];

        if let Some(change_amount) = change_amount {
            let change_script = create_p2wpkh_script(&change_pubkey.unwrap_or(public_key))?;
            outputs.push(TxOut {
                value: change_amount,
                script_pubkey: change_script,
            });
        }

        let inputs = previous_outputs
            .iter()
            .map(|(outpoint, _)| TxIn {
                previous_output: *outpoint,
                ..Default::default()
            })
            .collect();

        let amounts = previous_outputs.iter().map(|(_, amount)| *amount).collect();

        let mut deposit_tx = create_tx(inputs, outputs, None);
        self.sign_transaction(&mut deposit_tx, amounts)?;

        Ok(deposit_tx)
    }

    /// Builds challenge transaction as PSBT and returns it. Needs an input from initial tx
    /// and Challenger's public key, which must be provided by the Challenger, as well as
    /// tweak value to combine with Acceptor's public key
    pub fn build_challenge_tx(
        &self,
        challenger_pubkey: &PublicKey,
        deposit_outpoint: OutPoint,
        third_rank_commitment: ThirdRankCommitment,
        lock_time: LockTime,
        amount: Amount,
        previous_outputs: Vec<(OutPoint, Amount)>,
        change_amount: Option<Amount>,
        change_pubkey: Option<PublicKey>,
    ) -> Result<Psbt, TransactionError> {
        let acceptor_public_key = self.secret_key.public_key(&self.ctx);
        let tweaked_acceptor_pubkey = third_rank_commitment.combine(&acceptor_public_key)?;

        let challenge_script = create_closing_p2wsh_script(
            challenger_pubkey,
            &PublicKey::new(tweaked_acceptor_pubkey),
            lock_time,
        );

        let mut outputs = vec![TxOut {
            value: amount * 2,
            script_pubkey: ScriptBuf::new_p2wsh(&challenge_script.wscript_hash()),
        }];

        if let Some(change_amount) = change_amount {
            let change_script = create_p2wpkh_script(
                &change_pubkey.unwrap_or(PublicKey::new(acceptor_public_key)),
            )?;
            outputs.push(TxOut {
                value: change_amount,
                script_pubkey: change_script,
            });
        }

        let mut inputs = vec![TxIn {
            previous_output: deposit_outpoint,
            ..Default::default()
        }];

        let acceptor_inputs = previous_outputs
            .iter()
            .map(|(outpoint, _)| TxIn {
                previous_output: *outpoint,
                ..Default::default()
            })
            .collect::<Vec<_>>();

        inputs.extend(acceptor_inputs);

        let closing_tx = create_tx(inputs, outputs, None);
        let mut psbt = Psbt::from_unsigned_tx(closing_tx)?;

        for (input_index, (_, amount)) in previous_outputs.iter().enumerate() {
            self.sign_psbt_input(&mut psbt, input_index + 1, *amount, None)?;
        }

        Ok(psbt)
    }

    pub fn complete_challenge_tx(
        &self,
        mut psbt: Psbt,
        deposit_amount: Amount,
        deposit_input_index: usize,
        first_rank_commitment: FirstRankCommitment,
    ) -> Result<Transaction, TransactionError> {
        let deposit_signing_key = first_rank_commitment.add_tweak(&self.secret_key)?;
        self.sign_psbt_input(
            &mut psbt,
            deposit_input_index,
            deposit_amount,
            Some(deposit_signing_key),
        )?;

        psbt.finalize_mut(&self.ctx)?;

        psbt.extract_tx()
            .map_err(TransactionError::ExtractTransactionFailed)
    }

    /// Signs single input inside `Transaction` by its index
    /// - `txout` refers to output being spent by this input
    pub fn sign_single_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        amount: Amount,
    ) -> Result<(), TransactionError> {
        let public_key = self.secret_key.public_key(&self.ctx);
        let script_code = ScriptBuf::new_p2wpkh(&PublicKey::new(public_key).wpubkey_hash()?);

        let mut sighash_cache = SighashCache::new(&*tx);
        let sighash = sighash_cache.p2wpkh_signature_hash(
            input_index,
            &script_code,
            amount,
            EcdsaSighashType::All,
        )?;

        let tx_input = tx
            .input
            .get_mut(input_index)
            .ok_or(TransactionError::InputIndexOutOfBounds)?;

        let message = Message::from_digest_slice(sighash.as_ref())?;
        let signature = self.ctx.sign_ecdsa(&message, &self.secret_key);

        let mut final_signature = signature.serialize_der().to_vec();
        final_signature.push(EcdsaSighashType::All as u8);

        tx_input.witness.clear();
        tx_input.witness.push(final_signature);
        tx_input.witness.push(public_key.serialize());

        Ok(())
    }

    /// Signs single input inside `Psbt` by its index
    /// - `txout` refers to output being spent by this input
    pub fn sign_psbt_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
        amount: Amount,
        secret_key: Option<SecretKey>,
    ) -> Result<(), TransactionError> {
        let psbt_input = psbt
            .inputs
            .get_mut(input_index)
            .ok_or(TransactionError::InputIndexOutOfBounds)?;

        let secret_key = secret_key.unwrap_or(self.secret_key);
        let public_key = secret_key.public_key(&self.ctx);
        let script_pubkey = create_p2wpkh_script(&public_key.into())?;

        let mut sighasher = SighashCache::new(&psbt.unsigned_tx);
        let sighash = sighasher.p2wpkh_signature_hash(
            input_index,
            &script_pubkey,
            amount,
            EcdsaSighashType::All,
        )?;

        let message = Message::from_digest_slice(sighash.as_ref())?;
        let signature = self.ctx.sign_ecdsa(&message, &secret_key);

        let final_signature = bitcoin::ecdsa::Signature {
            signature,
            sighash_type: EcdsaSighashType::All,
        };

        psbt_input
            .partial_sigs
            .insert(PublicKey::new(public_key), final_signature);

        let witness_utxo = TxOut {
            value: amount,
            script_pubkey,
        };
        psbt_input.witness_utxo = Some(witness_utxo);

        let psbt_sighash_type = PsbtSighashType::from(EcdsaSighashType::All);
        if psbt_input.sighash_type.is_none() {
            psbt_input.sighash_type = Some(psbt_sighash_type);
        }

        Ok(())
    }

    /// Signs multiple inputs with the same public and private keys,
    /// assuming the performer uses only outputs owned by the same public key
    pub fn sign_transaction(
        &self,
        tx: &mut Transaction,
        amounts: Vec<Amount>,
    ) -> Result<(), TransactionError> {
        if tx.input.len() != amounts.len() {
            return Err(TransactionError::InputsOutputsLengthMismatch);
        }

        for (input_index, amount) in amounts.iter().enumerate() {
            self.sign_single_input(tx, input_index, *amount)?;
        }

        Ok(())
    }
}

fn create_tx(input: Vec<TxIn>, output: Vec<TxOut>, lock_time: Option<LockTime>) -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: lock_time.unwrap_or(LockTime::ZERO),
        input,
        output,
    }
}
