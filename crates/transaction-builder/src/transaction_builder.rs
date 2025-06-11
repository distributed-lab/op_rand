use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut,
    absolute::LockTime,
    hashes::{Hash, sha256},
    key::{Secp256k1, Verification},
    psbt::PsbtSighashType,
    secp256k1::{self, All, Context, Message, SecretKey, Signing},
    sighash::SighashCache,
    transaction::Version,
};
use miniscript::psbt::PsbtExt;
use op_rand_types::{FirstRankCommitment, ThirdRankCommitment};

use crate::{
    errors::TransactionError,
    scripts::{create_challenge_p2wsh_script, create_p2wpkh_script},
};

/// `TransactionBuilder` is used by both parties to build deposit and challenge transactions.
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
    /// Creates a new `TransactionBuilder` with the given secret key and context.
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

        // Combine the chosen first rank commitment with the public key to get the challenge public key
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

    /// This method should be used by the Acceptor to build a challenge transaction.
    /// Needs a third rank commitment to combine with Acceptor's public key
    ///
    /// At this point, a PSBT is created and signed only by the Acceptor.
    /// The PSBT is then returned to the Challenger to complete the transaction.
    ///
    /// Note: fees must be handled by the caller
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<(ScriptBuf, Psbt), TransactionError> {
        let acceptor_public_key = self.secret_key.public_key(&self.ctx);

        // Combine the chosen third rank commitment with the acceptor's public key to get the challenge public key
        let tweaked_acceptor_pubkey = third_rank_commitment.combine(&acceptor_public_key)?;

        let challenge_script = create_challenge_p2wsh_script(
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

        let challenge_tx = create_tx(inputs, outputs, None);
        let mut psbt = Psbt::from_unsigned_tx(challenge_tx)?;

        for (input_index, (_, amount)) in previous_outputs.iter().enumerate() {
            // Increment input index by 1 to skip the deposit input
            self.sign_psbt_input(&mut psbt, input_index + 1, *amount, None)?;
        }

        Ok((challenge_script, psbt))
    }

    /// This method should be used by the Challenger to complete the challenge transaction.
    /// It signs the deposit input and finalizes the PSBT.
    pub fn complete_challenge_tx(
        &self,
        mut psbt: Psbt,
        deposit_amount: Amount,
        deposit_input_index: usize,
        first_rank_commitment: FirstRankCommitment,
    ) -> Result<Transaction, TransactionError> {
        // Sign the deposit transaction output using the chosen first rank commitment
        let deposit_signing_key = first_rank_commitment.add_tweak(&self.secret_key)?;
        self.sign_psbt_input(
            &mut psbt,
            deposit_input_index,
            deposit_amount,
            Some(deposit_signing_key),
        )?;

        psbt.finalize_mut(&self.ctx)?;

        psbt.extract_tx()
            .map_err(|_e| TransactionError::ExtractTransactionFailed)
    }

    /// This method should be used by the Acceptor to sweep the challenge output.
    /// It will result in a correct transaction only if the acceptor chose the correct
    /// third rank commitment.
    pub fn sweep_challenge_output_acceptor(
        &self,
        challenge_transaction: &Transaction,
        challenger_pubkey: &PublicKey,
        witness_script: &ScriptBuf,
        recipient_pubkey: Option<PublicKey>,
        fee: Amount,
    ) -> Result<Transaction, TransactionError> {
        let inputs = vec![TxIn {
            previous_output: OutPoint::new(challenge_transaction.compute_txid(), 0),
            ..Default::default()
        }];

        let outputs = vec![TxOut {
            value: challenge_transaction.output[0].value - fee,
            script_pubkey: create_p2wpkh_script(
                &recipient_pubkey.unwrap_or(self.secret_key.public_key(&self.ctx).into()),
            )?,
        }];

        // Extract the witness stack from the deposit input
        let deposit_input_witness_stack = &challenge_transaction.input[0].witness;

        // Extract the witness pubkey from the witness stack
        let witness_pubkey = PublicKey::from_slice(&deposit_input_witness_stack[1])
            .map_err(|_e| TransactionError::Secp256k1(secp256k1::Error::InvalidPublicKey))?;

        // Extract the second rank commitment by subtracting challenger_pubkey from witness_pubkey
        let negated_challenger_pubkey = challenger_pubkey.inner.negate(&self.ctx);
        let second_rank_commitment = witness_pubkey.inner.combine(&negated_challenger_pubkey)?;
        let second_rank_commitment_hash = sha256::Hash::hash(&second_rank_commitment.serialize());
        let second_rank_commitment_sk =
            SecretKey::from_slice(second_rank_commitment_hash.as_byte_array())?;

        // Add the second rank commitment to the acceptor's secret key to get the tweaked secret key
        let tweaked_acceptor_sk = self
            .secret_key
            .add_tweak(&second_rank_commitment_sk.into())?;

        let mut tx = create_tx(inputs, outputs, None);

        self.sign_p2wsh_input_acceptor(
            &mut tx,
            0,
            challenge_transaction.output[0].value,
            witness_script,
            tweaked_acceptor_sk,
        )?;

        Ok(tx)
    }

    /// Signs a p2wsh input for the acceptor using the OP_IF (immediate) branch
    fn sign_p2wsh_input_acceptor(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        amount: Amount,
        witness_script: &ScriptBuf,
        tweaked_secret_key: SecretKey,
    ) -> Result<(), TransactionError> {
        let mut sighash_cache = SighashCache::new(&*tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(input_index, witness_script, amount, EcdsaSighashType::All)
            .map_err(|_e| TransactionError::FailedToSignP2wshInput)?;

        let message = Message::from_digest_slice(sighash.as_ref())?;
        let signature = self.ctx.sign_ecdsa(&message, &tweaked_secret_key);

        let mut final_signature = signature.serialize_der().to_vec();
        final_signature.push(EcdsaSighashType::All as u8);

        let tx_input = tx
            .input
            .get_mut(input_index)
            .ok_or(TransactionError::InputIndexOutOfBounds)?;

        // Build witness for OP_IF branch: <signature> <1> <witness_script>
        tx_input.witness.clear();
        tx_input.witness.push(final_signature); // Acceptor's signature with tweaked key
        tx_input.witness.push(vec![1]); // Push 1 to take OP_IF branch
        tx_input.witness.push(witness_script.to_bytes()); // The witness script

        Ok(())
    }

    /// This method should be used by the Challenger to sweep the challenge output.
    /// It will result in a correct transaction only after the time lock has expired and
    /// the acceptor has not swept the challenge output.
    pub fn sweep_challenge_output_challenger(
        &self,
        challenge_transaction: &Transaction,
        witness_script: &ScriptBuf,
        lock_time: LockTime,
        recipient_pubkey: Option<PublicKey>,
        fee: Amount,
    ) -> Result<Transaction, TransactionError> {
        let challenger_pubkey = self.secret_key.public_key(&self.ctx);

        let inputs = vec![TxIn {
            previous_output: OutPoint::new(challenge_transaction.compute_txid(), 0),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            ..Default::default()
        }];

        let outputs = vec![TxOut {
            value: challenge_transaction.output[0].value - fee,
            script_pubkey: create_p2wpkh_script(
                &recipient_pubkey.unwrap_or(PublicKey::new(challenger_pubkey)),
            )?,
        }];

        let mut tx = create_tx(inputs, outputs, Some(lock_time));

        // Challenger sweep tx is signed by the original secret key
        self.sign_p2wsh_input_challenger(
            &mut tx,
            0,
            challenge_transaction.output[0].value,
            witness_script,
        )?;

        Ok(tx)
    }

    /// Signs a p2wsh input for the challenger using the OP_ELSE (delayed) branch
    fn sign_p2wsh_input_challenger(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        amount: Amount,
        witness_script: &ScriptBuf,
    ) -> Result<(), TransactionError> {
        let mut sighash_cache = SighashCache::new(&*tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(input_index, witness_script, amount, EcdsaSighashType::All)
            .map_err(|_e| TransactionError::FailedToSignP2wshInput)?;

        let message = Message::from_digest_slice(sighash.as_ref())?;
        let signature = self.ctx.sign_ecdsa(&message, &self.secret_key);

        let mut final_signature = signature.serialize_der().to_vec();
        final_signature.push(EcdsaSighashType::All as u8);

        let tx_input = tx
            .input
            .get_mut(input_index)
            .ok_or(TransactionError::InputIndexOutOfBounds)?;

        // Build witness for OP_ELSE branch: <signature> <0> <witness_script>
        tx_input.witness.clear();
        tx_input.witness.push(final_signature); // Challenger's signature
        tx_input.witness.push(vec![]); // Push 0 to take OP_ELSE branch
        tx_input.witness.push(witness_script.to_bytes()); // The witness script

        Ok(())
    }

    /// Signs a single input inside `Transaction` by its index
    fn sign_single_input(
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

    /// Signs a single input inside `Psbt` by its index
    /// If the secret key is not provided, the original secret key will be used
    fn sign_psbt_input(
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

    /// Signs all transaction inputs with the same secret key
    fn sign_transaction(
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

/// Creates a new `Transaction` with the given inputs, outputs and lock time
fn create_tx(input: Vec<TxIn>, output: Vec<TxOut>, lock_time: Option<LockTime>) -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: lock_time.unwrap_or(LockTime::ZERO),
        input,
        output,
    }
}
