use bitcoin::{
    Amount, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, WPubkeyHash,
    absolute::LockTime,
    hashes::{Hash, sha256},
    key::{Secp256k1, Verification},
    secp256k1::{self, All, Context, SecretKey, Signing},
    transaction::Version,
};
use miniscript::psbt::PsbtExt;
use op_rand_types::{FirstRankCommitment, ThirdRankCommitment};

use crate::{
    errors::TransactionError,
    scripts::{create_challenge_p2wsh_script, create_p2wpkh_script},
    transaction_signer::TransactionSigner,
};

/// `TransactionBuilder` is used by both parties to build deposit and challenge transactions.
#[derive(Debug, Clone)]
pub struct TransactionBuilder<C: Context> {
    public_key: PublicKey,
    signer: TransactionSigner<C>,
}

impl From<SecretKey> for TransactionBuilder<All> {
    fn from(secret_key: SecretKey) -> Self {
        let signer = TransactionSigner::from(secret_key);
        let public_key = secret_key.public_key(signer.ctx());
        TransactionBuilder {
            signer,
            public_key: public_key.into(),
        }
    }
}

impl From<&SecretKey> for TransactionBuilder<All> {
    fn from(secret_key: &SecretKey) -> Self {
        let signer = TransactionSigner::from(secret_key);
        let public_key = secret_key.public_key(signer.ctx());
        TransactionBuilder {
            signer,
            public_key: public_key.into(),
        }
    }
}

impl<C: Signing + Verification> TransactionBuilder<C> {
    /// Creates a new `TransactionBuilder` with the given secret key and context.
    pub fn new(secret_key: SecretKey, ctx: Secp256k1<C>) -> Self {
        let signer = TransactionSigner::new(secret_key, ctx);
        let public_key = secret_key.public_key(signer.ctx());
        TransactionBuilder {
            signer,
            public_key: public_key.into(),
        }
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
        // Combine the chosen first rank commitment with the public key to get the challenge public key
        let challenge_pubkey = first_rank_commitment.combine(&self.public_key.inner)?;
        let deposit_script = create_p2wpkh_script(&challenge_pubkey.into())?;

        let mut outputs = vec![TxOut {
            value: deposit_amount,
            script_pubkey: deposit_script,
        }];

        if let Some(change_amount) = change_amount {
            let change_script = create_p2wpkh_script(&change_pubkey.unwrap_or(self.public_key))?;
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
        self.signer.sign_transaction(&mut deposit_tx, amounts)?;

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
    ) -> Result<Psbt, TransactionError> {
        // Combine the chosen third rank commitment with the acceptor's public key to get the challenge public key
        let tweaked_acceptor_pubkey = third_rank_commitment.combine(&self.public_key.inner)?;

        let challenge_script = create_challenge_p2wsh_script(
            challenger_pubkey,
            &PublicKey::new(tweaked_acceptor_pubkey).wpubkey_hash()?,
            lock_time,
        )?;

        let mut outputs = vec![TxOut {
            value: amount * 2,
            script_pubkey: ScriptBuf::new_p2wsh(&challenge_script.wscript_hash()),
        }];

        if let Some(change_amount) = change_amount {
            let change_script = create_p2wpkh_script(&change_pubkey.unwrap_or(self.public_key))?;
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
            self.signer
                .sign_psbt_input(&mut psbt, input_index + 1, *amount, None)?;
        }

        Ok(psbt)
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
        self.signer.sign_psbt_input(
            &mut psbt,
            deposit_input_index,
            deposit_amount,
            Some(first_rank_commitment),
        )?;

        psbt.finalize_mut(self.signer.ctx())?;

        let tx = psbt
            .extract_tx()
            .map_err(|_e| TransactionError::ExtractTransactionFailed)?;

        Ok(tx)
    }

    /// This method should be used by the Acceptor to sweep the challenge output.
    /// It will result in a correct transaction only if the acceptor chose the correct
    /// third rank commitment.
    pub fn sweep_challenge_output_acceptor(
        &self,
        challenge_transaction: &Transaction,
        challenger_pubkey: &PublicKey,
        recipient_pubkey: Option<PublicKey>,
        lock_time: LockTime,
        fee: Amount,
    ) -> Result<Transaction, TransactionError> {
        let inputs = vec![TxIn {
            previous_output: OutPoint::new(challenge_transaction.compute_txid(), 0),
            ..Default::default()
        }];

        let outputs = vec![TxOut {
            value: challenge_transaction.output[0].value - fee,
            script_pubkey: create_p2wpkh_script(&recipient_pubkey.unwrap_or(self.public_key))?,
        }];

        // Extract the witness stack from the deposit input
        let deposit_input_witness_stack = &challenge_transaction.input[0].witness;

        // Extract the witness pubkey from the witness stack
        let witness_pubkey = PublicKey::from_slice(&deposit_input_witness_stack[1])
            .map_err(|_e| TransactionError::Secp256k1(secp256k1::Error::InvalidPublicKey))?;

        // Extract the second rank commitment by subtracting challenger_pubkey from witness_pubkey
        let negated_challenger_pubkey = challenger_pubkey.inner.negate(self.signer.ctx());
        let second_rank_commitment = witness_pubkey.inner.combine(&negated_challenger_pubkey)?;
        let second_rank_commitment_hash = sha256::Hash::hash(&second_rank_commitment.serialize());
        let second_rank_commitment_sk =
            SecretKey::from_slice(second_rank_commitment_hash.as_byte_array())?;

        let mut tx = create_tx(inputs, outputs, None);

        self.signer.sign_p2wsh_input_acceptor(
            &mut tx,
            0,
            challenge_transaction.output[0].value,
            challenger_pubkey,
            second_rank_commitment_sk,
            lock_time,
        )?;

        Ok(tx)
    }

    /// This method should be used by the Challenger to sweep the challenge output.
    /// It will result in a correct transaction only after the time lock has expired and
    /// the acceptor has not swept the challenge output.
    pub fn sweep_challenge_output_challenger(
        &self,
        challenge_transaction: &Transaction,
        lock_time: LockTime,
        acceptor_pubkey_hash: WPubkeyHash,
        recipient_pubkey: Option<PublicKey>,
        fee: Amount,
    ) -> Result<Transaction, TransactionError> {
        let inputs = vec![TxIn {
            previous_output: OutPoint::new(challenge_transaction.compute_txid(), 0),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            ..Default::default()
        }];

        let outputs = vec![TxOut {
            value: challenge_transaction.output[0].value - fee,
            script_pubkey: create_p2wpkh_script(&recipient_pubkey.unwrap_or(self.public_key))?,
        }];

        let mut tx = create_tx(inputs, outputs, Some(lock_time));
        let witness_script =
            create_challenge_p2wsh_script(&self.public_key, &acceptor_pubkey_hash, lock_time)?;

        // Challenger sweep tx is signed by the original secret key
        self.signer.sign_p2wsh_input_challenger(
            &mut tx,
            0,
            challenge_transaction.output[0].value,
            &witness_script,
        )?;

        Ok(tx)
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
