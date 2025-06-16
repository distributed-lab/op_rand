use bitcoin::{
    Amount, EcdsaSighashType, Psbt, PublicKey, ScriptBuf, Transaction,
    secp256k1::{self, All, Context, Message, Scalar, SecretKey, Signing},
    sighash::SighashCache,
};
use op_rand_types::FirstRankCommitment;

use crate::errors::TransactionError;

/// `TransactionSigner` handles all transaction signing operations
#[derive(Debug, Clone)]
pub struct TransactionSigner<C: Context> {
    secret_key: SecretKey,
    ctx: secp256k1::Secp256k1<C>,
}

impl From<SecretKey> for TransactionSigner<All> {
    fn from(secret_key: SecretKey) -> Self {
        let ctx = secp256k1::Secp256k1::new();
        TransactionSigner { secret_key, ctx }
    }
}

impl From<&SecretKey> for TransactionSigner<All> {
    fn from(secret_key: &SecretKey) -> Self {
        let ctx = secp256k1::Secp256k1::new();
        TransactionSigner {
            secret_key: *secret_key,
            ctx,
        }
    }
}

impl<C: Signing> TransactionSigner<C> {
    /// Creates a new `TransactionSigner` with the given secret key and context
    pub fn new(secret_key: SecretKey, ctx: secp256k1::Secp256k1<C>) -> Self {
        TransactionSigner { secret_key, ctx }
    }

    /// Returns the context of the `TransactionSigner`
    pub fn ctx(&self) -> &secp256k1::Secp256k1<C> {
        &self.ctx
    }

    /// Signs a p2wsh input for the acceptor using the OP_IF (immediate) branch
    pub fn sign_p2wsh_input_acceptor(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        amount: Amount,
        witness_script: &ScriptBuf,
        second_rank_commitment: SecretKey,
    ) -> Result<(), TransactionError> {
        let mut sighash_cache = SighashCache::new(&*tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(input_index, witness_script, amount, EcdsaSighashType::All)
            .map_err(|_e| TransactionError::FailedToSignP2wshInput)?;

        let scalar = Scalar::from(second_rank_commitment);
        let signing_key = self.secret_key.add_tweak(&scalar)?;
        let message = Message::from_digest_slice(sighash.as_ref())?;
        let signature = self.ctx.sign_ecdsa(&message, &signing_key);

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

    /// Signs a p2wsh input for the challenger using the OP_ELSE (delayed) branch
    pub fn sign_p2wsh_input_challenger(
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

    /// Signs a single input inside `Psbt` by its index
    /// If the secret key is not provided, the original secret key will be used
    pub fn sign_psbt_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
        amount: Amount,
        first_rank_commitment: Option<FirstRankCommitment>,
    ) -> Result<(), TransactionError> {
        let psbt_input = psbt
            .inputs
            .get_mut(input_index)
            .ok_or(TransactionError::InputIndexOutOfBounds)?;

        let mut secret_key = self.secret_key;
        if let Some(first_rank_commitment) = first_rank_commitment {
            secret_key = first_rank_commitment.add_tweak(&self.secret_key)?;
        }

        let public_key = secret_key.public_key(&self.ctx);
        let script_pubkey = ScriptBuf::new_p2wpkh(&PublicKey::new(public_key).wpubkey_hash()?);

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

        let witness_utxo = bitcoin::TxOut {
            value: amount,
            script_pubkey,
        };
        psbt_input.witness_utxo = Some(witness_utxo);

        let psbt_sighash_type = bitcoin::psbt::PsbtSighashType::from(EcdsaSighashType::All);
        if psbt_input.sighash_type.is_none() {
            psbt_input.sighash_type = Some(psbt_sighash_type);
        }

        Ok(())
    }

    /// Signs all transaction inputs with the same secret key
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
