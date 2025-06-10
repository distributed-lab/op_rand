use bitcoin::{
    secp256k1::{Message, All},
    key::{Secp256k1, PrivateKey},
    sighash::SighashCache,
    script::ScriptBuf,
    EcdsaSighashType, Transaction, TxOut, Psbt
};
use bitcoin::psbt::PsbtSighashType;
use crate::transactions::{
    errors::TransactionError,
};

/// `TransactionSigner` performs signing of any transaction, passed to corresponding methods,
/// with a same Secp256k1 context and same private key
pub struct TransactionSigner {
    secp: Secp256k1<All>,
    private_key: PrivateKey,
}

impl TransactionSigner {
    pub fn new(secp: Secp256k1<All>, private_key: PrivateKey) -> TransactionSigner {
        TransactionSigner { secp, private_key }
    }

    /// Signs single input inside `Transaction` by its index
    /// - `txout` refers to output being spent by this input
    fn sign_tx_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        txout: &TxOut,
    ) -> Result<(), TransactionError> {
        let public_key = self.private_key.public_key(&self.secp);
        let script_code = ScriptBuf::new_p2pkh(&public_key.pubkey_hash());

        let mut sighasher = SighashCache::new(&*tx);
        let sighash = sighasher.p2wpkh_signature_hash(
            input_index, &script_code, txout.value, EcdsaSighashType::All,
        )?;

        let tx_input = tx.input.get_mut(input_index)
            .ok_or(TransactionError::InputIndexOutOfBounds)?;

        let message = Message::from_digest_slice(sighash.as_ref())?;
        let signature = self.secp.sign_ecdsa(&message, &self.private_key.inner);

        let mut final_signature = signature.serialize_der().to_vec();
        final_signature.push(EcdsaSighashType::All as u8);

        tx_input.witness.clear();
        tx_input.witness.push(final_signature);
        tx_input.witness.push(public_key.to_bytes());

        Ok(())
    }

    /// Signs single input inside `Psbt` by its index
    /// - `txout` refers to output being spent by this input
    pub fn sign_psbt_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
        txout: &TxOut,
    ) -> Result<(), TransactionError> {
        let psbt_input = psbt.inputs.get_mut(input_index)
            .ok_or(TransactionError::InputIndexOutOfBounds)?;

        let public_key = self.private_key.public_key(&self.secp);
        let script_code = ScriptBuf::new_p2pkh(&public_key.pubkey_hash());

        let mut sighasher = SighashCache::new(&psbt.unsigned_tx);
        let sighash = sighasher.p2wpkh_signature_hash(
            input_index, &script_code, txout.value, EcdsaSighashType::All,
        )?;

        let message = Message::from_digest_slice(sighash.as_ref())?;
        let signature = self.secp.sign_ecdsa(&message, &self.private_key.inner);

        let final_signature = bitcoin::ecdsa::Signature {
            signature, sighash_type: EcdsaSighashType::All
        };

        psbt_input.partial_sigs.insert(public_key, final_signature);

        let psbt_sighash_type = PsbtSighashType::from(EcdsaSighashType::All);
        if psbt_input.sighash_type.is_none() {
            psbt_input.sighash_type = Some(psbt_sighash_type);
        }

        Ok(())
    }

    /// Signs multiple inputs with the same public and private keys,
    /// assuming the performer uses only outputs owned by the same public key
    pub fn sign_multi_input(
        &self,
        tx: &mut Transaction,
        txouts: Vec<TxOut>,
    ) -> Result<(), TransactionError> {
        if tx.input.len() != txouts.len() {
            return Err(TransactionError::InputsOutputsLengthMismatch);
        }

        for (input_index, txout) in txouts.iter().enumerate() {
            self.sign_tx_input(tx, input_index, txout)?;
        }

        Ok(())
    }
}