use bitcoin::{
    key::{PublicKey, Secp256k1, PrivateKey},
    script::ScriptBuf,
    Transaction,
    TxOut,
    EcdsaSighashType,
    sighash::{SighashCache},
    secp256k1::{Message, All, Scalar},
    Network
};

use std::error::Error;

/// Helper function, performing exact logic on signing single input corresponding to P2WPKH output
fn sign_p2wpkh_input(
    secp: &Secp256k1<All>,
    tx: &mut Transaction,
    input_index: usize,
    txout: &TxOut,
    public_key: &PublicKey,
    private_key: &PrivateKey,
    sighash_type: EcdsaSighashType,
) -> Result<(), Box<dyn Error>> {
    let script_code = ScriptBuf::new_p2pkh(&public_key.pubkey_hash());
    let mut sighasher = SighashCache::new(tx.clone());

    let sighash = sighasher.p2wpkh_signature_hash(
        input_index,
        &script_code,
        txout.value,
        sighash_type,
    ).expect("Error computing sighash.");

    let message = Message::from_digest_slice(sighash.as_ref())
        .expect("Invalid message digest.");
    let signature = secp.sign_ecdsa(&message, &private_key.inner);

    let mut final_signature = signature.serialize_der().to_vec();
    final_signature.push(sighash_type as u8);

    tx.input[input_index].witness.clear();
    tx.input[input_index].witness.push(final_signature);
    tx.input[input_index].witness.push(public_key.to_bytes());

    Ok(())
}

/// Signs deposit transaction's multiple inputs with the same public and private key,
/// assuming the counterparty deposits only outputs owned by the same public key
pub fn sign_multi_input_dep_tx(
    secp: &Secp256k1<All>,
    tx: &mut Transaction,
    txouts: Vec<TxOut>,
    public_key: &PublicKey,
    private_key: &PrivateKey,
) -> Result<(), Box<dyn Error>> {
    if tx.input.len() != txouts.len() {
        return Err(Box::from(
            "Txouts number must match number of transaction inputs."
        ))
    }

    for (input_index, txout) in txouts.iter().enumerate() {
        sign_p2wpkh_input(
            secp,
            tx,
            input_index,
            txout,
            public_key,
            private_key,
            EcdsaSighashType::All,
        )?;
    }

    Ok(())
}

/// Signs initial transaction input, corresponding to deposit transaction's output, with
/// provided public and private keys
pub fn sign_init_tx(
    secp: &Secp256k1<All>,
    tx: &mut Transaction,
    txout: &TxOut,
    public_key: &PublicKey,
    private_key: &PrivateKey,
) -> Result<(), Box<dyn Error>> {
    sign_p2wpkh_input(
        secp,
        tx,
        0,
        txout,
        public_key,
        private_key,
        EcdsaSighashType::All
    )
}

/// Signs closing transaction's inputs, corresponding to initial transaction and deposit
/// transaction, with provided public and private keys
pub fn sign_close_tx(
    secp: &Secp256k1<All>,
    tx: &mut Transaction,
    init_txout: &TxOut,
    init_public_key: &PublicKey,
    init_private_key: &PrivateKey,
    dep_txout: &TxOut,
    dep_public_key: &PublicKey,
    dep_private_key: &PrivateKey,
) -> Result<(), Box<dyn Error>> {
    sign_p2wpkh_input(
        secp,
        tx,
        0,
        init_txout,
        init_public_key,
        init_private_key,
        EcdsaSighashType::All
    )?;

    sign_p2wpkh_input(
        secp,
        tx,
        1,
        dep_txout,
        dep_public_key,
        dep_private_key,
        EcdsaSighashType::All
    )?;

    Ok(())
}

/// Combines secret key `pk_base` with tweak `pk_tweak`, returning private key suitable
/// for signing messages with corresponding combined public key
pub fn combine_secret_keys(
    pk_base: &PrivateKey,
    pk_tweak: &PrivateKey,
) -> Result<PrivateKey, bitcoin::secp256k1::Error> {
    let combined_pk_inner = pk_base.inner;
    let tweak_scalar = Scalar::from_be_bytes(pk_tweak.inner.secret_bytes())
            .map_err(|_| bitcoin::secp256k1::Error::InvalidSecretKey)?;

    combined_pk_inner.add_tweak(&tweak_scalar)?;

    Ok(PrivateKey::from_slice(&combined_pk_inner.secret_bytes(), Network::Bitcoin)?)
}