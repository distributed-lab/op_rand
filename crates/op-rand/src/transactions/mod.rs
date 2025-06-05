mod pubkey_scripts;
mod signing;
mod building;
mod errors;

pub use {
    building::TransactionBuilder,
    signing::TransactionSigner,
};
use bitcoin::{
    Network, PrivateKey, PublicKey,
    secp256k1::Scalar
};
use errors::TransactionError;

/// Combines public key `pk_base` with tweak `pk_tweak`, returning public key
/// for scripts inside initial and closing transactions' outputs 
pub fn combine_public_keys(
    pk_base: &PublicKey,
    pk_tweak: &PublicKey,
) -> Result<PublicKey, TransactionError> {
    let pk_combined = pk_base.inner.combine(&pk_tweak.inner)?;

    Ok(PublicKey::new(pk_combined))
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