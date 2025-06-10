use bitcoin::{
    key::UncompressedPublicKeyError, psbt::Error as PsbtError, secp256k1::Error as Secp256k1Error,
    sighash::P2wpkhError,
};
use miniscript::psbt::SighashError;

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("Uncompressed public key error: {0}")]
    UncompressedPublicKey(UncompressedPublicKeyError),
    #[error("P2WPKH error: {0}")]
    P2wpkh(P2wpkhError),
    #[error("Secp256k1 error: {0}")]
    Secp256k1(Secp256k1Error),
    #[error("PSBT error: {0}")]
    Psbt(PsbtError),
    #[error("Sighash error: {0}")]
    Sighash(SighashError),
    #[error("Amounts and scripts must be of same length.")]
    AmountsScriptsLengthMismatch,
    #[error("Inputs and outputs must be of same length.")]
    InputsOutputsLengthMismatch,
    #[error("Transaction type mismatch.")]
    TransactionTypeMismatch,
    #[error("Input index out of bounds.")]
    InputIndexOutOfBounds,
    #[error("Failed to extract transaction from PSBT.")]
    ExtractTransactionFailed,
    #[error("Failed to finalize PSBT: {0:?}")]
    PsbtFinalizationFailed(Vec<miniscript::psbt::Error>),
    #[error("No deposit transaction stored.")]
    NoDepositTxStored,
    #[error("Failed to sign p2wsh input.")]
    FailedToSignP2wshInput,
}

impl From<UncompressedPublicKeyError> for TransactionError {
    fn from(err: UncompressedPublicKeyError) -> Self {
        TransactionError::UncompressedPublicKey(err)
    }
}

impl From<P2wpkhError> for TransactionError {
    fn from(err: P2wpkhError) -> Self {
        TransactionError::P2wpkh(err)
    }
}

impl From<Secp256k1Error> for TransactionError {
    fn from(err: Secp256k1Error) -> Self {
        TransactionError::Secp256k1(err)
    }
}

impl From<PsbtError> for TransactionError {
    fn from(err: PsbtError) -> Self {
        TransactionError::Psbt(err)
    }
}

impl From<Vec<miniscript::psbt::Error>> for TransactionError {
    fn from(errors: Vec<miniscript::psbt::Error>) -> Self {
        TransactionError::PsbtFinalizationFailed(errors)
    }
}

impl From<SighashError> for TransactionError {
    fn from(err: SighashError) -> Self {
        TransactionError::Sighash(err)
    }
}
