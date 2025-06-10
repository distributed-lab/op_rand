use bitcoin::{
    key::UncompressedPublicKeyError, psbt::Error as PsbtError, secp256k1::Error as Secp256k1Error,
    sighash::P2wpkhError,
};
use std::fmt;

#[derive(Debug)]
pub enum TransactionError {
    UncompressedPublicKey(UncompressedPublicKeyError),
    P2wpkh(P2wpkhError),
    Secp256k1(Secp256k1Error),
    Psbt(PsbtError),
    AmountsScriptsLengthMismatch,
    InputsOutputsLengthMismatch,
    NoDepositTxStored,
    TransactionTypeMismatch,
    InputIndexOutOfBounds,
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TransactionError::UncompressedPublicKey(ref err) => {
                write!(f, "Bictoin Uncompressed public key error: {}", err)
            }
            TransactionError::P2wpkh(ref err) => {
                write!(f, "Bitcoin P2WPKH error: {}", err)
            }
            TransactionError::Secp256k1(ref err) => {
                f.write_str(&format!("Bitcoin Secp256k1 error: {}", err))
            }
            TransactionError::Psbt(ref err) => f.write_str(&format!("Bitcoin PSBT error: {}", err)),
            TransactionError::NoDepositTxStored => {
                f.write_str("TransactionBuilder must store some deposit transaction.")
            }
            TransactionError::AmountsScriptsLengthMismatch => {
                f.write_str("Amounts and scripts must be of same length.")
            }
            TransactionError::InputsOutputsLengthMismatch => {
                f.write_str("Inputs and outputs must be of same length.")
            }
            TransactionError::TransactionTypeMismatch => {
                f.write_str("Transaction is a different type from expected.")
            }
            TransactionError::InputIndexOutOfBounds => {
                f.write_str("Provided input index is out of bounds for this transaction.")
            }
        }
    }
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
