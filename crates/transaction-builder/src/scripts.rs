use bitcoin::{
    WPubkeyHash,
    absolute::LockTime,
    key::PublicKey,
    opcodes,
    script::{self, ScriptBuf},
};

use crate::errors::TransactionError;

/// Creates a P2WPKH script from a public key.
pub(crate) fn create_p2wpkh_script(public_key: &PublicKey) -> Result<ScriptBuf, TransactionError> {
    let witness_pubkey_hash = public_key.wpubkey_hash()?;

    Ok(ScriptBuf::new_p2wpkh(&witness_pubkey_hash))
}

/// Constructs a challenge output script for a P2WSH address with conditional spending logic.
///
/// The script allows two spending paths:
///
/// - **If branch (`OP_IF`)**: Can be spent immediately with a signature from the acceptor,
///   but requires that the provided public key matches the `HASH160` of the tweaked acceptor's public key.
///
/// - **Else branch (`OP_ELSE`)**: Allows the challenger to spend the output after a specified `lock_time`,
///   using their own signature.
///
/// Script structure:
/// ```text
/// OP_IF
///     OP_DUP <HASH160(P_a + H)> OP_EQUALVERIFY OP_CHECKSIG
/// OP_ELSE
///     <lock_time> OP_CHECKLOCKTIMEVERIFY OP_DROP
///     <P_c> OP_CHECKSIG
/// OP_ENDIF
/// ```
pub(crate) fn create_challenge_p2wsh_script(
    challenger_pubkey: &PublicKey,
    tweaked_acceptor_pubkey_hash: &WPubkeyHash,
    lock_time: LockTime,
) -> Result<ScriptBuf, TransactionError> {
    let script = script::Builder::new()
        .push_opcode(opcodes::all::OP_IF)
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(tweaked_acceptor_pubkey_hash)
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ELSE)
        .push_lock_time(lock_time)
        .push_opcode(opcodes::all::OP_CLTV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_key(challenger_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();

    Ok(script)
}
