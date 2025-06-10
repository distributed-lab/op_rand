use bitcoin::{
    absolute::LockTime,
    key::PublicKey,
    opcodes,
    script::{self, ScriptBuf},
};

use crate::errors::TransactionError;

/// Creates PubKeyScript for P2WPKH with given `public_key`
pub(crate) fn create_p2wpkh_script(public_key: &PublicKey) -> Result<ScriptBuf, TransactionError> {
    let witness_pubkey_hash = public_key.wpubkey_hash()?;

    Ok(ScriptBuf::new_p2wpkh(&witness_pubkey_hash))
}

/// Creates custom script for closing transaction output:  
/// ```_
/// OP_IF
///     <P_a + H> OP_CHECKSIG
/// OP_ELSE  
///     <LT> OP_CHECKLOCKTIMEVERIFY OP_DROP  
///     <P_c> OP_CHECKSIG  
/// OP_ENDIF
pub(crate) fn create_closing_p2wsh_script(
    challenger_pubkey: &PublicKey,
    tweaked_acceptor_pubkey: &PublicKey,
    lock_time: LockTime,
) -> ScriptBuf {
    script::Builder::new()
        .push_opcode(opcodes::all::OP_IF)
        .push_key(tweaked_acceptor_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ELSE)
        .push_lock_time(lock_time)
        .push_opcode(opcodes::all::OP_CLTV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_key(challenger_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script()
}
