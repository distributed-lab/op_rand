use bitcoin::{
    key::PublicKey,
    absolute::LockTime,
    script::{self, ScriptBuf},
    opcodes,
};

use std::error::Error;

/// Creates PubKeyScript for P2WPKH with given `public_key`
pub fn create_p2wpkh_script(
    public_key: &PublicKey
) -> Result<script::ScriptBuf, Box<dyn Error>> {
    let witness_pubkey_hash = match public_key.wpubkey_hash() {
        Ok(hash) => hash,
        Err(_) => return Err("PubKey must be compressed for P2WPKH.".into())
    };
    
    Ok(ScriptBuf::new_p2wpkh(&witness_pubkey_hash))
}

/// Creates PubKeyScript for initial TX output
/// - `pubkey_a` refers to PubKey of the first counterparty
/// - `pubkey_a1` refers to chosen by 1st CP random value, called A in the paper
pub fn create_init_output_script(
    pubkey_a: &PublicKey,
    pubkey_a1: &PublicKey,
) -> Result<ScriptBuf, Box<dyn Error>> {
    let combined_pubkey = combine_public_keys(pubkey_a, pubkey_a1)?;

    create_p2wpkh_script(&combined_pubkey)
}

/// Create PubKeyScript for closing TX output
/// - `pubkey_a` refers to PubKey of the first counterparty
/// - `pubkey_b` refers to PubKey of the second counterparty
/// - `pubkey_h1` refers to chosen by 2nd CP random value, called H1 in the paper
pub fn create_close_output_script(
    pubkey_a: &PublicKey,
    pubkey_b: &PublicKey,
    pubkey_h1: &PublicKey,
    lock_time: LockTime,
) -> Result<ScriptBuf, Box<dyn Error>> {
    let combined_b_h1 = combine_public_keys(pubkey_b, pubkey_h1)?;
    let witness_script = create_closing_witness_script(
        pubkey_a, &combined_b_h1, lock_time
    );

    Ok(ScriptBuf::new_p2wsh(&witness_script.wscript_hash()))
}

/// Combines public key `pk_base` with tweak `pk_tweak`, returning public key
/// for scripts inside initial and closing transactions' outputs 
pub fn combine_public_keys(
    pk_base: &PublicKey,
    pk_tweak: &PublicKey,
) -> Result<PublicKey, Box<dyn Error>> {
    let pk_combined = match pk_base.inner.combine(&pk_tweak.inner) {
        Ok(pk) => pk,
        Err(_) => return Err("Error combining public key".into()),
    };

    Ok(PublicKey::new(pk_combined))
}

fn create_closing_witness_script(
    pubkey_a: &PublicKey,
    combined_pubkey_b: &PublicKey,
    lock_time: LockTime,
) -> ScriptBuf {
    // As in the paper:
    // OP_IF
    //     <P_b + H1> OP_CHECKSIG
    // OP_ELSE
    //     <LT> OP_CHECKLOCKTIMEVERIFY OP_DROP
    //     <P_a> OP_CHECKSIG
    // OP_ENDIF
    script::Builder::new()
        .push_opcode(opcodes::all::OP_IF)
        .push_key(combined_pubkey_b)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ELSE)
        .push_lock_time(lock_time)
        .push_opcode(opcodes::all::OP_CLTV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_key(pubkey_a)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script()
}