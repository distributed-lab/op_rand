use bitcoin::{
    Psbt, PublicKey, ScriptBuf, Transaction, WPubkeyHash, absolute::LockTime, hashes::Hash,
};
use eyre::ensure;

use crate::scripts::create_challenge_p2wsh_script;

/// Checks that the specified deposit transaction output has a valid locking script:
/// `hash160(P_C)`, where `P_C` is the pubkey of the challenger combined with one of the
/// first rank commitments.
///
/// Should be called by the acceptor to validate the deposit transaction to make sure it
/// can be used as a challenge transaction input.
pub fn validate_deposit_transaction(
    transaction: &Transaction,
    challenger_pubkey_hash: &[u8],
    output_index: usize,
) -> eyre::Result<()> {
    let output = transaction.output[output_index].clone();
    let output_script = output.script_pubkey;
    let pubkey_hash = WPubkeyHash::from_slice(challenger_pubkey_hash)?;
    let expected_script = ScriptBuf::new_p2wpkh(&pubkey_hash);

    ensure!(
        output_script == expected_script,
        "Output script does not match expected script"
    );

    Ok(())
}

/// Checks that the specified PSBT has a valid challenge output. For the the challenger it's
/// important to check that the output script contains their original pubkey with the specified
/// locktime.
///
/// Should be called by the challenger to validate the PSBT to make sure it contains a valid
/// challenge output.
pub fn validate_challenge_psbt(
    psbt: &Psbt,
    acceptor_pubkey_hash: WPubkeyHash,
    challenger_pubkey: PublicKey,
    locktime: LockTime,
    output_index: usize,
) -> eyre::Result<()> {
    let challenge_script =
        create_challenge_p2wsh_script(&challenger_pubkey, acceptor_pubkey_hash, locktime)?;

    let output = psbt.unsigned_tx.output[output_index].clone();
    let output_script = output.script_pubkey;

    let expected_script = ScriptBuf::new_p2wsh(&challenge_script.wscript_hash());

    ensure!(
        output_script == expected_script,
        "Output script does not match expected script"
    );

    Ok(())
}
