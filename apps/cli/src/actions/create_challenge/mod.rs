use bitcoin::{
    Address, Amount, CompressedPublicKey, OutPoint, PublicKey, Txid,
    consensus::Encodable,
    hashes::{Hash, ripemd160, sha256},
    secp256k1::rand::thread_rng,
};
use clap::Args;
use color_eyre::{
    eyre,
    eyre::{OptionExt, ensure},
};
use op_rand_prover::{BarretenbergProver, OpRandProver};
use op_rand_types::Commitments;
use serde::{Deserialize, Serialize};
use std::{fs, str::FromStr};

use crate::{
    context::{Context, setup_progress_bar},
    util::{FEES, MIN_CHANGE, select_utxos},
};

#[derive(Args, Debug)]
pub struct CreateChallengeArgs {
    /// Challenge amount in satoshis.
    #[clap(long)]
    pub amount: u64,

    /// Number of commitments to create.s
    #[clap(long, default_value = "2")]
    pub commitments_count: u32,

    /// Change public key.
    #[clap(long)]
    pub change_pubkey: Option<String>,

    /// Output file path for the challenge JSON
    #[clap(long, default_value = "challenger.json")]
    pub public_output: String,

    /// Output file path for the private challenge JSON
    #[clap(long, default_value = "private_challenger.json")]
    pub private_output: String,
}

#[derive(Serialize, Deserialize)]
pub struct PublicChallengerData {
    pub id: String,
    pub amount: u64,
    pub deposit_outpoint: OutPoint,
    pub third_rank_commitments: [String; 2],
    pub challenger_pubkey: String,
    pub challenger_pubkey_hash: String,
    pub proof: String,
    pub vk: String,
}

#[derive(Serialize, Deserialize)]
pub struct PrivateChallengerData {
    pub id: String,
    pub amount: u64,
    pub deposit_transaction: String,
    pub first_rank_commitments: [String; 2],
    pub selected_first_rank_commitment: String,
}

pub async fn run(
    CreateChallengeArgs {
        amount,
        commitments_count,
        public_output,
        private_output,
        change_pubkey,
    }: CreateChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    ensure!(
        commitments_count == 2,
        "OP_RAND currently only supports 2 commitments"
    );

    let cfg = ctx.config()?;
    let esplora_client = ctx.esplora_client()?;
    let transaction_builder = ctx.transaction_builder()?;
    let private_key = cfg.private_key;
    let secp = ctx.secp_ctx();
    let public_key = private_key.public_key(secp).inner;
    let address = Address::p2wpkh(
        &CompressedPublicKey::from_private_key(secp, &private_key).unwrap(),
        cfg.network,
    );

    let utxos = esplora_client.get_utxos(&address.to_string()).await?;
    let selected_utxos = select_utxos(utxos, amount + FEES)?;

    let prover = BarretenbergProver::default();

    let pb = setup_progress_bar("Setting up the challenger circuit...".into());
    let prover_clone = prover.clone();
    tokio::task::spawn_blocking(move || {
        prover_clone
            .setup_challenger_circuit()
            .expect("Failed to setup challenger circuit")
    })
    .await?;
    pb.finish_with_message("Challenger circuit is set up");

    let commitments = Commitments::generate(secp, &mut thread_rng())?;

    let first_rank_commitments = commitments.first_rank_commitments();
    let random_first_rank_commitment = commitments
        .pick_random_first_rank_commitment(&mut thread_rng())
        .ok_or_eyre("No first rank commitments available")?;

    let (_commitment_sk, commitment_pk) = random_first_rank_commitment.inner();
    let tweaked_pk = public_key.combine(&commitment_pk)?;

    let third_rank_commitments = commitments.third_rank_commitments();

    let sha256_hash = sha256::Hash::hash(&tweaked_pk.serialize());
    let ripemd160_hash = ripemd160::Hash::hash(sha256_hash.as_byte_array());

    let pb = setup_progress_bar("Generating the challenger proof...".into());
    let proof = prover.generate_challenger_proof(
        first_rank_commitments.to_owned(),
        third_rank_commitments.to_owned(),
        &public_key,
        ripemd160_hash.to_byte_array(),
    )?;
    pb.finish_with_message("Challenger proof generated");

    let inputs_sum = selected_utxos.iter().map(|utxo| utxo.value).sum::<u64>();
    let change_amount = inputs_sum - amount - FEES;
    let change = if change_amount < MIN_CHANGE {
        None
    } else {
        Some(Amount::from_sat(change_amount))
    };
    let prevouts = selected_utxos
        .iter()
        .map(|utxo| {
            Ok((
                OutPoint::new(Txid::from_str(&utxo.txid)?, utxo.vout),
                Amount::from_sat(utxo.value),
            ))
        })
        .collect::<Result<Vec<_>, eyre::Error>>()?;

    let pb = setup_progress_bar("Creating a deposit transaction...".into());
    let deposit_tx = transaction_builder.build_deposit_transaction(
        random_first_rank_commitment.to_owned(),
        prevouts,
        Amount::from_sat(amount),
        change,
        change_pubkey.and_then(|pk| PublicKey::from_str(&pk).ok()),
    )?;

    pb.finish_with_message("Deposit transaction created");

    let pb = setup_progress_bar("Assembling the challenger data...".into());
    let id = uuid::Uuid::new_v4().to_string();

    let public_challenge_output = PublicChallengerData {
        id: id.clone(),
        amount,
        deposit_outpoint: OutPoint::new(deposit_tx.compute_txid(), 0),
        third_rank_commitments: [
            hex::encode(third_rank_commitments[0].inner().serialize()),
            hex::encode(third_rank_commitments[1].inner().serialize()),
        ],
        challenger_pubkey: hex::encode(public_key.serialize()),
        challenger_pubkey_hash: hex::encode(ripemd160_hash.to_byte_array()),
        proof: hex::encode(proof.proof()),
        vk: hex::encode(proof.vk()),
    };

    let json_output = serde_json::to_string_pretty(&public_challenge_output)?;
    fs::write(&public_output, json_output)?;

    let mut tx_bytes = Vec::new();
    deposit_tx.consensus_encode(&mut tx_bytes)?;

    let private_challenge_output = PrivateChallengerData {
        id,
        amount,
        deposit_transaction: hex::encode(tx_bytes),
        first_rank_commitments: [
            hex::encode(first_rank_commitments[0].inner().0.secret_bytes()),
            hex::encode(first_rank_commitments[1].inner().0.secret_bytes()),
        ],
        selected_first_rank_commitment: hex::encode(
            random_first_rank_commitment.inner().0.secret_bytes(),
        ),
    };

    let private_json_output = serde_json::to_string_pretty(&private_challenge_output)?;
    fs::write(&private_output, private_json_output)?;

    pb.finish_with_message(format!(
        "Challenge created successfully.\nShare the public data saved in {} with the acceptor\nDo not share the private data saved in {}",
        public_output,
        private_output
    ));

    Ok(())
}
